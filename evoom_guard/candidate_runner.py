# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""How the black-box judge *actually* runs the candidate — and proves it.

The black-box judge exercises the candidate only across a process boundary. The
question this module answers honestly is: **across what kind of boundary?** A
plain host subprocess shares the machine, the filesystem and the user with the
judge; a container does not. The earlier design let the caller *ask* for
``--isolation docker`` and then wrote ``candidate_isolation: docker`` into the
verdict **without ever starting a container** — a verdict that lied about its own
guarantee. This module removes that gap.

A :class:`CandidateRunner` delivers a real boundary and returns
:class:`IsolationEvidence` describing **what actually ran**, never what was
requested. If a stronger boundary was asked for and cannot be delivered — the
Docker daemon is down, the image does not exist, the runtime is missing — the
runner **raises** :class:`IsolationUnavailable` (fail-closed). There is no silent
fallback to a weaker boundary, because a fallback is exactly how a verdict comes
to claim isolation it never had.

The launcher is a Python file with a POSIX shebang and is executed directly to
preserve its shell-free argv contract. Native Windows cannot execute that file
through ``CreateProcess``; every black-box isolation mode therefore fails closed
before probing subprocess, Docker, or gVisor. Repo-native verification remains a
separate Windows-capable path.

The candidate is launched through a small **launcher script** the runner writes
outside both the candidate copy and the judge-owned pack. The pack stays
isolation-agnostic: it invokes ``$EVOGUARD_EXEC <argv…>`` and the launcher runs
that argv in the delivered boundary with the repo copy as the working root. In
Docker mode the repo copy is mounted **read-only** and the pack is **not mounted
at all**, so candidate code cannot reach the pack to tamper with it, nor write to
the host — the two attacks that survive a same-host subprocess.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from typing import Any


class IsolationUnavailable(RuntimeError):
    """The requested candidate boundary could not be delivered honestly.

    Raised instead of falling back to a weaker boundary, so a verdict never
    claims isolation it did not actually run under.
    """


@dataclass
class IsolationEvidence:
    """What the candidate *actually* ran under — recorded from delivery, not request.

    ``delivered`` is the ground truth the assurance profile and the enforceable
    policy must read; ``requested`` is kept only so a verdict can show the gap
    was honored rather than papered over.
    """

    requested: str
    delivered: str
    image: str | None = None
    image_digest: str | None = None
    network: str | None = None
    runtime: str | None = None
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "requested": self.requested,
            "delivered": self.delivered,
            "image": self.image,
            "image_digest": self.image_digest,
            "network": self.network,
            "runtime": self.runtime,
            "note": self.note,
        }


@dataclass
class CandidateRunner:
    """Builds the launcher + env that the black-box pack uses to reach the candidate.

    Construct with the *requested* isolation; call :meth:`prepare` to (a) verify
    the boundary can really be delivered and (b) materialize the launcher. The
    returned :class:`IsolationEvidence` reflects delivery.
    """

    isolation: str = "subprocess"
    docker_image: str | None = None
    docker_network: str = "none"
    docker_runtime: str | None = None
    mem_limit_mb: int = 0
    python: str = ""  # interpreter token the pack uses for python targets
    _launcher: str = field(default="", init=False)

    # ---- public API -------------------------------------------------------- #
    def prepare(self, workdir: str, target: str) -> tuple[str, dict[str, str], IsolationEvidence]:
        """Return ``(launcher_path, env_extra, evidence)`` for reaching ``target``.

        ``env_extra`` is merged into the judge's environment; the pack reads
        ``EVOGUARD_EXEC`` (the launcher) and ``EVOGUARD_PYTHON`` (interpreter
        token). Raises :class:`IsolationUnavailable` when the requested
        black-box launcher or isolation boundary cannot be delivered.
        """
        if os.name == "nt":
            raise IsolationUnavailable(
                "black-box candidate launching currently requires a POSIX host; "
                "use GitHub Actions/Linux or WSL on Windows"
            )
        if self.isolation in ("docker", "gvisor"):
            return self._prepare_container(workdir, target)
        return self._prepare_subprocess(workdir, target)

    # ---- subprocess boundary ---------------------------------------------- #
    def _prepare_subprocess(
        self, workdir: str, target: str
    ) -> tuple[str, dict[str, str], IsolationEvidence]:
        launcher = self._write_launcher(workdir, {"mode": "subprocess", "target": target})
        evidence = IsolationEvidence(
            requested=self.isolation,
            delivered="subprocess",
            note=(
                "candidate ran as a host subprocess: same machine, filesystem and "
                "user as the judge (the judge process still never imports it). "
                "Use --isolation docker for a container boundary."
            ),
        )
        env = {
            "EVOGUARD_EXEC": launcher,
            "EVOGUARD_TARGET": target,
            "EVOGUARD_PYTHON": self.python or "python3",
        }
        return launcher, env, evidence

    # ---- container boundary ----------------------------------------------- #
    def _prepare_container(
        self, workdir: str, target: str
    ) -> tuple[str, dict[str, str], IsolationEvidence]:
        if not self.docker_image:
            raise IsolationUnavailable(
                f"{self.isolation} isolation requires a container image (--docker-image)"
            )
        if shutil.which("docker") is None:
            raise IsolationUnavailable(
                f"{self.isolation} isolation requested but the docker CLI was not found"
            )
        # Fail-closed daemon probe: no daemon → no container → no docker verdict.
        probe = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True, text=True, timeout=30,
        )
        if probe.returncode != 0:
            raise IsolationUnavailable(
                f"{self.isolation} isolation requested but the Docker daemon is not "
                f"reachable: {(probe.stderr or probe.stdout).strip()[:200]}"
            )
        runtime = self.docker_runtime or ("runsc" if self.isolation == "gvisor" else None)
        image_digest = self._ensure_image(self.docker_image)
        # Prove the boundary really executes (image + runtime actually run a
        # container) before we let any verdict claim it.
        self._delivery_probe(image_digest, runtime)

        # A fully-resolved argv PREFIX (no shell, no env expansion). The launcher
        # appends the pack's argv and execs it directly, so image/network/runtime/
        # target are never interpolated into a shell string.
        prefix = [
            "docker", "run", "--rm", "--network", self.docker_network,
            "--read-only", "--tmpfs", "/tmp:rw,exec",
            "--pids-limit", "256", "--cpus", "1",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--ulimit", "nofile=1024:1024",
            "-e", "HOME=/tmp", "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "LANG=C.UTF-8",
            "-v", f"{target}:/candidate:ro", "-w", "/candidate",
        ]
        getuid = getattr(os, "getuid", None)
        getgid = getattr(os, "getgid", None)
        if callable(getuid) and callable(getgid):
            prefix += ["--user", f"{getuid()}:{getgid()}"]
        if runtime:
            prefix += ["--runtime", runtime]
        if self.mem_limit_mb > 0:
            prefix += ["--memory", f"{self.mem_limit_mb}m"]
        # Execute the exact image bytes we inspected, never the mutable tag.
        prefix.append(image_digest)
        launcher = self._write_launcher(workdir, {"mode": "docker", "prefix": prefix})

        evidence = IsolationEvidence(
            requested=self.isolation,
            delivered=self.isolation,
            image=self.docker_image,
            image_digest=image_digest,
            network=self.docker_network,
            runtime=runtime,
            note=(
                "candidate ran inside a network-less, read-only container; the repo "
                "copy was mounted read-only and the judge-owned pack was not mounted "
                "at all, so candidate code could neither write the host nor reach the "
                "pack. Verdict still came from the judge's own out-of-container pytest."
            ),
        )
        env = {
            "EVOGUARD_EXEC": launcher,
            "EVOGUARD_TARGET": target,
            # Inside the container the interpreter is just "python"/"python3".
            "EVOGUARD_PYTHON": "python3",
        }
        return launcher, env, evidence

    # ---- helpers ----------------------------------------------------------- #
    def _ensure_image(self, image: str) -> str:
        """Return the image's content digest, pulling it once if absent."""
        digest = self._image_digest(image)
        if digest is not None:
            return digest
        pull = subprocess.run(
            ["docker", "pull", image], capture_output=True, text=True, timeout=600
        )
        if pull.returncode != 0:
            raise IsolationUnavailable(
                f"container image {image!r} is not available and could not be pulled: "
                f"{(pull.stderr or pull.stdout).strip()[:200]}"
            )
        digest = self._image_digest(image)
        if digest is None:
            raise IsolationUnavailable(
                f"container image {image!r} was pulled but has no resolvable image ID"
            )
        return digest

    @staticmethod
    def _image_digest(image: str) -> str | None:
        r = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode != 0:
            return None
        return r.stdout.strip() or None

    def _delivery_probe(self, image: str, runtime: str | None) -> None:
        cmd = ["docker", "run", "--rm", "--network", "none"]
        if runtime:
            cmd += ["--runtime", runtime]
        cmd += [image, "true"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise IsolationUnavailable(
                f"container boundary could not be started for {image!r}"
                + (f" with runtime {runtime!r}" if runtime else "")
                + f": {(r.stderr or r.stdout).strip()[:200]}"
            )

    @staticmethod
    def _write_launcher(workdir: str, cfg: dict[str, Any]) -> str:
        """Write a SHELL-FREE launcher (+ its JSON config) and return its path.

        The launcher execs the candidate via ``os.execvp`` with an argv **list**,
        so no value (image / network / runtime / target) is ever interpolated into
        a shell command — there is no shell, hence no command-injection surface.
        The config travels in a sidecar JSON file, so nothing is embedded in code
        either.
        """
        import json as _json

        path = os.path.join(workdir, "evoguard_exec.py")
        with open(path + ".json", "w", encoding="utf-8") as f:
            _json.dump(cfg, f)
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "with open(__file__ + '.json', encoding='utf-8') as _f:\n"
                "    CFG = json.load(_f)\n"
                "argv = sys.argv[1:]\n"
                "if not argv:\n"
                "    sys.exit('evoguard launcher: no command given')\n"
                "if CFG['mode'] == 'subprocess':\n"
                "    os.chdir(CFG['target'])\n"
                "    os.execvp(argv[0], argv)\n"
                "else:\n"
                "    cmd = CFG['prefix'] + argv\n"
                "    os.execvp(cmd[0], cmd)\n"
            )
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IRUSR)
        return path
