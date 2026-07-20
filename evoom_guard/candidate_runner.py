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

A :class:`CandidateRunner` prepares a real boundary and returns
:class:`IsolationEvidence` describing **what is available to its launcher**,
never merely what was requested. Actual use is a separate fact: the black-box
judge records a launcher receipt, plus a runtime-written CID for container
modes. If a stronger boundary was asked for and cannot be prepared — the Docker
daemon is down, the image does not exist, the runtime is missing — the runner
**raises** :class:`IsolationUnavailable` (fail-closed). There is no silent
fallback to a weaker boundary.

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

from evoom_guard.execution import (
    ProcessContainmentError as _SubprocessContainmentError,
)
from evoom_guard.execution import (
    ProcessOutputLimitExceeded as _SubprocessOutputLimitExceeded,
)
from evoom_guard.execution import (
    run_bounded_subprocess as _run_bounded_subprocess,
)
from evoom_guard.isolation import (
    DOCKER_CONTROL_TIMEOUT_SECONDS as _DOCKER_CONTROL_TIMEOUT_SECONDS,
)
from evoom_guard.isolation import (
    DOCKER_PULL_TIMEOUT_SECONDS as _DOCKER_PULL_TIMEOUT_SECONDS,
)
from evoom_guard.isolation import (
    DockerControlRequest,
    execute_docker_control,
    inspect_docker_image,
)

# Docker writes candidate container IDs here.  The directory is owned by the
# judge and deliberately lives beside (not inside) the disposable repo copy, so
# candidate code cannot forge cleanup targets through its mounted source tree.
CANDIDATE_CID_DIRNAME = "candidate-container-cids"

class IsolationUnavailable(RuntimeError):
    """The requested candidate boundary could not be delivered honestly.

    Raised instead of falling back to a weaker boundary, so a verdict never
    claims isolation it did not actually run under.
    """


def _run_docker_control(
    command: list[str], *, timeout: float
) -> subprocess.CompletedProcess[str]:
    """Run a Docker control-plane command without unbounded host capture.

    The Docker daemon and client diagnostics are outside the judge's trust
    boundary.  An image pull or inspect must therefore not retain arbitrary
    output in memory, and an interrupted Docker client must have its process
    tree contained before the preflight can be reported as unavailable.
    """
    try:
        request = DockerControlRequest.from_command(
            command,
            timeout=timeout,
            environment=os.environ,
        )
        return execute_docker_control(
            request,
            process_runner=_run_bounded_subprocess,
            process_argv=command,
        ).as_completed_process(args=command)
    except (_SubprocessOutputLimitExceeded, _SubprocessContainmentError) as exc:
        raise IsolationUnavailable(
            f"Docker control command could not be safely captured: {exc}"
        ) from exc


@dataclass
class IsolationEvidence:
    """What boundary the launcher prepared — actual invocation is recorded elsewhere.

    ``delivered`` is a capability fact, not proof that the pack invoked the
    launcher. Assurance policy must combine it with the black-box invocation
    receipt; ``requested`` is kept so a verdict can show the gap was honored.
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
    returned :class:`IsolationEvidence` reflects preparation. The caller must
    separately observe a launcher invocation before claiming candidate isolation.
    """

    isolation: str = "subprocess"
    docker_image: str | None = None
    docker_network: str = "none"
    docker_runtime: str | None = None
    mem_limit_mb: int = 0
    python: str = ""  # interpreter token the pack uses for python targets
    # Optional judge-owned receipt channel.  These values are written only to
    # the launcher sidecar (outside the candidate tree), never exported to the
    # candidate environment.  The launcher sends the unguessable token before
    # it starts the candidate, giving the judge evidence that EVOGUARD_EXEC was
    # actually invoked rather than merely prepared.
    invocation_socket: str | None = None
    invocation_token: str | None = None
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
        return self._prepare_supported_host(workdir, target)

    def _prepare_supported_host(
        self, workdir: str, target: str
    ) -> tuple[str, dict[str, str], IsolationEvidence]:
        """Prepare after the public POSIX platform gate has succeeded."""
        try:
            if self.isolation in ("docker", "gvisor"):
                return self._prepare_container(workdir, target)
            return self._prepare_subprocess(workdir, target)
        except IsolationUnavailable:
            raise
        except (OSError, subprocess.SubprocessError) as exc:
            # Docker CLI discovery/version/inspect/pull and launcher writes are
            # environmental delivery failures, not guard crashes. Preserve
            # KeyboardInterrupt/SystemExit (BaseException) for the operator.
            raise IsolationUnavailable(
                f"{self.isolation} isolation preflight failed: {exc}"
            ) from exc

    # ---- subprocess boundary ---------------------------------------------- #
    def _prepare_subprocess(
        self, workdir: str, target: str
    ) -> tuple[str, dict[str, str], IsolationEvidence]:
        launcher = self._write_launcher(
            workdir,
            self._launcher_config({"mode": "subprocess", "target": target}),
        )
        evidence = IsolationEvidence(
            requested=self.isolation,
            delivered="subprocess",
            note=(
                "candidate launcher prepared for a host subprocess: same machine, "
                "filesystem and user as the judge. A launcher receipt is required "
                "before assurance can claim this boundary was invoked."
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
        probe = _run_docker_control(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            timeout=_DOCKER_CONTROL_TIMEOUT_SECONDS,
        )
        if probe.returncode != 0:
            raise IsolationUnavailable(
                f"{self.isolation} isolation requested but the Docker daemon is not "
                f"reachable: {(probe.stderr or probe.stdout).strip()[:200]}"
            )
        runtime = self.docker_runtime or ("runsc" if self.isolation == "gvisor" else None)
        image_digest = self._ensure_image(self.docker_image)

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
        # The launcher runs with the pack snapshot as cwd, so Docker needs an
        # absolute host path for --cidfile even if an embedding caller supplied
        # a relative workdir.
        cidfile_dir = os.path.join(os.path.abspath(workdir), CANDIDATE_CID_DIRNAME)
        os.makedirs(cidfile_dir, mode=0o700, exist_ok=True)
        launcher = self._write_launcher(
            workdir,
            self._launcher_config(
                {
                    "mode": "docker",
                    "prefix": prefix,
                    "cidfile_dir": cidfile_dir,
                }
            ),
        )

        evidence = IsolationEvidence(
            requested=self.isolation,
            delivered=self.isolation,
            image=self.docker_image,
            image_digest=image_digest,
            network=self.docker_network,
            runtime=runtime,
            note=(
                "candidate launcher prepared a network-less, read-only container; "
                "the repo copy is mounted read-only and the judge-owned pack is not "
                "mounted. A launcher receipt plus runtime-written CID is required "
                "before assurance can claim the container boundary was invoked."
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
    def _launcher_config(self, cfg: dict[str, Any]) -> dict[str, Any]:
        """Attach an invocation receipt only when the channel is complete.

        A socket without its token (or vice versa) cannot produce trustworthy
        evidence, so an embedding caller that cannot create the POSIX receipt
        channel gets a conservative launcher with no receipt claim.
        """
        if self.invocation_socket and self.invocation_token:
            return {
                **cfg,
                "invocation_socket": self.invocation_socket,
                "invocation_token": self.invocation_token,
            }
        return cfg

    def _ensure_image(self, image: str) -> str:
        """Return the image's content digest, pulling it once if absent."""
        digest = self._image_digest(image)
        if digest is not None:
            return digest
        pull = _run_docker_control(
            ["docker", "pull", image], timeout=_DOCKER_PULL_TIMEOUT_SECONDS
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
        inspected = inspect_docker_image(
            image,
            control_runner=_run_docker_control,
            timeout=_DOCKER_CONTROL_TIMEOUT_SECONDS,
        )
        if inspected.returncode != 0:
            return None
        return inspected.stdout.strip() or None

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
        # The sidecar may contain the judge's invocation token. Keep it
        # owner-only even if an embedding caller supplied a permissive umask.
        os.chmod(path + ".json", stat.S_IRUSR | stat.S_IWUSR)
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "#!/usr/bin/env python3\n"
                "import json, os, secrets, socket, sys\n"
                "with open(__file__ + '.json', encoding='utf-8') as _f:\n"
                "    CFG = json.load(_f)\n"
                "argv = sys.argv[1:]\n"
                "if not argv:\n"
                "    sys.exit('evoguard launcher: no command given')\n"
                "receipt_path = CFG.get('invocation_socket')\n"
                "receipt_token = CFG.get('invocation_token')\n"
                "if receipt_path and receipt_token:\n"
                "    # Fail closed: a candidate must not run if the judge cannot\n"
                "    # first record that this launcher invocation happened.\n"
                "    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as _s:\n"
                "        _s.sendto(receipt_token.encode('ascii'), receipt_path)\n"
                "if CFG['mode'] == 'subprocess':\n"
                "    os.chdir(CFG['target'])\n"
                "    os.execvp(argv[0], argv)\n"
                "else:\n"
                "    prefix = CFG['prefix']\n"
                "    cidfile_dir = CFG.get('cidfile_dir')\n"
                "    if cidfile_dir:\n"
                "        # One launcher can be invoked concurrently by many pack tests.\n"
                "        # Docker requires each --cidfile path not to exist yet.\n"
                "        cidfile = os.path.join(\n"
                "            cidfile_dir,\n"
                "            f'{os.getpid()}-{secrets.token_hex(16)}.cid',\n"
                "        )\n"
                "        # The pinned image is the final prefix item; --cidfile is a\n"
                "        # docker-run option and therefore must precede that image.\n"
                "        cmd = prefix[:-1] + ['--cidfile', cidfile, prefix[-1]] + argv\n"
                "    else:\n"
                "        cmd = prefix + argv\n"
                "    os.execvp(cmd[0], cmd)\n"
            )
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IRUSR)
        return path
