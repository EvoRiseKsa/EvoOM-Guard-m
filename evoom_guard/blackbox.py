# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""The external black-box judge — the fix for same-process report forgery.

The default judge runs the candidate's code in the **same process** as pytest
and the report writer, so a patch that writes ``atexit`` + ``os._exit(0)`` +
a forged ``--junitxml`` can fake a ``PASS`` (see ``docs/ASSURANCE.md``). No
in-process change can close that: same-process authority is same-process control.

The black-box judge closes it by construction:

  * The **verdict-producing process is the judge's own** — it runs a pack of
    **judge-owned tests** (the "protocol pack") and NEVER imports the candidate's
    code. Its exit code is therefore authoritative: the candidate cannot register
    an ``atexit`` hook in it, cannot call ``os._exit`` on it, cannot rewrite its
    report.
  * The candidate is exercised **only across a process boundary** — the pack
    invokes it as a subprocess (a CLI, a server, `python -m tool`, …) through the
    ``EVOGUARD_EXEC`` launcher, which runs it under the delivered isolation, and
    asserts on its observable outputs. Forgery
    code in the candidate's source runs only inside those child processes, where
    ``os._exit(0)`` affects the child, not the judge. The pack checks *outputs*,
    not the child's exit code, so a lying child changes nothing.

Guarantee and its edge (stated plainly):

  * report_integrity becomes **external_process_isolated**: the demonstrated
    same-process forgery is defeated — proven by an adversarial test that plants
    the exact ``atexit``/``os._exit`` forgery in the candidate and still gets the
    correct ``FAIL``.
  * The one residual is a *detached* grandchild the candidate spawns that sleeps
    and races the judge's read of its report. The judge reads its report into
    memory the instant pytest returns (all pack subprocesses have exited by then)
    and grades primarily by its **own exit code**, so this race is already
    impractical; run with ``--isolation docker`` to remove it entirely (the
    container is torn down, reaping any lingering process). Documented, not hidden.

Scope: this fits targets with a **process/protocol boundary** — CLIs, HTTP
services, DB-backed programs. A pure library that the pack must ``import`` is
back in-process and gets the same-process assurance; wrap it behind a thin CLI
to get the black-box guarantee. See ``docs/BLACKBOX.md``.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, NamedTuple

from evoom_guard.candidate_runner import CandidateRunner, IsolationUnavailable
from evoom_guard.verifiers.repo_verifier import (
    apply_blocks_to_copy,
    copy_repo_tree,
    distill_diagnostics,
    is_safe_relpath,
    parse_file_blocks,
    parse_junit_xml,
    parse_patch_blocks,
)


class BlackboxResult(NamedTuple):
    passed: bool
    tests_passed: int
    tests_total: int
    diagnostics: str
    ran: bool          # did the judge pack actually run to a verdict?
    error: str | None  # set when the run could not be graded (setup problem)
    pack_sha256: str | None = None       # content digest of the judge-owned pack
    pack_manifest: dict | None = None    # optional pack.json (id/version/…)
    junit_sha256: str | None = None      # digest of the judge-owned report
    isolation: dict[str, Any] | None = None   # IsolationEvidence.as_dict() — DELIVERED
    deleted_applied: list[str] | None = None  # deletions actually applied to the copy


def _pack_digest_and_manifest(pack_dir: str) -> tuple[str, dict | None]:
    """Content digest of the pack (order-independent) + optional pack.json.

    The pack is judge-owned and lives OUTSIDE the candidate copy, so there is no
    before/after to reconcile — the digest binds the verdict to exactly which
    protocol tests judged it, for the attestation."""
    import hashlib
    import json as _json

    digest = hashlib.sha256()
    manifest: dict | None = None
    for dirpath, dirnames, filenames in os.walk(pack_dir):
        dirnames.sort()
        for fn in sorted(filenames):
            rel = os.path.relpath(os.path.join(dirpath, fn), pack_dir)
            digest.update(rel.encode("utf-8"))
            with open(os.path.join(dirpath, fn), "rb") as pf:
                digest.update(pf.read())
    mpath = os.path.join(pack_dir, "pack.json")
    if os.path.isfile(mpath):
        try:
            with open(mpath, encoding="utf-8") as mf:
                m = _json.load(mf)
            if isinstance(m, dict):
                manifest = {k: m[k] for k in ("id", "version", "description", "target_type") if k in m}
        except (OSError, ValueError):
            manifest = None
    return digest.hexdigest(), manifest


def _judge_command(pack_dir: str, xml_path: str) -> list[str]:
    # The JUDGE's own pytest, run over the judge-owned pack. No candidate code is
    # imported here; the pack reaches the candidate only via subprocess.
    return [
        sys.executable, "-m", "pytest", "-q", "--color=no",
        "-p", "no:cacheprovider", pack_dir,
        f"--junitxml={xml_path}", "-o", "junit_family=xunit2",
    ]


def run_blackbox(
    repo_path: str,
    candidate: str,
    pack_dir: str,
    *,
    timeout: int = 120,
    isolation: str = "subprocess",
    docker_image: str | None = None,
    docker_network: str = "none",
    docker_runtime: str | None = None,
    mem_limit_mb: int = 0,
    deleted_paths: tuple[str, ...] = (),
    file_blocks: dict[str, str] | None = None,
) -> BlackboxResult:
    """Judge ``candidate`` against ``repo_path`` through the black-box ``pack_dir``.

    The patch (including deletions) is applied to a throwaway copy; the judge then
    runs ``pack_dir``'s tests in its own process, reaching the candidate only
    through a :class:`CandidateRunner`-provided launcher (``EVOGUARD_EXEC``) that
    runs it under the **delivered** isolation boundary. The verdict is the judge's
    own pytest result — a process the candidate never runs in — and the returned
    :class:`BlackboxResult` records the isolation that was *actually* delivered,
    never the value that was requested.
    """
    if not pack_dir or not os.path.isdir(pack_dir):
        return BlackboxResult(False, 0, 0, "", False, f"verifier pack not found: {pack_dir!r}")

    pack_sha256, pack_manifest = _pack_digest_and_manifest(pack_dir)
    workdir = tempfile.mkdtemp(prefix="evo_blackbox_")
    copy = os.path.join(workdir, "repo")
    try:
        copy_repo_tree(repo_path, copy)
        apply_error = apply_blocks_to_copy(
            copy,
            file_blocks if file_blocks else parse_file_blocks(candidate),
            [] if file_blocks else parse_patch_blocks(candidate),
        )
        if apply_error is not None:
            return BlackboxResult(False, 0, 0, apply_error, False, "patch did not apply",
                                  pack_sha256, pack_manifest)

        # Apply deletions to the copy so the judged tree matches the real merge —
        # a change that removes a file must be judged with that file ABSENT.
        deleted_applied: list[str] = []
        for rel in deleted_paths:
            if not is_safe_relpath(rel):
                continue
            target = os.path.join(copy, *rel.split("/"))
            try:
                os.remove(target)
                deleted_applied.append(rel)
            except IsADirectoryError:
                shutil.rmtree(target, ignore_errors=True)
                deleted_applied.append(rel)
            except OSError:
                pass  # already absent — nothing to judge against

        # Deliver a REAL isolation boundary (fail-closed) and record what ran.
        runner = CandidateRunner(
            isolation=isolation, docker_image=docker_image,
            docker_network=docker_network, docker_runtime=docker_runtime,
            mem_limit_mb=mem_limit_mb, python=sys.executable,
        )
        try:
            _launcher, run_env, evidence = runner.prepare(workdir, copy)
        except IsolationUnavailable as exc:
            # A stronger boundary was required but cannot be delivered. Refuse to
            # run rather than silently judge under a weaker one.
            return BlackboxResult(
                False, 0, 0, str(exc), False, "isolation unavailable",
                pack_sha256, pack_manifest, None,
                {"requested": isolation, "delivered": "unavailable", "note": str(exc)},
                deleted_applied,
            )
        iso = evidence.as_dict()

        xml_path = os.path.join(workdir, "judge-blackbox.xml")
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin"),
            "HOME": workdir,
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            # How the pack reaches the candidate. EVOGUARD_TARGET stays for
            # backward compatibility; EVOGUARD_EXEC is the delivered-isolation
            # launcher the pack should prefer.
            **run_env,
        }
        t0 = time.perf_counter()
        try:
            r = subprocess.run(
                _judge_command(pack_dir, xml_path),
                cwd=pack_dir,            # judge runs in the pack, NOT in the repo copy
                capture_output=True, text=True, timeout=timeout, env=env,
            )
        except subprocess.TimeoutExpired:
            return BlackboxResult(False, 0, 0, f"black-box pack timed out after {timeout}s",
                                  False, "timeout", pack_sha256, pack_manifest,
                                  None, iso, deleted_applied)
        # Read the judge-owned report immediately (all pack subprocesses have
        # exited by now). The JUDGE's exit code is authoritative regardless.
        junit = None
        junit_sha256 = None
        try:
            with open(xml_path, encoding="utf-8") as f:
                xml_text = f.read()
            junit = parse_junit_xml(xml_text)
            junit_sha256 = hashlib.sha256(xml_text.encode("utf-8")).hexdigest()
        except OSError:
            pass
        _elapsed = time.perf_counter() - t0
        diagnostics = distill_diagnostics(r.stdout + "\n" + r.stderr)

        # The judge process ran no candidate code, so its exit code is trustworthy.
        # exit 0 = pack passed; exit 1 = pack failed. Counts come from the report
        # when present (the judge wrote it), else fall back to the exit code.
        if junit is not None and junit.total > 0:
            tp, tt = junit.passed, junit.total
        else:
            tp, tt = (0, 0)
        if r.returncode == 0:
            return BlackboxResult(True, tp or tt, tt, diagnostics, True, None, pack_sha256,
                                  pack_manifest, junit_sha256, iso, deleted_applied)
        if r.returncode == 1:
            return BlackboxResult(False, tp, tt, diagnostics, True, None, pack_sha256,
                                  pack_manifest, junit_sha256, iso, deleted_applied)
        # 2+ = pytest usage/collection error in the pack itself (author's bug).
        return BlackboxResult(False, tp, tt, diagnostics, False,
                              f"black-box pack did not run cleanly (pytest exit {r.returncode})",
                              pack_sha256, pack_manifest, junit_sha256, iso, deleted_applied)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
