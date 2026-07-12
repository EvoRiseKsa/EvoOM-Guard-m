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
from evoom_guard.pack_manifest import (
    PackManifestError,
    digest_and_manifest,
    snapshot_pack,
    verify_pack_snapshot,
)
from evoom_guard.verifiers.repo_verifier import (
    apply_blocks_to_copy,
    copy_repo_tree,
    distill_diagnostics,
    is_safe_relpath,
    judge_subprocess_env,
    parse_file_blocks,
    parse_junit_xml,
    parse_patch_blocks,
)
from evoom_guard.workspace import UnsafeWorkspacePath, delete_path_within_root


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
    """Compatibility wrapper around the canonical pack-contract parser."""
    return digest_and_manifest(pack_dir)


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
    expect_verifier_pack_sha256: str | None = None,
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

    workdir = tempfile.mkdtemp(prefix="evo_blackbox_")
    copy = os.path.join(workdir, "repo")
    pack_workdir: str | None = None
    try:
        try:
            # The candidate inherits HOME=workdir. Keep hidden checks outside
            # that tree so subprocess mode does not hand it $HOME/pack.
            pack_workdir = tempfile.mkdtemp(prefix="evo_blackbox_pack_")
            pack_snapshot = os.path.join(pack_workdir, "pack")
            pack_identity = snapshot_pack(pack_dir, pack_snapshot)
            pack_sha256, pack_manifest = pack_identity
        except PackManifestError as exc:
            # The snapshot is the exact tree the judge executes; a broken or
            # moving contract must stop rather than produce an unbound verdict.
            return BlackboxResult(
                False, 0, 0, str(exc), False, "verifier pack invalid"
            )
        expected_pack_sha256 = (expect_verifier_pack_sha256 or "").lower()
        if expected_pack_sha256 and pack_sha256.lower() != expected_pack_sha256:
            return BlackboxResult(
                False,
                0,
                0,
                (
                    "verifier-pack identity mismatch: expected "
                    f"{expected_pack_sha256}, observed {pack_sha256}"
                ),
                False,
                "verifier pack identity mismatch",
                pack_sha256,
                pack_manifest,
            )
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
        try:
            for rel in deleted_paths:
                if not is_safe_relpath(rel):
                    continue
                if delete_path_within_root(copy, rel):
                    deleted_applied.append(rel)
        except (OSError, UnsafeWorkspacePath) as exc:
            return BlackboxResult(
                False,
                0,
                0,
                f"candidate deletion could not be applied safely: {exc}",
                False,
                "unsafe deletion path",
                pack_sha256,
                pack_manifest,
            )

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
            **judge_subprocess_env(workdir),
            # How the pack reaches the candidate. EVOGUARD_TARGET stays for
            # backward compatibility; EVOGUARD_EXEC is the delivered-isolation
            # launcher the pack should prefer.
            **run_env,
        }
        t0 = time.perf_counter()
        try:
            verify_pack_snapshot(pack_snapshot, pack_identity)
            r = subprocess.run(
                _judge_command(pack_snapshot, xml_path),
                cwd=pack_snapshot,       # judge runs in the snapshot, NOT in the repo copy
                capture_output=True, text=True, timeout=timeout, env=env,
            )
        except subprocess.TimeoutExpired:
            return BlackboxResult(False, 0, 0, f"black-box pack timed out after {timeout}s",
                                  False, "timeout", pack_sha256, pack_manifest,
                                  None, iso, deleted_applied)
        except PackManifestError as exc:
            return BlackboxResult(
                False, 0, 0, str(exc), False, "verifier pack snapshot changed",
                pack_sha256, pack_manifest, None, iso, deleted_applied,
            )
        try:
            verify_pack_snapshot(pack_snapshot, pack_identity)
        except PackManifestError as exc:
            return BlackboxResult(
                False, 0, 0, str(exc), False,
                "verifier pack changed while executing", pack_sha256,
                pack_manifest, None, iso, deleted_applied,
            )
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
        if junit is None or junit.total <= 0:
            return BlackboxResult(
                False, 0, 0, diagnostics, False,
                "black-box pack produced no judge-owned test results",
                pack_sha256, pack_manifest, junit_sha256, iso, deleted_applied,
            )
        tp, tt = junit.passed, junit.total
        junit_all_passed = junit.failures == 0 and junit.errors == 0 and tp == tt
        if (r.returncode == 0 and not junit_all_passed) or (
            r.returncode == 1 and junit_all_passed
        ):
            return BlackboxResult(
                False, tp, tt, diagnostics, False,
                "black-box JUnit/exit mismatch", pack_sha256, pack_manifest,
                junit_sha256, iso, deleted_applied,
            )
        if r.returncode == 0:
            return BlackboxResult(True, tp, tt, diagnostics, True, None, pack_sha256,
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
        if pack_workdir is not None:
            shutil.rmtree(pack_workdir, ignore_errors=True)
