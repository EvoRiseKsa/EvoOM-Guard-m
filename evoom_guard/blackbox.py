# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Sole owner & author: Mana Alharbi (مانع الحربي).
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
    ``EVOGUARD_TARGET`` env var, and asserts on its observable outputs. Forgery
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

import os
import shutil
import subprocess
import sys
import tempfile
import time
from typing import NamedTuple

from evoom_guard.verifiers.repo_verifier import (
    COPY_IGNORE,
    apply_blocks_to_copy,
    distill_diagnostics,
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
) -> BlackboxResult:
    """Judge ``candidate`` against ``repo_path`` through the black-box ``pack_dir``.

    The patch is applied to a throwaway copy; the judge then runs ``pack_dir``'s
    tests in its own process with ``EVOGUARD_TARGET`` pointing at that copy, so
    the pack can invoke the candidate out-of-process and assert on its outputs.
    The verdict is the judge's own pytest result — a process the candidate never
    runs in.
    """
    if not pack_dir or not os.path.isdir(pack_dir):
        return BlackboxResult(False, 0, 0, "", False, f"verifier pack not found: {pack_dir!r}")

    workdir = tempfile.mkdtemp(prefix="evo_blackbox_")
    copy = os.path.join(workdir, "repo")
    try:
        shutil.copytree(repo_path, copy, ignore=shutil.ignore_patterns(*COPY_IGNORE))
        apply_error = apply_blocks_to_copy(
            copy, parse_file_blocks(candidate), parse_patch_blocks(candidate)
        )
        if apply_error is not None:
            return BlackboxResult(False, 0, 0, apply_error, False, "patch did not apply")

        xml_path = os.path.join(workdir, "judge-blackbox.xml")
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin"),
            "HOME": workdir,
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            # How the pack reaches the candidate — the repo copy, and the
            # interpreter to launch it with. The pack invokes it as a subprocess.
            "EVOGUARD_TARGET": copy,
            "EVOGUARD_PYTHON": sys.executable,
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
                                  False, "timeout")
        # Read the judge-owned report immediately (all pack subprocesses have
        # exited by now). The JUDGE's exit code is authoritative regardless.
        try:
            with open(xml_path, encoding="utf-8") as f:
                junit = parse_junit_xml(f.read())
        except OSError:
            junit = None
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
            return BlackboxResult(True, tp or tt, tt, diagnostics, True, None)
        if r.returncode == 1:
            return BlackboxResult(False, tp, tt, diagnostics, True, None)
        # 2+ = pytest usage/collection error in the pack itself (author's bug).
        return BlackboxResult(False, tp, tt, diagnostics, False,
                              f"black-box pack did not run cleanly (pytest exit {r.returncode})")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
