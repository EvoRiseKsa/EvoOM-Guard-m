# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Changed-line coverage evidence (the first non-test evidence source).

A suite can be green without ever *executing* the lines a patch changed — the
change is then simply unverified, however green the check looks. This module
answers one narrow question, as evidence rather than as a verdict:

    Of the lines this candidate changed, which did the suite actually execute?

Honesty contract (printed with the evidence, never dropped):

  * "executed" is NOT "asserted" — a test can run a line and check nothing
    about it. Executed-changed-lines is a *floor* of scrutiny, not a proof of
    correctness. (Mutation-on-diff, the follow-up evidence source, targets the
    asserted question.)
  * Only Python files are measured (``coverage.py``); changed lines in other
    languages are reported as unmeasured, not silently counted.
  * Non-executable changed lines (comments, blank lines, docstrings) are
    excluded from the denominator using coverage's own statement knowledge —
    they cannot be executed, so counting them would fake a gap.

The measurement runs the suite ONE extra time in its own throwaway copy with
``coverage run`` wrapping the same pytest invocation, and reads a judge-owned
``coverage json`` written outside stdout — the same trust posture as the main
verdict. It is opt-in (``--diff-coverage``) because it doubles suite runtime,
and it needs ``coverage`` importable in the judge environment (the ``cov``
extra); when unavailable it degrades to an explicit "not measured", never to a
silent pass.
"""

from __future__ import annotations

import difflib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any

from evoom_guard.patch_applier import PatchError, apply_patch
from evoom_guard.verifiers.repo_verifier import (
    apply_blocks_to_copy,
    copy_repo_tree,
    is_safe_relpath,
    parse_file_blocks,
    parse_patch_blocks,
)

# The honesty line shipped inside every measurement (report + JSON).
EXECUTED_IS_NOT_ASSERTED = (
    "executed is not asserted: a test can run a changed line and check nothing "
    "about it — this evidence is a floor of scrutiny, not a proof of correctness"
)


def _new_content_map(repo_path: str, candidate: str) -> dict[str, str | None]:
    """Post-apply content per changed path (``None`` when a PATCH fails to apply).

    Mirrors the verifier's application order: whole FILE blocks first, then the
    surgical PATCH blocks in document order (possibly stacking on a FILE block
    for the same path).
    """
    out: dict[str, str | None] = dict(parse_file_blocks(candidate))
    for pb in parse_patch_blocks(candidate):
        base = out.get(pb.path)
        if base is None:
            try:
                with open(os.path.join(repo_path, *pb.path.split("/")), encoding="utf-8") as f:
                    base = f.read()
            except OSError:
                out[pb.path] = None
                continue
        try:
            out[pb.path] = apply_patch(base, pb.search, pb.replace)
        except (PatchError, ValueError):
            out[pb.path] = None
    return out


def changed_lines(repo_path: str, candidate: str) -> dict[str, set[int]]:
    """``{path: {1-indexed line numbers changed/added in the NEW file}}``.

    Computed against the base file at ``repo_path`` with :mod:`difflib` — the
    same ground truth the risk scorer uses. Paths whose patches do not apply
    are omitted (the main verdict already surfaces that failure).
    """
    out: dict[str, set[int]] = {}
    for path, new in _new_content_map(repo_path, candidate).items():
        if new is None or not is_safe_relpath(path):
            continue
        try:
            with open(os.path.join(repo_path, *path.split("/")), encoding="utf-8") as f:
                old_lines = f.read().splitlines()
        except OSError:
            old_lines = []
        new_lines = new.splitlines()
        touched: set[int] = set()
        matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
        for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
            if tag in ("replace", "insert"):
                touched.update(range(j1 + 1, j2 + 1))
        if touched:
            out[path] = touched
    return out


def _coverage_wrap(cmd: list[str], data_file: str) -> list[str] | None:
    """Rewrite a pytest invocation to run under ``coverage run``; None if not pytest."""
    try:
        idx = next(i for i, tok in enumerate(cmd) if "pytest" in os.path.basename(str(tok)))
    except StopIteration:
        return None
    return [
        sys.executable, "-m", "coverage", "run",
        f"--data-file={data_file}",
        "-m", "pytest", *[str(t) for t in cmd[idx + 1:]],
    ]


def _judge_env(workdir: str) -> dict[str, str]:
    # Mirrors the verifier's restricted env (see RepoVerifier.verify).
    return {
        "PATH": os.environ.get("PATH", "/usr/bin"),
        "HOME": workdir,
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }


def collect_diff_coverage(
    repo_path: str,
    candidate: str,
    *,
    deleted: tuple[str, ...] = (),
    test_command: list[str] | None = None,
    timeout: int = 240,
    file_blocks: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Measure changed-line coverage; always returns a dict with ``measured`` set.

    ``measured: False`` results carry a ``note`` naming the exact reason
    (coverage missing, non-pytest runner, nothing changed in Python files, the
    wrapped run failing) — explicit degradation, never a silent number.
    """
    lines_map = {p: s for p, s in changed_lines(repo_path, candidate).items() if p.endswith(".py")}
    non_py = sorted(
        p for p in changed_lines(repo_path, candidate) if not p.endswith(".py")
    )
    base: dict[str, Any] = {
        "measured": False,
        "note": "",
        "unmeasured_files": non_py,
        "caveat": EXECUTED_IS_NOT_ASSERTED,
    }
    if not lines_map:
        base["note"] = "no changed Python lines to measure"
        return base
    try:
        import coverage  # noqa: F401
    except ImportError:
        base["note"] = (
            "the 'coverage' package is not installed in the judge environment — "
            "install the extra: pip install \"evoom-guard[cov]\""
        )
        return base

    cmd = list(test_command) if test_command else [sys.executable, "-m", "pytest", "-q"]
    workdir = tempfile.mkdtemp(prefix="evo_guard_cov_")
    try:
        data_file = os.path.join(workdir, "judge-coverage.db")
        wrapped = _coverage_wrap(cmd, data_file)
        if wrapped is None:
            base["note"] = "changed-line coverage currently supports pytest commands only"
            return base

        copy = os.path.join(workdir, "repo")
        copy_repo_tree(repo_path, copy)
        apply_error = apply_blocks_to_copy(
            copy,
            file_blocks if file_blocks else parse_file_blocks(candidate),
            [] if file_blocks else parse_patch_blocks(candidate),
        )
        if apply_error is not None:
            base["note"] = "candidate did not apply for the coverage run"
            return base
        for rel in deleted:
            if not is_safe_relpath(rel):
                continue
            target = os.path.join(copy, *rel.split("/"))
            try:
                os.remove(target)
            except IsADirectoryError:
                shutil.rmtree(target, ignore_errors=True)
            except OSError:
                pass

        env = _judge_env(workdir)
        try:
            subprocess.run(
                wrapped, cwd=copy, capture_output=True, text=True,
                timeout=timeout, env=env,
            )
        except (OSError, subprocess.TimeoutExpired):
            base["note"] = "the coverage-wrapped suite run did not complete"
            return base

        cov_json = os.path.join(workdir, "judge-coverage.json")
        r = subprocess.run(
            [sys.executable, "-m", "coverage", "json",
             f"--data-file={data_file}", "-o", cov_json, "-q"],
            cwd=copy, capture_output=True, text=True, timeout=60, env=env,
        )
        if r.returncode != 0 or not os.path.exists(cov_json):
            base["note"] = "coverage produced no report (suite may not have started)"
            return base
        with open(cov_json, encoding="utf-8") as f:
            files = json.load(f).get("files", {})
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    per_file: dict[str, Any] = {}
    executed_total = 0
    measurable_total = 0
    for path, touched in sorted(lines_map.items()):
        entry = files.get(path)
        if entry is None:
            # Never imported during the run: every executable changed line missed.
            # Without coverage's statement list we can't drop comment lines, so
            # report the raw changed lines and say so.
            per_file[path] = {
                "executed": [], "missed": sorted(touched),
                "note": "file never imported by the suite (raw changed lines shown)",
            }
            measurable_total += len(touched)
            continue
        stmts = set(entry.get("executed_lines", [])) | set(entry.get("missing_lines", []))
        measurable = touched & stmts  # comments/blanks/docstrings drop out here
        executed = measurable & set(entry.get("executed_lines", []))
        missed = sorted(measurable - executed)
        per_file[path] = {"executed": sorted(executed), "missed": missed}
        executed_total += len(executed)
        measurable_total += len(measurable)

    percent = round(100.0 * executed_total / measurable_total, 1) if measurable_total else 100.0
    return {
        "measured": True,
        "percent": percent,
        "executed": executed_total,
        "total": measurable_total,
        "files": per_file,
        "unmeasured_files": non_py,
        "caveat": EXECUTED_IS_NOT_ASSERTED,
    }
