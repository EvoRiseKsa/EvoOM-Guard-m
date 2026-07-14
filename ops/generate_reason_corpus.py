#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Regenerate the reason-code golden corpus from the real producer.

Runs an actual ``guard()``/``guard_from_diff()`` scenario for every reason
code the frozen 1.11 contract names and rewrites
``tests/fixtures/contracts/reason-corpus.jsonl``.  The corpus is a frozen,
hand-reviewed artifact: regenerate it only when the contract legitimately
gains or changes a reason code, then review the diff line by line before
committing (``tests/test_reason_code_coverage.py`` holds it to the contract).

Three scenarios cover black-box launcher facts the host cannot produce
natively; they stub ``run_blackbox`` exactly the way this repository's own
tests do and are marked ``producer-stubbed-blackbox`` in their provenance.

    python ops/generate_reason_corpus.py

Exits non-zero when any contract reason code failed to produce a record or
any produced record fails independent verification.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import traceback
from collections.abc import Callable
from types import SimpleNamespace
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from evoom_guard.guard import GuardResult, guard, guard_from_diff  # noqa: E402
from evoom_guard.record_verifier import verify_record  # noqa: E402
from evoom_guard.verdict_contract_v1_11 import REASON_CODES  # noqa: E402

CORPUS_PATH = os.path.join(
    _ROOT, "tests", "fixtures", "contracts", "reason-corpus.jsonl"
)

# "python" keeps the generating interpreter's absolute path out of the frozen
# records' effective_policy.
PY = "python" if shutil.which("python") else sys.executable
PYTEST = [PY, "-m", "pytest", "-q"]

FIX = "<<<FILE: app.py>>>\ndef dbl(x):\n    return x * 2\n<<<END FILE>>>"
WRONG = "<<<FILE: app.py>>>\ndef dbl(x):\n    return x * 3\n<<<END FILE>>>"

SCENARIOS: list[tuple[str, Callable[[str], object]]] = []
STUBBED = frozenset(
    {
        "verifier_pack_snapshot_changed",
        "candidate_not_exercised",
        "runtime_cleanup_failed",
    }
)


def make_repo(root: str, *, buggy: bool = True) -> None:
    os.makedirs(os.path.join(root, "tests"), exist_ok=True)
    body = (
        "def dbl(x):\n    return x + x + 1\n"
        if buggy
        else "def dbl(x):\n    return x * 2\n"
    )
    with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as f:
        f.write(body)
    with open(os.path.join(root, "tests", "test_app.py"), "w", encoding="utf-8") as f:
        f.write("from app import dbl\n\n\ndef test_dbl():\n    assert dbl(3) == 6\n")


def make_pack(root: str) -> str:
    pack = os.path.join(root, "pack")
    os.makedirs(pack, exist_ok=True)
    with open(os.path.join(pack, "test_protocol.py"), "w", encoding="utf-8") as f:
        f.write("def test_trivial():\n    assert True\n")
    return pack


def bx_stub(**overrides: object) -> SimpleNamespace:
    base: dict[str, object] = dict(
        passed=True, tests_passed=1, tests_total=1, diagnostics="",
        ran=True, error=None, pack_sha256="0" * 64, pack_manifest=None,
        junit_sha256="1" * 64, isolation=None, deleted_applied=[],
        started=True, completed=True, execution_state="completed",
        execution_phase="blackbox_pack", pack_present=True,
        candidate_invocations=0,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def scenario(name: str) -> Callable[[Callable[[str], object]], Callable[[str], object]]:
    def wrap(fn: Callable[[str], object]) -> Callable[[str], object]:
        SCENARIOS.append((name, fn))
        return fn

    return wrap


@scenario("tests_passed")
def s_tests_passed(tmp: str) -> object:
    make_repo(tmp)
    return guard(tmp, FIX, test_command=list(PYTEST), mem_limit_mb=0)


@scenario("tests_failed")
def s_tests_failed(tmp: str) -> object:
    make_repo(tmp)
    return guard(tmp, WRONG, test_command=list(PYTEST), mem_limit_mb=0)


@scenario("protected_harness_edit")
def s_protected(tmp: str) -> object:
    make_repo(tmp)
    cheat = (
        "<<<FILE: tests/test_app.py>>>\ndef test_dbl():\n    assert True\n<<<END FILE>>>"
    )
    return guard(tmp, cheat, test_command=list(PYTEST), mem_limit_mb=0)


@scenario("no_parseable_edits")
def s_no_parseable(tmp: str) -> object:
    make_repo(tmp)
    return guard(
        tmp, "a prose answer with no file blocks",
        test_command=list(PYTEST), mem_limit_mb=0,
    )


@scenario("unsafe_path")
def s_unsafe(tmp: str) -> object:
    make_repo(tmp)
    return guard(
        tmp, "<<<FILE: ../evil.py>>>\nx = 1\n<<<END FILE>>>",
        test_command=list(PYTEST), mem_limit_mb=0,
    )


@scenario("empty_diff")
def s_empty_diff(tmp: str) -> object:
    make_repo(tmp)
    return guard_from_diff(tmp, "", test_command=list(PYTEST), mem_limit_mb=0)


@scenario("binary_patch")
def s_binary(tmp: str) -> object:
    make_repo(tmp)
    diff = (
        "diff --git a/blob.bin b/blob.bin\n"
        "index 0000000..1111111 100644\n"
        "GIT binary patch\n"
        "literal 4\n"
        "LcmZQzWMT#Y01f~L\n"
    )
    return guard_from_diff(tmp, diff, test_command=list(PYTEST), mem_limit_mb=0)


@scenario("reverse_apply_failed")
def s_reverse_apply(tmp: str) -> object:
    make_repo(tmp)
    diff = (
        "--- a/ghost.py\n"
        "+++ b/ghost.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-old ghost line\n"
        "+new ghost line\n"
    )
    return guard_from_diff(tmp, diff, test_command=list(PYTEST), mem_limit_mb=0)


@scenario("no_verifiable_changes")
def s_no_verifiable(tmp: str) -> object:
    make_repo(tmp)
    diff = (
        "diff --git a/app.py b/app.py\n"
        "old mode 100644\n"
        "new mode 100755\n"
    )
    return guard_from_diff(tmp, diff, test_command=list(PYTEST), mem_limit_mb=0)


@scenario("patch_apply_failed")
def s_patch_apply(tmp: str) -> object:
    make_repo(tmp)
    cand = (
        "<<<PATCH: app.py>>>\n<<<SEARCH>>>\n"
        "this anchor does not exist in the file\n"
        "<<<REPLACE>>>\nreplacement\n<<<END PATCH>>>"
    )
    return guard(tmp, cand, test_command=list(PYTEST), mem_limit_mb=0)


@scenario("no_test_verdict")
def s_no_test_verdict(tmp: str) -> object:
    make_repo(tmp)
    return guard(
        tmp, FIX, test_command=[PY, "-c", "raise SystemExit(1)"], mem_limit_mb=0
    )


@scenario("junit_exit_mismatch")
def s_junit_mismatch(tmp: str) -> object:
    make_repo(tmp)
    with open(os.path.join(tmp, "conftest.py"), "w", encoding="utf-8") as f:
        f.write(
            "def pytest_sessionfinish(session, exitstatus):\n"
            "    session.exitstatus = 0\n"
        )
    return guard(tmp, WRONG, test_command=list(PYTEST), mem_limit_mb=0)


@scenario("diff_coverage_below_threshold")
def s_diff_coverage(tmp: str) -> object:
    make_repo(tmp)
    cand = (
        "<<<FILE: app.py>>>\ndef dbl(x):\n    return x * 2\n<<<END FILE>>>\n"
        "<<<FILE: never_imported.py>>>\ndef unused():\n    return 42\n<<<END FILE>>>"
    )
    return guard(
        tmp, cand, test_command=list(PYTEST), mem_limit_mb=0,
        diff_coverage=True, min_diff_coverage=99.0,
    )


@scenario("test_timeout")
def s_test_timeout(tmp: str) -> object:
    make_repo(tmp)
    return guard(
        tmp, FIX, test_command=[PY, "-c", "import time; time.sleep(5)"],
        timeout=1, mem_limit_mb=0,
    )


@scenario("setup_timeout")
def s_setup_timeout(tmp: str) -> object:
    make_repo(tmp)
    return guard(
        tmp, FIX, test_command=list(PYTEST),
        setup_command=[PY, "-c", "import time; time.sleep(5)"],
        timeout=1, mem_limit_mb=0,
    )


@scenario("setup_failed")
def s_setup_failed(tmp: str) -> object:
    make_repo(tmp)
    return guard(
        tmp, FIX, test_command=list(PYTEST),
        setup_command=[PY, "-c", "raise SystemExit(3)"],
        mem_limit_mb=0,
    )


@scenario("assurance_requirement_not_met")
def s_assurance(tmp: str) -> object:
    make_repo(tmp)
    return guard(
        tmp, FIX, test_command=[PY, "-c", "raise SystemExit(0)"],
        require_report_integrity="external_process_isolated", mem_limit_mb=0,
    )


@scenario("fix_not_demonstrated")
def s_fix_not_demo(tmp: str) -> object:
    make_repo(tmp, buggy=False)
    cand = "<<<FILE: app.py>>>\ndef dbl(x):\n    return 2 * x\n<<<END FILE>>>"
    return guard(
        tmp, cand, test_command=list(PYTEST), mem_limit_mb=0,
        baseline_evidence=True, require_demonstrated_fix=True,
    )


@scenario("policy_requirement_unsupported")
def s_policy_unsupported(tmp: str) -> object:
    # Exits at the fail-closed preflight gate before any docker use, and the
    # echoed policy stays typed-valid so the independent verifier accepts it.
    make_repo(tmp)
    return guard(
        tmp, FIX, test_command=list(PYTEST),
        require_demonstrated_fix=True, isolation="docker", mem_limit_mb=0,
    )


@scenario("test_command_unavailable")
def s_cmd_unavailable(tmp: str) -> object:
    make_repo(tmp)
    return guard(
        tmp, FIX, test_command=["definitely-missing-evoguard-command"], mem_limit_mb=0
    )


@scenario("verifier_pack_not_found")
def s_pack_not_found(tmp: str) -> object:
    make_repo(tmp)
    return guard(
        tmp, FIX, test_command=list(PYTEST),
        verifier_pack="missing-pack-dir", mem_limit_mb=0,
    )


@scenario("verifier_pack_invalid")
def s_pack_invalid(tmp: str) -> object:
    # A relative pack path keeps the generating machine's tmp directory out of
    # the frozen record's diagnostics.
    make_repo(tmp)
    pack = make_pack(tmp)
    with open(os.path.join(pack, "pack.json"), "w", encoding="utf-8") as f:
        f.write("{not valid json")
    cwd = os.getcwd()
    os.chdir(tmp)
    try:
        return guard(
            tmp, FIX, test_command=list(PYTEST), verifier_pack="pack", mem_limit_mb=0
        )
    finally:
        os.chdir(cwd)


@scenario("verifier_pack_identity_mismatch")
def s_pack_identity(tmp: str) -> object:
    make_repo(tmp)
    pack = make_pack(tmp)
    return guard(
        tmp, FIX, test_command=list(PYTEST), verifier_pack=pack,
        expect_verifier_pack_sha256="0" * 64, mem_limit_mb=0,
    )


@scenario("verifier_pack_required")
def s_pack_required(tmp: str) -> object:
    make_repo(tmp)
    return guard(tmp, FIX, test_command=list(PYTEST), blackbox=True, mem_limit_mb=0)


@scenario("verifier_pack_snapshot_changed")
def s_pack_snapshot(tmp: str) -> object:
    make_repo(tmp)
    pack = make_pack(tmp)
    from evoom_guard.blackbox import PackManifestError

    with mock.patch(
        "evoom_guard.verifiers.repo_verifier.verify_pack_snapshot",
        side_effect=PackManifestError("changed"),
    ):
        return guard(
            tmp, FIX, test_command=[PY, "-c", "raise SystemExit(0)"],
            verifier_pack=pack, mem_limit_mb=0,
        )


@scenario("candidate_tree_changed_during_run")
def s_tree_changed(tmp: str) -> object:
    make_repo(tmp)
    pack = make_pack(tmp)
    return guard(
        tmp, FIX,
        test_command=[PY, "-c", "open('app.py', 'w').write('x = 999\\n')"],
        verifier_pack=pack, mem_limit_mb=0,
    )


@scenario("candidate_not_exercised")
def s_not_exercised(tmp: str) -> object:
    make_repo(tmp)
    pack = make_pack(tmp)
    with mock.patch("evoom_guard.blackbox.run_blackbox", return_value=bx_stub()):
        return guard(
            tmp, FIX, verifier_pack=pack, blackbox=True, blackbox_only=True,
            mem_limit_mb=0,
        )


@scenario("runtime_cleanup_failed")
def s_cleanup_failed(tmp: str) -> object:
    make_repo(tmp)
    pack = make_pack(tmp)
    stub = bx_stub(
        ran=False, error="candidate container cleanup failed",
        passed=False, tests_passed=0, tests_total=0,
        started=True, completed=False, execution_state="started_incomplete",
    )
    with mock.patch("evoom_guard.blackbox.run_blackbox", return_value=stub):
        return guard(
            tmp, FIX, verifier_pack=pack, blackbox=True, blackbox_only=True,
            mem_limit_mb=0,
        )


def main() -> int:
    # Neutral tmp root on Windows: producer diagnostics may embed absolute
    # paths, and the frozen fixture must not carry the generating user's home
    # directory.
    neutral: str | None = None
    if os.name == "nt":
        neutral = r"C:\Users\Public\evo-corpus-tmp"
        os.makedirs(neutral, exist_ok=True)
        tempfile.tempdir = neutral

    out: dict[str, dict] = {}
    problems: list[str] = []
    try:
        for name, fn in SCENARIOS:
            tmp = tempfile.mkdtemp(prefix=f"evo_corpus_{name}_")
            try:
                result = fn(tmp)
                if isinstance(result, tuple):
                    result = result[0]
                assert isinstance(result, GuardResult)
                record = result.to_dict()
                got = record.get("reason_code")
                print(f"{name:40s} -> {'OK' if got == name else f'MISMATCH got={got!r}'}")
                if got == name:
                    out[name] = record
                else:
                    problems.append(f"{name}: produced {got!r} ({record.get('reason')!r})")
            except Exception:  # noqa: BLE001 - report and continue to the summary
                print(f"{name:40s} -> EXCEPTION")
                problems.append(f"{name}: {traceback.format_exc(limit=3)}")
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
    finally:
        if neutral:
            tempfile.tempdir = None
            shutil.rmtree(neutral, ignore_errors=True)

    for code, record in sorted(out.items()):
        report = verify_record(record)
        if not report["ok"]:
            bad = [c["id"] for c in report["checks"] if c["status"] == "fail"]
            problems.append(f"{code}: verify_record failed: {bad}")

    missing = sorted(REASON_CODES - out.keys())
    if missing:
        problems.append(f"missing contract reason codes: {', '.join(missing)}")

    with open(CORPUS_PATH, "w", encoding="utf-8", newline="\n") as f:
        for code in sorted(out):
            row = {
                "reason_code": code,
                "provenance": (
                    "producer-stubbed-blackbox" if code in STUBBED else "producer"
                ),
                "record": out[code],
            }
            f.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")
    print(f"wrote {len(out)} records -> {CORPUS_PATH}")

    for problem in problems:
        print(f"PROBLEM: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
