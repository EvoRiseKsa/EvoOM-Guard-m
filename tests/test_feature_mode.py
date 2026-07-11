# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Feature mode (`allow_new_tests`) — the opt-in net-new-test relaxation.

Adversarial spec for the narrow relaxation: a brand-new *test file* may be added,
but editing an existing test, or planting any config / auto-exec / CI / lock /
caller-protected file, stays REJECTED — in both modes. See docs/FEATURE_MODE.md.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard.cli import _load_config
from evoom_guard.cli import main as cli_main
from evoom_guard.guard import PASS, REJECTED, guard
from evoom_guard.verifiers.repo_verifier import is_addable_new_test


def _repo(root):
    # source + an existing colocated test (test_*.py is protected by name).
    (root / "m.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (root / "test_m.py").write_text(
        "from m import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n",
        encoding="utf-8",
    )


_NEW_TEST = (
    "<<<FILE: test_extra.py>>>\n"
    "from m import add\n\n\ndef test_extra():\n    assert add(1, 1) == 2\n"
    "<<<END FILE>>>"
)


# ───────────────────────────── the relaxation ────────────────────────────────
def test_default_rejects_a_new_test_file(tmp_path):
    _repo(tmp_path)
    res = guard(str(tmp_path), _NEW_TEST)            # allow_new_tests defaults off
    assert res.verdict == REJECTED
    assert "test_extra.py" in res.protected_violations


def test_feature_mode_allows_a_new_test_file(tmp_path):
    _repo(tmp_path)
    res = guard(str(tmp_path), _NEW_TEST, allow_new_tests=True)
    assert res.verdict == PASS                       # existing + new tests both pass
    assert res.protected_violations == []
    assert res.verdict_source == "junit+exit"


# ───────────────────────────── still rejected ────────────────────────────────
def test_feature_mode_still_rejects_editing_an_existing_test(tmp_path):
    _repo(tmp_path)
    # overwrite the existing test to weaken it — the classic reward-hack.
    cand = (
        "<<<FILE: test_m.py>>>\n"
        "def test_add():\n    assert True\n"
        "<<<END FILE>>>"
    )
    res = guard(str(tmp_path), cand, allow_new_tests=True)
    assert res.verdict == REJECTED
    assert "test_m.py" in res.protected_violations


def test_feature_mode_still_rejects_a_new_conftest(tmp_path):
    _repo(tmp_path)
    cand = "<<<FILE: conftest.py>>>\nimport sys\nsys.modules['m'] = object()\n<<<END FILE>>>"
    res = guard(str(tmp_path), cand, allow_new_tests=True)
    assert res.verdict == REJECTED                   # auto-exec, not a plain test


def test_feature_mode_still_rejects_a_new_config(tmp_path):
    _repo(tmp_path)
    cand = "<<<FILE: pytest.ini>>>\n[pytest]\naddopts = -k nope\n<<<END FILE>>>"
    res = guard(str(tmp_path), cand, allow_new_tests=True)
    assert res.verdict == REJECTED                   # test/build config


def test_feature_mode_respects_caller_protected_globs(tmp_path):
    _repo(tmp_path)
    # a new file that *looks* like a test but sits under a caller-protected glob.
    cand = "<<<FILE: secret/test_x.py>>>\ndef test_x():\n    assert True\n<<<END FILE>>>"
    res = guard(str(tmp_path), cand, allow_new_tests=True, protected=("secret/*",))
    assert res.verdict == REJECTED


# ───────────────────────────── the predicate ─────────────────────────────────
def test_is_addable_new_test_predicate():
    # a net-new plain test file is addable …
    assert is_addable_new_test("tests/test_new.py", (), is_new=True)
    assert is_addable_new_test("src/widget.test.ts", (), is_new=True)
    # … but only when new …
    assert not is_addable_new_test("tests/test_new.py", (), is_new=False)
    # … never an auto-exec / config / CI file, even if new …
    assert not is_addable_new_test("tests/conftest.py", (), is_new=True)
    assert not is_addable_new_test("pytest.ini", (), is_new=True)
    assert not is_addable_new_test(".github/workflows/ci.yml", (), is_new=True)
    # … never a caller-protected path …
    assert not is_addable_new_test("secret/test_x.py", ("secret/*",), is_new=True)
    # … and not a non-test source file.
    assert not is_addable_new_test("m.py", (), is_new=True)


# ───────────────────────────── config / CLI wiring ───────────────────────────
def test_config_reads_allow_new_tests(tmp_path):
    cfg = tmp_path / ".evoguard.json"
    cfg.write_text('{"allow_new_tests": true}', encoding="utf-8")
    assert _load_config(str(cfg), out=lambda *_: None).get("allow_new_tests") is True


def test_cli_flag_enables_feature_mode(tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    _repo(repo)
    patch = tmp_path / "c.patch"
    patch.write_text(_NEW_TEST, encoding="utf-8")
    # default: a new test file is a reward-hack → non-zero exit.
    assert cli_main(["guard", str(repo), "--patch", str(patch)]) == 1
    capsys.readouterr()
    # with the flag: the net-new test is allowed and the suite passes → exit 0.
    assert cli_main(["guard", str(repo), "--patch", str(patch), "--allow-new-tests"]) == 0
