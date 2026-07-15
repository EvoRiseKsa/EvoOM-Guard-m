# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Baseline allowlist (`allow`) for adopter-defined extra protected paths only.

Built-in tests, configuration, CI and judge auto-exec paths are never
allowlist-exempt: a pull-request workflow can otherwise turn its own inputs into
authority to rewrite the evidence being judged.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard.cli import _load_config
from evoom_guard.cli import main as cli_main
from evoom_guard.guard import PASS, REJECTED, guard
from evoom_guard.verifiers.repo_verifier import reject_unsafe_or_protected


# ───────────────────────────── the gate function ─────────────────────────────
def test_allow_never_exempts_builtin_harness_paths():
    R = reject_unsafe_or_protected
    # without the allowlist, each is a protected hit …
    assert R(["tests/test_x.py"], ()) is not None
    assert R(["pytest.ini"], ()) is not None
    assert R([".github/workflows/ci.yml"], ()) is not None
    assert R([".ci/guard/action.yml"], ()) is not None
    # A matching allow glob still cannot waive a built-in judge-owned path.
    assert R(["tests/test_x.py"], (), allow=("tests/test_x.py",)) is not None
    assert R(["pytest.ini"], (), allow=("pytest.ini",)) is not None
    assert R([".github/workflows/ci.yml"], (), allow=(".github/workflows/*",)) is not None
    assert R([".ci/guard/action.yml"], (), allow=("*",)) is not None
    assert R([".evoguard.json"], (), allow=("*",)) is not None
    # a non-matching allow does NOT help.
    assert R(["pytest.ini"], (), allow=("other.ini",)) is not None
    # NEVER exemptible — even with a catch-all `*`:
    assert R(["sitecustomize.py"], (), allow=("*",)) is not None   # auto-exec (runs in judge)
    assert R(["a.pth"], (), allow=("*",)) is not None              # auto-exec
    assert R(["../escape.py"], (), allow=("*",)) is not None       # unsafe path


# ───────────────────────────── end-to-end (guard) ────────────────────────────
def _repo(root):
    (root / "m.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (root / "test_m.py").write_text(
        "from m import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8"
    )


def test_guard_allow_does_not_exempt_a_makefile_edit(tmp_path):
    _repo(tmp_path)
    (tmp_path / "Makefile").write_text("all:\n\techo hi\n", encoding="utf-8")
    cand = "<<<FILE: Makefile>>>\nall:\n\techo hello\n<<<END FILE>>>"
    # default: a Makefile is a protected build/test config → REJECTED
    assert guard(str(tmp_path), cand).verdict == REJECTED
    # An allowlist entry cannot waive this built-in test/build configuration.
    res = guard(str(tmp_path), cand, allow=("Makefile",))
    assert res.verdict == REJECTED
    assert res.protected_violations == ["Makefile"]


def test_guard_allow_never_exempts_autoexec(tmp_path):
    _repo(tmp_path)
    cand = "<<<FILE: sitecustomize.py>>>\nimport os  # runs in the judge process\n<<<END FILE>>>"
    assert guard(str(tmp_path), cand, allow=("sitecustomize.py",)).verdict == REJECTED


def test_guard_allow_never_exempts_builtin_harness_paths(tmp_path):
    _repo(tmp_path)
    for path, allow in (
        (".evoguard.json", (".evoguard.json",)),
        ("tests/test_m.py", ("tests/*",)),
        (".github/workflows/ci.yml", (".github/workflows/*",)),
        (".ci/guard/action.yml", ("*",)),
    ):
        result = guard(
            str(tmp_path),
            f"<<<FILE: {path}>>>\ncandidate-controlled\n<<<END FILE>>>",
            allow=allow,
        )
        assert result.verdict == REJECTED


def test_guard_allow_exempts_only_adopter_defined_extra_paths(tmp_path):
    _repo(tmp_path)
    (tmp_path / "metadata.txt").write_text("base\n", encoding="utf-8")
    cand = "<<<FILE: metadata.txt>>>\ncandidate\n<<<END FILE>>>"
    assert guard(str(tmp_path), cand, protected=("metadata.txt",)).verdict == REJECTED
    assert (
        guard(
            str(tmp_path),
            cand,
            protected=("metadata.txt",),
            allow=("metadata.txt",),
        ).verdict
        == PASS
    )


# ───────────────────────────── config / CLI wiring ───────────────────────────
def test_config_reads_allow(tmp_path):
    cfg = tmp_path / ".evoguard.json"
    cfg.write_text('{"allow": ["Makefile", "docs/*"]}', encoding="utf-8")
    assert _load_config(str(cfg), out=lambda *_: None).get("allow") == ["Makefile", "docs/*"]


def test_cli_allow_flag_does_not_exempt_builtin_config(tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    _repo(repo)
    (repo / "Makefile").write_text("all:\n\techo hi\n", encoding="utf-8")
    patch = tmp_path / "c.patch"
    patch.write_text("<<<FILE: Makefile>>>\nall:\n\techo hello\n<<<END FILE>>>", encoding="utf-8")
    assert cli_main(["guard", str(repo), "--patch", str(patch)]) == 1            # REJECTED
    capsys.readouterr()
    assert cli_main(["guard", str(repo), "--patch", str(patch), "--allow", "Makefile"]) == 1  # REJECTED
