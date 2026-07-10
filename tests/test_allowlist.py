# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Sole owner & author: Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Baseline allowlist (`allow`) — exempt a *misclassified* protected path.

The allowlist is adopter-curated: a matching path is exempt from the test / config
/ CI rejection (a built-in pattern's false positive, or a known pre-existing hit).
It must **never** exempt an auto-exec judge file (`sitecustomize.py` / `*.pth`) or
an unsafe path — those are never legitimate.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard.cli import _load_config
from evoom_guard.cli import main as cli_main
from evoom_guard.guard import PASS, REJECTED, guard
from evoom_guard.verifiers.repo_verifier import reject_unsafe_or_protected


# ───────────────────────────── the gate function ─────────────────────────────
def test_allow_exempts_test_config_ci_but_never_autoexec_or_unsafe():
    R = reject_unsafe_or_protected
    # without the allowlist, each is a protected hit …
    assert R(["tests/test_x.py"], ()) is not None
    assert R(["pytest.ini"], ()) is not None
    assert R([".github/workflows/ci.yml"], ()) is not None
    # … and a matching allow glob exempts the test / config / CI cases.
    assert R(["tests/test_x.py"], (), allow=("tests/test_x.py",)) is None
    assert R(["pytest.ini"], (), allow=("pytest.ini",)) is None
    assert R([".github/workflows/ci.yml"], (), allow=(".github/workflows/*",)) is None
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


def test_guard_allow_exempts_a_makefile_edit(tmp_path):
    _repo(tmp_path)
    (tmp_path / "Makefile").write_text("all:\n\techo hi\n", encoding="utf-8")
    cand = "<<<FILE: Makefile>>>\nall:\n\techo hello\n<<<END FILE>>>"
    # default: a Makefile is a protected build/test config → REJECTED
    assert guard(str(tmp_path), cand).verdict == REJECTED
    # allowlisted: exempt → the (unrelated) pytest suite runs and passes → PASS
    res = guard(str(tmp_path), cand, allow=("Makefile",))
    assert res.verdict == PASS
    assert res.protected_violations == []


def test_guard_allow_never_exempts_autoexec(tmp_path):
    _repo(tmp_path)
    cand = "<<<FILE: sitecustomize.py>>>\nimport os  # runs in the judge process\n<<<END FILE>>>"
    assert guard(str(tmp_path), cand, allow=("sitecustomize.py",)).verdict == REJECTED


# ───────────────────────────── config / CLI wiring ───────────────────────────
def test_config_reads_allow(tmp_path):
    cfg = tmp_path / ".evoguard.json"
    cfg.write_text('{"allow": ["Makefile", "docs/*"]}', encoding="utf-8")
    assert _load_config(str(cfg), out=lambda *_: None).get("allow") == ["Makefile", "docs/*"]


def test_cli_allow_flag_exempts(tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    _repo(repo)
    (repo / "Makefile").write_text("all:\n\techo hi\n", encoding="utf-8")
    patch = tmp_path / "c.patch"
    patch.write_text("<<<FILE: Makefile>>>\nall:\n\techo hello\n<<<END FILE>>>", encoding="utf-8")
    assert cli_main(["guard", str(repo), "--patch", str(patch)]) == 1            # REJECTED
    capsys.readouterr()
    assert cli_main(["guard", str(repo), "--patch", str(patch), "--allow", "Makefile"]) == 0  # PASS
