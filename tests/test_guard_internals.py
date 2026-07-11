# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Sole owner & author: Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Unit tests for `guard.py` internals — the risk map, the diff helpers, the
report renderer, and the JSON writer.

These are pure/offline (no suite run) except the PATCH-anchor ERROR path, which
needs only copytree + apply (still no pytest). They pin behaviour the end-to-end
tests in ``test_guard.py`` do not isolate.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard.guard import (
    ERROR,
    FAIL,
    PASS,
    TAMPERED,
    GuardResult,
    _diff_target_paths,
    _risk_map,
    _walk_text_files,
    guard,
    render_report,
    write_json,
)

PATCH_BLOCK = (
    "<<<PATCH: a.py>>>\n<<<SEARCH>>>\nold line\n<<<REPLACE>>>\nnew one\nnew two\n<<<END PATCH>>>"
)


def _result(verdict: str, **kw) -> GuardResult:
    base = dict(
        verdict=verdict,
        passed=(verdict == PASS),
        reason="because",
        files_changed=["a.py"],
        protected_violations=[],
        risk_level="low",
        risk_score=0.1,
    )
    base.update(kw)
    return GuardResult(**base)


# ───────────────────────────── _risk_map ────────────────────────────────────
def test_risk_map_counts_patch_blocks(tmp_path):
    # No a.py on disk → base reads as "" ; the PATCH block contributes its
    # search/replace line counts (added=2, removed=1).
    m = _risk_map(str(tmp_path), PATCH_BLOCK)
    assert m["a.py"] == (2, 1)


# ───────────────────────────── _walk_text_files ─────────────────────────────
def test_walk_text_files_skips_large_and_binary(tmp_path):
    (tmp_path / "small.py").write_text("ok\n", encoding="utf-8")
    (tmp_path / "big.py").write_text("x" * 500, encoding="utf-8")
    (tmp_path / "blob.bin").write_bytes(b"\xff\xfe\x00\x01not-utf8\x80")
    walked = _walk_text_files(str(tmp_path), max_bytes=20)
    assert "small.py" in walked
    assert "big.py" not in walked    # over max_bytes → skipped
    assert "blob.bin" not in walked  # not valid UTF-8 → skipped


# ───────────────────────────── _diff_target_paths ───────────────────────────
def test_diff_target_paths_excludes_dev_null():
    diff = "--- /dev/null\n+++ b/new.py\n@@ -0,0 +1 @@\n+x\n"
    assert _diff_target_paths(diff) == ["new.py"]


# ───────────────────────────── guard ERROR (bad anchor) ─────────────────────
def test_guard_patch_anchor_not_found_is_error(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("hello world\n", encoding="utf-8")
    cand = "<<<PATCH: a.py>>>\n<<<SEARCH>>>\nNOT-PRESENT\n<<<REPLACE>>>\nx\n<<<END PATCH>>>"
    # Pass test_command + protected so the problem-dict wiring is exercised too; the
    # anchor fails before any suite runs, so the verdict is still a clean ERROR.
    res = guard(str(repo), cand, test_command=["pytest", "-q"], protected=("docs/*",))
    assert res.verdict == ERROR
    assert res.reason_code == "patch_apply_failed"
    assert res.exit_code == 1


# ───────────────────────────── render_report ────────────────────────────────
def test_render_report_pass_with_deleted_and_files():
    out = render_report(_result(PASS), deleted=["gone.py"])
    assert "✅ PASS" in out
    assert "gone.py" in out          # the deleted-files note
    assert "Files changed" in out    # the files-changed <details> block


def test_render_report_tampered_shows_section_and_diagnostics():
    out = render_report(_result(TAMPERED, diagnostics="exit/report desync trace"))
    assert "🚨" in out
    assert "Tamper signature" in out
    assert "exit/report desync trace" in out  # diagnostics block for FAIL/ERROR/TAMPERED


def test_render_report_fail_shows_diagnostics():
    out = render_report(_result(FAIL, tests_passed=1, tests_total=2, diagnostics="boom"))
    assert "❌ FAIL" in out
    assert "boom" in out


def test_render_report_footer_reflects_isolation():
    # the footer must describe the *actual* judge, not always "subprocess".
    assert "subprocess" in render_report(_result(PASS))                  # default
    assert "container" in render_report(_result(PASS, isolation="docker"))
    g = render_report(_result(PASS, isolation="gvisor"))
    assert "gVisor" in g and "runsc" in g
    assert "subprocess" not in g                                         # not misreported


# ───────────────────────────── write_json ───────────────────────────────────
def test_write_json_includes_deleted(tmp_path):
    path = tmp_path / "v.json"
    write_json(_result(PASS), str(path), deleted=["gone.py"])
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["verdict"] == PASS
    assert payload["deleted"] == ["gone.py"]
    assert payload["schema_version"] == "1.4"
