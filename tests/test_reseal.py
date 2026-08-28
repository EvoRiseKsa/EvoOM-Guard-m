# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""The one-command re-seal helper preserves the trust model it automates.

These pin the pure, non-mutating helpers of ``tools/ci/reseal.py``: it reads the
source pin from the *real* ``REVIEWED_DISPOSITIONS`` structure (never a regex
guess), reads the manifest's recorded source digest, re-pins across both the
registry module and its test, and its dry run changes nothing. The three-commit
ritual itself is exercised end to end by the benchmark and failure-registry
suites plus a live re-seal on the branch.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_RESEAL = _ROOT / "tools" / "ci" / "reseal.py"


def _load_reseal():
    spec = importlib.util.spec_from_file_location("_reseal_under_test", _RESEAL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reseal = _load_reseal()

_HEX_A = "a" * 64
_HEX_B = "b" * 64


def test_pinned_source_sha256_reads_the_real_disposition_key() -> None:
    # The live pin equals the source digest recorded in the live manifest, which
    # is exactly the invariant a re-seal must keep true.
    pin = reseal._pinned_source_sha256()
    assert reseal._SHA_RE.fullmatch(pin)
    assert pin == reseal._manifest_source_sha256()


def test_pinned_source_reads_first_tuple_element(tmp_path: Path) -> None:
    src = tmp_path / "failure_registry.py"
    src.write_text(
        "REVIEWED_DISPOSITIONS = {\n"
        f'    ("{_HEX_A}", "{_HEX_B}", "case-x", "false_accept"): "known_security_gap",\n'
        f'    ("{_HEX_A}", "{_HEX_B}", "case-y", "false_reject"): "deliberate_policy_tradeoff",\n'
        "}\n",
        encoding="utf-8",
    )
    # The corpus digest (_HEX_B) also recurs, so a naive "most common" heuristic
    # would be ambiguous; reading tuple[0] is unambiguous.
    assert reseal._pinned_source_sha256(src) == _HEX_A


def test_pinned_source_rejects_inconsistent_pins(tmp_path: Path) -> None:
    src = tmp_path / "failure_registry.py"
    src.write_text(
        "REVIEWED_DISPOSITIONS = {\n"
        f'    ("{_HEX_A}", "{_HEX_B}", "case-x", "false_accept"): "known_security_gap",\n'
        f'    ("{_HEX_B}", "{_HEX_A}", "case-y", "false_reject"): "deliberate_policy_tradeoff",\n'
        "}\n",
        encoding="utf-8",
    )
    with pytest.raises(reseal.ReSealError, match="differing source digests"):
        reseal._pinned_source_sha256(src)


def test_manifest_source_sha256_reads_the_digest(tmp_path: Path) -> None:
    manifest = tmp_path / "run-manifest.json"
    manifest.write_text(json.dumps({"source": {"sha256": _HEX_A}}), encoding="utf-8")
    assert reseal._manifest_source_sha256(manifest) == _HEX_A


def test_manifest_source_sha256_rejects_a_missing_digest(tmp_path: Path) -> None:
    manifest = tmp_path / "run-manifest.json"
    manifest.write_text(json.dumps({"source": {}}), encoding="utf-8")
    with pytest.raises(reseal.ReSealError, match="source.sha256"):
        reseal._manifest_source_sha256(manifest)


def test_repin_replaces_across_module_and_test(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "failure_registry.py"
    test = tmp_path / "test_registry.py"
    src.write_text(f'PIN = "{_HEX_A}"  # x3 in practice\n', encoding="utf-8")
    test.write_text(f'source_sha256 = "{_HEX_A}"\n', encoding="utf-8")
    monkeypatch.setattr(reseal, "FAILURE_REGISTRY_SRC", src)
    monkeypatch.setattr(reseal, "FAILURE_REGISTRY_TEST", test)

    edited = reseal._repin(_HEX_B, _HEX_A)

    assert set(edited) == {src, test}
    assert _HEX_A not in src.read_text(encoding="utf-8")
    assert _HEX_B in src.read_text(encoding="utf-8")
    assert _HEX_B in test.read_text(encoding="utf-8")


def test_dry_run_changes_nothing_and_lists_every_step(capsys: pytest.CaptureFixture[str]) -> None:
    assert reseal.re_seal("demo change", repin=False, dry_run=True) == 0
    out = capsys.readouterr().out
    assert "run_live.py --replace" in out
    assert "--finalize-provenance" in out
    assert "failure_registry.py --generate" in out
    assert "after demo change" in out
