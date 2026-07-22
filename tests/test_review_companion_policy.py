"""Static promises that keep frozen review companions honest and reproducible."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "audit" / "v3.7.0"
PRODUCT_SHA = "1f0ceae5009198b1bf161a3a07fced54c1f01337"
PRODUCT_ASSET_SHA256 = "1d36f7ec45f47f9f6c3178a25a58accf8f8beb0ffd9d29e7bf93b7fe17ad3ec9"
COMPANION_TAG = "review-v3.7.0-r1"
AUDIT_V410 = ROOT / "audit" / "v4.1.0"
PRODUCT_V410_SHA = "16029f3e34237ed07b97649c5c9be35d0a356bf7"
PRODUCT_V410_TREE = "7c749ed298050840fdd52577e6364a6e63cd36a6"
PRODUCT_V410_ASSET_SHA256 = (
    "d5ce7dbefa870307d6fe49ddec1e9847cad89d15f6afe2b74f4e7b8953fc62b2"
)
COMPANION_V410_TAG = "review-v4.1.0-r1"


def test_review_companion_is_separately_pinned_and_names_the_frozen_target() -> None:
    manifest = json.loads((AUDIT / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["format"] == "EVOGUARD_EXTERNAL_REVIEW_TARGET_V1"
    assert manifest["target"]["release_tag"] == "v3.7.0"
    assert manifest["target"]["resolved_commit"] == PRODUCT_SHA
    assert manifest["assets"][0]["sha256"] == PRODUCT_ASSET_SHA256
    assert manifest["companion_status"] == {
        "is_part_of_frozen_target": False,
        "does_not_change_release_claims": True,
        "does_not_establish_independent_review": True,
        "is_frozen_separately": True,
        "review_companion_tag": COMPANION_TAG,
        "review_companion_release_url": (
            "https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/"
            f"{COMPANION_TAG}"
        ),
    }
    assert manifest["verification"]["default_executes_released_zipapp"] is False
    assert "optional_smoke_command" in manifest["verification"]


def test_default_reproduction_is_identity_only_and_smoke_is_explicit() -> None:
    bash = (AUDIT / "reproduce.sh").read_text(encoding="utf-8")
    powershell = (AUDIT / "reproduce.ps1").read_text(encoding="utf-8")
    readme = (AUDIT / "README.md").read_text(encoding="utf-8")
    runbook = (AUDIT / "REVIEWER_RUNBOOK.md").read_text(encoding="utf-8")

    assert "--smoke" in bash
    assert 'if [[ "$run_smoke" == true ]]; then' in bash
    assert "[switch]$Smoke" in powershell
    assert "if ($Smoke)" in powershell
    assert '"$PYTHON_BIN" -I' in bash[bash.index('if [[ "$run_smoke" == true ]]; then'):]
    assert "& $Python -I" in powershell[powershell.index("if ($Smoke)"):]
    assert "do **not** execute the released zipapp" in readme
    assert COMPANION_TAG in runbook
    assert "Potential vulnerabilities belong in the private reporting route" in runbook


def test_v410_companion_pins_product_and_separate_round1_evidence() -> None:
    manifest = json.loads((AUDIT_V410 / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["format"] == "EVOGUARD_EXTERNAL_REVIEW_TARGET_V1"
    assert manifest["target"]["release_tag"] == "v4.1.0"
    assert manifest["target"]["resolved_commit"] == PRODUCT_V410_SHA
    assert manifest["target"]["source_tree"] == PRODUCT_V410_TREE
    assert manifest["assets"][0]["sha256"] == PRODUCT_V410_ASSET_SHA256
    assert manifest["companion_status"] == {
        "is_part_of_frozen_target": False,
        "does_not_change_release_claims": True,
        "does_not_establish_independent_review": True,
        "is_frozen_separately": True,
        "review_companion_tag": COMPANION_V410_TAG,
        "review_companion_release_url": (
            "https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/"
            f"{COMPANION_V410_TAG}"
        ),
    }
    evidence = manifest["operational_evidence"]
    assert evidence["status"] == "same_owner_pilot_not_independent_review"
    assert evidence["target_commit"] == (
        "af8e4592ef5572acfe2ea295c435eed6a8e122fc"
    )
    assert evidence["positive_runs"] == {
        "reverify": "29896945747/1",
        "receipt": "29896982146/1",
        "admit_and_detached_verify": "29897001564/1",
    }
    assert manifest["verification"]["default_executes_released_zipapp"] is False


def test_v410_default_reproduction_is_identity_only_and_smoke_is_explicit() -> None:
    bash = (AUDIT_V410 / "reproduce.sh").read_text(encoding="utf-8")
    powershell = (AUDIT_V410 / "reproduce.ps1").read_text(encoding="utf-8")
    readme = (AUDIT_V410 / "README.md").read_text(encoding="utf-8")
    runbook = (AUDIT_V410 / "REVIEWER_RUNBOOK.md").read_text(encoding="utf-8")
    matrix = (AUDIT_V410 / "TEST_MATRIX.md").read_text(encoding="utf-8")

    assert "--smoke" in bash
    assert 'if [[ "$run_smoke" == true ]]; then' in bash
    assert "[switch]$Smoke" in powershell
    assert "if ($Smoke)" in powershell
    assert '"$PYTHON_BIN" -I' in bash[bash.index('if [[ "$run_smoke" == true ]]; then'):]
    assert "& $Python -I" in powershell[powershell.index("if ($Smoke)"):]
    assert "do **not** execute the released zipapp" in readme
    assert COMPANION_V410_TAG in runbook
    assert "Potential vulnerabilities belong in the private reporting route" in runbook
    assert "does not bind an artifact" in matrix
