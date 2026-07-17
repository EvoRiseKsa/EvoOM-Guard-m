"""Static promises that keep the v3.7 review companion honest and reproducible."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "audit" / "v3.7.0"
PRODUCT_SHA = "1f0ceae5009198b1bf161a3a07fced54c1f01337"
PRODUCT_ASSET_SHA256 = "1d36f7ec45f47f9f6c3178a25a58accf8f8beb0ffd9d29e7bf93b7fe17ad3ec9"
COMPANION_TAG = "review-v3.7.0-r1"


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
