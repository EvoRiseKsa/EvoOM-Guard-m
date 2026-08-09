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
AUDIT_V450 = ROOT / "audit" / "v4.5.0"
PRODUCT_V450_SHA = "6bb4c328e56661b661e50532886802c6ba36a997"
PRODUCT_V450_TREE = "bd81a595ca8608ad7da04390f31d5e489f5083ef"
PRODUCT_V450_ASSET_SHA256 = "44bf036666bc7bb2903b647f33b63254771771887de4f170c91e8cdd8307c89d"
PRODUCT_V450_SBOM_SHA256 = "d073198e6a3a7d565895b3cf885c95386768670a243e05e5b1471636a0f8da4b"
PRODUCT_V450_SUMS_SHA256 = "0172d35b903661328f16366517fe5a8f666aaf282cf26c5ec4e263da4abedd0f"
PRODUCT_V450_LEDGER_SHA256 = "9ee6c49e7a3c93d611c34e208f5e3936f147bf0ed0b8ff2c41b3e53b891da239"


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


def test_v450_companion_pins_the_immutable_target_without_inventing_a_tag() -> None:
    manifest = json.loads((AUDIT_V450 / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["format"] == "EVOGUARD_EXTERNAL_REVIEW_TARGET_V1"
    assert manifest["target"] == {
        "repository": "EvoRiseKsa/EvoOM-Guard-m",
        "release_tag": "v4.5.0",
        "release_id": 363544789,
        "release_url": ("https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.5.0"),
        "resolved_commit": PRODUCT_V450_SHA,
        "source_tree": PRODUCT_V450_TREE,
        "guard_version": "4.5.0",
        "evidence_schema_versions": ["1.11", "1.12"],
        "release_is_immutable": True,
        "release_published_at": "2026-08-01T14:32:33Z",
        "tag_ci_run_id": 30703985270,
        "tag_ci_url": ("https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/runs/30703985270"),
        "review_issue": "https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues/141",
        "marketplace_url": "https://github.com/marketplace/actions/evoom-guard",
    }
    assert manifest["companion_status"] == {
        "is_part_of_frozen_target": False,
        "does_not_change_release_claims": True,
        "does_not_establish_independent_review": True,
        "is_frozen_separately": False,
        "revision": "audit-v4.5.0-r1",
        "repository_path": "audit/v4.5.0",
        "publication_status": "source-controlled-no-companion-tag-or-release",
    }
    assert manifest["target_commit_verification"] == {
        "verified": False,
        "reason": "unsigned",
        "expected_api_observation": (
            "GitHub reports commit.verification.verified=false and "
            "reason=unsigned for the release commit."
        ),
        "release_attestation_is_not_commit_signature": True,
    }


def test_v450_companion_pins_the_exact_three_asset_release() -> None:
    manifest = json.loads((AUDIT_V450 / "manifest.json").read_text(encoding="utf-8"))
    assets = {asset["name"]: asset for asset in manifest["assets"]}

    assert set(assets) == {"evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS"}
    assert assets["evo-guard.pyz"] == {
        "id": 497974096,
        "name": "evo-guard.pyz",
        "role": "runtime",
        "size_bytes": 2356398,
        "sha256": PRODUCT_V450_ASSET_SHA256,
    }
    assert assets["evo-guard.spdx.json"] == {
        "id": 497974097,
        "name": "evo-guard.spdx.json",
        "role": "spdx-sbom",
        "size_bytes": 99797,
        "sha256": PRODUCT_V450_SBOM_SHA256,
    }
    assert assets["SHA256SUMS"]["id"] == 497974098
    assert assets["SHA256SUMS"]["size_bytes"] == 166
    assert assets["SHA256SUMS"]["sha256"] == PRODUCT_V450_SUMS_SHA256
    assert assets["SHA256SUMS"]["utf8_content"] == (
        f"{PRODUCT_V450_ASSET_SHA256}  evo-guard.pyz\n"
        f"{PRODUCT_V450_SBOM_SHA256}  evo-guard.spdx.json\n"
    )


def test_v450_later_evidence_is_explicitly_outside_the_frozen_target() -> None:
    manifest = json.loads((AUDIT_V450 / "manifest.json").read_text(encoding="utf-8"))
    later = manifest["post_publication_evidence"]
    ledger = later["release_ledger"]
    gvisor = later["gvisor_observation"]

    assert ledger["status"] == ("same-owner-post-publication-evidence-not-part-of-release-target")
    assert ledger["is_present_in_v4.5.0_tree"] is False
    assert ledger["sha256"] == PRODUCT_V450_LEDGER_SHA256
    assert ledger["validation_requires_external_root_and_disjoint_parent_checkout"]
    assert ledger["does_not_establish_independence"] is True
    assert gvisor["status"] == "same-owner-supplemental-later-on-main"
    assert gvisor["source_run_id"] == 31298956172
    assert gvisor["is_part_of_release_ledger"] is False
    assert gvisor["independent"] is False
    assert gvisor["production"] is False
    assert gvisor["field_evaluation"] is False
    assert gvisor["hostile_host"] is False
    assert later["firecracker"] == {
        "status": "design-only",
        "implemented_or_exercised_for_v4.5.0": False,
    }
    assert manifest["independence"]["independent_audit_completed"] is False


def test_v450_reproduction_requires_attestation_and_expected_unsigned_commit() -> None:
    bash = (AUDIT_V450 / "reproduce.sh").read_text(encoding="utf-8")
    powershell = (AUDIT_V450 / "reproduce.ps1").read_text(encoding="utf-8")
    readme = (AUDIT_V450 / "README.md").read_text(encoding="utf-8")
    runbook = (AUDIT_V450 / "REVIEWER_RUNBOOK.md").read_text(encoding="utf-8")
    matrix = (AUDIT_V450 / "TEST_MATRIX.md").read_text(encoding="utf-8")

    assert 'gh release verify "$TAG" --repo "$REPOSITORY"' in bash
    assert "& gh release verify $tag --repo $repository" in powershell
    assert "$'false\\tunsigned'" in bash
    assert "$verification.verified -ne $false" in powershell
    assert "$verification.reason -cne 'unsigned'" in powershell
    assert "--smoke" in bash
    assert 'if [[ "$run_smoke" == true ]]; then' in bash
    assert "[switch]$Smoke" in powershell
    assert "if ($Smoke)" in powershell
    assert '"$PYTHON_BIN" -I' in bash[bash.index('if [[ "$run_smoke" == true ]]; then') :]
    assert "& $Python -I" in powershell[powershell.index("if ($Smoke)") :]
    assert "do **not** execute the released zipapp" in readme
    assert "No `review-v4.5.0-*` tag or companion Release is claimed" in runbook
    assert "Firecracker" in matrix and "design-only" in matrix
