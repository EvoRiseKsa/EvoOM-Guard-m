# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Keep the Public Beta offer bounded, measurable, and fail closed."""

from pathlib import Path

ROOT = Path(__file__).parents[1]
BETA = ROOT / "docs" / "PUBLIC_BETA.md"
PRODUCT = ROOT / "docs" / "PRODUCT_CONTRACT.md"
CURRENT_RELEASE = "v4.8.0"
CURRENT_RELEASE_SHA = "07e361cb9a75cc1822cd905ca65df42235b3b910"


def test_product_contract_preserves_the_one_question_and_nonclaims() -> None:
    text = PRODUCT.read_text(encoding="utf-8")

    assert CURRENT_RELEASE in text
    assert CURRENT_RELEASE_SHA in text
    assert "Did this change satisfy the selected judge without editing or deleting an" in text
    assert "evidence path protected by the active policy?" in text
    assert "Public Beta" in text
    assert "not a hosted SaaS" in text
    assert "does not mean Core GA" in text
    assert "not currently a supported product" in text
    assert "It cannot compensate for a weak" in text
    assert "is never merge, release, or deployment authority" in text
    assert "Independently validated" not in text
    assert "independently validated merely because" in text


def test_public_beta_is_advisory_first_and_evidence_promoted() -> None:
    text = BETA.read_text(encoding="utf-8")
    normalized = " ".join(text.split())

    assert CURRENT_RELEASE in text
    assert CURRENT_RELEASE_SHA in text
    assert "keep its check non-required" in text
    assert "at least **10 attempts**" in text
    assert "first four are fixed" in text
    assert "remaining six attempts" in text
    assert "no known P0 or P1 defect remains" in text
    assert "**3–5 repositories**" in text
    assert "target under 30 minutes" in text
    assert "target at least 95%" in text
    assert "100% retained-receipt verification" in text
    assert "They do not establish population efficacy" in normalized


def test_public_beta_support_fails_closed_without_promising_an_sla() -> None:
    beta = BETA.read_text(encoding="utf-8")
    support = (ROOT / "SUPPORT.md").read_text(encoding="utf-8")

    assert "must not convert it into `PASS`" in beta
    assert "has no response-time, resolution-time" in beta
    assert "P0 — security bypass" in support
    assert "P1 — wrong admission" in support
    assert "Roll the affected repository back to advisory" in support
    assert "Never convert an unavailable or" in support


def test_public_entry_points_link_the_beta_contracts() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    docs_index = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")

    assert "[product contract](docs/PRODUCT_CONTRACT.md)" in readme
    assert "[Public Beta promotion gates](docs/PUBLIC_BETA.md)" in readme
    assert "[`PRODUCT_CONTRACT.md`](PRODUCT_CONTRACT.md)" in docs_index
    assert "[`PUBLIC_BETA.md`](PUBLIC_BETA.md)" in docs_index
