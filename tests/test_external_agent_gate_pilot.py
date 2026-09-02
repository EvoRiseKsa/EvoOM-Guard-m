# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Protect the bounded claims and public safety of the external pilot kit."""

from pathlib import Path

ROOT = Path(__file__).parents[1]
PROTOCOL = ROOT / "docs" / "EXTERNAL_AGENT_GATE_PILOT.md"
ISSUE_FORM = ROOT / ".github" / "ISSUE_TEMPLATE" / "external-agent-gate-pilot.yml"


def test_external_pilot_keeps_adoption_and_independent_efficacy_separate() -> None:
    text = PROTOCOL.read_text(encoding="utf-8")

    assert "does **not** replace the separately preregistered independent efficacy study" in text
    assert "must not be described as independent validation" in text
    assert "Keep scientific efficacy claims" in text
    assert "independent 80-case protocol" in text
    assert "Agent identity is `DECLARED_UNVERIFIED`" in text
    assert "`ERROR`; it is not converted" in text


def test_external_pilot_requires_immutable_action_and_base_owned_judge() -> None:
    text = PROTOCOL.read_text(encoding="utf-8")

    assert "base-owned EvoOM policy and base-owned judge configuration" in text
    assert "full commit SHA or immutable release" in text
    assert "never a floating major tag" in text
    assert "@v4.x" not in text
    assert "a different change author" in text
    assert "exact verifier command/version" in text
    assert "structural `verify-record` and authenticated" in text
    assert "at least 10 attempts" in text
    assert "three to five repositories" in text
    assert "promotes the gate to a required blocking check only after" in text
    assert "median clean-checkout-to-first-complete-receipt time below 30 minutes" in text


def test_public_pilot_form_warns_against_sensitive_or_escalated_claims() -> None:
    text = ISSUE_FORM.read_text(encoding="utf-8")

    assert "This form is public" in text
    assert "Do not paste credentials, private source, private prompts" in text
    assert "not automatically an independent efficacy study" in text
    assert "This is a declaration, not a verified agent identity" in text
    assert "full commit SHA or immutable release tag" in text
    assert "does not itself prove independent efficacy" in text
    assert "Relationship to EvoOM Guard" in text
    assert "Retained-evidence verifier contract" in text
    assert "someone other than the operator who configures the gate" in text
    assert "judge-owned report" in text
    assert "authorized to retain the bounded records" in text
    assert "starts advisory" in text
    assert "at least 10 recorded attempts before blocking promotion" in text
    assert "non-required advisory check" in text
