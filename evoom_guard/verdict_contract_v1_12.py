# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Data vocabulary for the EvoGuard verdict-record 1.12 contract.

Schema 1.12 preserves the complete 1.11 envelope and reason vocabulary while
adding optional digest-bound policy fields, including ``operating_profile`` and
``harness_inputs``. The separate module keeps the published 1.11 contract
frozen.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from evoom_guard import verdict_contract_v1_11 as _v1_11

SCHEMA_VERSION = "1.12"

VERDICTS = _v1_11.VERDICTS
EXECUTION_STATES = _v1_11.EXECUTION_STATES
REASON_CODES = _v1_11.REASON_CODES
_reason_contract = dict(_v1_11.REASON_CONTRACT)
_candidate_tree_verdicts, _candidate_tree_states = _reason_contract[
    _v1_11.REASON_CANDIDATE_TREE_CHANGED
]
_reason_contract[_v1_11.REASON_CANDIDATE_TREE_CHANGED] = (
    _candidate_tree_verdicts,
    _candidate_tree_states | frozenset({_v1_11.EXECUTION_NOT_STARTED}),
)
REASON_CONTRACT: Mapping[
    str, tuple[frozenset[str], frozenset[str]]
] = MappingProxyType(_reason_contract)
POLICY_KEYS = _v1_11.POLICY_KEYS
OPTIONAL_POLICY_KEYS = frozenset(
    {"harness_inputs", "operating_profile", "strict_harness"}
)
ALLOWED_POLICY_KEYS = POLICY_KEYS | OPTIONAL_POLICY_KEYS
REQUIRED_TOP_LEVEL = _v1_11.REQUIRED_TOP_LEVEL
REQUIRED_ASSURANCE = _v1_11.REQUIRED_ASSURANCE
REQUIRED_ATTESTATION = _v1_11.REQUIRED_ATTESTATION

__all__ = (
    "ALLOWED_POLICY_KEYS",
    "EXECUTION_STATES",
    "OPTIONAL_POLICY_KEYS",
    "POLICY_KEYS",
    "REASON_CODES",
    "REASON_CONTRACT",
    "REQUIRED_ASSURANCE",
    "REQUIRED_ATTESTATION",
    "REQUIRED_TOP_LEVEL",
    "SCHEMA_VERSION",
    "VERDICTS",
)
