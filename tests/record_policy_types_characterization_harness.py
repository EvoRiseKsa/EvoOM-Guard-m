# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Deterministic pre-extraction characterization for policy-record validation."""

from __future__ import annotations

import copy
import hashlib
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from evoom_guard import record_verifier

ROOT = Path(__file__).resolve().parents[1]
GOLDEN_RECORD = ROOT / "tests/fixtures/contracts/schema-1.11-golden.json"


@dataclass(frozen=True, slots=True)
class PolicyCase:
    policy: dict[str, Any]
    schema_version: object = "1.11"


def _valid_record(*, schema_version: str = "1.11") -> dict[str, Any]:
    payload = json.loads(GOLDEN_RECORD.read_text(encoding="utf-8"))
    record = cast(
        dict[str, Any],
        copy.deepcopy(payload["records"]["valid_composite"]),
    )
    if schema_version == "1.12":
        record["schema_version"] = schema_version
        record["attestation"]["effective_policy"]["operating_profile"] = "local"
        record["attestation"]["policy_sha256"] = record_verifier._policy_sha256(
            record["attestation"]["effective_policy"]
        )
    return record


def _valid_policy(*, schema_version: str = "1.11") -> dict[str, Any]:
    return copy.deepcopy(
        _valid_record(schema_version=schema_version)["attestation"]["effective_policy"]
    )


def _updated(
    *,
    schema_version: str = "1.11",
    updates: dict[object, Any] | None = None,
    removed: tuple[str, ...] = (),
) -> PolicyCase:
    policy = _valid_policy(schema_version=schema_version)
    for field in removed:
        del policy[field]
    if updates:
        for field, value in updates.items():
            policy[cast(str, field)] = copy.deepcopy(value)
    return PolicyCase(policy=policy, schema_version=schema_version)


def cases() -> dict[str, PolicyCase]:
    return {
        "valid_schema_1_11": _updated(),
        "valid_schema_1_12": _updated(schema_version="1.12"),
        "unsupported_schema_falls_back": PolicyCase(_valid_policy(), "9.9"),
        "missing_sorted": _updated(removed=("allow", "timeout", "mode")),
        "extra_sorted": _updated(updates={"zeta": 1, "alpha": 2}),
        "non_string_key": _updated(updates={7: "value"}),
        "mode_invalid": _updated(updates={"mode": []}),
        "isolation_invalid": _updated(updates={"isolation": "not_run"}),
        "docker_fields_invalid": _updated(
            updates={"docker_image": [], "docker_network": None}
        ),
        "commands_invalid": _updated(
            updates={"test_command": [], "setup_command": []}
        ),
        "path_arrays_invalid": _updated(
            updates={"setup_output_globs": [1], "protected": None, "allow": "src"}
        ),
        "booleans_invalid": _updated(
            updates={
                "trust_setup_on_host": 1,
                "allow_new_tests": None,
                "verifier_pack_required": "true",
                "blackbox": 1,
                "blackbox_only": 0,
                "baseline_evidence": [],
                "require_demonstrated_fix": {},
            }
        ),
        "strict_harness_invalid": _updated(updates={"strict_harness": "true"}),
        "harness_inputs_invalid": _updated(updates={"harness_inputs": ["b", "a"]}),
        "harness_input_conflict": _updated(
            updates={
                "harness_inputs": ["ci/judge.py"],
                "setup_output_globs": ["ci/"],
            }
        ),
        "operating_profile_invalid": _updated(
            schema_version="1.12", updates={"operating_profile": "unknown"}
        ),
        "operating_profile_hostile_violations": _updated(
            schema_version="1.12", updates={"operating_profile": "hostile"}
        ),
        "numeric_fields_invalid": _updated(
            updates={"timeout": True, "mem_limit_mb": -1, "min_diff_coverage": 101}
        ),
        "pack_digest_invalid": _updated(
            updates={"expect_verifier_pack_sha256": "A" * 64}
        ),
        "assurance_floors_invalid": _updated(
            updates={
                "require_report_integrity": "unknown",
                "require_candidate_isolation": "not_run",
            }
        ),
        "identity_invalid": _updated(updates={"policy_id": [], "policy_version": 1}),
        "mode_blackbox_disagreement": _updated(updates={"mode": "repo"}),
        "blackbox_only_requires_blackbox": _updated(
            updates={"blackbox": False, "blackbox_only": True, "mode": "repo"}
        ),
        "pack_digest_requires_pack": _updated(
            updates={
                "expect_verifier_pack_sha256": "a" * 64,
                "verifier_pack_required": False,
            }
        ),
        "simultaneous_faults": _updated(
            schema_version="1.12",
            removed=("allow", "timeout"),
            updates={
                "zeta": 1,
                7: "value",
                "mode": [],
                "isolation": "not_run",
                "docker_image": [],
                "docker_network": None,
                "test_command": [],
                "setup_command": [],
                "setup_output_globs": [1],
                "protected": None,
                "trust_setup_on_host": 1,
                "strict_harness": "true",
                "harness_inputs": ["b", "a"],
                "operating_profile": "unknown",
                "mem_limit_mb": -1,
                "expect_verifier_pack_sha256": "A" * 64,
                "require_report_integrity": "unknown",
                "require_candidate_isolation": "not_run",
                "min_diff_coverage": 101,
                "policy_id": [],
                "policy_version": 1,
                "blackbox_only": True,
                "verifier_pack_required": False,
            },
        ),
    }


def capture(case: PolicyCase) -> list[str]:
    before = copy.deepcopy(case.policy)
    result = record_verifier._policy_type_errors(
        case.policy,
        case.schema_version,
    )
    assert case.policy == before
    return result


def capture_all() -> dict[str, list[str]]:
    return {name: capture(case) for name, case in cases().items()}


def public_cases() -> dict[str, dict[str, Any]]:
    schema_1_11 = _valid_record()
    policy_1_11 = schema_1_11["attestation"]["effective_policy"]
    policy_1_11.update({"mode": "repo", "timeout": 0, "blackbox_only": True})
    schema_1_11["attestation"]["policy_sha256"] = record_verifier._policy_sha256(
        policy_1_11
    )

    schema_1_12 = _valid_record(schema_version="1.12")
    policy_1_12 = schema_1_12["attestation"]["effective_policy"]
    policy_1_12["operating_profile"] = "hostile"
    schema_1_12["attestation"]["policy_sha256"] = record_verifier._policy_sha256(
        policy_1_12
    )
    return {
        "invalid_schema_1_11_policy": schema_1_11,
        "invalid_schema_1_12_profile": schema_1_12,
    }


def capture_public_all() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for name, record in public_cases().items():
        before = copy.deepcopy(record)
        result[name] = record_verifier.verify_record(record)
        assert record == before
    return result


_GENERATED_FIELDS = (
    "allow",
    "allow_new_tests",
    "baseline_evidence",
    "blackbox",
    "blackbox_only",
    "docker_image",
    "docker_network",
    "expect_verifier_pack_sha256",
    "harness_inputs",
    "isolation",
    "mem_limit_mb",
    "min_diff_coverage",
    "mode",
    "operating_profile",
    "policy_id",
    "policy_version",
    "protected",
    "require_candidate_isolation",
    "require_demonstrated_fix",
    "require_report_integrity",
    "setup_command",
    "setup_output_globs",
    "strict_harness",
    "test_command",
    "timeout",
    "trust_setup_on_host",
    "verifier_pack_required",
)
_GENERATED_VALUES: tuple[Any, ...] = (
    None,
    True,
    False,
    -1,
    0,
    1,
    101,
    "",
    "repo",
    "blackbox",
    "subprocess",
    "not_run",
    "A" * 64,
    "a" * 64,
    [],
    ["ci/judge.py"],
    [1],
    {},
)


def generated_trace_digest(*, count: int = 20_000, seed: int = 0xE7012) -> str:
    """Hash exact ordered traces for a reproducible, broad JSON-like corpus."""

    rng = random.Random(seed)
    digest = hashlib.sha256()
    for _ in range(count):
        schema_version = rng.choice(("1.11", "1.12", "9.9", None))
        base_version = "1.12" if schema_version == "1.12" else "1.11"
        policy: dict[str, Any] = _valid_policy(schema_version=base_version)
        for _ in range(rng.randint(1, 8)):
            field = rng.choice(_GENERATED_FIELDS)
            if rng.randrange(5) == 0:
                policy.pop(field, None)
            else:
                policy[field] = copy.deepcopy(rng.choice(_GENERATED_VALUES))
        if rng.randrange(4) == 0:
            policy[f"extra_{rng.randrange(4)}"] = rng.randrange(3)
        errors = record_verifier._policy_type_errors(policy, schema_version)
        digest.update(
            json.dumps(
                errors,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        digest.update(b"\n")
    return digest.hexdigest()
