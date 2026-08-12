"""Run a deterministic, bounded mutation gate over assurance-sensitive logic.

This is intentionally smaller than a general mutation framework.  Every mutant
models a reviewed security regression, must apply exactly once, and is executed
against one focused test in an isolated package overlay.  A mutant is killed
only by a normal pytest assertion failure (exit 1); collection errors, timeouts,
and infrastructure failures fail the gate instead of becoming false positives.

The outer watchdog is a liveness guard, not a sandbox.  On POSIX it can stop
only processes that remain in pytest's dedicated process group; a descendant
that deliberately creates a new session escapes that boundary.  Real-process
mutation contracts therefore terminate by themselves even when their target
check is bypassed, and an outer timeout is always an infrastructure error.
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MAX_WORKERS = 8


@dataclass(frozen=True)
class Mutation:
    name: str
    path: str
    before: str
    after: str
    test: str


MUTATIONS = (
    Mutation(
        name="record-envelope-string-type-bypass",
        path="evoom_guard/verifiers/record_envelope_types.py",
        before=(
            "        if field in record and not isinstance(record[field], str):\n"
        ),
        after=(
            "        if False and field in record and "
            "not isinstance(record[field], str):\n"
        ),
        test=(
            "tests/test_record_envelope_types.py::"
            "test_string_and_boolean_field_families_preserve_order"
        ),
    ),
    Mutation(
        name="record-envelope-boolean-type-bypass",
        path="evoom_guard/verifiers/record_envelope_types.py",
        before=(
            "        if field in record and not isinstance(record[field], bool):\n"
        ),
        after=(
            "        if False and field in record and "
            "not isinstance(record[field], bool):\n"
        ),
        test=(
            "tests/test_record_envelope_types.py::"
            "test_string_and_boolean_field_families_preserve_order"
        ),
    ),
    Mutation(
        name="record-envelope-integer-boolean-bypass",
        path="evoom_guard/verifiers/record_envelope_types.py",
        before=(
            "    return isinstance(value, int) and not isinstance(value, bool)\n"
        ),
        after="    return isinstance(value, int)\n",
        test=(
            "tests/test_record_envelope_types.py::"
            "test_integer_and_number_types_reject_boolean_and_non_finite_values"
        ),
    ),
    Mutation(
        name="record-envelope-non-finite-number-bypass",
        path="evoom_guard/verifiers/record_envelope_types.py",
        before="    return isinstance(value, int) or math.isfinite(value)\n",
        after="    return isinstance(value, (int, float))\n",
        test=(
            "tests/test_record_envelope_types.py::"
            "test_integer_and_number_types_reject_boolean_and_non_finite_values"
        ),
    ),
    Mutation(
        name="record-envelope-nullable-integer-boolean-bypass",
        path="evoom_guard/verifiers/record_envelope_types.py",
        before="    return value is None or _is_int(value)\n",
        after="    return value is None or isinstance(value, int)\n",
        test=(
            "tests/test_record_envelope_types.py::"
            "test_integer_and_number_types_reject_boolean_and_non_finite_values"
        ),
    ),
    Mutation(
        name="record-envelope-string-tuple-bypass",
        path="evoom_guard/verifiers/record_envelope_types.py",
        before=(
            "    return isinstance(value, list) and all("
            "isinstance(item, str) for item in value)\n"
        ),
        after=(
            "    return isinstance(value, (list, tuple)) and all("
            "isinstance(item, str) for item in value)\n"
        ),
        test=(
            "tests/test_record_envelope_types.py::"
            "test_string_arrays_require_real_lists_with_only_strings"
        ),
    ),
    Mutation(
        name="record-envelope-nullable-string-bypass",
        path="evoom_guard/verifiers/record_envelope_types.py",
        before="    return value is None or isinstance(value, str)\n",
        after="    return value is None or True\n",
        test=(
            "tests/test_record_envelope_types.py::"
            "test_nullable_strings_and_objects_keep_exact_dict_semantics"
        ),
    ),
    Mutation(
        name="record-envelope-nullable-object-bypass",
        path="evoom_guard/verifiers/record_envelope_types.py",
        before=(
            "        if field in record and record[field] is not None and "
            "not isinstance(record[field], dict):\n"
        ),
        after=(
            "        if False and field in record and record[field] is not None "
            "and not isinstance(record[field], dict):\n"
        ),
        test=(
            "tests/test_record_envelope_types.py::"
            "test_nullable_strings_and_objects_keep_exact_dict_semantics"
        ),
    ),
    Mutation(
        name="record-envelope-assurance-object-bypass",
        path="evoom_guard/verifiers/record_envelope_types.py",
        before=(
            '    if "assurance" in record and not '
            'isinstance(record["assurance"], dict):\n'
        ),
        after=(
            '    if False and "assurance" in record and not '
            'isinstance(record["assurance"], dict):\n'
        ),
        test=(
            "tests/test_record_envelope_types.py::"
            "test_nullable_strings_and_objects_keep_exact_dict_semantics"
        ),
    ),
    Mutation(
        name="record-envelope-attestation-object-bypass",
        path="evoom_guard/verifiers/record_envelope_types.py",
        before=(
            '        "attestation" in record\n'
            '        and record["attestation"] is not None\n'
            '        and not isinstance(record["attestation"], dict)\n'
        ),
        after=(
            '        "attestation" in record\n'
            '        and record["attestation"] is not None\n'
            '        and False\n'
        ),
        test=(
            "tests/test_record_envelope_types.py::"
            "test_nullable_strings_and_objects_keep_exact_dict_semantics"
        ),
    ),
    Mutation(
        name="record-baseline-non-string-key-bypass",
        path="evoom_guard/verifiers/record_baseline_types.py",
        before=(
            "    if any(not isinstance(key, str) for key in baseline):\n"
            '        return ("all baseline keys must be strings",)\n'
        ),
        after=(
            "    if False and any(not isinstance(key, str) for key in baseline):\n"
            '        return ("all baseline keys must be strings",)\n'
        ),
        test=(
            "tests/test_record_baseline_types.py::"
            "test_non_string_keys_fail_closed_before_value_validation"
        ),
    ),
    Mutation(
        name="record-baseline-producer-key-set-bypass",
        path="evoom_guard/verifiers/record_baseline_types.py",
        before=(
            "    if not _BASELINE_KEYS <= keys or not keys <= "
            "_BASELINE_KEYS | _BASELINE_SETUP_KEYS:\n"
        ),
        after="    if False:\n",
        test=(
            "tests/test_record_baseline_types.py::"
            "test_required_and_unknown_producer_keys_cannot_be_bypassed"
        ),
    ),
    Mutation(
        name="record-baseline-unsupported-shape-bypass",
        path="evoom_guard/verifiers/record_baseline_types.py",
        before=(
            "        errors.extend(\n"
            "            _unsupported_errors(\n"
            "                keys,\n"
            "                verdict=verdict,\n"
            "                passed=passed,\n"
            "                total=total,\n"
            "                effect=effect,\n"
            "            )\n"
            "        )\n"
        ),
        after="        errors.extend(())\n",
        test=(
            "tests/test_record_baseline_types.py::"
            "test_unsupported_mode_requires_exact_keys_and_null_evidence"
        ),
    ),
    Mutation(
        name="record-baseline-count-truth-bypass",
        path="evoom_guard/verifiers/record_baseline_types.py",
        before=(
            "    errors.extend(_count_errors(verdict=verdict, "
            "passed=passed, total=total))\n"
        ),
        after="    errors.extend(())\n",
        test=(
            "tests/test_record_baseline_types.py::"
            "test_counts_reject_boolean_negative_and_out_of_order_values"
        ),
    ),
    Mutation(
        name="record-baseline-repair-effect-bypass",
        path="evoom_guard/verifiers/record_baseline_types.py",
        before=(
            "    errors.extend(_repair_effect_errors(verdict=verdict, "
            "effect=effect))\n"
        ),
        after="    errors.extend(())\n",
        test=(
            "tests/test_record_baseline_types.py::"
            "test_repair_effect_remains_bound_to_cleanliness"
        ),
    ),
    Mutation(
        name="record-baseline-setup-enum-bypass",
        path="evoom_guard/verifiers/record_baseline_types.py",
        before=(
            '        if setup not in ("unverified", "setup_failed", '
            '"changed_judged_tree"):\n'
        ),
        after="        if False:\n",
        test=(
            "tests/test_record_baseline_types.py::"
            "test_setup_fidelity_requires_an_unclean_unmeasured_baseline"
        ),
    ),
    Mutation(
        name="record-baseline-setup-cleanliness-bypass",
        path="evoom_guard/verifiers/record_baseline_types.py",
        before=(
            '        if verdict != "NO_CLEAN_VERDICT" or effect != "unmeasured":\n'
        ),
        after="        if False:\n",
        test=(
            "tests/test_record_baseline_types.py::"
            "test_setup_fidelity_requires_an_unclean_unmeasured_baseline"
        ),
    ),
    Mutation(
        name="record-baseline-changed-path-canonicality-bypass",
        path="evoom_guard/verifiers/record_baseline_types.py",
        before=(
            "        if not (\n"
            "            _is_string_list(changes)\n"
            "            and bool(changes)\n"
            "            and changes == sorted(set(changes))\n"
            "        ):\n"
        ),
        after=(
            "        if False and not (\n"
            "            _is_string_list(changes)\n"
            "            and bool(changes)\n"
            "            and changes == sorted(set(changes))\n"
            "        ):\n"
        ),
        test=(
            "tests/test_record_baseline_types.py::"
            "test_changed_tree_paths_are_nonempty_sorted_unique_strings"
        ),
    ),
    Mutation(
        name="record-coverage-python-path-safety-bypass",
        path="evoom_guard/verifiers/record_coverage_types.py",
        before="    if not _coverage_path(path, python=True):\n",
        after="    if False and not _coverage_path(path, python=True):\n",
        test=(
            "tests/test_record_coverage_types.py::"
            "test_python_coverage_paths_remain_safe_and_repo_relative"
        ),
    ),
    Mutation(
        name="record-coverage-positive-line-bypass",
        path="evoom_guard/verifiers/record_coverage_types.py",
        before="        and all(_is_int(item) and item > 0 for item in value)\n",
        after="        and all(_is_int(item) for item in value)\n",
        test=(
            "tests/test_record_coverage_types.py::"
            "test_line_arrays_require_sorted_unique_positive_non_boolean_lines"
        ),
    ),
    Mutation(
        name="record-coverage-line-overlap-bypass",
        path="evoom_guard/verifiers/record_coverage_types.py",
        before="    if set(executed_lines) & set(missed_lines):\n",
        after="    if False and set(executed_lines) & set(missed_lines):\n",
        test=(
            "tests/test_record_coverage_types.py::"
            "test_executed_and_missed_lines_cannot_overlap"
        ),
    ),
    Mutation(
        name="record-coverage-file-count-binding-bypass",
        path="evoom_guard/verifiers/record_coverage_types.py",
        before="    if _is_int(executed) and executed != file_executed:\n",
        after="    if False and _is_int(executed) and executed != file_executed:\n",
        test=(
            "tests/test_record_coverage_types.py::"
            "test_top_level_counts_remain_bound_to_per_file_totals"
        ),
    ),
    Mutation(
        name="record-coverage-percentage-binding-bypass",
        path="evoom_guard/verifiers/record_coverage_types.py",
        before="        if percent != calculated:\n",
        after="        if False and percent != calculated:\n",
        test=(
            "tests/test_record_coverage_types.py::"
            "test_percentage_remains_bound_to_the_exact_producer_calculation"
        ),
    ),
    Mutation(
        name="record-coverage-unmeasured-python-bypass",
        path="evoom_guard/verifiers/record_coverage_types.py",
        before="        and all(_coverage_path(path, python=False) for path in unmeasured)\n",
        after="        and True\n",
        test=(
            "tests/test_record_coverage_types.py::"
            "test_unmeasured_paths_cannot_claim_python_files_as_out_of_scope"
        ),
    ),
    Mutation(
        name="record-policy-required-fields-bypass",
        path="evoom_guard/verifiers/record_policy_types.py",
        before="    missing = sorted(policy_keys - policy.keys())\n",
        after="    missing = []\n",
        test=(
            "tests/test_record_policy_types.py::"
            "test_required_policy_fields_and_error_order_cannot_be_bypassed"
        ),
    ),
    Mutation(
        name="record-policy-extra-fields-bypass",
        path="evoom_guard/verifiers/record_policy_types.py",
        before=(
            "        if isinstance(key, str) and key not in allowed_policy_keys\n"
        ),
        after="        if False and isinstance(key, str) and key not in allowed_policy_keys\n",
        test=(
            "tests/test_record_policy_types.py::"
            "test_schema_specific_extra_keys_cannot_be_bypassed"
        ),
    ),
    Mutation(
        name="record-policy-harness-canonicality-bypass",
        path="evoom_guard/verifiers/record_policy_types.py",
        before='    if not harness_input_validator(policy["harness_inputs"]):\n',
        after='    if False and not harness_input_validator(policy["harness_inputs"]):\n',
        test=(
            "tests/test_record_policy_types.py::"
            "test_harness_inputs_remain_canonical_and_visible_to_setup_conflicts"
        ),
    ),
    Mutation(
        name="record-policy-harness-conflict-bypass",
        path="evoom_guard/verifiers/record_policy_types.py",
        before="    if conflicts:\n",
        after="    if False and conflicts:\n",
        test=(
            "tests/test_record_policy_types.py::"
            "test_harness_inputs_remain_canonical_and_visible_to_setup_conflicts"
        ),
    ),
    Mutation(
        name="record-policy-timeout-positivity-bypass",
        path="evoom_guard/verifiers/record_policy_types.py",
        before="    if not _is_int(timeout) or timeout <= 0:\n",
        after="    if not _is_int(timeout):\n",
        test=(
            "tests/test_record_policy_types.py::"
            "test_timeout_rejects_bool_zero_and_negative_values"
        ),
    ),
    Mutation(
        name="record-policy-uppercase-pack-digest-bypass",
        path="evoom_guard/verifiers/record_policy_types.py",
        before='_HEX_64 = re.compile(r"^[0-9a-f]{64}$")\n',
        after='_HEX_64 = re.compile(r"^[0-9A-Fa-f]{64}$")\n',
        test=(
            "tests/test_record_policy_types.py::"
            "test_pack_digest_remains_lowercase_and_requires_the_pack"
        ),
    ),
    Mutation(
        name="record-policy-pack-required-bypass",
        path="evoom_guard/verifiers/record_policy_types.py",
        before=(
            '    if expected_pack is not None and policy.get("verifier_pack_required") is not True:\n'
        ),
        after=(
            '    if False and expected_pack is not None and policy.get("verifier_pack_required") is not True:\n'
        ),
        test=(
            "tests/test_record_policy_types.py::"
            "test_pack_digest_remains_lowercase_and_requires_the_pack"
        ),
    ),
    Mutation(
        name="record-policy-profile-semantic-reverification-bypass",
        path="evoom_guard/record_verifier.py",
        before="    if projection.operating_profile is not None:\n",
        after="    if False and projection.operating_profile is not None:\n",
        test=(
            "tests/test_record_policy_types.py::"
            "test_valid_hostile_profile_cannot_skip_semantic_reverification"
        ),
    ),
    Mutation(
        name="record-nested-assurance-required-fields-bypass",
        path="evoom_guard/verifiers/record_nested.py",
        before=(
            "            missing_fields=tuple(sorted(REQUIRED_ASSURANCE - assurance.keys())),\n"
        ),
        after="            missing_fields=(),\n",
        test=(
            "tests/test_record_nested.py::"
            "test_required_nested_fields_cannot_be_bypassed"
        ),
    ),
    Mutation(
        name="record-nested-attestation-required-fields-bypass",
        path="evoom_guard/verifiers/record_nested.py",
        before=(
            "            missing_fields=tuple("
            "sorted(REQUIRED_ATTESTATION - attestation.keys())),\n"
        ),
        after="            missing_fields=(),\n",
        test=(
            "tests/test_record_nested.py::"
            "test_required_nested_fields_cannot_be_bypassed"
        ),
    ),
    Mutation(
        name="record-nested-preflight-null-command-bypass",
        path="evoom_guard/verifiers/record_nested.py",
        before=(
            '        and attestation.get("test_command_started") is False\n'
        ),
        after="        and True\n",
        test=(
            "tests/test_record_nested.py::"
            "test_preflight_null_isolation_requires_the_complete_truth_table"
        ),
    ),
    Mutation(
        name="record-nested-preflight-null-state-bypass",
        path="evoom_guard/verifiers/record_nested.py",
        before=(
            '        and attestation.get("execution_state") == "not_started"\n'
        ),
        after="        and True\n",
        test=(
            "tests/test_record_nested.py::"
            "test_preflight_null_isolation_requires_the_complete_truth_table"
        ),
    ),
    Mutation(
        name="record-nested-preflight-null-delivery-bypass",
        path="evoom_guard/verifiers/record_nested.py",
        before=(
            '        and attestation.get("delivered_isolation") == "not_run"\n'
        ),
        after="        and True\n",
        test=(
            "tests/test_record_nested.py::"
            "test_preflight_null_isolation_requires_the_complete_truth_table"
        ),
    ),
    Mutation(
        name="record-nested-uppercase-sha256-bypass",
        path="evoom_guard/verifiers/record_nested.py",
        before='_HEX_64 = re.compile(r"^[0-9a-f]{64}$")\n',
        after='_HEX_64 = re.compile(r"^[0-9A-Fa-f]{64}$")\n',
        test=(
            "tests/test_record_nested.py::"
            "test_sha256_shape_requires_exact_lowercase_hex"
        ),
    ),
    Mutation(
        name="record-nested-sha256-length-bypass",
        path="evoom_guard/verifiers/record_nested.py",
        before='_HEX_64 = re.compile(r"^[0-9a-f]{64}$")\n',
        after='_HEX_64 = re.compile(r"^[0-9a-f]{63,64}$")\n',
        test=(
            "tests/test_record_nested.py::"
            "test_sha256_shape_requires_exact_lowercase_hex"
        ),
    ),
    Mutation(
        name="record-nested-junit-pair-coupling-bypass",
        path="evoom_guard/verifiers/record_nested.py",
        before=(
            "    return (digest is None and digest_format is None) or (\n"
            "        _valid_sha256(digest) and "
            "_known_string(digest_format, allowed_formats)\n"
            "    )\n"
        ),
        after=(
            "    return (digest is None and digest_format is None) or (\n"
            "        _valid_sha256(digest) or "
            "_known_string(digest_format, allowed_formats)\n"
            "    )\n"
        ),
        test=(
            "tests/test_record_nested.py::"
            "test_junit_digest_and_format_remain_coupled"
        ),
    ),
    Mutation(
        name="record-nested-pack-configured-bypass",
        path="evoom_guard/verifiers/record_nested.py",
        before='    if pack.get("configured") is not True:\n',
        after='    if False and pack.get("configured") is not True:\n',
        test="tests/test_record_nested.py::test_nested_pack_shape_cannot_be_bypassed",
    ),
    Mutation(
        name="record-nested-negative-invocations-bypass",
        path="evoom_guard/verifiers/record_nested.py",
        before="    if _is_int(invocations) and invocations < 0:\n",
        after="    if False and _is_int(invocations) and invocations < 0:\n",
        test=(
            "tests/test_record_nested.py::"
            "test_candidate_invocations_cannot_be_negative"
        ),
    ),
    Mutation(
        name="record-nested-null-attestation-skip-bypass",
        path="evoom_guard/record_verifier.py",
        before='        checks.skip("attestation.types", "attestation is null")\n',
        after='        checks.pass_("attestation.types", "attestation is null")\n',
        test="tests/test_record_nested.py::test_null_skip_order_and_early_return_are_exact",
    ),
    Mutation(
        name="policy-path-validation-order-bypass",
        path="evoom_guard/policy/config.py",
        before=(
            '    for key in ("protected", "allow", "setup_output_globs", '
            '"harness_inputs"):\n'
        ),
        after=(
            '    for key in ("harness_inputs", "protected", "allow", '
            '"setup_output_globs"):\n'
        ),
        test=(
            "tests/test_policy_config_characterization.py::"
            "test_command_and_path_error_precedence_is_frozen"
        ),
    ),
    Mutation(
        name="policy-harness-normalization-bypass",
        path="evoom_guard/policy/config.py",
        before="                    cfg[key] = list(normalize_harness_inputs(value))\n",
        after="                    cfg[key] = list(value)\n",
        test=(
            "tests/test_policy_config_characterization.py::"
            "test_harness_normalization_failure_precedes_conflict_detection"
        ),
    ),
    Mutation(
        name="policy-harness-conflict-bypass",
        path="evoom_guard/policy/config.py",
        before="        if conflicts:\n",
        after="        if False and conflicts:\n",
        test=(
            "tests/test_policy_config_characterization.py::"
            "test_harness_conflict_remains_fail_closed"
        ),
    ),
    Mutation(
        name="release-source-finalizer-snapshot-validation-bypass",
        path="evoom_guard/release_source_finalizer.py",
        before="        validate_source_context=_validate_source_context,\n",
        after="        validate_source_context=lambda _source, _context: None,\n",
        test=(
            "tests/test_release_source_producer_receipt.py::"
            "test_release_source_finalizer_primitive_snapshot_is_exact_and_immutable"
        ),
    ),
    Mutation(
        name="release-source-finalizer-snapshot-module-global-bypass",
        path="evoom_guard/release_source_finalizer.py",
        before=(
            "def snapshot_release_source_finalizer_primitives() -> "
            "ReleaseSourceFinalizerPrimitiveSnapshot:\n"
            '    """Resolve one immutable set of current finalizer operations at call time."""\n'
            "\n"
            "    return ReleaseSourceFinalizerPrimitiveSnapshot(\n"
            "        publish_bytes=_publish_bytes,\n"
            "        record_snapshot=_record_snapshot,\n"
            "        validate_source_context=_validate_source_context,\n"
            "        derive_release_source_bindings=derive_release_source_bindings,\n"
            "        context_from_release_source_bindings=context_from_release_source_bindings,\n"
            "    )\n"
        ),
        after=(
            "_MODULE_GLOBAL_RELEASE_SOURCE_FINALIZER_PRIMITIVES = "
            "ReleaseSourceFinalizerPrimitiveSnapshot(\n"
            "    publish_bytes=_publish_bytes,\n"
            "    record_snapshot=_record_snapshot,\n"
            "    validate_source_context=_validate_source_context,\n"
            "    derive_release_source_bindings=derive_release_source_bindings,\n"
            "    context_from_release_source_bindings=context_from_release_source_bindings,\n"
            ")\n"
            "\n"
            "\n"
            "def snapshot_release_source_finalizer_primitives() -> "
            "ReleaseSourceFinalizerPrimitiveSnapshot:\n"
            '    """Resolve one immutable set of current finalizer operations at call time."""\n'
            "\n"
            "    return _MODULE_GLOBAL_RELEASE_SOURCE_FINALIZER_PRIMITIVES\n"
        ),
        test=(
            "tests/test_release_source_finalizer.py::"
            "test_finalizer_primitive_snapshot_is_call_time_owned_and_immutable"
        ),
    ),
    Mutation(
        name="workspace-parent-component-bypass",
        path="evoom_guard/workspace/__init__.py",
        before=(
            '    return all(part not in ("", ".", "..") '
            'for part in path.split("/"))\n'
        ),
        after=(
            '    return any(part not in ("", ".", "..") '
            'for part in path.split("/"))\n'
        ),
        test=(
            "tests/test_direct_reviewed_mutation_contract.py::"
            "test_workspace_rejects_parent_components"
        ),
    ),
    Mutation(
        name="runtime-identity-digest-fallback-bypass",
        path="evoom_guard/runtime_identity.py",
        before="    if not changes and expected.sha256 != observed.sha256:\n",
        after="    if not changes and expected.sha256 == observed.sha256:\n",
        test=(
            "tests/test_direct_reviewed_mutation_contract.py::"
            "test_runtime_identity_binds_the_fallback_tree_digest"
        ),
    ),
    Mutation(
        name="fidelity-preexisting-default-output-ignore-bypass",
        path="evoom_guard/verifiers/fidelity.py",
        before="        and rel not in baseline_keys\n",
        after="        and rel in baseline_keys\n",
        test=(
            "tests/test_direct_reviewed_mutation_contract.py::"
            "test_fidelity_keeps_preexisting_default_outputs_bound"
        ),
    ),
    Mutation(
        name="release-artifact-run-separation-bypass",
        path="evoom_guard/admission/release_artifact.py",
        before=(
            "            raise ReleaseArtifactAdmissionError(\n"
            '                f"{role} workflow ID, path, and run must be distinct '
            'from every release-source role"\n'
            "            )\n"
            '    for field in ("workflow_id", "workflow_path", "workflow_run_id"):\n'
            "        if builder[field] == admitter[field]:\n"
        ),
        after=(
            "            raise ReleaseArtifactAdmissionError(\n"
            '                f"{role} workflow ID, path, and run must be distinct '
            'from every release-source role"\n'
            "            )\n"
            '    for field in ("workflow_id", "workflow_path", "workflow_run_id"):\n'
            '        if field != "workflow_run_id" and '
            "builder[field] == admitter[field]:\n"
        ),
        test=(
            "tests/test_direct_reviewed_mutation_contract.py::"
            "test_release_artifact_builder_and_admitter_runs_are_distinct"
        ),
    ),
    Mutation(
        name="agent-change-protected-test-path-bypass",
        path="evoom_guard/admission/agent_change.py",
        before="        is_protected(path)\n        or is_protected_config(path, strict_harness=True)\n",
        after="        False\n        or is_protected_config(path, strict_harness=True)\n",
        test=(
            "tests/test_direct_reviewed_mutation_contract.py::"
            "test_agent_change_cannot_authorize_judge_owned_tests"
        ),
    ),
    Mutation(
        name="finalizer-deployment-parent-path-bypass",
        path="evoom_guard/finalizer/deployment.py",
        before='        part in {"", ".", ".."}\n',
        after='        part in {"", "."}\n',
        test=(
            "tests/test_direct_reviewed_mutation_contract.py::"
            "test_finalizer_deployment_rejects_parent_paths"
        ),
    ),
    Mutation(
        name="artifact-v1-nonfile-subject-bypass",
        path="evoom_guard/artifact_admission.py",
        before='    if subject.get("kind") != "file":\n',
        after='    if subject.get("kind") not in {"file", "oci"}:\n',
        test=(
            "tests/test_direct_reviewed_mutation_contract.py::"
            "test_artifact_v1_rejects_nonfile_subjects"
        ),
    ),
    Mutation(
        name="release-source-receipt-host-isolation-bypass",
        path="evoom_guard/release_source_producer_receipt.py",
        before=(
            '    isolation = execution.get("candidate_isolation")\n'
            '    if isolation not in {"docker", "gvisor"}:\n'
        ),
        after=(
            '    isolation = execution.get("candidate_isolation")\n'
            '    if isolation not in {"docker", "gvisor", "host"}:\n'
        ),
        test=(
            "tests/test_direct_reviewed_mutation_contract.py::"
            "test_release_source_receipt_rejects_host_isolation"
        ),
    ),
    Mutation(
        name="artifact-v2-unsupported-digest-algorithm-bypass",
        path="evoom_guard/artifact_digest_admission.py",
        before="    if _SHA256_WITH_ALGORITHM.fullmatch(digest) is None:\n",
        after="    if False and _SHA256_WITH_ALGORITHM.fullmatch(digest) is None:\n",
        test=(
            "tests/test_direct_reviewed_mutation_contract.py::"
            "test_artifact_v2_rejects_unsupported_digest_algorithms"
        ),
    ),
    Mutation(
        name="artifact-provider-v3-ghcr-registry-restriction-bypass",
        path="evoom_guard/admission/artifact_provider_v3.py",
        before="    match = _GHCR_REPOSITORY.fullmatch(registry_repository)\n",
        after='    match = re.fullmatch(r".+", registry_repository)\n',
        test=(
            "tests/test_artifact_provider_v3.py::"
            "test_v3_subject_accepts_only_canonical_immutable_ghcr"
        ),
    ),
    Mutation(
        name="artifact-provider-v3-digest-algorithm-bypass",
        path="evoom_guard/admission/artifact_provider_v3.py",
        before=(
            "    if not isinstance(digest, str) or "
            "_SHA256_DIGEST.fullmatch(digest) is None:\n"
        ),
        after=(
            "    if not isinstance(digest, str) or "
            "False:\n"
        ),
        test=(
            "tests/test_artifact_provider_v3.py::"
            "test_v3_subject_accepts_only_canonical_immutable_ghcr"
        ),
    ),
    Mutation(
        name="artifact-provider-v3-receipt-count-type-bypass",
        path="evoom_guard/admission/artifact_provider_v3.py",
        before="    if type(count) is not int or count != 1:\n",
        after="    if count != 1:\n",
        test=(
            "tests/test_artifact_provider_v3.py::"
            "test_v3_receipt_validation_is_closed_world_and_type_exact"
        ),
    ),
    Mutation(
        name="artifact-provider-v3-policy-limit-type-bypass",
        path="evoom_guard/admission/artifact_provider_v3.py",
        before=(
            '    if type(policy.get("attestation_limit")) is not int or policy.get(\n'
            '        "attestation_limit"\n'
            "    ) != 1:\n"
        ),
        after='    if policy.get("attestation_limit") != 1:\n',
        test=(
            "tests/test_artifact_provider_v3.py::"
            "test_v3_receipt_validation_is_closed_world_and_type_exact"
        ),
    ),
    Mutation(
        name="artifact-provider-v3-direct-revision-bypass",
        path="evoom_guard/admission/artifact_provider_v3.py",
        before="    if policy.signer_digest != policy.source_digest:\n",
        after="    if False and policy.signer_digest != policy.source_digest:\n",
        test=(
            "tests/test_artifact_provider_v3.py::"
            "test_v3_external_relation_fails_closed"
        ),
    ),
    Mutation(
        name="artifact-provider-v3-finalizer-repository-binding-bypass",
        path="evoom_guard/admission/artifact_provider_v3.py",
        before=(
            '    if expected_finalizer_context.get("repository") '
            "!= policy.repository:\n"
        ),
        after=(
            '    if False and expected_finalizer_context.get("repository") '
            "!= policy.repository:\n"
        ),
        test=(
            "tests/test_artifact_provider_v3.py::"
            "test_v3_repository_mismatch_stops_before_provider_execution"
        ),
    ),
    Mutation(
        name="artifact-provider-v3-finalizer-source-binding-bypass",
        path="evoom_guard/admission/artifact_provider_v3.py",
        before=(
            '    if expected_finalizer_context.get("head_sha") '
            "!= policy.source_digest:\n"
        ),
        after=(
            '    if False and expected_finalizer_context.get("head_sha") '
            "!= policy.source_digest:\n"
        ),
        test=(
            "tests/test_artifact_provider_v3.py::"
            "test_v3_external_relation_fails_closed"
        ),
    ),
    Mutation(
        name="artifact-provider-v3-ghcr-owner-binding-bypass",
        path="evoom_guard/admission/artifact_provider_v3.py",
        before=(
            '    if namespace.group("namespace") != '
            'policy.repository.split("/", 1)[0].lower():\n'
        ),
        after=(
            '    if False and namespace.group("namespace") != '
            'policy.repository.split("/", 1)[0].lower():\n'
        ),
        test=(
            "tests/test_artifact_provider_v3.py::"
            "test_v3_external_relation_fails_closed"
        ),
    ),
    Mutation(
        name="artifact-provider-v3-build-finalizer-run-separation-bypass",
        path="evoom_guard/admission/artifact_provider_v3.py",
        before=(
            "    if (\n"
            '        expected_finalizer_context.get("run_id") == checked_run_id\n'
            '        and expected_finalizer_context.get("run_attempt") == checked_attempt\n'
            "    ):\n"
        ),
        after=(
            "    if False and (\n"
            '        expected_finalizer_context.get("run_id") == checked_run_id\n'
            '        and expected_finalizer_context.get("run_attempt") == checked_attempt\n'
            "    ):\n"
        ),
        test=(
            "tests/test_artifact_provider_v3.py::"
            "test_v3_external_relation_fails_closed"
        ),
    ),
    Mutation(
        name="artifact-provider-v3-live-isolation-bypass",
        path="evoom_guard/admission/artifact_provider_v3.py",
        before=(
            "    if type(provider_isolation) is not "
            "GitHubAttestationProviderIsolation:\n"
            "        raise ArtifactProviderV3Error(\n"
            '            "provider V3 live verification requires '
            'GitHubAttestationProviderIsolation"\n'
            "        )\n"
            "    if os.path.abspath(receipt_path) == os.path.abspath(raw_output_path):\n"
        ),
        after=(
            "    if os.path.abspath(receipt_path) == os.path.abspath(raw_output_path):\n"
        ),
        test=(
            "tests/test_artifact_provider_v3.py::"
            "test_v3_live_paths_require_isolation_and_no_alias"
        ),
    ),
    Mutation(
        name="artifact-provider-v3-signing-key-isolation-bypass",
        path="evoom_guard/admission/artifact_provider_v3.py",
        before=(
            "        validate_provider_isolated_signing_key_path(\n"
            "            private_key_path, provider_isolation\n"
            "        )\n"
        ),
        after="        pass\n",
        test=(
            "tests/test_artifact_provider_v3.py::"
            "test_v3_seal_requires_key_isolation_before_provider_execution"
        ),
    ),
    Mutation(
        name="github-attestation-oci-subject-name-binding-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "    if subject_name is not None:\n"
            "        _require_semantic_match(\n"
        ),
        after=(
            "    if False and subject_name is not None:\n"
            "        _require_semantic_match(\n"
        ),
        test=(
            "tests/test_artifact_provider_v3.py::"
            "test_provider_semantics_bind_subject_name_digest_and_build_invocation"
        ),
    ),
    Mutation(
        name="github-attestation-oci-run-binding-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "    if expected_run is not None and "
            "(workflow_run_id, workflow_run_attempt) != expected_run:\n"
        ),
        after=(
            "    if False and expected_run is not None and "
            "(workflow_run_id, workflow_run_attempt) != expected_run:\n"
        ),
        test=(
            "tests/test_artifact_provider_v3.py::"
            "test_provider_semantics_bind_subject_name_digest_and_build_invocation"
        ),
    ),
    Mutation(
        name="github-attestation-oci-registry-bundle-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "            isolation_input_path=None,\n"
            "            bundle_from_oci=True,\n"
        ),
        after=(
            "            isolation_input_path=None,\n"
            "            bundle_from_oci=False,\n"
        ),
        test=(
            "tests/test_artifact_provider_v3.py::"
            "test_oci_provider_runner_uses_only_digest_qualified_ghcr_and_registry_bundle"
        ),
    ),
    Mutation(
        name="release-source-key-domain-separation-bypass",
        path="evoom_guard/admission/release_source.py",
        before="    if len(set(checked.values())) != len(checked):\n",
        after="    if False and len(set(checked.values())) != len(checked):\n",
        test=(
            "tests/test_direct_reviewed_mutation_contract.py::"
            "test_release_source_admission_requires_distinct_domain_keys"
        ),
    ),
    Mutation(
        name="release-source-v1-deny-only-bypass",
        path="evoom_guard/release_source_finalizer.py",
        before='    del record\n    return "DENY"\n',
        after='    del record\n    return "ALLOW"\n',
        test=(
            "tests/test_direct_reviewed_mutation_contract.py::"
            "test_release_source_v1_remains_deny_only"
        ),
    ),
    Mutation(
        name="cli-artifact-v1-seal-stdin-short-circuit-bypass",
        path="evoom_guard/cli/artifact_admission_commands.py",
        before='    if args.artifact == "-" or args.finalizer_bundle == "-":\n',
        after='    if args.artifact == "-" and args.finalizer_bundle == "-":\n',
        test=(
            "tests/test_cli_artifact_admission_v1_characterization.py::"
            "test_frozen_cli_artifact_admission_v1_behavior"
            "[seal_artifact_stdin_short_circuit]"
        ),
    ),
    Mutation(
        name="cli-artifact-v1-verify-eager-stdin-read-bypass",
        path="evoom_guard/cli/artifact_admission_commands.py",
        before=(
            '    if any(value == "-" for value in '
            "(args.binding, args.artifact, args.finalizer_bundle)):\n"
        ),
        after='    if args.binding == "-":\n',
        test=(
            "tests/test_cli_artifact_admission_v1_characterization.py::"
            "test_frozen_cli_artifact_admission_v1_behavior"
            "[verify_binding_stdin_reads_all_paths]"
        ),
    ),
    Mutation(
        name="cli-artifact-v1-seal-reader-reresolution-bypass",
        path="evoom_guard/cli/__init__.py",
        before=(
            "            seal_artifact_admission=seal_artifact_admission,\n"
            "            read_external_object_provider=lambda: "
            "_read_external_finalizer_object,\n"
        ),
        after=(
            "            seal_artifact_admission=seal_artifact_admission,\n"
            "            read_external_object_provider=lambda "
            "_reader=_read_external_finalizer_object: _reader,\n"
        ),
        test=(
            "tests/test_cli_artifact_admission_v1_characterization.py::"
            "test_frozen_cli_artifact_admission_v1_behavior"
            "[seal_source_property_rebinds_reader]"
        ),
    ),
    Mutation(
        name="cli-artifact-v1-verify-reader-eager-read-bypass",
        path="evoom_guard/cli/artifact_admission_commands.py",
        before=(
            "def execute_verify_artifact_admission(\n"
            "    args: argparse.Namespace,\n"
            "    *,\n"
            "    services: VerifyArtifactAdmissionServices,\n"
            "    out: _Output = print,\n"
            ") -> int:\n"
            '    """Verify a file binding with external artifact/finalizer trust inputs."""\n'
            "\n"
        ),
        after=(
            "def execute_verify_artifact_admission(\n"
            "    args: argparse.Namespace,\n"
            "    *,\n"
            "    services: VerifyArtifactAdmissionServices,\n"
            "    out: _Output = print,\n"
            ") -> int:\n"
            '    """Verify a file binding with external artifact/finalizer trust inputs."""\n'
            "\n"
            "    _ = services.read_external_object_provider()(\n"
            "        args.expected_source,\n"
            '        label="expected source",\n'
            "    )\n"
        ),
        test=(
            "tests/test_cli_artifact_admission_v1_characterization.py::"
            "test_frozen_cli_artifact_admission_v1_behavior"
            "[verify_binding_stdin_reads_all_paths]"
        ),
    ),
    Mutation(
        name="cli-artifact-v1-seal-invalid-error-classification-bypass",
        path="evoom_guard/cli/artifact_admission_commands.py",
        before=(
            '                "status": "INVALID_INPUT",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 1\n"
        ),
        after=(
            '                "status": "ERROR",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 2\n"
        ),
        test=(
            "tests/test_cli_artifact_admission_v1_characterization.py::"
            "test_frozen_cli_artifact_admission_v1_behavior"
            "[seal_domain_error_class_and_reporter_snapshot]"
        ),
    ),
    Mutation(
        name="cli-artifact-v1-verify-invalid-error-classification-bypass",
        path="evoom_guard/cli/artifact_admission_commands.py",
        before=(
            '                "status": "INVALID",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 1\n"
        ),
        after=(
            '                "status": "ERROR",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 2\n"
        ),
        test=(
            "tests/test_cli_artifact_admission_v1_characterization.py::"
            "test_frozen_cli_artifact_admission_v1_behavior"
            "[verify_domain_error_class_and_reporter_snapshot]"
        ),
    ),
    Mutation(
        name="cli-artifact-v1-verify-offline-argument-boundary-bypass",
        path="evoom_guard/cli/artifact_admission_commands.py",
        before=(
            '    """Verify a file binding with external artifact/finalizer trust inputs."""\n'
            "\n"
            "    if any(value == "
        ),
        after=(
            '    """Verify a file binding with external artifact/finalizer trust inputs."""\n'
            "\n"
            "    _ = args.sign_key\n"
            "    if any(value == "
        ),
        test=(
            "tests/test_cli_artifact_admission_v1_characterization.py::"
            "test_frozen_cli_artifact_admission_v1_behavior"
            "[verify_success_offline_boundary]"
        ),
    ),
    Mutation(
        name="cli-artifact-v1-seal-success-projection-order-bypass",
        path="evoom_guard/cli/artifact_admission_commands.py",
        before=(
            '            "binding": sealed.binding_path,\n'
            '            "subject": sealed.subject.as_dict(),\n'
        ),
        after=(
            '            "subject": sealed.subject.as_dict(),\n'
            '            "binding": sealed.binding_path,\n'
        ),
        test=(
            "tests/test_cli_artifact_admission_v1_characterization.py::"
            "test_frozen_cli_artifact_admission_v1_behavior"
            "[seal_success]"
        ),
    ),
    Mutation(
        name="cli-artifact-v1-verify-success-projection-order-bypass",
        path="evoom_guard/cli/artifact_admission_commands.py",
        before=(
            '            "subject": verified.subject.as_dict(),\n'
            '            "finalizer": verified.inspection.finalizer,\n'
        ),
        after=(
            '            "finalizer": verified.inspection.finalizer,\n'
            '            "subject": verified.subject.as_dict(),\n'
        ),
        test=(
            "tests/test_cli_artifact_admission_v1_characterization.py::"
            "test_frozen_cli_artifact_admission_v1_behavior"
            "[verify_success_offline_boundary]"
        ),
    ),
    Mutation(
        name="cli-artifact-digest-v2-seal-eager-stdin-read-bypass",
        path="evoom_guard/cli/artifact_digest_admission_commands.py",
        before=(
            '    if any(value == "-" for value in '
            "(args.finalizer_bundle, args.provenance)):\n"
        ),
        after=(
            '    if args.finalizer_bundle == "-" or args.provenance == "-":\n'
        ),
        test=(
            "tests/test_cli_artifact_digest_v2_characterization.py::"
            "test_frozen_cli_artifact_digest_v2_behavior"
            "[seal_finalizer_stdin_reads_provenance]"
        ),
    ),
    Mutation(
        name="cli-artifact-digest-v2-verify-eager-stdin-read-bypass",
        path="evoom_guard/cli/artifact_digest_admission_commands.py",
        before=(
            "    if any(\n"
            '        value == "-"\n'
            "        for value in "
            "(args.binding, args.finalizer_bundle, args.provenance)\n"
            "    ):\n"
        ),
        after=(
            '    if args.binding == "-" or args.finalizer_bundle == "-" '
            'or args.provenance == "-":\n'
        ),
        test=(
            "tests/test_cli_artifact_digest_v2_characterization.py::"
            "test_frozen_cli_artifact_digest_v2_behavior"
            "[verify_binding_stdin_reads_all_paths]"
        ),
    ),
    Mutation(
        name="cli-artifact-digest-v2-verify-provenance-stdin-bypass",
        path="evoom_guard/cli/artifact_digest_admission_commands.py",
        before=(
            "        for value in "
            "(args.binding, args.finalizer_bundle, args.provenance)\n"
        ),
        after=(
            "        for value in (args.binding, args.finalizer_bundle)\n"
        ),
        test=(
            "tests/test_cli_artifact_digest_v2_characterization.py::"
            "test_frozen_cli_artifact_digest_v2_behavior"
            "[verify_provenance_stdin_short_circuit]"
        ),
    ),
    Mutation(
        name="cli-artifact-digest-v2-seal-reader-reresolution-bypass",
        path="evoom_guard/cli/__init__.py",
        before=(
            "                seal_artifact_digest_admission="
            "seal_artifact_digest_admission,\n"
            "                read_external_object_provider=lambda: (\n"
            "                    _read_external_finalizer_object\n"
            "                ),\n"
        ),
        after=(
            "                seal_artifact_digest_admission="
            "seal_artifact_digest_admission,\n"
            "                read_external_object_provider=lambda "
            "_reader=_read_external_finalizer_object: _reader,\n"
        ),
        test=(
            "tests/test_cli_artifact_digest_v2_characterization.py::"
            "test_frozen_cli_artifact_digest_v2_behavior"
            "[seal_source_property_rebinds_reader]"
        ),
    ),
    Mutation(
        name="cli-artifact-digest-v2-verify-context-eager-read-bypass",
        path="evoom_guard/cli/artifact_digest_admission_commands.py",
        before=(
            '    """Verify V2 with external subject, provenance, and '
            'finalizer inputs."""\n'
            "\n"
            "    if any(\n"
        ),
        after=(
            '    """Verify V2 with external subject, provenance, and '
            'finalizer inputs."""\n'
            "\n"
            "    _ = args.expected_context\n"
            "    if any(\n"
        ),
        test=(
            "tests/test_cli_artifact_digest_v2_characterization.py::"
            "test_frozen_cli_artifact_digest_v2_behavior"
            "[verify_context_property_rebinds_reader]"
        ),
    ),
    Mutation(
        name="cli-artifact-digest-v2-seal-invalid-classification-bypass",
        path="evoom_guard/cli/artifact_digest_admission_commands.py",
        before=(
            '                "status": "INVALID_INPUT",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 1\n"
        ),
        after=(
            '                "status": "ERROR",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 2\n"
        ),
        test=(
            "tests/test_cli_artifact_digest_v2_characterization.py::"
            "test_frozen_cli_artifact_digest_v2_behavior"
            "[seal_domain_error_class_and_reporter_snapshot]"
        ),
    ),
    Mutation(
        name="cli-artifact-digest-v2-verify-invalid-classification-bypass",
        path="evoom_guard/cli/artifact_digest_admission_commands.py",
        before=(
            '                "status": "INVALID",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 1\n"
        ),
        after=(
            '                "status": "ERROR",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 2\n"
        ),
        test=(
            "tests/test_cli_artifact_digest_v2_characterization.py::"
            "test_frozen_cli_artifact_digest_v2_behavior"
            "[verify_domain_error_class_and_reporter_snapshot]"
        ),
    ),
    Mutation(
        name="cli-artifact-digest-v2-verify-metadata-oserror-bypass",
        path="evoom_guard/cli/artifact_digest_admission_commands.py",
        before=(
            "        expected_context = services.read_external_object_provider()(\n"
            "            args.expected_context,\n"
            '            label="expected context",\n'
            "        )\n"
            "    except (OSError, UnicodeError, ValueError) as exc:\n"
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.binding_format,\n'
            '                "ok": False,\n'
            '                "verified": False,\n'
        ),
        after=(
            "        expected_context = services.read_external_object_provider()(\n"
            "            args.expected_context,\n"
            '            label="expected context",\n'
            "        )\n"
            "    except (UnicodeError, ValueError) as exc:\n"
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.binding_format,\n'
            '                "ok": False,\n'
            '                "verified": False,\n'
        ),
        test=(
            "tests/test_cli_artifact_digest_v2_characterization.py::"
            "test_frozen_cli_artifact_digest_v2_behavior"
            "[verify_source_read_error]"
        ),
    ),
    Mutation(
        name="cli-artifact-digest-v2-verify-offline-argument-bypass",
        path="evoom_guard/cli/artifact_digest_admission_commands.py",
        before=(
            '    """Verify V2 with external subject, provenance, and '
            'finalizer inputs."""\n'
            "\n"
            "    if any(\n"
        ),
        after=(
            '    """Verify V2 with external subject, provenance, and '
            'finalizer inputs."""\n'
            "\n"
            "    _ = args.telemetry_endpoint\n"
            "    if any(\n"
        ),
        test=(
            "tests/test_cli_artifact_digest_v2_characterization.py::"
            "test_frozen_cli_artifact_digest_v2_behavior"
            "[verify_success_offline_boundary]"
        ),
    ),
    Mutation(
        name="cli-artifact-digest-v2-seal-projection-order-bypass",
        path="evoom_guard/cli/artifact_digest_admission_commands.py",
        before=(
            '            "subject": sealed.subject.as_dict(),\n'
            '            "provenance_reference": '
            "sealed.provenance_reference.as_dict(),\n"
        ),
        after=(
            '            "provenance_reference": '
            "sealed.provenance_reference.as_dict(),\n"
            '            "subject": sealed.subject.as_dict(),\n'
        ),
        test=(
            "tests/test_cli_artifact_digest_v2_characterization.py::"
            "test_frozen_cli_artifact_digest_v2_behavior[seal_success]"
        ),
    ),
    Mutation(
        name="cli-artifact-digest-v2-verify-projection-order-bypass",
        path="evoom_guard/cli/artifact_digest_admission_commands.py",
        before=(
            '            "subject": verified.subject.as_dict(),\n'
            '            "provenance_reference": '
            "verified.provenance_reference.as_dict(),\n"
        ),
        after=(
            '            "provenance_reference": '
            "verified.provenance_reference.as_dict(),\n"
            '            "subject": verified.subject.as_dict(),\n'
        ),
        test=(
            "tests/test_cli_artifact_digest_v2_characterization.py::"
            "test_frozen_cli_artifact_digest_v2_behavior"
            "[verify_success_offline_boundary]"
        ),
    ),
    Mutation(
        name="cli-github-receipt-create-live-policy-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "                create_github_attestation_receipt=(\n"
            "                    create_github_attestation_receipt\n"
            "                ),\n"
            "                policy_kwargs_provider=lambda: (\n"
            "                    _github_attestation_policy_kwargs\n"
            "                ),\n"
        ),
        after=(
            "                create_github_attestation_receipt=(\n"
            "                    create_github_attestation_receipt\n"
            "                ),\n"
            "                policy_kwargs_provider=lambda _policy=(\n"
            "                    _github_attestation_policy_kwargs\n"
            "                ): _policy,\n"
        ),
        test=(
            "tests/test_cli_github_attestation_receipt_characterization.py::"
            "test_frozen_cli_github_attestation_receipt_behavior"
            "[create_policy_helper_is_live_after_paths]"
        ),
    ),
    Mutation(
        name="cli-github-receipt-create-live-isolation-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "                provider_isolation_provider=lambda: (\n"
            "                    _github_attestation_provider_isolation\n"
            "                ),\n"
            "                machine_report_provider=lambda: _machine_report,\n"
            "            )\n"
            "        ),\n"
            "        out=out,\n"
            "    )\n"
            "\n"
            "\n"
            "def cmd_verify_github_attestation_receipt("
        ),
        after=(
            "                provider_isolation_provider=lambda _isolation=(\n"
            "                    _github_attestation_provider_isolation\n"
            "                ): _isolation,\n"
            "                machine_report_provider=lambda: _machine_report,\n"
            "            )\n"
            "        ),\n"
            "        out=out,\n"
            "    )\n"
            "\n"
            "\n"
            "def cmd_verify_github_attestation_receipt("
        ),
        test=(
            "tests/test_cli_github_attestation_receipt_characterization.py::"
            "test_frozen_cli_github_attestation_receipt_behavior"
            "[create_isolation_helper_is_live_after_timeout]"
        ),
    ),
    Mutation(
        name="cli-github-receipt-reverify-live-policy-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "                reverify_github_attestation_receipt=(\n"
            "                    reverify_github_attestation_receipt\n"
            "                ),\n"
            "                policy_kwargs_provider=lambda: (\n"
            "                    _github_attestation_policy_kwargs\n"
            "                ),\n"
        ),
        after=(
            "                reverify_github_attestation_receipt=(\n"
            "                    reverify_github_attestation_receipt\n"
            "                ),\n"
            "                policy_kwargs_provider=lambda _policy=(\n"
            "                    _github_attestation_policy_kwargs\n"
            "                ): _policy,\n"
        ),
        test=(
            "tests/test_cli_github_attestation_receipt_characterization.py::"
            "test_frozen_cli_github_attestation_receipt_behavior"
            "[reverify_policy_helper_is_live_after_paths]"
        ),
    ),
    Mutation(
        name="cli-github-receipt-reverify-live-isolation-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "                reverify_github_attestation_receipt=(\n"
            "                    reverify_github_attestation_receipt\n"
            "                ),\n"
            "                policy_kwargs_provider=lambda: (\n"
            "                    _github_attestation_policy_kwargs\n"
            "                ),\n"
            "                provider_isolation_provider=lambda: (\n"
            "                    _github_attestation_provider_isolation\n"
            "                ),\n"
        ),
        after=(
            "                reverify_github_attestation_receipt=(\n"
            "                    reverify_github_attestation_receipt\n"
            "                ),\n"
            "                policy_kwargs_provider=lambda: (\n"
            "                    _github_attestation_policy_kwargs\n"
            "                ),\n"
            "                provider_isolation_provider=lambda _isolation=(\n"
            "                    _github_attestation_provider_isolation\n"
            "                ): _isolation,\n"
        ),
        test=(
            "tests/test_cli_github_attestation_receipt_characterization.py::"
            "test_frozen_cli_github_attestation_receipt_behavior"
            "[reverify_isolation_helper_is_live_after_timeout]"
        ),
    ),
    Mutation(
        name="cli-github-receipt-create-rejection-classification-bypass",
        path="evoom_guard/cli/github_attestation_receipt_commands.py",
        before=(
            "        created = services.create_github_attestation_receipt(\n"
            "            args.artifact,\n"
            "            args.receipt_out,\n"
            "            args.raw_output_out,\n"
            "            **services.policy_kwargs_provider()(args),\n"
            "            gh_executable=args.gh_executable,\n"
            "            timeout_seconds=args.timeout_seconds,\n"
            "            provider_isolation=services.provider_isolation_provider()(args),\n"
            "        )\n"
            "    except services.github_error as exc:\n"
        ),
        after=(
            "        created = services.create_github_attestation_receipt(\n"
            "            args.artifact,\n"
            "            args.receipt_out,\n"
            "            args.raw_output_out,\n"
            "            **services.policy_kwargs_provider()(args),\n"
            "            gh_executable=args.gh_executable,\n"
            "            timeout_seconds=args.timeout_seconds,\n"
            "            provider_isolation=services.provider_isolation_provider()(args),\n"
            "        )\n"
            "    except () as exc:\n"
        ),
        test=(
            "tests/test_cli_github_attestation_receipt_characterization.py::"
            "test_frozen_cli_github_attestation_receipt_behavior"
            "[create_domain_error_subclass_precedes_value_error]"
        ),
    ),
    Mutation(
        name="cli-github-receipt-verify-invalid-classification-bypass",
        path="evoom_guard/cli/github_attestation_receipt_commands.py",
        before=(
            '                "status": "INVALID",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 1\n"
            "    except (OSError, ValueError) as exc:\n"
        ),
        after=(
            '                "status": "ERROR",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 2\n"
            "    except (OSError, ValueError) as exc:\n"
        ),
        test=(
            "tests/test_cli_github_attestation_receipt_characterization.py::"
            "test_frozen_cli_github_attestation_receipt_behavior"
            "[verify_domain_error_subclass_precedes_value_error]"
        ),
    ),
    Mutation(
        name="cli-github-receipt-reverify-rejection-classification-bypass",
        path="evoom_guard/cli/github_attestation_receipt_commands.py",
        before=(
            "        fresh = services.reverify_github_attestation_receipt(\n"
            "            args.receipt,\n"
            "            args.artifact,\n"
            "            **services.policy_kwargs_provider()(args),\n"
            "            gh_executable=args.gh_executable,\n"
            "            timeout_seconds=args.timeout_seconds,\n"
            "            provider_isolation=services.provider_isolation_provider()(args),\n"
            "        )\n"
            "    except services.github_error as exc:\n"
        ),
        after=(
            "        fresh = services.reverify_github_attestation_receipt(\n"
            "            args.receipt,\n"
            "            args.artifact,\n"
            "            **services.policy_kwargs_provider()(args),\n"
            "            gh_executable=args.gh_executable,\n"
            "            timeout_seconds=args.timeout_seconds,\n"
            "            provider_isolation=services.provider_isolation_provider()(args),\n"
            "        )\n"
            "    except () as exc:\n"
        ),
        test=(
            "tests/test_cli_github_attestation_receipt_characterization.py::"
            "test_frozen_cli_github_attestation_receipt_behavior"
            "[reverify_domain_error_subclass_precedes_value_error]"
        ),
    ),
    Mutation(
        name="cli-github-receipt-verify-offline-argument-bypass",
        path="evoom_guard/cli/github_attestation_receipt_commands.py",
        before=(
            '    """Check retained evidence continuity without making a live provider call."""\n'
            "\n"
            "    try:\n"
        ),
        after=(
            '    """Check retained evidence continuity without making a live provider call."""\n'
            "\n"
            "    _ = args.gh_executable\n"
            "    try:\n"
        ),
        test=(
            "tests/test_cli_github_attestation_receipt_characterization.py::"
            "test_frozen_cli_github_attestation_receipt_behavior"
            "[verify_success_offline_boundary]"
        ),
    ),
    Mutation(
        name="cli-github-receipt-create-isolation-bypass",
        path="evoom_guard/cli/github_attestation_receipt_commands.py",
        before=(
            "        created = services.create_github_attestation_receipt(\n"
            "            args.artifact,\n"
            "            args.receipt_out,\n"
            "            args.raw_output_out,\n"
            "            **services.policy_kwargs_provider()(args),\n"
            "            gh_executable=args.gh_executable,\n"
            "            timeout_seconds=args.timeout_seconds,\n"
            "            provider_isolation=services.provider_isolation_provider()(args),\n"
            "        )\n"
            "    except services.github_error as exc:\n"
        ),
        after=(
            "        created = services.create_github_attestation_receipt(\n"
            "            args.artifact,\n"
            "            args.receipt_out,\n"
            "            args.raw_output_out,\n"
            "            **services.policy_kwargs_provider()(args),\n"
            "            gh_executable=args.gh_executable,\n"
            "            timeout_seconds=args.timeout_seconds,\n"
            "            provider_isolation=None,\n"
            "        )\n"
            "    except services.github_error as exc:\n"
        ),
        test=(
            "tests/test_cli_github_attestation_receipt_characterization.py::"
            "test_frozen_cli_github_attestation_receipt_behavior"
            "[create_success_isolated_boundary]"
        ),
    ),
    Mutation(
        name="cli-github-receipt-create-projection-order-bypass",
        path="evoom_guard/cli/github_attestation_receipt_commands.py",
        before=(
            '            "receipt": created.receipt_path,\n'
            '            "raw_output": created.raw_output_path,\n'
            '            "artifact": created.artifact.as_dict(),\n'
        ),
        after=(
            '            "artifact": created.artifact.as_dict(),\n'
            '            "receipt": created.receipt_path,\n'
            '            "raw_output": created.raw_output_path,\n'
        ),
        test=(
            "tests/test_cli_github_attestation_receipt_characterization.py::"
            "test_frozen_cli_github_attestation_receipt_behavior"
            "[create_success_unisolated_boundary]"
        ),
    ),
    Mutation(
        name="cli-github-receipt-verify-projection-order-bypass",
        path="evoom_guard/cli/github_attestation_receipt_commands.py",
        before=(
            '            "artifact": verified.artifact.as_dict(),\n'
            '            "verification_policy": verified.policy.as_dict(),\n'
        ),
        after=(
            '            "verification_policy": verified.policy.as_dict(),\n'
            '            "artifact": verified.artifact.as_dict(),\n'
        ),
        test=(
            "tests/test_cli_github_attestation_receipt_characterization.py::"
            "test_frozen_cli_github_attestation_receipt_behavior"
            "[verify_success_offline_boundary]"
        ),
    ),
    Mutation(
        name="cli-github-receipt-reverify-projection-order-bypass",
        path="evoom_guard/cli/github_attestation_receipt_commands.py",
        before=(
            '            "artifact": fresh.artifact.as_dict(),\n'
            '            "verification_policy": fresh.policy.as_dict(),\n'
            '            "verified_attestation_count": fresh.verified_attestation_count,\n'
        ),
        after=(
            '            "verified_attestation_count": fresh.verified_attestation_count,\n'
            '            "artifact": fresh.artifact.as_dict(),\n'
            '            "verification_policy": fresh.policy.as_dict(),\n'
        ),
        test=(
            "tests/test_cli_github_attestation_receipt_characterization.py::"
            "test_frozen_cli_github_attestation_receipt_behavior"
            "[reverify_success_unisolated_boundary]"
        ),
    ),
    Mutation(
        name="cli-github-admission-seal-eager-path-bypass",
        path="evoom_guard/cli/github_attestation_admission_commands.py",
        before=(
            '    if any(value == "-" for value in regular_paths):\n'
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.binding_format,\n'
            '                "ok": False,\n'
            '                "sealed": False,\n'
        ),
        after=(
            '    if args.artifact == "-":\n'
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.binding_format,\n'
            '                "ok": False,\n'
            '                "sealed": False,\n'
        ),
        test=(
            "tests/test_cli_github_attestation_admission_characterization.py::"
            "test_frozen_cli_github_attestation_admission_behavior"
            "[seal_finalizer_bundle_stdin_short_circuit]"
        ),
    ),
    Mutation(
        name="cli-github-admission-verify-eager-path-bypass",
        path="evoom_guard/cli/github_attestation_admission_commands.py",
        before=(
            '    if any(value == "-" for value in regular_paths):\n'
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.binding_format,\n'
            '                "ok": False,\n'
            '                "verified": False,\n'
        ),
        after=(
            '    if args.binding == "-":\n'
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.binding_format,\n'
            '                "ok": False,\n'
            '                "verified": False,\n'
        ),
        test=(
            "tests/test_cli_github_attestation_admission_characterization.py::"
            "test_frozen_cli_github_attestation_admission_behavior"
            "[verify_trusted_pub_stdin_short_circuit]"
        ),
    ),
    Mutation(
        name="cli-github-admission-seal-reader-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "                    seal_github_attestation_admission=(\n"
            "                        seal_github_attestation_admission\n"
            "                    ),\n"
            "                    read_external_object_provider=lambda: (\n"
            "                        _read_external_finalizer_object\n"
            "                    ),\n"
        ),
        after=(
            "                    seal_github_attestation_admission=(\n"
            "                        seal_github_attestation_admission\n"
            "                    ),\n"
            "                    read_external_object_provider=lambda _reader=(\n"
            "                        _read_external_finalizer_object\n"
            "                    ): _reader,\n"
        ),
        test=(
            "tests/test_cli_github_attestation_admission_characterization.py::"
            "test_frozen_cli_github_attestation_admission_behavior"
            "[seal_source_property_rebinds_reader]"
        ),
    ),
    Mutation(
        name="cli-github-admission-verify-reader-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "                    verify_github_attestation_admission=(\n"
            "                        verify_github_attestation_admission\n"
            "                    ),\n"
            "                    read_external_object_provider=lambda: (\n"
            "                        _read_external_finalizer_object\n"
            "                    ),\n"
        ),
        after=(
            "                    verify_github_attestation_admission=(\n"
            "                        verify_github_attestation_admission\n"
            "                    ),\n"
            "                    read_external_object_provider=lambda _reader=(\n"
            "                        _read_external_finalizer_object\n"
            "                    ): _reader,\n"
        ),
        test=(
            "tests/test_cli_github_attestation_admission_characterization.py::"
            "test_frozen_cli_github_attestation_admission_behavior"
            "[verify_source_property_rebinds_reader]"
        ),
    ),
    Mutation(
        name="cli-github-admission-seal-policy-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "                    policy_kwargs_provider=lambda: (\n"
            "                        _github_attestation_policy_kwargs\n"
            "                    ),\n"
            "                    provider_isolation_provider=lambda: (\n"
            "                        _github_attestation_provider_isolation\n"
            "                    ),\n"
        ),
        after=(
            "                    policy_kwargs_provider=lambda _policy=(\n"
            "                        _github_attestation_policy_kwargs\n"
            "                    ): _policy,\n"
            "                    provider_isolation_provider=lambda: (\n"
            "                        _github_attestation_provider_isolation\n"
            "                    ),\n"
        ),
        test=(
            "tests/test_cli_github_attestation_admission_characterization.py::"
            "test_frozen_cli_github_attestation_admission_behavior"
            "[seal_policy_helper_is_live_after_positionals]"
        ),
    ),
    Mutation(
        name="cli-github-admission-verify-policy-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "                    verify_github_attestation_admission=(\n"
            "                        verify_github_attestation_admission\n"
            "                    ),\n"
            "                    read_external_object_provider=lambda: (\n"
            "                        _read_external_finalizer_object\n"
            "                    ),\n"
            "                    policy_kwargs_provider=lambda: (\n"
            "                        _github_attestation_policy_kwargs\n"
            "                    ),\n"
        ),
        after=(
            "                    verify_github_attestation_admission=(\n"
            "                        verify_github_attestation_admission\n"
            "                    ),\n"
            "                    read_external_object_provider=lambda: (\n"
            "                        _read_external_finalizer_object\n"
            "                    ),\n"
            "                    policy_kwargs_provider=lambda _policy=(\n"
            "                        _github_attestation_policy_kwargs\n"
            "                    ): _policy,\n"
        ),
        test=(
            "tests/test_cli_github_attestation_admission_characterization.py::"
            "test_frozen_cli_github_attestation_admission_behavior"
            "[verify_policy_helper_is_live_after_positionals]"
        ),
    ),
    Mutation(
        name="cli-github-admission-seal-isolation-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "                    provider_isolation_provider=lambda: (\n"
            "                        _github_attestation_provider_isolation\n"
            "                    ),\n"
            "                    machine_report_provider=lambda: _machine_report,\n"
        ),
        after=(
            "                    provider_isolation_provider=lambda _isolation=(\n"
            "                        _github_attestation_provider_isolation\n"
            "                    ): _isolation,\n"
            "                    machine_report_provider=lambda: _machine_report,\n"
        ),
        test=(
            "tests/test_cli_github_attestation_admission_characterization.py::"
            "test_frozen_cli_github_attestation_admission_behavior"
            "[seal_isolation_helper_is_live_after_timeout]"
        ),
    ),
    Mutation(
        name="cli-github-admission-seal-isolation-bypass",
        path="evoom_guard/cli/github_attestation_admission_commands.py",
        before=(
            "            timeout_seconds=args.timeout_seconds,\n"
            "            provider_isolation=services.provider_isolation_provider()(args),\n"
        ),
        after=(
            "            timeout_seconds=args.timeout_seconds,\n"
            "            provider_isolation=None,\n"
        ),
        test=(
            "tests/test_cli_github_attestation_admission_characterization.py::"
            "test_frozen_cli_github_attestation_admission_behavior"
            "[seal_success_isolated_boundary]"
        ),
    ),
    Mutation(
        name="cli-github-admission-seal-force-bypass",
        path="evoom_guard/cli/github_attestation_admission_commands.py",
        before=(
            '    """Freshly verify provider evidence, then bind it to a finalizer ALLOW."""\n'
            "\n"
            "    regular_paths = (\n"
        ),
        after=(
            '    """Freshly verify provider evidence, then bind it to a finalizer ALLOW."""\n'
            "\n"
            "    _ = args.force\n"
            "    regular_paths = (\n"
        ),
        test=(
            "tests/test_cli_github_attestation_admission_characterization.py::"
            "test_frozen_cli_github_attestation_admission_behavior"
            "[seal_no_force_closed_world]"
        ),
    ),
    Mutation(
        name="cli-github-admission-verify-online-argument-bypass",
        path="evoom_guard/cli/github_attestation_admission_commands.py",
        before=(
            '    """Verify retained provider bytes and their V2 finalizer-bound relation."""\n'
            "\n"
            "    regular_paths = (\n"
        ),
        after=(
            '    """Verify retained provider bytes and their V2 finalizer-bound relation."""\n'
            "\n"
            "    _ = args.gh_executable\n"
            "    regular_paths = (\n"
        ),
        test=(
            "tests/test_cli_github_attestation_admission_characterization.py::"
            "test_frozen_cli_github_attestation_admission_behavior"
            "[verify_no_live_provider_or_force_closed_world]"
        ),
    ),
    Mutation(
        name="cli-github-admission-seal-domain-catch-bypass",
        path="evoom_guard/cli/github_attestation_admission_commands.py",
        before=(
            "            provider_isolation=services.provider_isolation_provider()(args),\n"
            "        )\n"
            "    except services.github_error as exc:\n"
        ),
        after=(
            "            provider_isolation=services.provider_isolation_provider()(args),\n"
            "        )\n"
            "    except () as exc:\n"
        ),
        test=(
            "tests/test_cli_github_attestation_admission_characterization.py::"
            "test_frozen_cli_github_attestation_admission_behavior"
            "[seal_domain_error_subclass_precedes_value_error]"
        ),
    ),
    Mutation(
        name="cli-github-admission-verify-invalid-classification-bypass",
        path="evoom_guard/cli/github_attestation_admission_commands.py",
        before=(
            '                "status": "INVALID",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 1\n"
            "    except (OSError, ValueError, services.signing_unavailable_error) as exc:\n"
        ),
        after=(
            '                "status": "ERROR",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 2\n"
            "    except (OSError, ValueError, services.signing_unavailable_error) as exc:\n"
        ),
        test=(
            "tests/test_cli_github_attestation_admission_characterization.py::"
            "test_frozen_cli_github_attestation_admission_behavior"
            "[verify_domain_error_subclass_precedes_value_error]"
        ),
    ),
    Mutation(
        name="cli-github-admission-seal-valueerror-catch-bypass",
        path="evoom_guard/cli/github_attestation_admission_commands.py",
        before=(
            "    except (OSError, ValueError, services.signing_unavailable_error) as exc:\n"
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.binding_format,\n'
            '                "ok": False,\n'
            '                "sealed": False,\n'
        ),
        after=(
            "    except (OSError, services.signing_unavailable_error) as exc:\n"
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.binding_format,\n'
            '                "ok": False,\n'
            '                "sealed": False,\n'
        ),
        test=(
            "tests/test_cli_github_attestation_admission_characterization.py::"
            "test_frozen_cli_github_attestation_admission_behavior"
            "[seal_plain_value_error_is_operational]"
        ),
    ),
    Mutation(
        name="cli-github-admission-verify-valueerror-catch-bypass",
        path="evoom_guard/cli/github_attestation_admission_commands.py",
        before=(
            "    except (OSError, ValueError, services.signing_unavailable_error) as exc:\n"
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.binding_format,\n'
            '                "ok": False,\n'
            '                "verified": False,\n'
        ),
        after=(
            "    except (OSError, services.signing_unavailable_error) as exc:\n"
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.binding_format,\n'
            '                "ok": False,\n'
            '                "verified": False,\n'
        ),
        test=(
            "tests/test_cli_github_attestation_admission_characterization.py::"
            "test_frozen_cli_github_attestation_admission_behavior"
            "[verify_plain_value_error_is_operational]"
        ),
    ),
    Mutation(
        name="cli-github-admission-seal-metadata-oserror-bypass",
        path="evoom_guard/cli/github_attestation_admission_commands.py",
        before=(
            "    except (OSError, UnicodeError, ValueError) as exc:\n"
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.binding_format,\n'
            '                "ok": False,\n'
            '                "sealed": False,\n'
        ),
        after=(
            "    except (UnicodeError, ValueError) as exc:\n"
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.binding_format,\n'
            '                "ok": False,\n'
            '                "sealed": False,\n'
        ),
        test=(
            "tests/test_cli_github_attestation_admission_characterization.py::"
            "test_frozen_cli_github_attestation_admission_behavior"
            "[seal_source_read_error]"
        ),
    ),
    Mutation(
        name="cli-github-admission-verify-metadata-oserror-bypass",
        path="evoom_guard/cli/github_attestation_admission_commands.py",
        before=(
            "    except (OSError, UnicodeError, ValueError) as exc:\n"
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.binding_format,\n'
            '                "ok": False,\n'
            '                "verified": False,\n'
        ),
        after=(
            "    except (UnicodeError, ValueError) as exc:\n"
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.binding_format,\n'
            '                "ok": False,\n'
            '                "verified": False,\n'
        ),
        test=(
            "tests/test_cli_github_attestation_admission_characterization.py::"
            "test_frozen_cli_github_attestation_admission_behavior"
            "[verify_source_read_error]"
        ),
    ),
    Mutation(
        name="cli-github-admission-seal-projection-order-bypass",
        path="evoom_guard/cli/github_attestation_admission_commands.py",
        before=(
            '            "receipt": sealed.receipt.receipt_path,\n'
            '            "raw_output": sealed.receipt.raw_output_path,\n'
            '            "binding": sealed.admission.binding_path,\n'
        ),
        after=(
            '            "binding": sealed.admission.binding_path,\n'
            '            "receipt": sealed.receipt.receipt_path,\n'
            '            "raw_output": sealed.receipt.raw_output_path,\n'
        ),
        test=(
            "tests/test_cli_github_attestation_admission_characterization.py::"
            "test_frozen_cli_github_attestation_admission_behavior"
            "[seal_repeated_projection_order]"
        ),
    ),
    Mutation(
        name="cli-github-admission-verify-projection-order-bypass",
        path="evoom_guard/cli/github_attestation_admission_commands.py",
        before=(
            '            "artifact": verified.receipt.artifact.as_dict(),\n'
            '            "verification_policy": verified.receipt.policy.as_dict(),\n'
        ),
        after=(
            '            "verification_policy": verified.receipt.policy.as_dict(),\n'
            '            "artifact": verified.receipt.artifact.as_dict(),\n'
        ),
        test=(
            "tests/test_cli_github_attestation_admission_characterization.py::"
            "test_frozen_cli_github_attestation_admission_behavior"
            "[verify_repeated_projection_order]"
        ),
    ),
    Mutation(
        name="cli-release-source-handoff-stdin-exit-bypass",
        path="evoom_guard/cli/release_source_finalizer_commands.py",
        before=(
            '                    "release-source-handoff verdict must be a regular file, "\n'
            '                    "not standard input"\n'
            "                ),\n"
            "            },\n"
            "        )\n"
            "        return 2\n"
        ),
        after=(
            '                    "release-source-handoff verdict must be a regular file, "\n'
            '                    "not standard input"\n'
            "                ),\n"
            "            },\n"
            "        )\n"
            "        return 1\n"
        ),
        test=(
            "tests/test_cli_release_source_finalizer_characterization.py::"
            "test_frozen_cli_release_source_finalizer_behavior"
            "[handoff_verdict_stdin]"
        ),
    ),
    Mutation(
        name="cli-release-source-handoff-reader-snapshot-bypass",
        path="evoom_guard/cli/__init__.py",
        before=(
            "                create_release_source_handoff="
            "create_release_source_handoff,\n"
            "                read_external_object_provider=lambda: (\n"
            "                    _read_external_finalizer_object\n"
            "                ),\n"
        ),
        after=(
            "                create_release_source_handoff="
            "create_release_source_handoff,\n"
            "                read_external_object_provider=lambda _reader=(\n"
            "                    _read_external_finalizer_object\n"
            "                ): _reader,\n"
        ),
        test=(
            "tests/test_cli_release_source_finalizer_characterization.py::"
            "test_frozen_cli_release_source_finalizer_behavior"
            "[handoff_source_property_rebinds_reader]"
        ),
    ),
    Mutation(
        name="cli-release-source-handoff-invalid-classification-bypass",
        path="evoom_guard/cli/release_source_finalizer_commands.py",
        before=(
            "    except (OSError, ValueError, services.finalizer_error) as exc:\n"
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.handoff_format,\n'
            '                "ok": False,\n'
            '                "status": "INVALID_INPUT",\n'
        ),
        after=(
            "    except (OSError, ValueError, services.finalizer_error) as exc:\n"
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.handoff_format,\n'
            '                "ok": False,\n'
            '                "status": "ERROR",\n'
        ),
        test=(
            "tests/test_cli_release_source_finalizer_characterization.py::"
            "test_frozen_cli_release_source_finalizer_behavior"
            "[handoff_provider_valueerror]"
        ),
    ),
    Mutation(
        name="cli-release-source-seal-signing-classification-bypass",
        path="evoom_guard/cli/release_source_finalizer_commands.py",
        before=(
            "    except services.signing_unavailable_error as exc:\n"
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.evidence_format,\n'
            '                "ok": False,\n'
            '                "sealed": False,\n'
            '                "status": "INCOMPLETE",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 2\n"
            "    allowed = sealed.decision == \"ALLOW\"\n"
        ),
        after=(
            "    except services.signing_unavailable_error as exc:\n"
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.evidence_format,\n'
            '                "ok": False,\n'
            '                "sealed": False,\n'
            '                "status": "INVALID_INPUT",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 1\n"
            "    allowed = sealed.decision == \"ALLOW\"\n"
        ),
        test=(
            "tests/test_cli_release_source_finalizer_characterization.py::"
            "test_frozen_cli_release_source_finalizer_behavior"
            "[seal_signing_unavailable]"
        ),
    ),
    Mutation(
        name="cli-release-source-seal-deny-opt-in-bypass",
        path="evoom_guard/cli/release_source_finalizer_commands.py",
        before=(
            '            "record_sha256": sealed.manifest["record"]["sha256"],\n'
            '            "key_id": sealed.manifest["authentication"]["key_id"],\n'
            "        },\n"
            "    )\n"
            "    return 0 if allowed or args.allow_deny_evidence else 1\n"
        ),
        after=(
            '            "record_sha256": sealed.manifest["record"]["sha256"],\n'
            '            "key_id": sealed.manifest["authentication"]["key_id"],\n'
            "        },\n"
            "    )\n"
            "    return 0 if allowed else 1\n"
        ),
        test=(
            "tests/test_cli_release_source_finalizer_characterization.py::"
            "test_frozen_cli_release_source_finalizer_behavior"
            "[seal_success_deny_opt_in]"
        ),
    ),
    Mutation(
        name="cli-release-source-verify-signing-classification-bypass",
        path="evoom_guard/cli/release_source_finalizer_commands.py",
        before=(
            "    except services.signing_unavailable_error as exc:\n"
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.evidence_format,\n'
            '                "ok": False,\n'
            '                "verified": False,\n'
            '                "status": "INCOMPLETE",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 2\n"
            "    except (OSError, ValueError, services.finalizer_error) as exc:\n"
        ),
        after=(
            "    except services.signing_unavailable_error as exc:\n"
            "        services.machine_report_provider()(\n"
            "            out,\n"
            "            {\n"
            '                "format": services.evidence_format,\n'
            '                "ok": False,\n'
            '                "verified": False,\n'
            '                "status": "INVALID",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 1\n"
            "    except (OSError, ValueError, services.finalizer_error) as exc:\n"
        ),
        test=(
            "tests/test_cli_release_source_finalizer_characterization.py::"
            "test_frozen_cli_release_source_finalizer_behavior"
            "[verify_signing_unavailable]"
        ),
    ),
    Mutation(
        name="cli-release-source-verify-deny-opt-in-bypass",
        path="evoom_guard/cli/release_source_finalizer_commands.py",
        before=(
            '            "record": verified.record_report,\n'
            "        },\n"
            "    )\n"
            "    return 0 if allowed or args.allow_deny_evidence else 1\n"
        ),
        after=(
            '            "record": verified.record_report,\n'
            "        },\n"
            "    )\n"
            "    return 0 if allowed else 1\n"
        ),
        test=(
            "tests/test_cli_release_source_finalizer_characterization.py::"
            "test_frozen_cli_release_source_finalizer_behavior"
            "[verify_success_deny_opt_in]"
        ),
    ),
    Mutation(
        name="cli-release-source-derive-publication-order-bypass",
        path="evoom_guard/cli/release_source_finalizer_commands.py",
        before=(
            "        services.publish_bytes(\n"
            "            args.source_out,\n"
            "            services.canonical_json(bindings.source),\n"
            "            force=args.force,\n"
            '            prefix=".evoguard-release-source-",\n'
            '            label="verified release source",\n'
            "        )\n"
            "        services.publish_bytes(\n"
            "            args.context_out,\n"
            "            services.canonical_json(context),\n"
            "            force=args.force,\n"
            '            prefix=".evoguard-release-source-context-",\n'
            '            label="verified release-source context",\n'
            "        )\n"
        ),
        after=(
            "        services.publish_bytes(\n"
            "            args.context_out,\n"
            "            services.canonical_json(context),\n"
            "            force=args.force,\n"
            '            prefix=".evoguard-release-source-context-",\n'
            '            label="verified release-source context",\n'
            "        )\n"
            "        services.publish_bytes(\n"
            "            args.source_out,\n"
            "            services.canonical_json(bindings.source),\n"
            "            force=args.force,\n"
            '            prefix=".evoguard-release-source-",\n'
            '            label="verified release source",\n'
            "        )\n"
        ),
        test=(
            "tests/test_cli_release_source_finalizer_characterization.py::"
            "test_frozen_cli_release_source_finalizer_behavior"
            "[derive_publish_context_oserror_preserves_source]"
        ),
    ),
    Mutation(
        name="cli-release-source-derive-admission-claim-bypass",
        path="evoom_guard/cli/release_source_finalizer_commands.py",
        before=(
            '            "decision": "NONE",\n'
            '            "admission": False,\n'
        ),
        after=(
            '            "decision": "ALLOW",\n'
            '            "admission": True,\n'
        ),
        test=(
            "tests/test_cli_release_source_finalizer_characterization.py::"
            "test_frozen_cli_release_source_finalizer_behavior"
            "[derive_success_boundary]"
        ),
    ),
    Mutation(
        name="cli-release-source-derive-path-snapshot-bypass",
        path="evoom_guard/cli/__init__.py",
        before=(
            "                derive_release_source_bindings=(\n"
            "                    finalizer_primitives.derive_release_source_bindings\n"
            "                ),\n"
            "                read_external_object_provider=lambda: (\n"
            "                    _read_external_finalizer_object\n"
            "                ),\n"
            "                absolute_path_provider=lambda: os.path.abspath,\n"
        ),
        after=(
            "                derive_release_source_bindings=(\n"
            "                    finalizer_primitives.derive_release_source_bindings\n"
            "                ),\n"
            "                read_external_object_provider=lambda: (\n"
            "                    _read_external_finalizer_object\n"
            "                ),\n"
            "                absolute_path_provider=lambda _abspath=(\n"
            "                    os.path.abspath\n"
            "                ): _abspath,\n"
        ),
        test=(
            "tests/test_cli_release_source_finalizer_characterization.py::"
            "test_frozen_cli_release_source_finalizer_behavior"
            "[derive_source_out_property_rebinds_abspath]"
        ),
    ),
    Mutation(
        name="cli-producer-receipt-create-eager-stdin-bypass",
        path="evoom_guard/cli/release_source_producer_receipt_commands.py",
        before=(
            '    if any(value == "-" for value in (args.verdict, args.handoff)):\n'
        ),
        after='    if args.verdict == "-":\n',
        test=(
            "tests/test_cli_release_source_producer_receipt_characterization.py::"
            "test_frozen_cli_release_source_producer_receipt_behavior"
            "[create_handoff_stdin]"
        ),
    ),
    Mutation(
        name="cli-producer-receipt-verify-eager-stdin-bypass",
        path="evoom_guard/cli/release_source_producer_receipt_commands.py",
        before=(
            "def execute_verify_producer_receipt(\n"
            "    args: argparse.Namespace,\n"
            "    *,\n"
            "    services: VerifyProducerReceiptServices,\n"
            "    out: _Output = print,\n"
            ") -> int:\n"
            '    """Verify local/raw-Git producer binding without treating it as '
            'provider proof."""\n'
            "\n"
            '    if any(value == "-" for value in '
            "(args.receipt, args.handoff, args.verdict)):\n"
        ),
        after=(
            "def execute_verify_producer_receipt(\n"
            "    args: argparse.Namespace,\n"
            "    *,\n"
            "    services: VerifyProducerReceiptServices,\n"
            "    out: _Output = print,\n"
            ") -> int:\n"
            '    """Verify local/raw-Git producer binding without treating it as '
            'provider proof."""\n'
            "\n"
            '    if args.receipt == "-":\n'
        ),
        test=(
            "tests/test_cli_release_source_producer_receipt_characterization.py::"
            "test_frozen_cli_release_source_producer_receipt_behavior"
            "[verify_handoff_stdin]"
        ),
    ),
    Mutation(
        name="cli-producer-receipt-reverify-eager-stdin-bypass",
        path="evoom_guard/cli/release_source_producer_receipt_commands.py",
        before=(
            "def execute_reverify_producer_receipt(\n"
            "    args: argparse.Namespace,\n"
            "    *,\n"
            "    services: ReverifyProducerReceiptServices,\n"
            "    out: _Output = print,\n"
            ") -> int:\n"
            '    """Make a fresh GitHub provider check after local/raw-Git '
            'verification."""\n'
            "\n"
            '    if any(value == "-" for value in '
            "(args.receipt, args.handoff, args.verdict)):\n"
        ),
        after=(
            "def execute_reverify_producer_receipt(\n"
            "    args: argparse.Namespace,\n"
            "    *,\n"
            "    services: ReverifyProducerReceiptServices,\n"
            "    out: _Output = print,\n"
            ") -> int:\n"
            '    """Make a fresh GitHub provider check after local/raw-Git '
            'verification."""\n'
            "\n"
            '    if args.receipt == "-":\n'
        ),
        test=(
            "tests/test_cli_release_source_producer_receipt_characterization.py::"
            "test_frozen_cli_release_source_producer_receipt_behavior"
            "[reverify_handoff_stdin]"
        ),
    ),
    Mutation(
        name="cli-producer-receipt-create-reader-snapshot-bypass",
        path="evoom_guard/cli/__init__.py",
        before=(
            "            create_producer_receipt="
            "create_release_source_producer_receipt,\n"
            "            read_external_object_provider=lambda: "
            "_read_external_finalizer_object,\n"
        ),
        after=(
            "            create_producer_receipt="
            "create_release_source_producer_receipt,\n"
            "            read_external_object_provider=lambda _reader=(\n"
            "                _read_external_finalizer_object\n"
            "            ): _reader,\n"
        ),
        test=(
            "tests/test_cli_release_source_producer_receipt_characterization.py::"
            "test_frozen_cli_release_source_producer_receipt_behavior"
            "[create_source_property_rebinds_reader]"
        ),
    ),
    Mutation(
        name="cli-producer-receipt-verify-helper-snapshot-bypass",
        path="evoom_guard/cli/__init__.py",
        before=(
            "            verify_producer_receipt="
            "verify_release_source_producer_receipt,\n"
            "            external_inputs_provider=lambda: "
            "_producer_receipt_external_inputs,\n"
        ),
        after=(
            "            verify_producer_receipt="
            "verify_release_source_producer_receipt,\n"
            "            external_inputs_provider=lambda _inputs=(\n"
            "                _producer_receipt_external_inputs\n"
            "            ): _inputs,\n"
        ),
        test=(
            "tests/test_cli_release_source_producer_receipt_characterization.py::"
            "test_frozen_cli_release_source_producer_receipt_behavior"
            "[verify_external_helper_is_live_after_stdin]"
        ),
    ),
    Mutation(
        name="cli-producer-receipt-create-rejection-classification-bypass",
        path="evoom_guard/cli/release_source_producer_receipt_commands.py",
        before=(
            '                "status": "REJECTED",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 1\n"
            "    services.machine_report_provider()(\n"
            "        out,\n"
            "        {\n"
            '            "format": services.receipt_format,\n'
            '            "ok": True,\n'
        ),
        after=(
            '                "status": "ERROR",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 2\n"
            "    services.machine_report_provider()(\n"
            "        out,\n"
            "        {\n"
            '            "format": services.receipt_format,\n'
            '            "ok": True,\n'
        ),
        test=(
            "tests/test_cli_release_source_producer_receipt_characterization.py::"
            "test_frozen_cli_release_source_producer_receipt_behavior"
            "[create_provider_valueerror]"
        ),
    ),
    Mutation(
        name="cli-producer-receipt-verify-rejection-classification-bypass",
        path="evoom_guard/cli/release_source_producer_receipt_commands.py",
        before=(
            '                "status": "REJECTED",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 1\n"
            "    services.machine_report_provider()(\n"
            "        out,\n"
            "        {\n"
            '            "format": services.receipt_format,\n'
            '            "ok": False,\n'
            '            "verified": True,\n'
            '            "status": "NONADMITTING_LOCAL_AND_RAW_GIT_VERIFIED",\n'
        ),
        after=(
            '                "status": "ERROR",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 2\n"
            "    services.machine_report_provider()(\n"
            "        out,\n"
            "        {\n"
            '            "format": services.receipt_format,\n'
            '            "ok": False,\n'
            '            "verified": True,\n'
            '            "status": "NONADMITTING_LOCAL_AND_RAW_GIT_VERIFIED",\n'
        ),
        test=(
            "tests/test_cli_release_source_producer_receipt_characterization.py::"
            "test_frozen_cli_release_source_producer_receipt_behavior"
            "[verify_provider_valueerror]"
        ),
    ),
    Mutation(
        name="cli-producer-receipt-reverify-rejection-classification-bypass",
        path="evoom_guard/cli/release_source_producer_receipt_commands.py",
        before=(
            '                "status": "REJECTED",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 1\n"
            "    services.machine_report_provider()(\n"
            "        out,\n"
            "        {\n"
            '            "format": services.receipt_format,\n'
            '            "ok": False,\n'
            '            "verified": True,\n'
            '            "status": "NONADMITTING_FRESH_PROVIDER_VERIFIED",\n'
        ),
        after=(
            '                "status": "ERROR",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 2\n"
            "    services.machine_report_provider()(\n"
            "        out,\n"
            "        {\n"
            '            "format": services.receipt_format,\n'
            '            "ok": False,\n'
            '            "verified": True,\n'
            '            "status": "NONADMITTING_FRESH_PROVIDER_VERIFIED",\n'
        ),
        test=(
            "tests/test_cli_release_source_producer_receipt_characterization.py::"
            "test_frozen_cli_release_source_producer_receipt_behavior"
            "[reverify_provider_valueerror]"
        ),
    ),
    Mutation(
        name="cli-producer-receipt-verify-admission-claim-bypass",
        path="evoom_guard/cli/release_source_producer_receipt_commands.py",
        before=(
            '            "status": "NONADMITTING_LOCAL_AND_RAW_GIT_VERIFIED",\n'
            '            "record_sha256": verified.receipt.payload["record"]["sha256"],\n'
            '            "decision": "NONE",\n'
            '            "admission": False,\n'
        ),
        after=(
            '            "status": "NONADMITTING_LOCAL_AND_RAW_GIT_VERIFIED",\n'
            '            "record_sha256": verified.receipt.payload["record"]["sha256"],\n'
            '            "decision": "ALLOW",\n'
            '            "admission": True,\n'
        ),
        test=(
            "tests/test_cli_release_source_producer_receipt_characterization.py::"
            "test_frozen_cli_release_source_producer_receipt_behavior"
            "[verify_success_default_nonadmitting]"
        ),
    ),
    Mutation(
        name="cli-producer-receipt-reverify-admission-claim-bypass",
        path="evoom_guard/cli/release_source_producer_receipt_commands.py",
        before=(
            '            "github_raw_output": verified.github_receipt.raw_output_path,\n'
            '            "decision": "NONE",\n'
            '            "admission": False,\n'
        ),
        after=(
            '            "github_raw_output": verified.github_receipt.raw_output_path,\n'
            '            "decision": "ALLOW",\n'
            '            "admission": True,\n'
        ),
        test=(
            "tests/test_cli_release_source_producer_receipt_characterization.py::"
            "test_frozen_cli_release_source_producer_receipt_behavior"
            "[reverify_success_default_nonadmitting]"
        ),
    ),
    Mutation(
        name="cli-producer-receipt-verify-opt-in-exit-bypass",
        path="evoom_guard/cli/release_source_producer_receipt_commands.py",
        before=(
            '            "provider_verified": False,\n'
            '            "requires": (\n'
            '                "explicit-allow-nonadmitting-evidence-for-archive-only-success"\n'
            "            ),\n"
            "        },\n"
            "    )\n"
            "    return 0 if args.allow_nonadmitting_evidence else 1\n"
        ),
        after=(
            '            "provider_verified": False,\n'
            '            "requires": (\n'
            '                "explicit-allow-nonadmitting-evidence-for-archive-only-success"\n'
            "            ),\n"
            "        },\n"
            "    )\n"
            "    return 1\n"
        ),
        test=(
            "tests/test_cli_release_source_producer_receipt_characterization.py::"
            "test_frozen_cli_release_source_producer_receipt_behavior"
            "[verify_success_opt_in_nonadmitting]"
        ),
    ),
    Mutation(
        name="cli-producer-receipt-reverify-opt-in-exit-bypass",
        path="evoom_guard/cli/release_source_producer_receipt_commands.py",
        before=(
            '            "github_raw_output": verified.github_receipt.raw_output_path,\n'
            '            "decision": "NONE",\n'
            '            "admission": False,\n'
            '            "requires": (\n'
            '                "explicit-allow-nonadmitting-evidence-for-archive-only-success"\n'
            "            ),\n"
            "        },\n"
            "    )\n"
            "    return 0 if args.allow_nonadmitting_evidence else 1\n"
        ),
        after=(
            '            "github_raw_output": verified.github_receipt.raw_output_path,\n'
            '            "decision": "NONE",\n'
            '            "admission": False,\n'
            '            "requires": (\n'
            '                "explicit-allow-nonadmitting-evidence-for-archive-only-success"\n'
            "            ),\n"
            "        },\n"
            "    )\n"
            "    return 1\n"
        ),
        test=(
            "tests/test_cli_release_source_producer_receipt_characterization.py::"
            "test_frozen_cli_release_source_producer_receipt_behavior"
            "[reverify_success_opt_in_nonadmitting]"
        ),
    ),
    Mutation(
        name="cli-release-source-admission-seal-stdin-tuple-bypass",
        path="evoom_guard/cli/release_source_admission_commands.py",
        before=(
            '    if any(value == "-" for value in '
            "(args.receipt, args.handoff, args.verdict)):\n"
        ),
        after='    if args.receipt == "-":\n',
        test=(
            "tests/test_cli_release_source_admission_characterization.py::"
            "test_frozen_cli_release_source_admission_behavior"
            "[seal_handoff_stdin_short_circuit]"
        ),
    ),
    Mutation(
        name="cli-release-source-admission-producer-helper-snapshot-bypass",
        path="evoom_guard/cli/__init__.py",
        before=(
            "                    public_key_id=public_key_id,\n"
            "                    producer_inputs_provider=lambda: (\n"
            "                        _producer_receipt_external_inputs\n"
            "                    ),\n"
            "                    read_external_object_provider=lambda: (\n"
        ),
        after=(
            "                    public_key_id=public_key_id,\n"
            "                    producer_inputs_provider=lambda _inputs=(\n"
            "                        _producer_receipt_external_inputs\n"
            "                    ): _inputs,\n"
            "                    read_external_object_provider=lambda: (\n"
        ),
        test=(
            "tests/test_cli_release_source_admission_characterization.py::"
            "test_frozen_cli_release_source_admission_behavior"
            "[seal_producer_helper_is_live]"
        ),
    ),
    Mutation(
        name="cli-release-source-admission-key-helper-snapshot-bypass",
        path="evoom_guard/cli/__init__.py",
        before=(
            "                    key_separation_provider=lambda: (\n"
            "                        _release_source_key_separation\n"
            "                    ),\n"
            "                    preflight_provider=lambda: (\n"
        ),
        after=(
            "                    key_separation_provider=lambda _keys=(\n"
            "                        _release_source_key_separation\n"
            "                    ): _keys,\n"
            "                    preflight_provider=lambda: (\n"
        ),
        test=(
            "tests/test_cli_release_source_admission_characterization.py::"
            "test_frozen_cli_release_source_admission_behavior"
            "[seal_key_helper_is_live]"
        ),
    ),
    Mutation(
        name="cli-release-source-admission-seal-reader-snapshot-bypass",
        path="evoom_guard/cli/__init__.py",
        before=(
            "                    producer_inputs_provider=lambda: (\n"
            "                        _producer_receipt_external_inputs\n"
            "                    ),\n"
            "                    read_external_object_provider=lambda: (\n"
            "                        _read_external_finalizer_object\n"
            "                    ),\n"
        ),
        after=(
            "                    producer_inputs_provider=lambda: (\n"
            "                        _producer_receipt_external_inputs\n"
            "                    ),\n"
            "                    read_external_object_provider=lambda _reader=(\n"
            "                        _read_external_finalizer_object\n"
            "                    ): _reader,\n"
        ),
        test=(
            "tests/test_cli_release_source_admission_characterization.py::"
            "test_frozen_cli_release_source_admission_behavior"
            "[seal_reader_is_live_between_inputs]"
        ),
    ),
    Mutation(
        name="cli-release-source-admission-preflight-helper-snapshot-bypass",
        path="evoom_guard/cli/__init__.py",
        before=(
            "                    preflight_provider=lambda: (\n"
            "                        _preflight_release_source_admission_paths\n"
            "                    ),\n"
            "                    environment_provider=lambda: os.environ,\n"
        ),
        after=(
            "                    preflight_provider=lambda _preflight=(\n"
            "                        _preflight_release_source_admission_paths\n"
            "                    ): _preflight,\n"
            "                    environment_provider=lambda: os.environ,\n"
        ),
        test=(
            "tests/test_cli_release_source_admission_characterization.py::"
            "test_frozen_cli_release_source_admission_behavior"
            "[seal_preflight_is_live]"
        ),
    ),
    Mutation(
        name="cli-release-source-admission-preflight-execution-bypass",
        path="evoom_guard/cli/release_source_admission_commands.py",
        before="        services.preflight_provider()(args)\n",
        after="        _ = services.preflight_provider\n",
        test=(
            "tests/test_cli_release_source_admission_characterization.py::"
            "test_frozen_cli_release_source_admission_behavior"
            "[seal_output_alias_rejected]"
        ),
    ),
    Mutation(
        name="cli-release-source-admission-git-pin-bypass",
        path="evoom_guard/cli/release_source_admission_commands.py",
        before=(
            "        git_executable = services.git_executable_pin(\n"
            "            args.git_executable,\n"
            "            args.git_executable_sha256,\n"
            "        )\n"
        ),
        after=(
            "        _ = (args.git_executable, args.git_executable_sha256)\n"
            "        git_executable = None\n"
        ),
        test=(
            "tests/test_cli_release_source_admission_characterization.py::"
            "test_frozen_cli_release_source_admission_behavior"
            "[seal_success]"
        ),
    ),
    Mutation(
        name="cli-release-source-admission-provider-isolation-bypass",
        path="evoom_guard/cli/release_source_admission_commands.py",
        before=(
            "        provider_isolation = services.provider_isolation(\n"
            "            args.gh_executable,\n"
            "            args.gh_executable_sha256,\n"
            "            uid=args.provider_isolation_uid,\n"
            "            gid=args.provider_isolation_gid,\n"
            "        )\n"
        ),
        after=(
            "        _ = (\n"
            "            args.gh_executable,\n"
            "            args.gh_executable_sha256,\n"
            "            args.provider_isolation_uid,\n"
            "            args.provider_isolation_gid,\n"
            "        )\n"
            "        provider_isolation = None\n"
        ),
        test=(
            "tests/test_cli_release_source_admission_characterization.py::"
            "test_frozen_cli_release_source_admission_behavior"
            "[seal_success]"
        ),
    ),
    Mutation(
        name="cli-release-source-admission-event-context-bypass",
        path="evoom_guard/cli/release_source_admission_commands.py",
        before="        if not event_path:\n",
        after="        if False and not event_path:\n",
        test=(
            "tests/test_cli_release_source_admission_characterization.py::"
            "test_frozen_cli_release_source_admission_behavior"
            "[seal_event_path_missing]"
        ),
    ),
    Mutation(
        name="cli-release-source-admission-protected-key-binding-bypass",
        path="evoom_guard/cli/release_source_admission_commands.py",
        before="            protected_signing_key_path=args.sign_key,\n",
        after="            protected_signing_key_path=None,\n",
        test=(
            "tests/test_cli_release_source_admission_characterization.py::"
            "test_frozen_cli_release_source_admission_behavior"
            "[seal_success]"
        ),
    ),
    Mutation(
        name="cli-release-source-admission-partial-evidence-error-bypass",
        path="evoom_guard/cli/release_source_admission_commands.py",
        before=(
            "    except (\n"
            "        OSError,\n"
            "        UnicodeError,\n"
            "        ValueError,\n"
            "        services.release_source_error,\n"
            "        services.producer_receipt_error,\n"
        ),
        after=(
            "    except (\n"
            "        UnicodeError,\n"
            "        ValueError,\n"
            "        services.release_source_error,\n"
            "        services.producer_receipt_error,\n"
        ),
        test=(
            "tests/test_cli_release_source_admission_characterization.py::"
            "test_frozen_cli_release_source_admission_behavior"
            "[seal_partial_provider_output_preserved]"
        ),
    ),
    Mutation(
        name="cli-release-source-admission-seal-projection-order-bypass",
        path="evoom_guard/cli/release_source_admission_commands.py",
        before=(
            '            "bundle": sealed.bundle_path,\n'
            '            "key_id": sealed.manifest["authentication"]["key_id"],\n'
            '            "record_sha256": sealed.manifest["record"]["sha256"],\n'
        ),
        after=(
            '            "record_sha256": sealed.manifest["record"]["sha256"],\n'
            '            "bundle": sealed.bundle_path,\n'
            '            "key_id": sealed.manifest["authentication"]["key_id"],\n'
        ),
        test=(
            "tests/test_cli_release_source_admission_characterization.py::"
            "test_frozen_cli_release_source_admission_behavior"
            "[seal_success_projection_order]"
        ),
    ),
    Mutation(
        name="cli-release-source-admission-verify-online-argument-bypass",
        path="evoom_guard/cli/release_source_admission_commands.py",
        before=(
            '    """Verify a V2 source authorization using only external trust roots."""\n'
            "\n"
            '    if args.bundle == "-":\n'
        ),
        after=(
            '    """Verify a V2 source authorization using only external trust roots."""\n'
            "\n"
            "    _ = args.gh_executable\n"
            '    if args.bundle == "-":\n'
        ),
        test=(
            "tests/test_cli_release_source_admission_characterization.py::"
            "test_frozen_cli_release_source_admission_behavior"
            "[verify_success_offline_boundary]"
        ),
    ),
    Mutation(
        name="cli-release-source-admission-verify-key-helper-snapshot-bypass",
        path="evoom_guard/cli/__init__.py",
        before=(
            "                    verify_release_source_admission="
            "verify_release_source_admission,\n"
            "                    read_external_object_provider=lambda: (\n"
            "                        _read_external_finalizer_object\n"
            "                    ),\n"
            "                    key_separation_provider=lambda: (\n"
            "                        _release_source_key_separation\n"
            "                    ),\n"
        ),
        after=(
            "                    verify_release_source_admission="
            "verify_release_source_admission,\n"
            "                    read_external_object_provider=lambda: (\n"
            "                        _read_external_finalizer_object\n"
            "                    ),\n"
            "                    key_separation_provider=lambda _keys=(\n"
            "                        _release_source_key_separation\n"
            "                    ): _keys,\n"
        ),
        test=(
            "tests/test_cli_release_source_admission_characterization.py::"
            "test_frozen_cli_release_source_admission_behavior"
            "[verify_key_helper_is_live]"
        ),
    ),
    Mutation(
        name="cli-release-source-admission-verify-reader-snapshot-bypass",
        path="evoom_guard/cli/__init__.py",
        before=(
            "                    verify_release_source_admission="
            "verify_release_source_admission,\n"
            "                    read_external_object_provider=lambda: (\n"
            "                        _read_external_finalizer_object\n"
            "                    ),\n"
            "                    key_separation_provider=lambda: (\n"
        ),
        after=(
            "                    verify_release_source_admission="
            "verify_release_source_admission,\n"
            "                    read_external_object_provider=lambda _reader=(\n"
            "                        _read_external_finalizer_object\n"
            "                    ): _reader,\n"
            "                    key_separation_provider=lambda: (\n"
        ),
        test=(
            "tests/test_cli_release_source_admission_characterization.py::"
            "test_frozen_cli_release_source_admission_behavior"
            "[verify_reader_is_live_between_inputs]"
        ),
    ),
    Mutation(
        name="cli-release-source-admission-verify-authority-service-bypass",
        path="evoom_guard/cli/release_source_admission_commands.py",
        before=(
            "    machine_report_provider: Callable[[], _MachineReport]\n"
            "\n"
            "\n"
            "def execute_seal_release_source_admission(\n"
        ),
        after=(
            "    machine_report_provider: Callable[[], _MachineReport]\n"
            "    environment_provider: Callable[[], Mapping[str, str]] | None = None\n"
            "\n"
            "\n"
            "def execute_seal_release_source_admission(\n"
        ),
        test=(
            "tests/test_cli_release_source_admission_characterization.py::"
            "test_verify_service_contract_has_no_connected_authority_seam"
        ),
    ),
    Mutation(
        name="cli-release-source-admission-verify-projection-order-bypass",
        path="evoom_guard/cli/release_source_admission_commands.py",
        before=(
            '            "key_id": verified.bundle.manifest'
            '["authentication"]["key_id"],\n'
            '            "record_sha256": verified.bundle.manifest["record"]["sha256"],\n'
        ),
        after=(
            '            "record_sha256": verified.bundle.manifest["record"]["sha256"],\n'
            '            "key_id": verified.bundle.manifest'
            '["authentication"]["key_id"],\n'
        ),
        test=(
            "tests/test_cli_release_source_admission_characterization.py::"
            "test_frozen_cli_release_source_admission_behavior"
            "[verify_success_offline_boundary]"
        ),
    ),
    Mutation(
        name="cli-release-artifact-seal-preflight-reresolution-bypass",
        path="evoom_guard/cli/__init__.py",
        before=(
            "            preflight_provider=lambda: "
            "_preflight_release_artifact_admission_paths,\n"
        ),
        after=(
            "            preflight_provider=lambda _preflight="
            "_preflight_release_artifact_admission_paths: _preflight,\n"
        ),
        test=(
            "tests/test_cli_release_artifact_admission_characterization.py::"
            "test_frozen_cli_release_artifact_admission_behavior"
            "[seal_preflight_helper_is_live_after_environment_read]"
        ),
    ),
    Mutation(
        name="cli-release-artifact-seal-key-reresolution-bypass",
        path="evoom_guard/cli/__init__.py",
        before=(
            "            environment_provider=lambda: os.environ,\n"
            "            preflight_provider=lambda: "
            "_preflight_release_artifact_admission_paths,\n"
            "            nested_expectations_provider=lambda: (\n"
            "                _release_artifact_nested_expectations\n"
            "            ),\n"
            "            read_external_object_provider=lambda: "
            "_read_external_finalizer_object,\n"
            "            key_separation_provider=lambda: "
            "_release_artifact_key_separation,\n"
        ),
        after=(
            "            environment_provider=lambda: os.environ,\n"
            "            preflight_provider=lambda: "
            "_preflight_release_artifact_admission_paths,\n"
            "            nested_expectations_provider=lambda: (\n"
            "                _release_artifact_nested_expectations\n"
            "            ),\n"
            "            read_external_object_provider=lambda: "
            "_read_external_finalizer_object,\n"
            "            key_separation_provider=lambda _keys="
            "_release_artifact_key_separation: _keys,\n"
        ),
        test=(
            "tests/test_cli_release_artifact_admission_characterization.py::"
            "test_frozen_cli_release_artifact_admission_behavior"
            "[seal_key_helper_is_live_after_metadata_reads]"
        ),
    ),
    Mutation(
        name="cli-release-artifact-verify-nested-reresolution-bypass",
        path="evoom_guard/cli/__init__.py",
        before=(
            "            verify_release_artifact_admission="
            "verify_release_artifact_admission,\n"
            "            nested_expectations_provider=lambda: (\n"
            "                _release_artifact_nested_expectations\n"
            "            ),\n"
        ),
        after=(
            "            verify_release_artifact_admission="
            "verify_release_artifact_admission,\n"
            "            nested_expectations_provider=lambda _nested=(\n"
            "                _release_artifact_nested_expectations\n"
            "            ): _nested,\n"
        ),
        test=(
            "tests/test_cli_release_artifact_admission_characterization.py::"
            "test_frozen_cli_release_artifact_admission_behavior"
            "[verify_nested_helper_is_live_after_stdin_guard]"
        ),
    ),
    Mutation(
        name="cli-release-artifact-verify-reader-reresolution-bypass",
        path="evoom_guard/cli/__init__.py",
        before=(
            "            verify_release_artifact_admission="
            "verify_release_artifact_admission,\n"
            "            nested_expectations_provider=lambda: (\n"
            "                _release_artifact_nested_expectations\n"
            "            ),\n"
            "            read_external_object_provider=lambda: "
            "_read_external_finalizer_object,\n"
        ),
        after=(
            "            verify_release_artifact_admission="
            "verify_release_artifact_admission,\n"
            "            nested_expectations_provider=lambda: (\n"
            "                _release_artifact_nested_expectations\n"
            "            ),\n"
            "            read_external_object_provider=lambda _reader="
            "_read_external_finalizer_object: _reader,\n"
        ),
        test=(
            "tests/test_cli_release_artifact_admission_characterization.py::"
            "test_frozen_cli_release_artifact_admission_behavior"
            "[verify_reader_is_live_during_nested_reads]"
        ),
    ),
    Mutation(
        name="cli-release-artifact-seal-event-required-bypass",
        path="evoom_guard/cli/release_artifact_admission_commands.py",
        before="        if not event_path:\n",
        after="        if False and not event_path:\n",
        test=(
            "tests/test_cli_release_artifact_admission_characterization.py::"
            "test_frozen_cli_release_artifact_admission_behavior"
            "[seal_missing_event_path]"
        ),
    ),
    Mutation(
        name="cli-release-artifact-seal-key-separation-bypass",
        path="evoom_guard/cli/release_artifact_admission_commands.py",
        before=(
            "        if expected_signing_key_id in set(key_separation.values()):\n"
        ),
        after=(
            "        if False and expected_signing_key_id "
            "in set(key_separation.values()):\n"
        ),
        test=(
            "tests/test_cli_release_artifact_admission_characterization.py::"
            "test_frozen_cli_release_artifact_admission_behavior"
            "[seal_signer_domain_collision_precedes_execution_pins]"
        ),
    ),
    Mutation(
        name="cli-release-artifact-seal-isolation-identity-bypass",
        path="evoom_guard/cli/release_artifact_admission_commands.py",
        before=(
            "            provider_isolation=provider_isolation,\n"
            "            private_key_path=args.sign_key,\n"
        ),
        after=(
            "            provider_isolation=None,\n"
            "            private_key_path=args.sign_key,\n"
        ),
        test=(
            "tests/test_cli_release_artifact_admission_characterization.py::"
            "test_frozen_cli_release_artifact_admission_behavior"
            "[seal_success_online_boundary]"
        ),
    ),
    Mutation(
        name="cli-release-artifact-seal-partial-oserror-catch-bypass",
        path="evoom_guard/cli/release_artifact_admission_commands.py",
        before=(
            "    except (\n"
            "        OSError,\n"
            "        UnicodeError,\n"
            "        ValueError,\n"
            "        services.release_artifact_error,\n"
            "        services.github_error,\n"
            "        services.finalizer_error,\n"
            "        services.signing_unavailable_error,\n"
            "    ) as exc:\n"
        ),
        after=(
            "    except (\n"
            "        UnicodeError,\n"
            "        ValueError,\n"
            "        services.release_artifact_error,\n"
            "        services.github_error,\n"
            "        services.finalizer_error,\n"
            "        services.signing_unavailable_error,\n"
            "    ) as exc:\n"
        ),
        test=(
            "tests/test_cli_release_artifact_admission_characterization.py::"
            "test_frozen_cli_release_artifact_admission_behavior"
            "[seal_provider_oserror_preserves_partial_bundle]"
        ),
    ),
    Mutation(
        name="cli-release-artifact-verify-stdin-short-circuit-bypass",
        path="evoom_guard/cli/release_artifact_admission_commands.py",
        before='        if args.bundle == "-" or args.artifact == "-":\n',
        after='        if args.bundle == "-" and args.artifact == "-":\n',
        test=(
            "tests/test_cli_release_artifact_admission_characterization.py::"
            "test_frozen_cli_release_artifact_admission_behavior"
            "[verify_artifact_stdin_after_bundle_read]"
        ),
    ),
    Mutation(
        name="cli-release-artifact-verify-online-authority-bypass",
        path="evoom_guard/cli/release_artifact_admission_commands.py",
        before=(
            '    """Verify one RAAE, its artifact, nested RSAE, and all six roots offline."""\n'
            "\n"
            "    try:\n"
        ),
        after=(
            '    """Verify one RAAE, its artifact, nested RSAE, and all six roots offline."""\n'
            "\n"
            "    _ = services.environment_provider()\n"
            "    try:\n"
        ),
        test=(
            "tests/test_cli_release_artifact_admission_characterization.py::"
            "test_verify_facade_does_not_import_online_provider_or_git_capabilities"
        ),
    ),
    Mutation(
        name="cli-release-artifact-verify-live-provider-claim-bypass",
        path="evoom_guard/cli/release_artifact_admission_commands.py",
        before=(
            '            "verification_scope": '
            '"detached-offline-retained-provider-evidence",\n'
            '            "live_provider_reverification": False,\n'
        ),
        after=(
            '            "verification_scope": '
            '"detached-offline-retained-provider-evidence",\n'
            '            "live_provider_reverification": True,\n'
        ),
        test=(
            "tests/test_cli_release_artifact_admission_characterization.py::"
            "test_frozen_cli_release_artifact_admission_behavior"
            "[verify_success_offline_closed_world]"
        ),
    ),
    Mutation(
        name="cli-release-artifact-verify-isolation-pin-binding-bypass",
        path="evoom_guard/cli/release_artifact_admission_commands.py",
        before=(
            "            expected_provider_isolation_uid="
            "args.expected_provider_isolation_uid,\n"
            "            expected_provider_isolation_gid="
            "args.expected_provider_isolation_gid,\n"
        ),
        after=(
            "            expected_provider_isolation_uid="
            "args.expected_provider_isolation_gid,\n"
            "            expected_provider_isolation_gid="
            "args.expected_provider_isolation_gid,\n"
        ),
        test=(
            "tests/test_cli_release_artifact_admission_characterization.py::"
            "test_frozen_cli_release_artifact_admission_behavior"
            "[verify_success_offline_closed_world]"
        ),
    ),
    Mutation(
        name="repository-copy-windows-reparse-preflight-bypass",
        path="evoom_guard/workspace/repository.py",
        before='    if platform == "nt":\n',
        after='    if False and platform == "nt":\n',
        test=(
            "tests/test_repository_workspace_owner.py::"
            "test_repository_copy_rejects_simulated_windows_reparse_before_copying"
        ),
    ),
    Mutation(
        name="repository-copy-windows-root-symlink-bypass",
        path="evoom_guard/workspace/repository.py",
        before="        if root_probe(src):\n",
        after="        if False and root_probe(src):\n",
        test=(
            "tests/test_repository_workspace_owner.py::"
            "test_repository_copy_rejects_a_simulated_windows_symlink_root"
        ),
    ),
    Mutation(
        name="repository-cleanup-file-not-found-absence-proof-bypass",
        path="evoom_guard/workspace/repository.py",
        before="            if path_absent(path) is True:\n",
        after="            if True:\n",
        test=(
            "tests/test_repository_workspace_owner.py::"
            "test_repository_workspace_cleanup_requires_positive_root_absence_proof"
        ),
    ),
    Mutation(
        name="repository-copy-symlink-fidelity-bypass",
        path="evoom_guard/workspace/repository.py",
        before="        symlinks=True,\n",
        after="        symlinks=False,\n",
        test=(
            "tests/test_repository_workspace_owner.py::"
            "test_repository_workspace_owner_freezes_the_historical_copy_contract"
        ),
    ),
    Mutation(
        name="repository-copy-ignore-bypass",
        path="evoom_guard/workspace/repository.py",
        before="    ignore = ignore_patterns_provider(*copy_ignore)\n",
        after="    ignore = ignore_patterns_provider()\n",
        test=(
            "tests/test_repository_workspace_owner.py::"
            "test_repository_workspace_owner_freezes_the_historical_copy_contract"
        ),
    ),
    Mutation(
        name="repository-cleanup-primary-precedence-bypass",
        path="evoom_guard/workspace/repository.py",
        before="    if primary is not None:\n",
        after="    if False and primary is not None:\n",
        test=(
            "tests/test_repository_workspace_owner.py::"
            "test_repository_workspace_cleanup_attempts_every_path_and_preserves_primary"
        ),
    ),
    Mutation(
        name="repository-cleanup-stop-after-first-failure",
        path="evoom_guard/workspace/repository.py",
        before=(
            "        except BaseException as exc:\n"
            "            failures.append((safe_label, exc))\n"
        ),
        after=(
            "        except BaseException as exc:\n"
            "            failures.append((safe_label, exc)); break\n"
        ),
        test=(
            "tests/test_repository_workspace_owner.py::"
            "test_repository_workspace_cleanup_attempts_every_path_and_preserves_primary"
        ),
    ),
    Mutation(
        name="repository-cleanup-hostile-stringification-bypass",
        path="evoom_guard/workspace/repository.py",
        before=(
            "    try:\n"
            "        rendered = str(error)\n"
            "        detail = _exact_cleanup_text(rendered)\n"
            "    except BaseException as stringify_error:\n"
            "        detail = (\n"
            '            "<unprintable; __str__ raised "\n'
            "            f\"{_exception_type_name(stringify_error)}>\"\n"
            "        )\n"
        ),
        after=(
            "    try:\n"
            "        rendered = str(error)\n"
            "        detail = _exact_cleanup_text(rendered)\n"
            "    except Exception as stringify_error:\n"
            "        detail = (\n"
            '            "<unprintable; __str__ raised "\n'
            "            f\"{_exception_type_name(stringify_error)}>\"\n"
            "        )\n"
        ),
        test=(
            "tests/test_workspace_cleanup_reporting.py::"
            "test_hostile_cleanup_stringification_cannot_mask_active_primary"
        ),
    ),
    Mutation(
        name="repository-cleanup-str-subclass-normalization-bypass",
        path="evoom_guard/workspace/repository.py",
        before=(
            "            normalized = value if type(value) is str else "
            "str.__str__(value)\n"
        ),
        after="            normalized = value\n",
        test=(
            "tests/test_workspace_cleanup_reporting.py::"
            "test_default_note_reporter_normalizes_hostile_str_subclass"
        ),
    ),
    Mutation(
        name="repository-cleanup-owner-normalization-bypass",
        path="evoom_guard/workspace/repository.py",
        before="    safe_owner_name = _exact_cleanup_text(owner_name)\n",
        after="    safe_owner_name = owner_name\n",
        test=(
            "tests/test_workspace_cleanup_reporting.py::"
            "test_hostile_owner_and_label_text_cannot_mask_active_primary"
        ),
    ),
    Mutation(
        name="repository-cleanup-label-normalization-bypass",
        path="evoom_guard/workspace/repository.py",
        before="        safe_label = _exact_cleanup_text(label)\n",
        after="        safe_label = label\n",
        test=(
            "tests/test_workspace_cleanup_reporting.py::"
            "test_hostile_owner_and_label_text_preserve_first_cleanup_failure"
        ),
    ),
    Mutation(
        name="repository-cleanup-callback-suffix-priority-bypass",
        path="evoom_guard/workspace/repository.py",
        before=(
            "        fallback = _bounded_cleanup_diagnostic_with_suffix(\n"
            "            diagnostic,\n"
            "            callback_suffix,\n"
            "        )\n"
        ),
        after=(
            "        fallback = _bounded_cleanup_diagnostic(\n"
            "            diagnostic + callback_suffix\n"
            "        )\n"
        ),
        test=(
            "tests/test_workspace_cleanup_reporting.py::"
            "test_oversized_diagnostic_retains_callback_failure_evidence"
        ),
    ),
    Mutation(
        name="repository-cleanup-diagnostic-bound-bypass",
        path="evoom_guard/workspace/repository.py",
        before="    diagnostic = _bounded_cleanup_diagnostic(message)\n",
        after="    diagnostic = message\n",
        test=(
            "tests/test_workspace_cleanup_reporting.py::"
            "test_active_primary_cleanup_diagnostic_is_deterministically_bounded"
        ),
    ),
    Mutation(
        name="repository-cleanup-note-callback-baseexception-mask",
        path="evoom_guard/workspace/repository.py",
        before="    except BaseException as report_error:\n",
        after="    except Exception as report_error:\n",
        test=(
            "tests/test_workspace_cleanup_reporting.py::"
            "test_note_callback_baseexception_cannot_mask_active_primary"
        ),
    ),
    Mutation(
        name="repository-cleanup-note-callback-fallback-bypass",
        path="evoom_guard/workspace/repository.py",
        before="            note_cleanup_failure(target, fallback)\n",
        after="            None\n",
        test=(
            "tests/test_workspace_cleanup_reporting.py::"
            "test_note_callback_baseexception_cannot_replace_first_cleanup_failure"
        ),
    ),
    Mutation(
        name="repository-cleanup-default-note-bound-bypass",
        path="evoom_guard/workspace/repository.py",
        before="        message = _bounded_cleanup_diagnostic(message)\n",
        after="        message = message\n",
        test=(
            "tests/test_workspace_cleanup_reporting.py::"
            "test_default_note_reporter_bounds_direct_diagnostics"
        ),
    ),
    Mutation(
        name="repository-cleanup-first-failure-precedence-bypass",
        path="evoom_guard/workspace/repository.py",
        before="    raise first_error\n",
        after="    raise failures[-1][1]\n",
        test=(
            "tests/test_workspace_cleanup_reporting.py::"
            "test_hostile_secondary_stringification_preserves_first_cleanup_failure"
        ),
    ),
    Mutation(
        name="repository-allocator-rollback-formatting-bypass",
        path="evoom_guard/workspace/repository.py",
        before=(
            "            if rollback_error is not None:\n"
            "                note_cleanup_failure(\n"
            "                    primary,\n"
            "                    \"RepositoryWorkspaceAllocator rollback failed while \"\n"
            "                    \"preserving the capture exception: \"\n"
            "                    + _cleanup_exception_summary(rollback_error),\n"
            "                )\n"
            "            note_cleanup_failure(\n"
        ),
        after=(
            "            if rollback_error is not None:\n"
            "                note_cleanup_failure(\n"
            "                    primary,\n"
            "                    \"RepositoryWorkspaceAllocator rollback failed while \"\n"
            "                    \"preserving the capture exception: \"\n"
            "                    f\"{rollback_error}\",\n"
            "                )\n"
            "            note_cleanup_failure(\n"
        ),
        test=(
            "tests/test_owned_repository_workspace_cleanup.py::"
            "test_hostile_rollback_formatting_cannot_mask_capture_primary"
        ),
    ),
    Mutation(
        name="repository-allocator-proof-formatting-bypass",
        path="evoom_guard/workspace/repository.py",
        before=(
            "                \"RepositoryWorkspaceAllocator absence proof failed while \"\n"
            "                \"preserving the capture exception: \"\n"
            "                + _cleanup_exception_summary(proof_error),\n"
        ),
        after=(
            "                \"RepositoryWorkspaceAllocator absence proof failed while \"\n"
            "                \"preserving the capture exception: \"\n"
            "                f\"{proof_error}\",\n"
        ),
        test=(
            "tests/test_owned_repository_workspace_cleanup.py::"
            "test_hostile_absence_proof_formatting_cannot_mask_capture_primary"
        ),
    ),
    Mutation(
        name="repository-allocator-unproven-rollback-formatting-bypass",
        path="evoom_guard/workspace/repository.py",
        before=(
            "        else:\n"
            "            if absent is not True:\n"
            "                if rollback_error is not None:\n"
            "                    note_cleanup_failure(\n"
            "                        primary,\n"
            "                        \"RepositoryWorkspaceAllocator rollback failed while \"\n"
            "                        \"preserving the capture exception: \"\n"
            "                        + _cleanup_exception_summary(rollback_error),\n"
            "                    )\n"
            "                note_cleanup_failure(\n"
        ),
        after=(
            "        else:\n"
            "            if absent is not True:\n"
            "                if rollback_error is not None:\n"
            "                    note_cleanup_failure(\n"
            "                        primary,\n"
            "                        \"RepositoryWorkspaceAllocator rollback failed while \"\n"
            "                        \"preserving the capture exception: \"\n"
            "                        f\"{rollback_error}\",\n"
            "                    )\n"
            "                note_cleanup_failure(\n"
        ),
        test=(
            "tests/test_owned_repository_workspace_cleanup.py::"
            "test_hostile_rollback_formatting_cannot_mask_capture_primary"
        ),
    ),
    Mutation(
        name="guard-output-markdown-reason-sanitization-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before='        f"**{_markdown_text(r.reason)}**",\n',
        after='        f"**{r.reason}**",\n',
        test=(
            "tests/test_guard_output_security.py::"
            "test_markdown_projection_neutralizes_untrusted_structure"
        ),
    ),
    Mutation(
        name="guard-output-markdown-diagnostic-fence-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before="            _markdown_fenced_code(diag),\n",
        after='            f"```\\n{diag}\\n```",\n',
        test=(
            "tests/test_guard_output_security.py::"
            "test_markdown_projection_neutralizes_untrusted_structure"
        ),
    ),
    Mutation(
        name="guard-output-markdown-entity-introducer-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before='        elif markdown and character == "&":\n',
        after='        elif False and markdown and character == "&":\n',
        test=(
            "tests/test_guard_output_security.py::"
            "test_markdown_projection_neutralizes_untrusted_structure"
        ),
    ),
    Mutation(
        name="guard-output-percent-type-validation-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before=(
            "    if type(value) not in {int, float}:\n"
            '        raise ValueError(f"{field} must be a finite number '
            'from 0 to 100")\n'
        ),
        after=(
            "    if False and type(value) not in {int, float}:\n"
            '        raise ValueError(f"{field} must be a finite number '
            'from 0 to 100")\n'
        ),
        test=(
            "tests/test_guard_output_security.py::"
            "test_diff_coverage_numeric_evidence_fails_closed"
        ),
    ),
    Mutation(
        name="guard-output-count-type-validation-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before="    if type(value) is not int or value < 0:\n",
        after="    if False and type(value) is not int or value < 0:\n",
        test=(
            "tests/test_guard_output_security.py::"
            "test_missed_line_evidence_fails_closed"
        ),
    ),
    Mutation(
        name="guard-output-top-level-test-count-validation-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before=(
            "    tests = _validated_test_counts(\n"
            "        r.tests_passed,\n"
            "        r.tests_total,\n"
            "    )\n"
        ),
        after='    tests = "bypassed"\n',
        test=(
            "tests/test_guard_output_security.py::"
            "test_top_level_test_counts_fail_closed_before_markdown_projection"
        ),
    ),
    Mutation(
        name="guard-output-risk-score-validation-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before=(
            "    risk_score = _require_probability(\n"
            "        r.risk_score,\n"
            '        field="risk_score",\n'
            "    )\n"
        ),
        after="    risk_score = 0.0\n",
        test=(
            "tests/test_guard_output_security.py::"
            "test_risk_score_fails_closed_before_markdown_projection"
        ),
    ),
    Mutation(
        name="guard-output-atomic-fsync-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before="            os.fsync(stream.fileno())\n",
        after="            if False:\n                os.fsync(stream.fileno())\n",
        test=(
            "tests/test_guard_output_security.py::"
            "test_atomic_writer_fsyncs_before_same_directory_replace"
        ),
    ),
    Mutation(
        name="guard-output-atomic-same-directory-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before="        dir=directory,\n",
        after="        dir=None,\n",
        test=(
            "tests/test_guard_output_security.py::"
            "test_atomic_writer_fsyncs_before_same_directory_replace"
        ),
    ),
    Mutation(
        name="guard-output-stream-closefd-ownership-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before="            closefd=False,\n",
        after="            closefd=True,\n",
        test=(
            "tests/test_guard_output_security.py::"
            "test_atomic_close_after_wrapper_close_never_closes_a_victim"
        ),
    ),
    Mutation(
        name="guard-output-raw-descriptor-close-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before="            os.close(raw_descriptor)\n",
        after="            if False:\n                os.close(raw_descriptor)\n",
        test=(
            "tests/test_guard_output_security.py::"
            "test_atomic_close_before_wrapper_close_releases_raw_handle"
        ),
    ),
    Mutation(
        name="guard-output-raw-descriptor-disarm-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before=(
            "        raw_descriptor = descriptor\n"
            "        descriptor = -1\n"
            "        try:\n"
        ),
        after=(
            "        raw_descriptor = descriptor\n"
            "        try:\n"
        ),
        test=(
            "tests/test_guard_output_security.py::"
            "test_atomic_raw_descriptor_close_is_attempted_only_once"
        ),
    ),
    Mutation(
        name="guard-output-nonregular-destination-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before="    if not stat.S_ISREG(observed.st_mode):\n",
        after="    if False and not stat.S_ISREG(observed.st_mode):\n",
        test=(
            "tests/test_guard_output_security.py::"
            "test_atomic_writer_rejects_directory_destination"
        ),
    ),
    Mutation(
        name="guard-output-windows-reserved-name-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before='    if platform_name == "nt":\n',
        after='    if False and platform_name == "nt":\n',
        test=(
            "tests/test_guard_output_security.py::"
            "test_destination_validator_rejects_windows_devices_and_namespaces"
        ),
    ),
    Mutation(
        name="guard-output-read-only-mode-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before="    if mode & 0o222 == 0:\n",
        after="    if False and mode & 0o222 == 0:\n",
        test=(
            "tests/test_guard_output_security.py::"
            "test_destination_validator_rejects_simulated_read_only_regular_file"
        ),
    ),
    Mutation(
        name="guard-output-close-primary-precedence-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before="    if primary is None:\n",
        after="    if True:\n",
        test=(
            "tests/test_guard_output_security.py::"
            "test_atomic_writer_preserves_primary_when_close_also_fails"
        ),
    ),
    Mutation(
        name="guard-output-second-destination-validation-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before=(
            "        current_mode = "
            "_validate_output_destination(destination_path)\n"
        ),
        after="        current_mode = None\n",
        test=(
            "tests/test_guard_output_security.py::"
            "test_atomic_writer_revalidates_leaf_immediately_before_replace"
        ),
    ),
    Mutation(
        name="guard-output-mode-preservation-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before="            os.chmod(temp_path, replacement_mode)\n",
        after="            if False:\n                os.chmod(temp_path, replacement_mode)\n",
        test=(
            "tests/test_guard_output_security.py::"
            "test_atomic_writer_applies_existing_mode_before_replace"
        ),
    ),
    Mutation(
        name="guard-output-sarif-control-validation-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before=(
            "    if any(_is_unsafe_control(character) for character in path):\n"
        ),
        after=(
            "    if False and any("
            "_is_unsafe_control(character) for character in path):\n"
        ),
        test=(
            "tests/test_guard_output_security.py::"
            "test_sarif_rejects_control_or_non_repository_artifact_paths"
            "[src/control\\nname.py]"
        ),
    ),
    Mutation(
        name="guard-output-sarif-surrogate-validation-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before=(
            '    if any(unicodedata.category(character) == "Cs" '
            "for character in path):\n"
        ),
        after=(
            '    if False and any(unicodedata.category(character) == "Cs" '
            "for character in path):\n"
        ),
        test=(
            "tests/test_guard_output_security.py::"
            "test_sarif_path_errors_are_structured"
        ),
    ),
    Mutation(
        name="guard-output-sarif-backslash-validation-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before='    if "\\\\" in path:\n',
        after='    if False and "\\\\" in path:\n',
        test=(
            "tests/test_guard_output_security.py::"
            "test_sarif_path_errors_are_structured"
        ),
    ),
    Mutation(
        name="guard-output-sarif-drive-prefix-validation-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before="    if _has_ascii_drive_prefix(path):\n",
        after="    if False and _has_ascii_drive_prefix(path):\n",
        test=(
            "tests/test_guard_output_security.py::"
            "test_sarif_path_errors_are_structured"
        ),
    ),
    Mutation(
        name="guard-output-sarif-unicode-drive-prefix-regression",
        path="evoom_guard/integrations/guard_output.py",
        before=(
            '        and ("A" <= value[0] <= "Z" '
            'or "a" <= value[0] <= "z")\n'
        ),
        after="        and value[0].isalpha()\n",
        test=(
            "tests/test_guard_output_security.py::"
            "test_sarif_unicode_letter_colon_is_not_an_ascii_drive_prefix"
        ),
    ),
    Mutation(
        name="guard-output-sarif-message-control-escape-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before=(
            '                    f"{_visible_inline_text('
            'result.reason, markdown=False)}"\n'
        ),
        after='                    f"{result.reason}"\n',
        test=(
            "tests/test_guard_output_security.py::"
            "test_sarif_message_text_projects_controls_as_visible_escapes"
        ),
    ),
    Mutation(
        name="guard-output-sarif-uri-encoding-bypass",
        path="evoom_guard/integrations/guard_output.py",
        before='    return quote(path, safe="/-._~")\n',
        after="    return path\n",
        test=(
            "tests/test_guard_output_security.py::"
            "test_sarif_artifact_uri_is_normalized_and_percent_encoded"
        ),
    ),
    Mutation(
        name="guard-output-non-pass-sarif-suppression",
        path="evoom_guard/integrations/guard_output.py",
        before="    if result.verdict != pass_verdict_provider():\n",
        after="    if False and result.verdict != pass_verdict_provider():\n",
        test=(
            "tests/test_guard_output_characterization.py::"
            "test_output_owner_sarif_non_pass_is_not_suppressed"
        ),
    ),
    Mutation(
        name="candidate-tree-compatibility-snapshot-frozen-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before=(
            "@dataclass(frozen=True, slots=True)\n"
            "class CandidateTreeCompatibilitySnapshot:\n"
        ),
        after=(
            "@dataclass(slots=True)\n"
            "class CandidateTreeCompatibilitySnapshot:\n"
        ),
        test=(
            "tests/test_candidate_tree_characterization.py::"
            "test_candidate_tree_compatibility_snapshot_is_public_and_immutable"
        ),
    ),
    Mutation(
        name="candidate-tree-compatibility-snapshot-slots-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before=(
            "@dataclass(frozen=True, slots=True)\n"
            "class CandidateTreeCompatibilitySnapshot:\n"
        ),
        after=(
            "@dataclass(frozen=True)\n"
            "class CandidateTreeCompatibilitySnapshot:\n"
        ),
        test=(
            "tests/test_candidate_tree_characterization.py::"
            "test_candidate_tree_compatibility_snapshot_is_public_and_immutable"
        ),
    ),
    Mutation(
        name="candidate-tree-compatibility-error-owner-bypass",
        path="evoom_guard/guard.py",
        before=(
            "        unverifiable_changed_paths_error="
            "_UnverifiableChangedPathsError,\n"
        ),
        after=(
            "        unverifiable_changed_paths_error="
            "_candidate_tree.UnverifiableChangedPathsError,\n"
        ),
        test=(
            "tests/test_candidate_tree_characterization.py::"
            "test_candidate_tree_compatibility_snapshot_is_public_and_immutable"
        ),
    ),
    Mutation(
        name="candidate-tree-compatibility-callable-owner-bypass",
        path="evoom_guard/guard.py",
        before=(
            "        blocks_from_dirs=blocks_from_dirs,\n"
            "        serialize_candidate_blocks=serialize_candidate_blocks,\n"
        ),
        after=(
            "        blocks_from_dirs=_candidate_tree.blocks_from_dirs,\n"
            "        serialize_candidate_blocks="
            "_candidate_tree.serialize_candidate_blocks,\n"
        ),
        test=(
            "tests/test_candidate_tree_characterization.py::"
            "test_candidate_tree_compatibility_snapshot_is_public_and_immutable"
        ),
    ),
    Mutation(
        name="candidate-tree-reparse-classification-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before="    if is_windows_reparse(full_path, info):\n",
        after="    if False and is_windows_reparse(full_path, info):\n",
        test=(
            "tests/test_candidate_tree_snapshot_hardening.py::"
            "test_tree_entry_rejects_a_reparse_directory_before_walk"
        ),
    ),
    Mutation(
        name="candidate-tree-reparse-attribute-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before="    if attributes & reparse_flag:\n",
        after="    if False and attributes & reparse_flag:\n",
        test=(
            "tests/test_candidate_tree_snapshot_hardening.py::"
            "test_windows_reparse_attribute_detection_is_python_310_compatible"
        ),
    ),
    Mutation(
        name="candidate-tree-root-kind-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before='        if root_entry.kind != "directory":\n',
        after='        if False and root_entry.kind != "directory":\n',
        test=(
            "tests/test_candidate_tree_snapshot_hardening.py::"
            "test_blocks_from_dirs_rejects_a_non_directory_root_before_walk"
        ),
    ),
    Mutation(
        name="candidate-tree-object-identity-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before="        or stat_identity_provider(observed) != entry.identity\n",
        after="        or False\n",
        test=(
            "tests/test_candidate_tree_snapshot_hardening.py::"
            "test_snapshot_verifier_rejects_object_drift_independently_of_times"
        ),
    ),
    Mutation(
        name="candidate-tree-posix-open-support-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before="        if no_follow is None or non_block is None:\n",
        after="        if False and (no_follow is None or non_block is None):\n",
        test=(
            "tests/test_candidate_tree_snapshot_hardening.py::"
            "test_posix_open_flags_require_no_follow_and_non_block"
        ),
    ),
    Mutation(
        name="candidate-tree-posix-non-block-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before="        flags |= no_follow | non_block\n",
        after="        flags |= no_follow\n",
        test=(
            "tests/test_candidate_tree_snapshot_hardening.py::"
            "test_posix_open_flags_require_no_follow_and_non_block"
        ),
    ),
    Mutation(
        name="candidate-tree-posix-no-follow-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before="        flags |= no_follow | non_block\n",
        after="        flags |= non_block\n",
        test=(
            "tests/test_candidate_tree_snapshot_hardening.py::"
            "test_posix_open_flags_require_no_follow_and_non_block"
        ),
    ),
    Mutation(
        name="candidate-tree-path-time-drift-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before=(
            "            and (entry.path_times is None or "
            "stat_path_times_provider(observed) != entry.path_times)\n"
        ),
        after="            and False\n",
        test=(
            "tests/test_candidate_tree_snapshot_hardening.py::"
            "test_changed_text_rejects_metadata_drift_during_bounded_read"
        ),
    ),
    Mutation(
        name="candidate-tree-post-read-verification-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before='        verify_open_regular_snapshot_provider(entry, descriptor, "read")\n',
        after="        pass\n",
        test=(
            "tests/test_candidate_tree_snapshot_hardening.py::"
            "test_changed_text_rejects_metadata_drift_during_bounded_read"
        ),
    ),
    Mutation(
        name="candidate-tree-windows-write-delete-share-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before=(
            "        0x00000001,  # FILE_SHARE_READ; deliberately no WRITE "
            "or DELETE share\n"
        ),
        after=(
            "        0x00000007,  # unsafe READ | WRITE | DELETE sharing\n"
        ),
        test=(
            "tests/test_candidate_tree_snapshot_hardening.py::"
            "test_windows_native_open_contract_denies_write_delete_and_follows_ownership"
        ),
    ),
    Mutation(
        name="candidate-tree-windows-final-reparse-open-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before=(
            "        0x00200000 | 0x08000000,  # OPEN_REPARSE_POINT | "
            "SEQUENTIAL_SCAN\n"
        ),
        after=(
            "        0x08000000,  # unsafe: follows a raced final reparse point\n"
        ),
        test=(
            "tests/test_candidate_tree_snapshot_hardening.py::"
            "test_windows_native_open_contract_denies_write_delete_and_follows_ownership"
        ),
    ),
    Mutation(
        name="candidate-tree-windows-exclusive-open-dispatch-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before='        if platform == "nt"\n',
        after='        if False and platform == "nt"\n',
        test=(
            "tests/test_candidate_tree_snapshot_hardening.py::"
            "test_windows_open_dispatch_uses_write_exclusive_provider"
        ),
    ),
    Mutation(
        name="candidate-tree-comparison-snapshot-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before="                    base,\n                    head,\n",
        after="                    base,\n                    None,\n",
        test=(
            "tests/test_candidate_tree_snapshot_hardening.py::"
            "test_equal_file_comparison_rejects_hardlink_replacement_after_lstat"
        ),
    ),
    Mutation(
        name="candidate-tree-git-ignore-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before='    ignore = tuple(sorted(set(copy_ignore) | {".git"}))\n',
        after="    ignore = tuple(sorted(set(copy_ignore)))\n",
        test=(
            "tests/test_candidate_tree_characterization.py::"
            "test_walk_tree_uses_current_copy_ignore_and_always_ignores_git"
        ),
    ),
    Mutation(
        name="candidate-tree-gitfile-ignore-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before=(
            "            if _ignored_copy_name(filename, ignore):\n"
            "                continue\n"
        ),
        after=(
            "            if False and _ignored_copy_name(filename, ignore):\n"
            "                continue\n"
        ),
        test=(
            "tests/test_candidate_tree_characterization.py::"
            "test_gitfile_add_change_delete_is_invisible_without_hiding_git_names"
        ),
    ),
    Mutation(
        name="candidate-tree-windows-ignore-normcase-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before=(
            '    normalize = ntpath.normcase if platform == "nt" '
            "else posixpath.normcase\n"
        ),
        after="    normalize = posixpath.normcase\n",
        test=(
            "tests/test_candidate_tree_characterization.py::"
            "test_copy_ignore_matching_uses_windows_normcase_only_on_windows"
        ),
    ),
    Mutation(
        name="candidate-tree-live-copy-ignore-bypass",
        path="evoom_guard/guard.py",
        before="            copy_ignore=COPY_IGNORE,\n",
        after="            copy_ignore=(),\n",
        test=(
            "tests/test_candidate_tree_characterization.py::"
            "test_walk_tree_uses_current_copy_ignore_and_always_ignores_git"
        ),
    ),
    Mutation(
        name="candidate-tree-empty-directory-drop-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before=(
            "            if not directory_has_regular_descendant("
            "head_entries, rel):\n"
        ),
        after=(
            "            if False and not directory_has_regular_descendant("
            "head_entries, rel):\n"
        ),
        test=(
            "tests/test_candidate_tree_characterization.py::"
            "test_candidate_tree_reports_all_unrepresentable_paths_in_sorted_order"
        ),
    ),
    Mutation(
        name="candidate-tree-mode-change-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before="    if base.mode != head.mode:\n",
        after="    if False and base.mode != head.mode:\n",
        test=(
            "tests/test_guard_internals.py::"
            "test_directory_mode_change_is_unrepresentable"
        ),
    ),
    Mutation(
        name="candidate-tree-stale-size-limit-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before="    if entry.size > max_bytes:\n",
        after="    if False and entry.size > max_bytes:\n",
        test=(
            "tests/test_candidate_tree_characterization.py::"
            "test_changed_text_rejects_stale_size_metadata_above_limit"
        ),
    ),
    Mutation(
        name="candidate-tree-concurrent-growth-limit-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before="        data = read_fd_bounded_provider(descriptor, max_bytes + 1)\n",
        after="        data = read_fd_bounded_provider(descriptor, max_bytes)\n",
        test=(
            "tests/test_candidate_tree_characterization.py::"
            "test_changed_text_rejects_growth_after_snapshot"
        ),
    ),
    Mutation(
        name="candidate-tree-binary-decode-bypass",
        path="evoom_guard/workspace/candidate_tree.py",
        before='    return data.decode("utf-8")\n',
        after='    return data.decode("utf-8", errors="ignore")\n',
        test=(
            "tests/test_candidate_tree_characterization.py::"
            "test_candidate_tree_reports_all_unrepresentable_paths_in_sorted_order"
        ),
    ),
    Mutation(
        name="candidate-tree-late-comparison-provider-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "        entries_changed=lambda base, head: _entries_changed(\n"
            "            cast(_TreeEntry | None, base), cast(_TreeEntry, head)\n"
            "        ),\n"
        ),
        after="        entries_changed=_entries_changed,\n",
        test=(
            "tests/test_candidate_tree_characterization.py::"
            "test_blocks_from_dirs_resolves_later_helpers_after_walk_effects"
        ),
    ),
    Mutation(
        name="candidate-tree-late-entry-factory-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "            full_path,\n"
            "            entry_factory=lambda *args, **kwargs: cast(\n"
            "                Any,\n"
            "                _TreeEntry(*args, **kwargs),\n"
            "            ),\n"
        ),
        after=(
            "            full_path,\n"
            "            entry_factory=cast(Any, _TreeEntry),\n"
        ),
        test=(
            "tests/test_candidate_tree_characterization.py::"
            "test_tree_entry_resolves_private_type_after_lstat_effect"
        ),
    ),
    Mutation(
        name="candidate-tree-late-walk-error-entry-factory-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "            root,\n"
            "            copy_ignore=COPY_IGNORE,\n"
            "            tree_entry_lookup=lambda path: _tree_entry(path),\n"
            "            entry_factory=lambda *args, **kwargs: cast(\n"
            "                Any,\n"
            "                _TreeEntry(*args, **kwargs),\n"
            "            ),\n"
        ),
        after=(
            "            root,\n"
            "            copy_ignore=COPY_IGNORE,\n"
            "            tree_entry_lookup=lambda path: _tree_entry(path),\n"
            "            entry_factory=cast(Any, _TreeEntry),\n"
        ),
        test=(
            "tests/test_candidate_tree_characterization.py::"
            "test_walk_error_resolves_private_entry_type_after_os_walk_starts"
        ),
    ),
    Mutation(
        name="candidate-tree-late-error-factory-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "        unverifiable_error=lambda problems: "
            "_UnverifiableChangedPathsError(\n"
            "            problems\n"
            "        ),\n"
        ),
        after=(
            "        unverifiable_error=cast(\n"
            "            Any, _UnverifiableChangedPathsError\n"
            "        ),\n"
        ),
        test=(
            "tests/test_candidate_tree_characterization.py::"
            "test_blocks_from_dirs_resolves_private_error_after_walk_effects"
        ),
    ),
    Mutation(
        name="candidate-tree-late-serializer-provider-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "        serialize_blocks=lambda blocks: "
            "serialize_candidate_blocks(blocks),\n"
        ),
        after="        serialize_blocks=serialize_candidate_blocks,\n",
        test=(
            "tests/test_candidate_tree_characterization.py::"
            "test_candidate_from_dirs_resolves_serializer_after_derivation_effect"
        ),
    ),
    Mutation(
        name="guard-request-timeout-validation-bypass",
        path="evoom_guard/application/request_preparation.py",
        before="    if type(raw.timeout) is not int or raw.timeout < 1:\n",
        after=(
            "    if False and "
            "(type(raw.timeout) is not int or raw.timeout < 1):\n"
        ),
        test=(
            "tests/test_guard_request_preparation_characterization.py::"
            "test_invalid_runtime_values_fail_before_any_request_provider[timeout-zero]"
        ),
    ),
    Mutation(
        name="guard-request-memory-validation-bypass",
        path="evoom_guard/application/request_preparation.py",
        before=(
            "    if type(raw.mem_limit_mb) is not int or "
            "raw.mem_limit_mb < 0:\n"
        ),
        after=(
            "    if False and "
            "(type(raw.mem_limit_mb) is not int or raw.mem_limit_mb < 0):\n"
        ),
        test=(
            "tests/test_guard_request_preparation_characterization.py::"
            "test_invalid_runtime_values_fail_before_any_request_provider"
            "[memory-negative]"
        ),
    ),
    Mutation(
        name="guard-request-strict-boolean-validation-bypass",
        path="evoom_guard/application/request_preparation.py",
        before="    if type(raw.strict_harness) is not bool:\n",
        after="    if False and type(raw.strict_harness) is not bool:\n",
        test=(
            "tests/test_guard_request_preparation_characterization.py::"
            "test_invalid_runtime_values_fail_before_any_request_provider[strict-int]"
        ),
    ),
    Mutation(
        name="guard-request-coverage-boolean-validation-bypass",
        path="evoom_guard/application/request_preparation.py",
        before="            isinstance(raw.min_diff_coverage, bool)\n",
        after="            False\n",
        test=(
            "tests/test_guard_request_preparation_characterization.py::"
            "test_invalid_runtime_values_fail_before_any_request_provider[coverage-bool]"
        ),
    ),
    Mutation(
        name="guard-request-coverage-bounds-validation-bypass",
        path="evoom_guard/application/request_preparation.py",
        before="            or not 0 <= raw.min_diff_coverage <= 100\n",
        after="            or False\n",
        test=(
            "tests/test_guard_request_preparation_characterization.py::"
            "test_invalid_runtime_values_fail_before_any_request_provider"
            "[coverage-negative]"
        ),
    ),
    Mutation(
        name="guard-request-coverage-floor-collection-bypass",
        path="evoom_guard/application/request_preparation.py",
        before=(
            "    collect_diff_coverage = (\n"
            "        raw.collect_diff_coverage or raw.min_diff_coverage is not None\n"
            "    )\n"
        ),
        after="    collect_diff_coverage = raw.collect_diff_coverage\n",
        test=(
            "tests/test_guard_request_preparation.py::"
            "test_preparation_contracts_are_frozen_and_scoped_before_mode_support"
        ),
    ),
    Mutation(
        name="guard-request-blackbox-contradiction-bypass",
        path="evoom_guard/application/request_preparation.py",
        before="    if raw.blackbox_only and not raw.blackbox:\n",
        after="    if False and raw.blackbox_only and not raw.blackbox:\n",
        test=(
            "tests/test_guard_request_preparation_characterization.py::"
            "test_policy_contradictions_fail_before_any_request_provider"
            "[blackbox-only-without-blackbox]"
        ),
    ),
    Mutation(
        name="guard-request-pack-contradiction-bypass",
        path="evoom_guard/application/request_preparation.py",
        before=(
            "    if raw.expect_verifier_pack_sha256 is not None and "
            "not raw.verifier_pack_path:\n"
        ),
        after=(
            "    if False and raw.expect_verifier_pack_sha256 is not None and "
            "not raw.verifier_pack_path:\n"
        ),
        test=(
            "tests/test_guard_request_preparation_characterization.py::"
            "test_policy_contradictions_fail_before_any_request_provider"
            "[pack-digest-without-pack]"
        ),
    ),
    Mutation(
        name="guard-request-owned-file-block-projection-bypass",
        path="evoom_guard/application/request_preparation.py",
        before=(
            "            dict(request.candidate.file_blocks)\n"
            "            if request.candidate.file_blocks is not None\n"
        ),
        after=(
            "            dict(raw.file_blocks)\n"
            "            if raw.file_blocks is not None\n"
        ),
        test=(
            "tests/test_guard_request_preparation_characterization.py::"
            "test_frozen_request_policy_projection_and_provider_order"
        ),
    ),
    Mutation(
        name="guard-request-owned-setup-command-projection-bypass",
        path="evoom_guard/application/request_preparation.py",
        before=(
            "            list(request.policy.setup_command)\n"
            "            if request.policy.setup_command is not None\n"
        ),
        after=(
            "            list(raw.setup_command)\n"
            "            if raw.setup_command is not None\n"
        ),
        test=(
            "tests/test_guard_request_preparation.py::"
            "test_projection_uses_owned_request_containers_not_caller_containers"
        ),
    ),
    Mutation(
        name="guard-request-live-candidate-provider-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "            repository_input_provider=lambda: RepositoryInput,\n"
            "            candidate_input_provider=lambda: CandidateInput,\n"
        ),
        after=(
            "            repository_input_provider=lambda: RepositoryInput,\n"
            "            candidate_input_provider=(\n"
            "                lambda factory=CandidateInput: lambda: factory\n"
            "            )(),\n"
        ),
        test=(
            "tests/test_guard_request_preparation.py::"
            "test_guard_facade_resolves_providers_at_each_historical_call_position"
        ),
    ),
    Mutation(
        name="guard-request-live-source-provider-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "            candidate_input_provider=lambda: CandidateInput,\n"
            "            source_identity_provider=lambda: SourceIdentity,\n"
        ),
        after=(
            "            candidate_input_provider=lambda: CandidateInput,\n"
            "            source_identity_provider=(\n"
            "                lambda factory=SourceIdentity: lambda: factory\n"
            "            )(),\n"
        ),
        test=(
            "tests/test_guard_request_preparation.py::"
            "test_guard_facade_resolves_providers_at_each_historical_call_position"
        ),
    ),
    Mutation(
        name="guard-request-live-policy-provider-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "            source_identity_provider=lambda: SourceIdentity,\n"
            "            effective_policy_provider="
            "lambda: _build_effective_policy_contract,\n"
        ),
        after=(
            "            source_identity_provider=lambda: SourceIdentity,\n"
            "            effective_policy_provider=(\n"
            "                lambda factory=_build_effective_policy_contract: "
            "lambda: factory\n"
            "            )(),\n"
        ),
        test=(
            "tests/test_guard_request_preparation.py::"
            "test_guard_facade_resolves_providers_at_each_historical_call_position"
        ),
    ),
    Mutation(
        name="guard-request-live-payload-provider-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "            guard_request_provider=lambda: GuardRequest,\n"
            "            effective_policy_payload_provider="
            "lambda: _effective_policy_payload,\n"
        ),
        after=(
            "            guard_request_provider=lambda: GuardRequest,\n"
            "            effective_policy_payload_provider=(\n"
            "                lambda provider=_effective_policy_payload: "
            "lambda: provider\n"
            "            )(),\n"
        ),
        test=(
            "tests/test_guard_request_preparation.py::"
            "test_guard_facade_resolves_providers_at_each_historical_call_position"
        ),
    ),
    Mutation(
        name="guard-request-outer-provider-resolution-delay",
        path="evoom_guard/application/request_preparation.py",
        before="    request = guard_request_factory(\n",
        after="    request = services.guard_request_provider()(\n",
        test=(
            "tests/test_guard_request_preparation_characterization.py::"
            "test_outer_request_provider_is_resolved_before_nested_providers"
        ),
    ),
    Mutation(
        name="guard-request-provider-pre-validation-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "            effective_policy_provider="
            "lambda: _build_effective_policy_contract,\n"
            "            guard_request_provider=lambda: GuardRequest,\n"
        ),
        after=(
            "            effective_policy_provider="
            "lambda: _build_effective_policy_contract,\n"
            "            guard_request_provider=(\n"
            "                lambda factory=GuardRequest: lambda: factory\n"
            "            )(),\n"
        ),
        test=(
            "tests/test_guard_request_preparation_characterization.py::"
            "test_request_provider_is_resolved_after_coverage_implication"
        ),
    ),
    Mutation(
        name="guard-request-policy-provider-argument-delay",
        path="evoom_guard/application/request_preparation.py",
        before="    policy = services.effective_policy_provider()(\n",
        after=(
            "    policy = (lambda **values: "
            "services.effective_policy_provider()(**values))(\n"
        ),
        test=(
            "tests/test_guard_request_preparation_characterization.py::"
            "test_policy_provider_is_resolved_before_mode_argument_evaluation"
        ),
    ),
    Mutation(
        name="guard-request-payload-provider-property-delay",
        path="evoom_guard/application/request_preparation.py",
        before=(
            "    effective_policy = "
            "services.effective_policy_payload_provider()(request.policy)\n"
        ),
        after=(
            "    effective_policy = (lambda policy: "
            "services.effective_policy_payload_provider()(policy))(request.policy)\n"
        ),
        test=(
            "tests/test_guard_request_preparation_characterization.py::"
            "test_payload_provider_is_resolved_before_request_policy_access"
        ),
    ),
    Mutation(
        name="invocation-drain-batch-limit-bypass",
        path="evoom_guard/isolation/invocation.py",
        before=(
            "            for _ in range("
            "_MAX_INVOCATION_DATAGRAMS_PER_DRAIN):\n"
        ),
        after=(
            "            for _ in range("
            "_MAX_INVOCATION_DATAGRAMS_PER_DRAIN + 1):\n"
        ),
        test=(
            "tests/test_blackbox_invocation_recorder.py::"
            "test_flooded_receiver_has_a_bounded_lock_hold_and_close_path"
        ),
    ),
    Mutation(
        name="invocation-drain-stop-check-bypass",
        path="evoom_guard/isolation/invocation.py",
        before="                if self._stop.is_set() and not final:\n",
        after="                if False and self._stop.is_set() and not final:\n",
        test=(
            "tests/test_blackbox_invocation_recorder.py::"
            "test_stopped_background_drain_does_not_read_an_unbounded_source"
        ),
    ),
    Mutation(
        name="invocation-post-bind-unlink-bypass",
        path="evoom_guard/isolation/invocation.py",
        before=(
            "    if bound:\n"
            "        try:\n"
            "            os.unlink(path)\n"
        ),
        after=(
            "    if False and bound:\n"
            "        try:\n"
            "            os.unlink(path)\n"
        ),
        test=(
            "tests/test_blackbox_invocation_recorder.py::"
            "test_post_bind_failure_closes_and_unlinks_socket[chmod]"
        ),
    ),
    Mutation(
        name="judge-output-limit-validation-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        if type(self.max_output_bytes) is not int or "
            "self.max_output_bytes < 0:\n"
            "            raise ValueError("
            '"max_output_bytes must be a non-negative integer")\n'
        ),
        after=(
            "        if False and (type(self.max_output_bytes) is not int or "
            "self.max_output_bytes < 0):\n"
            "            raise ValueError("
            '"max_output_bytes must be a non-negative integer")\n'
        ),
        test=(
            "tests/test_judge_execution_kernel.py::"
            "test_judge_limits_reject_unbounded_values"
        ),
    ),
    Mutation(
        name="judge-finite-cleanup-limit-validation-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        ):\n"
            "            if (\n"
            "                isinstance(value, bool)\n"
            "                or not isinstance(value, (int, float))\n"
            "                or not math.isfinite(value)\n"
            "                or value < 0\n"
            "                or (not allow_zero and value == 0)\n"
            "            ):\n"
        ),
        after=(
            "        ):\n"
            "            if False and (\n"
            "                isinstance(value, bool)\n"
            "                or not isinstance(value, (int, float))\n"
            "                or not math.isfinite(value)\n"
            "                or value < 0\n"
            "                or (not allow_zero and value == 0)\n"
            "            ):\n"
        ),
        test=(
            "tests/test_judge_execution_kernel.py::"
            "test_judge_limits_reject_unbounded_values"
        ),
    ),
    Mutation(
        name="judge-sigkill-validation-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        if type(self.sigkill) is not int or self.sigkill <= 0:\n"
            "            raise ValueError("
            '"sigkill must be a positive integer signal number")\n'
        ),
        after=(
            "        if False and (type(self.sigkill) is not int or "
            "self.sigkill <= 0):\n"
            "            raise ValueError("
            '"sigkill must be a positive integer signal number")\n'
        ),
        test=(
            "tests/test_judge_execution_kernel.py::"
            "test_judge_limits_reject_unbounded_values"
        ),
    ),
    Mutation(
        name="judge-request-limits-type-validation-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        if type(self.limits) is not JudgeProcessLimits:\n"
            '            raise ValueError("limits must be a '
            'JudgeProcessLimits instance")\n'
        ),
        after=(
            "        if False and type(self.limits) is not JudgeProcessLimits:\n"
            '            raise ValueError("limits must be a '
            'JudgeProcessLimits instance")\n'
        ),
        test=(
            "tests/test_judge_execution_kernel.py::"
            "test_judge_request_rejects_unvalidated_limits_before_launch"
        ),
    ),
    Mutation(
        name="judge-request-timeout-validation-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        if type(self.timeout_seconds) is not int or "
            "self.timeout_seconds < 0:\n"
            '            raise ValueError("timeout_seconds must be a '
            'non-negative integer")\n'
        ),
        after=(
            "        if False and (type(self.timeout_seconds) is not int or "
            "self.timeout_seconds < 0):\n"
            '            raise ValueError("timeout_seconds must be a '
            'non-negative integer")\n'
        ),
        test=(
            "tests/test_judge_execution_kernel.py::"
            "test_judge_request_rejects_invalid_timeout_before_launch"
        ),
    ),
    Mutation(
        name="judge-default-group-proof-preflight-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            '        if os.name != "posix" or not callable('
            'getattr(os, "killpg", None)):\n'
            "            raise JudgeProcessCleanupError(\n"
            '                "default judge execution requires POSIX '
            'process-group cleanup; "\n'
            '                "provide an explicit trusted '
            'process_group_terminator"\n'
            "            )\n"
        ),
        after=(
            '        if False and (os.name != "posix" or not callable('
            'getattr(os, "killpg", None))):\n'
            "            raise JudgeProcessCleanupError(\n"
            '                "default judge execution requires POSIX '
            'process-group cleanup; "\n'
            '                "provide an explicit trusted '
            'process_group_terminator"\n'
            "            )\n"
        ),
        test=(
            "tests/test_judge_execution_kernel.py::"
            "test_default_direct_executor_rejects_missing_group_proof_before_launch"
        ),
    ),
    Mutation(
        name="judge-reader-start-cleanup-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "                termination_result: object = "
            "process_group_terminator(process)\n"
        ),
        after=(
            "                termination_result: object = None\n"
        ),
        test=(
            "tests/test_judge_abort_cleanup_observability.py::"
            "test_abort_cleanup_characterization_preserves_primary_and_attempt_order"
        ),
    ),
    Mutation(
        name="judge-reader-start-tracking-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "            reader_start_attempts.append(reader)\n"
            "            reader.start()\n"
        ),
        after="            reader.start()\n",
        test=(
            "tests/test_blackbox_judge_reader_start.py::"
            "test_reader_start_failure_cleans_group_handles_pipes_and_preserves_primary"
        ),
    ),
    Mutation(
        name="judge-reader-start-pipe-close-bypass",
        path="evoom_guard/execution/judge.py",
        before="        safe_to_close = index >= len(stopped) or stopped[index]\n",
        after="        safe_to_close = False\n",
        test=(
            "tests/test_blackbox_judge_reader_start.py::"
            "test_reader_start_failure_cleans_group_handles_pipes_and_preserves_primary"
        ),
    ),
    Mutation(
        name="judge-live-reader-synchronous-close",
        path="evoom_guard/execution/judge.py",
        before=(
            "        if not safe_to_close:\n"
            "            streams_closed = False\n"
            "            continue\n"
        ),
        after=(
            "        if False and not safe_to_close:\n"
            "            streams_closed = False\n"
            "            continue\n"
        ),
        test=(
            "tests/test_blackbox_judge_reader_start.py::"
            "test_live_reader_pipe_is_never_closed_synchronously"
        ),
    ),
    Mutation(
        name="judge-attempted-reader-ident-proof-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        except RuntimeError as exc:\n"
            "            # An interrupted Thread.start() can create the native thread before\n"
            "            # ``ident`` or ``_started`` becomes observable. A failed join is\n"
            "            # never proof that the corresponding pipe is safe to close.\n"
            "            if first_error is None:\n"
            "                first_error = exc\n"
        ),
        after=(
            "        except RuntimeError as exc:\n"
            "            # Mutant: treat missing ident as proof that no native reader exists.\n"
            "            reader_stopped = reader.ident is None\n"
            "            if not reader_stopped and first_error is None:\n"
            "                first_error = exc\n"
        ),
        test=(
            "tests/test_blackbox_judge_reader_start.py::"
            "test_attempted_reader_without_ident_is_not_assumed_safe_to_close"
        ),
    ),
    Mutation(
        name="judge-reader-start-primary-exception-mask",
        path="evoom_guard/execution/judge.py",
        before=(
            "            except BaseException as cleanup_error:\n"
            "                _note_abort_cleanup_failure(\n"
            "                    primary,\n"
            "                    (\n"
            '                        "Judge output-reader abort cleanup raised while preserving "\n'
            '                        "the primary exception: " + _abort_cleanup_exception_summary(cleanup_error)\n'
            "                    ),\n"
            "                )\n"
        ),
        after=(
            "            except BaseException as cleanup_error:\n"
            "                raise cleanup_error\n"
        ),
        test=(
            "tests/test_blackbox_judge_reader_start.py::"
            "test_reader_start_primary_survives_every_cleanup_baseexception"
        ),
    ),
    Mutation(
        name="judge-reader-start-terminator-baseexception-mask",
        path="evoom_guard/execution/judge.py",
        before=(
            "                termination_result: object = "
            "process_group_terminator(process)\n"
            "            except BaseException as cleanup_error:\n"
        ),
        after=(
            "                termination_result: object = "
            "process_group_terminator(process)\n"
            "            except Exception as cleanup_error:\n"
        ),
        test=(
            "tests/test_blackbox_judge_reader_start.py::"
            "test_reader_start_primary_survives_every_cleanup_baseexception"
        ),
    ),
    Mutation(
        name="judge-abort-reader-cleanup-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "                reader_cleanup_result = "
            "pipe_join(reader_start_attempts, streams)\n"
        ),
        after="                reader_cleanup_result = True\n",
        test=(
            "tests/test_judge_abort_cleanup_observability.py::"
            "test_abort_cleanup_characterization_preserves_primary_and_attempt_order"
        ),
    ),
    Mutation(
        name="judge-abort-terminator-exact-proof-bypass",
        path="evoom_guard/execution/judge.py",
        before="                if termination_result is not None:\n",
        after="                if termination_result:\n",
        test=(
            "tests/test_judge_abort_cleanup_observability.py::"
            "test_abort_cleanup_requires_owner_specific_positive_proof"
            "[terminator-false]"
        ),
    ),
    Mutation(
        name="judge-abort-reader-exact-proof-bypass",
        path="evoom_guard/execution/judge.py",
        before="                if reader_cleanup_result is not True:\n",
        after="                if not reader_cleanup_result:\n",
        test=(
            "tests/test_judge_abort_cleanup_observability.py::"
            "test_abort_cleanup_requires_owner_specific_positive_proof"
            "[reader-truthy-non-bool]"
        ),
    ),
    Mutation(
        name="judge-abort-terminator-raised-observability-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "            except BaseException as cleanup_error:\n"
            "                _note_abort_cleanup_failure(\n"
            "                    primary,\n"
            "                    (\n"
            '                        "Judge process-group abort cleanup raised while preserving "\n'
            '                        "the primary exception: " + _abort_cleanup_exception_summary(cleanup_error)\n'
            "                    ),\n"
            "                )\n"
        ),
        after=(
            "            except BaseException as cleanup_error:\n"
            "                pass\n"
        ),
        test=(
            "tests/test_judge_abort_cleanup_observability.py::"
            "test_abort_cleanup_preserves_ordered_raised_and_false_diagnostics"
        ),
    ),
    Mutation(
        name="judge-abort-reader-raised-observability-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "            except BaseException as cleanup_error:\n"
            "                _note_abort_cleanup_failure(\n"
            "                    primary,\n"
            "                    (\n"
            '                        "Judge output-reader abort cleanup raised while preserving "\n'
            '                        "the primary exception: " + _abort_cleanup_exception_summary(cleanup_error)\n'
            "                    ),\n"
            "                )\n"
        ),
        after=(
            "            except BaseException as cleanup_error:\n"
            "                pass\n"
        ),
        test=(
            "tests/test_judge_abort_cleanup_observability.py::"
            "test_abort_cleanup_requires_owner_specific_positive_proof"
            "[reader-raised]"
        ),
    ),
    Mutation(
        name="judge-abort-bare-reraise-bypass",
        path="evoom_guard/execution/judge.py",
        before="        raise\n\n\n__all__ = [\n",
        after="        raise primary\n\n\n__all__ = [\n",
        test=(
            "tests/test_judge_abort_cleanup_observability.py::"
            "test_abort_cleanup_characterization_preserves_primary_and_attempt_order"
        ),
    ),
    Mutation(
        name="judge-start-new-session-bypass",
        path="evoom_guard/execution/judge.py",
        before="            start_new_session=True,\n",
        after="            start_new_session=False,\n",
        test=(
            "tests/test_blackbox_judge_mutation_contract.py::"
            "test_judge_popen_starts_a_dedicated_session"
        ),
    ),
    Mutation(
        name="judge-timeout-cleanup-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "            if monotonic() >= deadline:\n"
            "                cleanup_and_prove(\"judge timed out\")\n"
            "                raise subprocess.TimeoutExpired(\n"
        ),
        after=(
            "            if False and monotonic() >= deadline:\n"
            "                cleanup_and_prove(\"judge timed out\")\n"
            "                raise subprocess.TimeoutExpired(\n"
        ),
        test=(
            "tests/test_blackbox_judge_mutation_contract.py::"
            "test_judge_timeout_is_not_bypassed_before_process_cleanup"
        ),
    ),
    Mutation(
        name="judge-post-completion-group-proof-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        cleanup_and_prove(\"judge completed\")\n"
            "        return JudgeProcessResult(\n"
        ),
        after="        return JudgeProcessResult(\n",
        test=(
            "tests/test_blackbox_judge_mutation_contract.py::"
            "test_completed_judge_still_proves_process_group_cleanup"
        ),
    ),
    Mutation(
        name="judge-live-output-checkpoint-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        while process.poll() is None:\n"
            "            if capture.exceeded:\n"
            "                cleanup_and_prove(\"judge output limit reached\")\n"
        ),
        after=(
            "        while process.poll() is None:\n"
            "            if False and capture.exceeded:\n"
            "                cleanup_and_prove(\"judge output limit reached\")\n"
        ),
        test=(
            "tests/test_blackbox_judge_mutation_contract.py::"
            "test_live_output_checkpoint_runs_before_the_next_poll"
        ),
    ),
    Mutation(
        name="judge-post-poll-output-checkpoint-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        if capture.exceeded:\n"
            "            cleanup_and_prove(\"judge output limit reached\")\n"
            "            raise JudgeOutputLimitError(capture.limit)\n"
            "        if not pipe_join(readers, streams):\n"
        ),
        after=(
            "        if False and capture.exceeded:\n"
            "            cleanup_and_prove(\"judge output limit reached\")\n"
            "            raise JudgeOutputLimitError(capture.limit)\n"
            "        if not pipe_join(readers, streams):\n"
        ),
        test=(
            "tests/test_blackbox_judge_mutation_contract.py::"
            "test_post_poll_output_checkpoint_precedes_normal_reader_join"
        ),
    ),
    Mutation(
        name="judge-post-join-output-checkpoint-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        if capture.exceeded:\n"
            "            cleanup_and_prove(\"judge output limit reached\")\n"
            "            raise JudgeOutputLimitError(capture.limit)\n"
            "        cleanup_and_prove(\"judge completed\")\n"
        ),
        after=(
            "        if False and capture.exceeded:\n"
            "            cleanup_and_prove(\"judge output limit reached\")\n"
            "            raise JudgeOutputLimitError(capture.limit)\n"
            "        cleanup_and_prove(\"judge completed\")\n"
        ),
        test=(
            "tests/test_blackbox_judge_mutation_contract.py::"
            "test_post_join_output_checkpoint_cannot_return_success"
        ),
    ),
    Mutation(
        name="judge-reader-join-failure-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        if not pipe_join(readers, streams):\n"
            "            cleanup_and_prove(\"judge exited with live output pipes\")\n"
            "            raise JudgeProcessCleanupError(\n"
            "                \"judge exited but its output pipes did not close\"\n"
            "            )\n"
        ),
        after=(
            "        pipe_join(readers, streams)\n"
        ),
        test=(
            "tests/test_blackbox_judge_mutation_contract.py::"
            "test_reader_join_failure_cannot_be_returned_as_success"
        ),
    ),
    Mutation(
        name="judge-runtime-baseexception-precedence-bypass",
        path="evoom_guard/execution/judge.py",
        before="        raise\n\n\n__all__ = [\n",
        after=(
            "        raise JudgeProcessCleanupError(\"mutant masked primary\")\n"
            "\n"
            "\n"
            "__all__ = [\n"
        ),
        test=(
            "tests/test_blackbox_judge_mutation_contract.py::"
            "test_runtime_baseexception_remains_primary_after_cleanup_failures"
        ),
    ),
    Mutation(
        name="docker-absence-daemon-failure-bypass",
        path="evoom_guard/isolation/docker.py",
        before=(
            "            absent=None,\n"
            "            query=listed,\n"
            '            error="docker_query_failed",\n'
        ),
        after=(
            "            absent=True,\n"
            "            query=listed,\n"
            '            error="docker_query_failed",\n'
        ),
        test=(
            "tests/test_isolation_docker.py::"
            "test_kernel_absence_query_rejects_daemon_failure"
        ),
    ),
    Mutation(
        name="docker-absence-present-name-bypass",
        path="evoom_guard/isolation/docker.py",
        before="        absent=name not in listed.stdout.splitlines(),\n",
        after="        absent=True,\n",
        test=(
            "tests/test_isolation_docker.py::"
            "test_kernel_absence_query_requires_success_and_exact_name"
        ),
    ),
    Mutation(
        name="docker-absence-stopped-container-bypass",
        path="evoom_guard/isolation/docker.py",
        before='                "--all",\n                "--filter",\n',
        after='                "--filter",\n',
        test=(
            "tests/test_isolation_docker.py::"
            "test_kernel_absence_query_requires_success_and_exact_name"
        ),
    ),
    Mutation(
        name="docker-absence-name-validation-bypass",
        path="evoom_guard/isolation/docker.py",
        before=(
            "    return _DOCKER_CONTAINER_NAME.fullmatch(name) is not None\n"
        ),
        after="    return True\n",
        test=(
            "tests/test_isolation_docker.py::"
            "test_kernel_absence_query_rejects_invalid_name_without_docker"
        ),
    ),
    Mutation(
        name="docker-absence-stability-streak-bypass",
        path="evoom_guard/isolation/docker.py",
        before=(
            "    proven = (\n"
            "        final_absent_observations\n"
            "        >= required_final_absent_observations\n"
            "    )\n"
        ),
        after="    proven = final_absent_observations > 0\n",
        test=(
            "tests/test_isolation_docker.py::"
            "test_kernel_cleanup_rejects_absence_not_stable_at_window_end"
        ),
    ),
    Mutation(
        name="docker-cleanup-total-budget-bypass",
        path="evoom_guard/isolation/docker.py",
        before="        return min(control_timeout, remaining)\n",
        after="        return control_timeout\n",
        test=(
            "tests/test_isolation_docker.py::"
            "test_kernel_cleanup_uses_decreasing_single_total_budget"
        ),
    ),
    Mutation(
        name="docker-cleanup-unverifiable-retry-bypass",
        path="evoom_guard/isolation/docker.py",
        before="        if not observation.observed:\n",
        after="        if False and not observation.observed:\n",
        test=(
            "tests/test_isolation_docker.py::"
            "test_kernel_cleanup_stops_immediately_when_absence_is_unverifiable"
        ),
    ),
    Mutation(
        name="docker-cleanup-baseexception-primary-mask",
        path="evoom_guard/isolation/docker.py",
        before="        except BaseException as cleanup_error:\n",
        after="        except Exception as cleanup_error:\n",
        test=(
            "tests/test_docker_containment.py::"
            "test_docker_cleanup_baseexception_cannot_mask_unexpected_primary"
        ),
    ),
    Mutation(
        name="docker-unproven-cleanup-note-bypass",
        path="evoom_guard/isolation/docker.py",
        before=(
            "        else:\n"
            "            if not cleanup_proven:\n"
            "                _note_secondary_cleanup_failure(\n"
        ),
        after=(
            "        else:\n"
            "            if False and not cleanup_proven:\n"
            "                _note_secondary_cleanup_failure(\n"
        ),
        test=(
            "tests/test_docker_containment.py::"
            "test_unproven_docker_cleanup_is_not_hidden_by_unexpected_primary"
        ),
    ),
    Mutation(
        name="repo-workspace-cleanup-error-hiding",
        path="evoom_guard/workspace/repository.py",
        before=(
            "    while True:\n"
            "        try:\n"
            "            remove_tree(path)\n"
            "            break\n"
        ),
        after=(
            "    while True:\n"
            "        try:\n"
            "            try:\n"
            "                remove_tree(path)\n"
            "            except BaseException:\n"
            "                return\n"
            "            break\n"
        ),
        test=(
            "tests/test_repo_verifier_cleanup_priority.py::"
            "test_workspace_cleanup_failure_is_visible_after_pending_result"
        ),
    ),
    Mutation(
        name="repo-workspace-cleanup-primary-mask",
        path="evoom_guard/verifiers/repo_verifier.py",
        before="                primary=cleanup_primary,\n",
        after="                primary=None,\n",
        test=(
            "tests/test_repo_verifier_cleanup_priority.py::"
            "test_workspace_cleanup_baseexception_cannot_mask_primary"
        ),
    ),
    Mutation(
        name="repo-workspace-caller-ambient-primary-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before="                primary=cleanup_primary,\n",
        after="                primary=sys.exc_info()[1],\n",
        test=(
            "tests/test_repo_verifier_cleanup_priority.py::"
            "test_workspace_cleanup_ignores_callers_ambient_exception"
        ),
    ),
    Mutation(
        name="repo-cleanup-effect-primary-forwarding-bypass",
        path="evoom_guard/verifiers/repo_cleanup.py",
        before="        primary=request.primary,\n",
        after="        primary=None,\n",
        test=(
            "tests/test_repo_cleanup_characterization.py::"
            "test_frozen_repo_cleanup_behavior"
            "[primary_baseexception_multiple_failures]"
        ),
    ),
    Mutation(
        name="finalizer-git-env-scrub-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before='        if not key.upper().startswith("GIT_")\n',
        after="        if True\n",
        test=(
            "tests/test_finalizer_derivation.py::"
            "test_raw_git_command_scrubs_all_ambient_git_environment"
        ),
    ),
    Mutation(
        name="finalizer-git-no-replace-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before='    command = [executable, "--no-replace-objects"]\n',
        after='    command = [executable]\n',
        test=(
            "tests/test_finalizer_derivation.py::"
            "test_raw_git_reader_ignores_replace_refs"
        ),
    ),
    Mutation(
        name="finalizer-git-tree-cleanup-proof-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before="    return terminate_process_tree(process, _GIT_PROCESS_LIMITS)\n",
        after="    return True\n",
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_timeout_reports_unproven_cleanup_without_unbounded_wait"
        ),
    ),
    Mutation(
        name="finalizer-git-process-group-launch-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before="                **process_group_popen_kwargs(),\n",
        after="                **{},\n",
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_git_launch_applies_the_managed_process_group_contract"
        ),
    ),
    Mutation(
        name="finalizer-git-reader-join-bound-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "            reader.join(min(_GIT_READER_JOIN_SECONDS, remaining))\n"
        ),
        after="            reader.join()\n",
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_git_bytes_remain_exact_and_reader_joins_are_bounded"
        ),
    ),
    Mutation(
        name="finalizer-git-reader-join-cap-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "            reader.join(min(_GIT_READER_JOIN_SECONDS, remaining))\n"
        ),
        after="            reader.join(remaining)\n",
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_reader_join_clamps_floating_point_deadline_overshoot"
        ),
    ),
    Mutation(
        name="finalizer-git-live-reader-close-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before="        safe_to_close = index >= len(stopped) or stopped[index]\n",
        after="        safe_to_close = True\n",
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_live_reader_stream_is_never_closed_synchronously"
        ),
    ),
    Mutation(
        name="finalizer-git-reader-start-tracking-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "            reader_start_attempts.append(reader)\n"
            "            reader.start()\n"
        ),
        after="            reader.start()\n",
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_reader_start_failure_kills_and_reaps_git_without_masking_primary"
        ),
    ),
    Mutation(
        name="finalizer-git-overflow-state-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "                        overflow.add(label)\n"
            "                        reader_signal.set()\n"
        ),
        after="                        reader_signal.set()\n",
        test=(
            "tests/test_finalizer_derivation.py::"
            "test_raw_git_command_bounds_pipes_while_the_child_is_running"
        ),
    ),
    Mutation(
        name="finalizer-git-reader-error-record-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "                read_errors.append(exc)\n"
            "                reader_signal.set()\n"
        ),
        after="                reader_signal.set()\n",
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_worker_read_failure_cannot_return_partial_git_output"
        ),
    ),
    Mutation(
        name="finalizer-git-reader-baseexception-narrowing",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "            except BaseException as exc:\n"
            "                read_errors.append(exc)\n"
        ),
        after=(
            "            except Exception as exc:\n"
            "                read_errors.append(exc)\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_worker_read_failure_cannot_return_partial_git_output"
        ),
    ),
    Mutation(
        name="finalizer-git-live-reader-error-cleanup-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "        interrupted = timed_out or bool(read_errors) or bool(overflow)\n"
        ),
        after="        interrupted = timed_out or bool(overflow)\n",
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_worker_read_failure_stops_a_still_live_git_child"
        ),
    ),
    Mutation(
        name="finalizer-git-interrupt-cleanup-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "        if interrupted:\n"
            "            if _terminate_git_process_tree(process) is not True:\n"
        ),
        after=(
            "        if interrupted:\n"
            "            if False and "
            "_terminate_git_process_tree(process) is not True:\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_timeout_uses_bounded_kill_reap_and_reader_join"
        ),
    ),
    Mutation(
        name="finalizer-git-interrupt-exact-proof-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "        if interrupted:\n"
            "            if _terminate_git_process_tree(process) is not True:\n"
        ),
        after=(
            "        if interrupted:\n"
            "            if not _terminate_git_process_tree(process):\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_interrupted_query_rejects_truthy_non_bool_cleanup_proof"
        ),
    ),
    Mutation(
        name="finalizer-git-posix-post-completion-proof-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            '            if os.name == "posix":\n'
            "                if _terminate_git_process_tree(process) is not True:\n"
        ),
        after=(
            '            if False and os.name == "posix":\n'
            "                if _terminate_git_process_tree(process) is not True:\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_posix_success_proves_post_completion_group_cleanup"
        ),
    ),
    Mutation(
        name="finalizer-git-posix-exact-proof-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            '            if os.name == "posix":\n'
            "                if _terminate_git_process_tree(process) is not True:\n"
        ),
        after=(
            '            if os.name == "posix":\n'
            "                if not _terminate_git_process_tree(process):\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_posix_completion_rejects_truthy_non_bool_cleanup_proof"
        ),
    ),
    Mutation(
        name="finalizer-git-post-poll-silent-cleanup-restore",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "            process.wait(timeout=_GIT_KILL_REAP_SECONDS)\n"
            '            if os.name == "posix":\n'
        ),
        after=(
            "            try:\n"
            "                process.wait(timeout=_GIT_KILL_REAP_SECONDS)\n"
            "            except BaseException:\n"
            "                try:\n"
            "                    _terminate_git_process_tree(process)\n"
            "                except BaseException:\n"
            "                    pass\n"
            "                raise\n"
            '            if os.name == "posix":\n'
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_post_poll_abort_does_not_hide_the_first_tree_cleanup_failure"
        ),
    ),
    Mutation(
        name="finalizer-git-abort-primary-reraise",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "                        )\n"
            "        raise\n"
            "\n\n"
            "def _git_command(\n"
        ),
        after=(
            "                        )\n"
            "        raise primary\n"
            "\n\n"
            "def _git_command(\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_raw_git_abort_cleanup_preserves_primary_and_runs_both_stages"
        ),
    ),
    Mutation(
        name="finalizer-git-reader-join-primary-suppression",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "    if first_error is not None:\n"
            "        raise first_error\n"
        ),
        after=(
            "    if False and first_error is not None:\n"
            "        raise first_error\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_reader_join_baseexception_remains_authoritative"
        ),
    ),
    Mutation(
        name="finalizer-git-abort-cleanup-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "    except BaseException as primary:\n"
            "        # Preserve the exact active exception while independently attempting\n"
        ),
        after=(
            "    except Exception as primary:\n"
            "        # Preserve the exact active exception while independently attempting\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_reader_start_failure_kills_and_reaps_git_without_masking_primary"
        ),
    ),
    Mutation(
        name="finalizer-git-abort-tree-exact-proof-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before="                    if tree_cleanup_result is True:\n",
        after="                    if tree_cleanup_result:\n",
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_raw_git_abort_cleanup_single_outcomes_are_observable"
        ),
    ),
    Mutation(
        name="finalizer-git-abort-tree-raised-observability-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "                except BaseException as cleanup_error:\n"
            "                    note_abort_cleanup_failure(\n"
            "                        primary,\n"
            '                        "Raw-Git finalizer process-tree abort cleanup raised while "\n'
            '                        "preserving the primary exception: "\n'
            "                        + abort_cleanup_exception_summary(cleanup_error),\n"
            "                    )\n"
        ),
        after=(
            "                except BaseException as cleanup_error:\n"
            "                    pass\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_raw_git_abort_cleanup_single_outcomes_are_observable"
        ),
    ),
    Mutation(
        name="finalizer-git-abort-tree-false-observability-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "                    else:\n"
            "                        note_abort_cleanup_failure(\n"
            "                            primary,\n"
            '                            "Raw-Git finalizer process-tree abort cleanup was not "\n'
            '                            "proven while preserving the primary exception",\n'
            "                        )\n"
        ),
        after=(
            "                    else:\n"
            "                        pass\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_raw_git_abort_cleanup_single_outcomes_are_observable"
        ),
    ),
    Mutation(
        name="finalizer-git-abort-reader-exact-proof-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before="                    if reader_cleanup_result is True:\n",
        after="                    if reader_cleanup_result:\n",
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_raw_git_abort_cleanup_single_outcomes_are_observable"
        ),
    ),
    Mutation(
        name="finalizer-git-abort-reader-raised-observability-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "                except BaseException as cleanup_error:\n"
            "                    note_abort_cleanup_failure(\n"
            "                        primary,\n"
            '                        "Raw-Git finalizer output-reader abort cleanup raised while "\n'
            '                        "preserving the primary exception: "\n'
            "                        + abort_cleanup_exception_summary(cleanup_error),\n"
            "                    )\n"
        ),
        after=(
            "                except BaseException as cleanup_error:\n"
            "                    pass\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_raw_git_abort_cleanup_single_outcomes_are_observable"
        ),
    ),
    Mutation(
        name="finalizer-git-abort-reader-false-observability-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "                    else:\n"
            "                        note_abort_cleanup_failure(\n"
            "                            primary,\n"
            '                            "Raw-Git finalizer output-reader abort cleanup was not "\n'
            '                            "proven while preserving the primary exception",\n'
            "                        )\n"
        ),
        after=(
            "                    else:\n"
            "                        pass\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_raw_git_abort_cleanup_single_outcomes_are_observable"
        ),
    ),
    Mutation(
        name="finalizer-git-abort-second-cleanup-stage-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before="            if readers_closed is not True:\n",
        after=(
            "            if cleanup_proven is True and readers_closed is not True:\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_raw_git_abort_cleanup_retains_two_ordered_bounded_failures"
        ),
    ),
    Mutation(
        name="github-attestation-tree-cleanup-proof-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "    return terminate_process_tree("
            "process, _GITHUB_ATTESTATION_PROCESS_LIMITS)\n"
        ),
        after="    return True\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_unproven_tree_cleanup_fails_closed"
        ),
    ),
    Mutation(
        name="github-attestation-process-group-launch-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "            launch_kwargs: dict[str, object] = "
            "dict(process_group_popen_kwargs())\n"
        ),
        after="            launch_kwargs: dict[str, object] = {}\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_launch_uses_managed_group_and_preserves_exact_raw_bytes"
        ),
    ),
    Mutation(
        name="github-attestation-reader-join-bound-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "            reader.join(max(0.0, deadline - time.monotonic()))\n"
        ),
        after="            reader.join()\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_launch_uses_managed_group_and_preserves_exact_raw_bytes"
        ),
    ),
    Mutation(
        name="github-attestation-reader-total-budget-reset",
        path="evoom_guard/github_attestation.py",
        before=(
            "    deadline = time.monotonic() + "
            "_GITHUB_ATTESTATION_READER_JOIN_SECONDS\n"
            "    for reader in readers:\n"
        ),
        after=(
            "    for reader in readers:\n"
            "        deadline = time.monotonic() + "
            "_GITHUB_ATTESTATION_READER_JOIN_SECONDS\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_reader_joins_share_one_total_budget"
        ),
    ),
    Mutation(
        name="github-attestation-poll-wait-bound-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "            reader_signal.wait("
            "min(_GITHUB_ATTESTATION_PROCESS_POLL_SECONDS, remaining))\n"
        ),
        after="            reader_signal.wait()\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_process_poll_wait_is_bounded_and_wakes_for_recheck"
        ),
    ),
    Mutation(
        name="github-attestation-live-reader-close-bypass",
        path="evoom_guard/github_attestation.py",
        before="        safe_to_close = index >= len(stopped) or stopped[index]\n",
        after="        safe_to_close = True\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_live_reader_stream_is_never_closed_synchronously"
        ),
    ),
    Mutation(
        name="github-attestation-stream-close-proof-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "        except (OSError, ValueError):\n"
            "            streams_closed = False\n"
        ),
        after=(
            "        except (OSError, ValueError):\n"
            "            streams_closed = True\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_stream_close_failure_cannot_be_a_successful_cleanup_proof"
        ),
    ),
    Mutation(
        name="github-attestation-stream-close-primary-suppression",
        path="evoom_guard/github_attestation.py",
        before=(
            "        except BaseException as exc:\n"
            "            streams_closed = False\n"
            "            if first_error is None:\n"
            "                first_error = exc\n"
        ),
        after=(
            "        except BaseException as exc:\n"
            "            streams_closed = False\n"
            "            if False and first_error is None:\n"
            "                first_error = exc\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_stream_close_baseexception_remains_authoritative"
        ),
    ),
    Mutation(
        name="github-attestation-unattempted-reader-pipe-close-bypass",
        path="evoom_guard/github_attestation.py",
        before="        safe_to_close = index >= len(stopped) or stopped[index]\n",
        after=(
            "        safe_to_close = index < len(stopped) and stopped[index]\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_reader_start_failure_cleans_child_without_masking_primary"
        ),
    ),
    Mutation(
        name="github-attestation-reader-start-tracking-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "            reader_start_attempts.append(reader)\n"
            "            reader.start()\n"
        ),
        after="            reader.start()\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_reader_start_failure_cleans_child_without_masking_primary"
        ),
    ),
    Mutation(
        name="github-attestation-overflow-state-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "                        overflow.add(label)\n"
            "                        reader_signal.set()\n"
        ),
        after="                        reader_signal.set()\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_stdout_and_stderr_limits_are_independent_and_fail_closed"
        ),
    ),
    Mutation(
        name="github-attestation-reader-error-record-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "                read_errors.append(exc)\n"
            "                reader_signal.set()\n"
        ),
        after="                reader_signal.set()\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_worker_failure_cannot_accept_plausible_partial_json"
        ),
    ),
    Mutation(
        name="github-attestation-reader-baseexception-narrowing",
        path="evoom_guard/github_attestation.py",
        before=(
            "            except BaseException as exc:\n"
            "                read_errors.append(exc)\n"
        ),
        after=(
            "            except Exception as exc:\n"
            "                read_errors.append(exc)\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_worker_failure_cannot_accept_plausible_partial_json"
        ),
    ),
    Mutation(
        name="github-attestation-live-reader-error-cleanup-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "        interrupted = timed_out or bool(read_errors) or bool(overflow)\n"
        ),
        after="        interrupted = timed_out or bool(overflow)\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_worker_failure_stops_a_still_live_child"
        ),
    ),
    Mutation(
        name="github-attestation-interrupt-cleanup-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "            if not root_exited_on_windows:\n"
            "                if _terminate_gh_process_tree(process) is not True:\n"
        ),
        after=(
            "            if not root_exited_on_windows:\n"
            "                if False and _terminate_gh_process_tree(process) is not True:\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_timeout_uses_tree_cleanup_and_independent_reader_budget"
        ),
    ),
    Mutation(
        name="github-attestation-windows-departed-root-reason-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            '            root_exited_on_windows = os.name == "nt" and '
            "process.poll() is not None\n"
        ),
        after="            root_exited_on_windows = False\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_windows_departed_root_preserves_original_failure_without_tree_claim"
        ),
    ),
    Mutation(
        name="github-attestation-windows-cleanup-race-recheck-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "                    root_exited_on_windows = (\n"
            "                        os.name == \"nt\" and process.poll() is not None\n"
            "                    )\n"
        ),
        after="                    root_exited_on_windows = False\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_windows_root_exit_during_cleanup_preserves_original_failure"
        ),
    ),
    Mutation(
        name="github-attestation-deadline-check-bypass",
        path="evoom_guard/github_attestation.py",
        before="            if remaining <= 0:\n",
        after="            if False and remaining <= 0:\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_windows_departed_root_preserves_original_failure_without_tree_claim"
        ),
    ),
    Mutation(
        name="github-attestation-posix-post-completion-proof-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "            if os.name == \"posix\":\n"
            "                if _terminate_gh_process_tree(process) is not True:\n"
        ),
        after=(
            "            if False and os.name == \"posix\":\n"
            "                if _terminate_gh_process_tree(process) is not True:\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_posix_success_proves_post_completion_group_cleanup"
        ),
    ),
    Mutation(
        name="github-attestation-post-poll-primary-suppression",
        path="evoom_guard/github_attestation.py",
        before=(
            "                raise\n"
            "            if os.name == \"posix\":\n"
        ),
        after=(
            "                pass\n"
            "            if os.name == \"posix\":\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_post_poll_wait_baseexception_remains_authoritative"
        ),
    ),
    Mutation(
        name="github-attestation-reader-join-primary-suppression",
        path="evoom_guard/github_attestation.py",
        before=(
            "    if first_error is not None:\n"
            "        raise first_error\n"
        ),
        after=(
            "    if False and first_error is not None:\n"
            "        raise first_error\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_reader_join_baseexception_remains_authoritative_and_stream_stays_open"
        ),
    ),
    Mutation(
        name="github-attestation-abort-cleanup-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "    except BaseException as primary:\n"
            "        # Preserve the exact active exception while independently attempting\n"
        ),
        after=(
            "    except Exception as primary:\n"
            "        # Preserve the exact active exception while independently attempting\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_reader_start_failure_cleans_child_without_masking_primary"
        ),
    ),
    Mutation(
        name="github-attestation-abort-reader-cleanup-independence-bypass",
        path="evoom_guard/github_attestation.py",
        before="            if readers_closed is not True:\n",
        after="            if False and readers_closed is not True:\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_abort_cleanup_reports_both_stages_in_order_and_preserves_primary"
            "[raised-results]"
        ),
    ),
    Mutation(
        name="github-attestation-initial-abort-tree-exact-proof-bypass",
        path="evoom_guard/github_attestation.py",
        before="                    if initial_tree_cleanup_result is True:\n",
        after="                    if initial_tree_cleanup_result:\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_post_poll_truthy_cleanup_result_is_not_positive_proof"
        ),
    ),
    Mutation(
        name="github-attestation-initial-abort-tree-raised-diagnostic-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "                except BaseException as cleanup_error:\n"
            "                    note_abort_cleanup_failure(\n"
            "                        primary,\n"
            "                        \"GitHub attestation subprocess-tree abort cleanup raised before \"\n"
            "                        \"retry while preserving the primary exception: \"\n"
            "                        + abort_cleanup_exception_summary(cleanup_error),\n"
            "                    )\n"
        ),
        after="                except BaseException as cleanup_error:\n                    pass\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_post_poll_raised_then_success_retains_first_failure_evidence"
        ),
    ),
    Mutation(
        name="github-attestation-initial-abort-tree-false-diagnostic-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "                    else:\n"
            "                        note_abort_cleanup_failure(\n"
            "                            primary,\n"
            "                            \"GitHub attestation subprocess-tree abort cleanup was not \"\n"
            "                            \"proven before retry while preserving the primary exception\",\n"
            "                        )\n"
        ),
        after="                    else:\n                        pass\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_post_poll_false_then_success_retains_first_failure_evidence"
        ),
    ),
    Mutation(
        name="github-attestation-abort-tree-exact-proof-bypass",
        path="evoom_guard/github_attestation.py",
        before="                    if tree_cleanup_result is True:\n",
        after="                    if tree_cleanup_result:\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_abort_cleanup_reports_both_stages_in_order_and_preserves_primary"
            "[truthy-non-proofs]"
        ),
    ),
    Mutation(
        name="github-attestation-abort-reader-exact-proof-bypass",
        path="evoom_guard/github_attestation.py",
        before="                    if reader_cleanup_result is True:\n",
        after="                    if reader_cleanup_result:\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_abort_cleanup_reports_both_stages_in_order_and_preserves_primary"
            "[truthy-non-proofs]"
        ),
    ),
    Mutation(
        name="github-attestation-abort-tree-raised-diagnostic-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "                except BaseException as cleanup_error:\n"
            "                    note_abort_cleanup_failure(\n"
            "                        primary,\n"
            "                        \"GitHub attestation subprocess-tree abort cleanup raised while \"\n"
            "                        \"preserving the primary exception: \"\n"
            "                        + abort_cleanup_exception_summary(cleanup_error),\n"
            "                    )\n"
        ),
        after="                except BaseException as cleanup_error:\n                    pass\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_abort_cleanup_reports_both_stages_in_order_and_preserves_primary"
            "[raised-results]"
        ),
    ),
    Mutation(
        name="github-attestation-abort-reader-false-diagnostic-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "                    else:\n"
            "                        note_abort_cleanup_failure(\n"
            "                            primary,\n"
            "                            \"GitHub attestation output-reader abort cleanup was not \"\n"
            "                            \"proven while preserving the primary exception\",\n"
            "                        )\n"
        ),
        after="                    else:\n                        pass\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_abort_cleanup_reports_both_stages_in_order_and_preserves_primary"
            "[false-results]"
        ),
    ),
    Mutation(
        name="github-attestation-abort-primary-precedence-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "        raise\n"
            "\n"
            "\n"
            "def _run_gh_attestation_verify_target(\n"
        ),
        after=(
            "        raise GitHubAttestationError(\"mutant masked primary\")\n"
            "\n"
            "\n"
            "def _run_gh_attestation_verify_target(\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_abort_cleanup_reports_both_stages_in_order_and_preserves_primary"
            "[raised-results]"
        ),
    ),
    Mutation(
        name="harness-input-candidate-preflight-branch-bypass",
        path="evoom_guard/verifiers/candidate_preflight.py",
        before=(
            "        if candidate_path_targets_harness_input(\n"
            "            request.repo_path,\n"
            "            path,\n"
            "            harness_inputs,\n"
            "        ):\n"
            "            return True\n"
        ),
        after=(
            "        if False and candidate_path_targets_harness_input(\n"
            "            request.repo_path,\n"
            "            path,\n"
            "            harness_inputs,\n"
            "        ):\n"
            "            return True\n"
        ),
        test=(
            "tests/test_harness_input_mutation_contract.py::"
            "test_candidate_preflight_makes_declared_harness_inputs_non_exemptible"
        ),
    ),
    Mutation(
        name="harness-input-repo-candidate-forwarding-bypass",
        path="evoom_guard/verifiers/repo_candidate.py",
        before=(
            "    rejection = services.reject_paths()(\n"
            "        changed,\n"
            "        extra,\n"
            "        harness_inputs=harness_inputs,\n"
        ),
        after=(
            "    rejection = services.reject_paths()(\n"
            "        changed,\n"
            "        extra,\n"
            "        harness_inputs=(),\n"
        ),
        test=(
            "tests/test_harness_input_mutation_contract.py::"
            "test_repo_candidate_forwards_harness_inputs_to_changed_path_policy"
        ),
    ),
    Mutation(
        name="harness-input-repo-candidate-deletion-forwarding-bypass",
        path="evoom_guard/verifiers/repo_candidate.py",
        before=(
            "        deletion_rejection = services.reject_paths()(\n"
            "            deleted_paths,\n"
            "            extra,\n"
            "            harness_inputs=harness_inputs,\n"
        ),
        after=(
            "        deletion_rejection = services.reject_paths()(\n"
            "            deleted_paths,\n"
            "            extra,\n"
            "            harness_inputs=(),\n"
        ),
        test=(
            "tests/test_harness_input_mutation_contract.py::"
            "test_repo_candidate_forwards_harness_inputs_to_deletion_policy"
        ),
    ),
    Mutation(
        name="harness-input-setup-output-ancestor-bypass",
        path="evoom_guard/domain/harness.py",
        before=(
            "                for end in range(1, len(path.split(\"/\")) + 1)\n"
        ),
        after="                for end in (len(path.split(\"/\")),)\n",
        test=(
            "tests/test_harness_input_mutation_contract.py::"
            "test_setup_output_conflict_includes_declared_input_ancestors"
        ),
    ),
    Mutation(
        name="harness-input-post-suite-checkpoint-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "            harness_failure = verify_harness_checkpoint(\n"
            '                "after the repository suite",\n'
            "                setup_isolation=setup_isolation,\n"
            "            )\n"
        ),
        after="            harness_failure = None\n",
        test=(
            "tests/test_harness_inputs.py::"
            "test_runtime_mutation_of_declared_helper_is_reported_as_tampering"
        ),
    ),
    Mutation(
        name="harness-input-windows-namespace-path-bypass",
        path="evoom_guard/domain/harness.py",
        before=(
            "        part not in {\"\", \".\", \"..\"}\n"
            "        and not is_windows_ambiguous_path_segment(part)\n"
        ),
        after=(
            "        part not in {\"\", \".\", \"..\"}\n"
            "        and True\n"
        ),
        test=(
            "tests/test_harness_input_mutation_contract.py::"
            "test_portable_path_rejects_windows_namespace_alias_spellings"
        ),
    ),
    Mutation(
        name="harness-input-ancestor-conflict-bypass",
        path="evoom_guard/domain/harness.py",
        before=(
            "        candidate == root.casefold()\n"
            "        or root.casefold().startswith(candidate + \"/\")\n"
        ),
        after=(
            "        candidate == root.casefold()\n"
            "        or False\n"
        ),
        test=(
            "tests/test_harness_input_mutation_contract.py::"
            "test_declared_harness_input_ancestor_is_a_path_conflict"
        ),
    ),
    Mutation(
        name="harness-input-filesystem-alias-identity-bypass",
        path="evoom_guard/verifiers/harness_policy.py",
        before=(
            "                if os.path.samefile(candidate_path, trusted_path):\n"
            "                    return True\n"
        ),
        after=(
            "                if False and os.path.samefile("
            "candidate_path, trusted_path):\n"
            "                    return True\n"
        ),
        test=(
            "tests/test_harness_input_mutation_contract.py::"
            "test_filesystem_alias_identity_is_a_path_conflict"
        ),
    ),
    Mutation(
        name="harness-input-trusted-pre-materialization-baseline-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "            candidate_harness_changes = harness_input_snapshot_changes(\n"
            "                trusted_harness_baseline,\n"
            "                candidate_harness_snapshot,\n"
            "            )\n"
        ),
        after=(
            "            candidate_harness_changes = harness_input_snapshot_changes(\n"
            "                candidate_harness_snapshot,\n"
            "                candidate_harness_snapshot,\n"
            "            )\n"
        ),
        test=(
            "tests/test_harness_inputs.py::"
            "test_trusted_harness_snapshot_precedes_candidate_materialization"
        ),
    ),
    Mutation(
        name="blackbox-harness-trusted-baseline-capture-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "                trusted_harness_baseline = "
            "capture_harness_input_snapshot(\n"
            "                    repo_path,\n"
            "                    harness_inputs,\n"
            "                )\n"
        ),
        after="                trusted_harness_baseline = None\n",
        test=(
            "tests/test_harness_input_mutation_contract.py::"
            "test_blackbox_compares_materialized_copy_with_trusted_source_snapshot"
        ),
    ),
    Mutation(
        name="blackbox-harness-materialization-comparison-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "            materialization_changes = harness_input_snapshot_changes(\n"
            "                trusted_harness_baseline,\n"
            "                candidate_harness_snapshot,\n"
            "            )\n"
        ),
        after=(
            "            materialization_changes = harness_input_snapshot_changes(\n"
            "                candidate_harness_snapshot,\n"
            "                candidate_harness_snapshot,\n"
            "            )\n"
        ),
        test=(
            "tests/test_harness_input_mutation_contract.py::"
            "test_blackbox_compares_materialized_copy_with_trusted_source_snapshot"
        ),
    ),
    Mutation(
        name="blackbox-harness-terminal-postcondition-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "            if not facts.attach_candidate_evidence:\n"
            "                pending_result = enforce_harness_postcondition(result)\n"
        ),
        after=(
            "            if not facts.attach_candidate_evidence:\n"
            "                pending_result = result\n"
        ),
        test=(
            "tests/test_harness_input_mutation_contract.py::"
            "test_blackbox_postcondition_checks_terminal_without_candidate_evidence"
        ),
    ),
    Mutation(
        name="blackbox-harness-evidenced-postcondition-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "                pending_result = enforce_harness_postcondition(\n"
            "                    with_candidate_evidence(\n"
            "                        result,\n"
            "                        wait_for_late_container_evidence=(\n"
            "                            facts.wait_for_late_container_evidence\n"
            "                        ),\n"
            "                    )\n"
            "                )\n"
        ),
        after=(
            "                pending_result = with_candidate_evidence(\n"
            "                    result,\n"
            "                    wait_for_late_container_evidence=(\n"
            "                        facts.wait_for_late_container_evidence\n"
            "                    ),\n"
            "                )\n"
        ),
        test=(
            "tests/test_harness_input_mutation_contract.py::"
            "test_blackbox_postcondition_invalidates_completed_pack_verdict"
        ),
    ),
    Mutation(
        name="blackbox-harness-public-facade-forwarding-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "            expect_verifier_pack_sha256=expect_verifier_pack_sha256,\n"
            "            harness_inputs=harness_inputs,\n"
        ),
        after=(
            "            expect_verifier_pack_sha256=expect_verifier_pack_sha256,\n"
            "            harness_inputs=(),\n"
        ),
        test=(
            "tests/test_harness_input_mutation_contract.py::"
            "test_blackbox_postcondition_invalidates_completed_pack_verdict"
        ),
    ),
    Mutation(
        name="guard-blackbox-harness-forwarding-bypass",
        path="evoom_guard/guard.py",
        before=(
            "        blackbox_harness_options: _BlackboxHarnessOptions = (\n"
            '            {"harness_inputs": harness_inputs}\n'
            "            if harness_inputs\n"
            "            else {}\n"
            "        )\n"
        ),
        after=(
            "        blackbox_harness_options: _BlackboxHarnessOptions = {}\n"
        ),
        test=(
            "tests/test_harness_input_mutation_contract.py::"
            "test_guard_forwards_nonempty_blackbox_harness_inputs_exactly"
        ),
    ),
    Mutation(
        name="guard-blackbox-empty-harness-compatibility-bypass",
        path="evoom_guard/guard.py",
        before=(
            '            {"harness_inputs": harness_inputs}\n'
            "            if harness_inputs\n"
            "            else {}\n"
        ),
        after=(
            '            {"harness_inputs": harness_inputs}\n'
            "            if True\n"
            "            else {}\n"
        ),
        test=(
            "tests/test_harness_input_mutation_contract.py::"
            "test_guard_omits_empty_blackbox_harness_keyword_for_compatibility"
        ),
    ),
    Mutation(
        name="blackbox-harness-tamper-finalization-bypass",
        path="evoom_guard/application/blackbox_finalization.py",
        before=(
            '        elif result.error == "candidate harness input changed":\n'
            "            verdict, reason_code = (\n"
            '                decision_symbol("TAMPERED"),\n'
            '                decision_symbol("REASON_CANDIDATE_TREE_CHANGED"),\n'
            "            )\n"
        ),
        after=(
            '        elif result.error == "candidate harness input changed":\n'
            "            verdict, reason_code = (\n"
            '                decision_symbol("ERROR"),\n'
            '                decision_symbol("REASON_ASSURANCE_REQUIREMENT_NOT_MET"),\n'
            "            )\n"
        ),
        test=(
            "tests/test_harness_input_mutation_contract.py::"
            "test_guard_maps_blackbox_harness_drift_to_tampered"
        ),
    ),
    Mutation(
        name="blackbox-trusted-harness-binding-classification-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "                    _TRUSTED_HARNESS_BINDING_FAILED,\n"
            "                    pack_sha256,\n"
        ),
        after=(
            "                    _HARNESS_INPUT_CHANGED,\n"
            "                    pack_sha256,\n"
        ),
        test=(
            "tests/test_harness_input_mutation_contract.py::"
            "test_blackbox_trusted_binding_failure_is_an_assurance_error"
        ),
    ),
    Mutation(
        name="blackbox-trusted-harness-binding-finalization-bypass",
        path="evoom_guard/application/blackbox_finalization.py",
        before=(
            '        elif result.error == "trusted harness input binding failed":\n'
            "            verdict, reason_code = (\n"
            '                decision_symbol("ERROR"),\n'
            '                decision_symbol("REASON_ASSURANCE_REQUIREMENT_NOT_MET"),\n'
            "            )\n"
        ),
        after=(
            '        elif result.error == "trusted harness input binding failed":\n'
            "            verdict, reason_code = (\n"
            '                decision_symbol("TAMPERED"),\n'
            '                decision_symbol("REASON_CANDIDATE_TREE_CHANGED"),\n'
            "            )\n"
        ),
        test=(
            "tests/test_harness_input_mutation_contract.py::"
            "test_blackbox_trusted_binding_failure_is_an_assurance_error"
        ),
    ),
    Mutation(
        name="record-harness-reason-version-contract-bypass",
        path="evoom_guard/record_verifier.py",
        before=(
            "    versioned_contract = (\n"
            "        _POLICY_CONTRACTS.get(schema_version, _contract)\n"
            "        if isinstance(schema_version, str)\n"
            "        else _contract\n"
            "    )\n"
        ),
        after="    versioned_contract = _contract\n",
        test=(
            "tests/test_harness_inputs.py::"
            "test_trusted_harness_snapshot_precedes_candidate_materialization"
        ),
    ),
    Mutation(
        name="schema-1-12-harness-not-started-reason-contract-bypass",
        path="evoom_guard/verdict_contract_v1_12.py",
        before=(
            "    _candidate_tree_states | "
            "frozenset({_v1_11.EXECUTION_NOT_STARTED}),\n"
        ),
        after="    _candidate_tree_states,\n",
        test=(
            "tests/test_harness_inputs.py::"
            "test_trusted_harness_snapshot_precedes_candidate_materialization"
        ),
    ),
    Mutation(
        name="record-harness-input-ancestor-exclusion-bypass",
        path="evoom_guard/record_verifier.py",
        before=(
            "        len(candidate_parts) <= len(declared_parts)\n"
        ),
        after=(
            "        len(candidate_parts) == len(declared_parts)\n"
        ),
        test=(
            "tests/test_harness_inputs.py::"
            "test_record_verifier_rejects_pass_namespace_alias_or_ancestor[ci]"
        ),
    ),
    Mutation(
        name="record-harness-input-not-started-reason-scope-bypass",
        path="evoom_guard/record_verifier.py",
        before=(
            '        "policy.harness_reason_scope",\n'
            "        _is_canonical_harness_input_list(harness_inputs),\n"
        ),
        after=(
            '        "policy.harness_reason_scope",\n'
            "        True,\n"
        ),
        test=(
            "tests/test_harness_inputs.py::"
            "test_blackbox_materialization_is_bound_to_trusted_harness_snapshot"
        ),
    ),
    Mutation(
        name="record-harness-input-trailing-alias-exclusion-bypass",
        path="evoom_guard/record_verifier.py",
        before=(
            "    if candidate.rstrip(\" .\").casefold() == declared.casefold():\n"
            "        return True\n"
        ),
        after=(
            "    if False and candidate.rstrip(\" .\").casefold() == "
            "declared.casefold():\n"
            "        return True\n"
        ),
        test=(
            "tests/test_harness_inputs.py::"
            "test_record_verifier_rejects_pass_namespace_alias_or_ancestor"
            "[ci/scripts/run-tests.py.]"
        ),
    ),
    Mutation(
        name="protected-edit-preflight-bypass",
        path="evoom_guard/verifiers/repo_candidate.py",
        before=(
            "    if rejection is not None:\n"
            "        return _terminal_admission(rejection)\n"
        ),
        after=(
            "    if False and rejection is not None:\n"
            "        return _terminal_admission(rejection)\n"
        ),
        test=(
            "tests/test_repo_verifier_characterization.py::"
            "test_frozen_repo_verifier_behavior_and_evidence[protected_test_edit]"
        ),
    ),
    Mutation(
        name="protected-deletion-preflight-bypass",
        path="evoom_guard/verifiers/repo_candidate.py",
        before=(
            "        if deletion_rejection is not None:\n"
            "            return _terminal_admission(deletion_rejection)\n"
        ),
        after=(
            "        if False and deletion_rejection is not None:\n"
            "            return _terminal_admission(deletion_rejection)\n"
        ),
        test=(
            "tests/test_repo_verifier_characterization.py::"
            "test_frozen_repo_verifier_behavior_and_evidence[deleted_protected_test]"
        ),
    ),
    Mutation(
        name="repo-candidate-invalid-root-admission-bypass",
        path="evoom_guard/verifiers/repo_candidate.py",
        before=(
            "    if not repo_path or not services.is_directory()(repo_path):\n"
        ),
        after=(
            "    if False and (\n"
            "        not repo_path or not services.is_directory()(repo_path)\n"
            "    ):\n"
        ),
        test=(
            "tests/test_repo_candidate_owner.py::"
            "test_invalid_repo_fails_before_candidate_or_workspace_lookup"
        ),
    ),
    Mutation(
        name="repo-candidate-structured-mode-bypass",
        path="evoom_guard/verifiers/repo_candidate.py",
        before="    if isinstance(file_blocks_override, dict):\n",
        after="    if False and isinstance(file_blocks_override, dict):\n",
        test=(
            "tests/test_repo_candidate_characterization.py::"
            "test_frozen_repo_candidate_behavior[structured_candidate]"
        ),
    ),
    Mutation(
        name="repo-candidate-empty-structured-fallback-regression",
        path="evoom_guard/verifiers/repo_candidate.py",
        before="    if isinstance(file_blocks_override, dict):\n",
        after=(
            "    if isinstance(file_blocks_override, dict) and "
            "file_blocks_override:\n"
        ),
        test=(
            "tests/test_repo_candidate_owner.py::"
            "test_empty_structured_mapping_never_falls_back_to_hypothesis_parser"
        ),
    ),
    Mutation(
        name="repo-candidate-strict-file-parser-bypass",
        path="evoom_guard/verifiers/repo_candidate.py",
        before=(
            "        file_blocks = services.parse_file_blocks()"
            "(request.hypothesis)\n"
        ),
        after="        file_blocks = {}\n",
        test=(
            "tests/test_repo_candidate_characterization.py::"
            "test_frozen_repo_candidate_behavior[textual_file_and_patch]"
        ),
    ),
    Mutation(
        name="repo-candidate-strict-patch-parser-bypass",
        path="evoom_guard/verifiers/repo_candidate.py",
        before=(
            "        patch_blocks = services.parse_patch_blocks()"
            "(request.hypothesis)\n"
        ),
        after="        patch_blocks = []\n",
        test=(
            "tests/test_repo_candidate_characterization.py::"
            "test_frozen_repo_candidate_behavior[textual_file_and_patch]"
        ),
    ),
    Mutation(
        name="repo-candidate-lenient-fallback-bypass",
        path="evoom_guard/verifiers/repo_candidate.py",
        before="        if not file_blocks and not patch_blocks:\n",
        after="        if False and not file_blocks and not patch_blocks:\n",
        test=(
            "tests/test_repo_candidate_characterization.py::"
            "test_frozen_repo_candidate_behavior[lenient_candidate]"
        ),
    ),
    Mutation(
        name="repo-candidate-empty-admission-bypass",
        path="evoom_guard/verifiers/repo_candidate.py",
        before=(
            "    if not file_blocks and not patch_blocks and "
            "not deleted_paths:\n"
        ),
        after=(
            "    if False and not file_blocks and not patch_blocks and "
            "not deleted_paths:\n"
        ),
        test=(
            "tests/test_repo_candidate_characterization.py::"
            "test_frozen_repo_candidate_behavior[empty_candidate]"
        ),
    ),
    Mutation(
        name="repo-candidate-file-change-set-bypass",
        path="evoom_guard/verifiers/repo_candidate.py",
        before=(
            "        set(file_blocks) | {block.path for block in patch_blocks}\n"
        ),
        after=(
            "        set() | {block.path for block in patch_blocks}\n"
        ),
        test=(
            "tests/test_repo_candidate_owner.py::"
            "test_admission_preserves_sorted_changes_and_deletion_input_order"
        ),
    ),
    Mutation(
        name="repo-candidate-safe-new-path-classification-bypass",
        path="evoom_guard/verifiers/repo_candidate.py",
        before="        if services.is_safe_relpath()(path)\n",
        after="        if False and services.is_safe_relpath()(path)\n",
        test=(
            "tests/test_repo_candidate_owner.py::"
            "test_admission_forwards_only_safe_absent_paths_as_new"
        ),
    ),
    Mutation(
        name="repo-candidate-copy-operation-bypass",
        path="evoom_guard/verifiers/repo_candidate.py",
        before=(
            "    services.copy_repo_tree()"
            "(candidate.repo_path, request.candidate_copy)\n"
        ),
        after=(
            "    if False:\n"
            "        services.copy_repo_tree()"
            "(candidate.repo_path, request.candidate_copy)\n"
        ),
        test=(
            "tests/test_repo_candidate_owner.py::"
            "test_copy_exception_identity_reaches_final_cleanup"
        ),
    ),
    Mutation(
        name="repo-candidate-materialization-failure-bypass",
        path="evoom_guard/verifiers/repo_candidate.py",
        before="    if apply_error is not None:\n",
        after="    if False and apply_error is not None:\n",
        test=(
            "tests/test_repo_candidate_characterization.py::"
            "test_frozen_repo_candidate_behavior[materialization_failure]"
        ),
    ),
    Mutation(
        name="repo-candidate-deletion-safety-bypass",
        path="evoom_guard/verifiers/repo_candidate.py",
        before=(
            "            if not services.is_safe_relpath()(relative_path):\n"
            "                continue\n"
        ),
        after=(
            "            if False and not services.is_safe_relpath()"
            "(relative_path):\n"
            "                continue\n"
        ),
        test=(
            "tests/test_repo_candidate_owner.py::"
            "test_deletion_owner_retains_belt_and_braces_safe_path_gate"
        ),
    ),
    Mutation(
        name="repo-candidate-delete-operation-bypass",
        path="evoom_guard/verifiers/repo_candidate.py",
        before=(
            "            services.delete_path()"
            "(request.candidate_copy, relative_path)\n"
        ),
        after=(
            "            if False:\n"
            "                services.delete_path()"
            "(request.candidate_copy, relative_path)\n"
        ),
        test=(
            "tests/test_repo_candidate_characterization.py::"
            "test_frozen_repo_candidate_behavior"
            "[deletion_success_after_pack_intake]"
        ),
    ),
    Mutation(
        name="repo-candidate-deletion-error-catch-bypass",
        path="evoom_guard/verifiers/repo_candidate.py",
        before="    except services.deletion_errors() as exc:\n",
        after="    except OSError as exc:\n",
        test=(
            "tests/test_repo_candidate_owner.py::"
            "test_deletion_exception_class_is_resolved_after_delete_call"
        ),
    ),
    Mutation(
        name="repo-candidate-admission-terminal-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "        if admission.terminal_result is not None:\n"
            "            return admission.terminal_result\n"
        ),
        after=(
            "        if False and admission.terminal_result is not None:\n"
            "            return admission.terminal_result\n"
        ),
        test=(
            "tests/test_repo_candidate_characterization.py::"
            "test_frozen_repo_candidate_behavior[empty_candidate]"
        ),
    ),
    Mutation(
        name="repo-candidate-materialization-terminal-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "            if materialization.terminal_result is not None:\n"
            "                return materialization.terminal_result\n"
        ),
        after=(
            "            if False and "
            "materialization.terminal_result is not None:\n"
            "                return materialization.terminal_result\n"
        ),
        test=(
            "tests/test_repo_candidate_characterization.py::"
            "test_frozen_repo_candidate_behavior[materialization_failure]"
        ),
    ),
    Mutation(
        name="repo-candidate-pack-before-deletion-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before="            if pack_intake.failure is not None:\n",
        after="            if False and pack_intake.failure is not None:\n",
        test=(
            "tests/test_repo_candidate_owner.py::"
            "test_pack_intake_failure_prevents_candidate_deletion"
        ),
    ),
    Mutation(
        name="repo-candidate-deletion-terminal-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "            if deletion.terminal_result is not None:\n"
            "                return deletion.terminal_result\n"
        ),
        after=(
            "            if False and deletion.terminal_result is not None:\n"
            "                return deletion.terminal_result\n"
        ),
        test=(
            "tests/test_repo_candidate_characterization.py::"
            "test_frozen_repo_candidate_behavior[deletion_failure]"
        ),
    ),
    Mutation(
        name="repo-candidate-live-patch-parser-seam-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before="                parse_patch_blocks=lambda: parse_patch_blocks,\n",
        after=(
            "                parse_patch_blocks=lambda: "
            "_candidate_edits.parse_patch_blocks,\n"
        ),
        test=(
            "tests/test_repo_candidate_owner.py::"
            "test_repo_verifier_resolves_each_parser_at_its_operation_site"
        ),
    ),
    Mutation(
        name="repo-candidate-live-rejection-seam-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                reject_paths=lambda: cast(\n"
            "                    Any, reject_unsafe_or_protected\n"
            "                ),\n"
        ),
        after=(
            "                reject_paths=lambda reject="
            "reject_unsafe_or_protected: cast(\n"
            "                    Any, reject\n"
            "                ),\n"
        ),
        test=(
            "tests/test_repo_candidate_owner.py::"
            "test_changed_path_gate_can_replace_the_deletion_gate_seam"
        ),
    ),
    Mutation(
        name="repo-candidate-live-materialization-seam-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                    apply_candidate_edits=lambda: cast(\n"
            "                        Any, apply_blocks_to_copy\n"
            "                    ),\n"
        ),
        after=(
            "                    apply_candidate_edits=lambda apply="
            "apply_blocks_to_copy: cast(\n"
            "                        Any, apply\n"
            "                    ),\n"
        ),
        test=(
            "tests/test_repo_candidate_owner.py::"
            "test_copy_operation_can_replace_the_later_materialization_seam"
        ),
    ),
    Mutation(
        name="repo-candidate-live-deletion-seam-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                    delete_path=lambda: delete_path_within_root,\n"
        ),
        after=(
            "                    delete_path=lambda delete="
            "delete_path_within_root: delete,\n"
        ),
        test=(
            "tests/test_repo_candidate_owner.py::"
            "test_each_deletion_resolves_the_current_facade_seam"
        ),
    ),
    Mutation(
        name="repo-materialization-package-snapshot-bypass",
        path="evoom_guard/verifiers/repo_materialization.py",
        before=(
            "    package_originals: dict[str, str | None] = {}\n"
            "    for relative_path in package_paths:\n"
        ),
        after=(
            "    package_originals: dict[str, str | None] = {}\n"
            "    for relative_path in ():\n"
        ),
        test=(
            "tests/test_repo_materialization_characterization.py::"
            "test_frozen_repo_materialization_behavior[file_then_patch_and_restore]"
        ),
    ),
    Mutation(
        name="repo-materialization-file-patch-order-inversion",
        path="evoom_guard/verifiers/repo_materialization.py",
        before=(
            "    for path, content in file_blocks.items():\n"
            "        write_error = safe_write(path, content)\n"
            "        if write_error is not None:\n"
            "            return write_error\n"
            "\n"
            "    for block in patch_blocks:\n"
            "        source, read_error = safe_read(block.path)\n"
            "        if read_error is not None:\n"
            "            return read_error\n"
            "        if source is None:\n"
            "            return (\n"
            "                f\"PATCH target not found: {block.path} — \"\n"
            "                \"use a <<<FILE>>> block \"\n"
            "                \"to create new files\"\n"
            "            )\n"
            "        try:\n"
            "            patched = patcher(source, block.search, block.replace)\n"
            "        except (PatchError, ValueError) as exc:\n"
            "            return (\n"
            "                f\"PATCH did not apply to {block.path}: \"\n"
            "                f\"{type(exc).__name__}: {exc} — \"\n"
            "                \"\"\n"
            "                \"copy a unique anchor verbatim from the shown file\"\n"
            "            )\n"
            "        write_error = safe_write(block.path, patched)\n"
            "        if write_error is not None:\n"
            "            return write_error\n"
        ),
        after=(
            "    for block in patch_blocks:\n"
            "        source, read_error = safe_read(block.path)\n"
            "        if read_error is not None:\n"
            "            return read_error\n"
            "        if source is None:\n"
            "            return (\n"
            "                f\"PATCH target not found: {block.path} — \"\n"
            "                \"use a <<<FILE>>> block \"\n"
            "                \"to create new files\"\n"
            "            )\n"
            "        try:\n"
            "            patched = patcher(source, block.search, block.replace)\n"
            "        except (PatchError, ValueError) as exc:\n"
            "            return (\n"
            "                f\"PATCH did not apply to {block.path}: \"\n"
            "                f\"{type(exc).__name__}: {exc} — \"\n"
            "                \"\"\n"
            "                \"copy a unique anchor verbatim from the shown file\"\n"
            "            )\n"
            "        write_error = safe_write(block.path, patched)\n"
            "        if write_error is not None:\n"
            "            return write_error\n"
            "\n"
            "    for path, content in file_blocks.items():\n"
            "        write_error = safe_write(path, content)\n"
            "        if write_error is not None:\n"
            "            return write_error\n"
        ),
        test=(
            "tests/test_repo_materialization_characterization.py::"
            "test_frozen_repo_materialization_behavior[file_then_patch_and_restore]"
        ),
    ),
    Mutation(
        name="repo-materialization-unsafe-read-as-absent",
        path="evoom_guard/verifiers/repo_materialization.py",
        before=(
            "        except (UnicodeError, UnsafeWorkspacePath, OSError) as exc:\n"
            "            return None, (\n"
        ),
        after=(
            "        except (UnicodeError, UnsafeWorkspacePath, OSError) as exc:\n"
            "            return None, None\n"
            "            return None, (\n"
        ),
        test=(
            "tests/test_repo_materialization_characterization.py::"
            "test_frozen_repo_materialization_behavior[unsafe_manifest_read]"
        ),
    ),
    Mutation(
        name="repo-materialization-file-write-fail-fast-bypass",
        path="evoom_guard/verifiers/repo_materialization.py",
        before=(
            "    for path, content in file_blocks.items():\n"
            "        write_error = safe_write(path, content)\n"
            "        if write_error is not None:\n"
            "            return write_error\n"
        ),
        after=(
            "    for path, content in file_blocks.items():\n"
            "        write_error = safe_write(path, content)\n"
            "        if False and write_error is not None:\n"
            "            return write_error\n"
        ),
        test=(
            "tests/test_repo_materialization_characterization.py::"
            "test_frozen_repo_materialization_behavior[write_failure]"
        ),
    ),
    Mutation(
        name="repo-materialization-dynamic-patcher-seam-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "        patcher=lambda source, search, replace: "
            "apply_patch(source, search, replace),\n"
        ),
        after=(
            "        patcher=lambda source, search, replace: "
            "source.replace(search, replace),\n"
        ),
        test=(
            "tests/test_repo_materialization_characterization.py::"
            "test_frozen_repo_materialization_behavior[patch_failure]"
        ),
    ),
    Mutation(
        name="repo-materialization-live-operation-seams-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "        write_text=lambda root, path, content: "
            "write_text_within_root(\n"
            "            root, path, content\n"
            "        ),\n"
        ),
        after="        write_text=write_text_within_root,\n",
        test=(
            "tests/test_repo_materialization_characterization.py::"
            "test_repo_verifier_facade_resolves_operation_seams_at_each_use"
        ),
    ),
    Mutation(
        name="repo-materialization-manifest-disappearance-bypass",
        path="evoom_guard/verifiers/repo_materialization.py",
        before="        if candidate_package is None:\n",
        after="        if False and candidate_package is None:\n",
        test=(
            "tests/test_repo_materialization_characterization.py::"
            "test_frozen_repo_materialization_behavior[manifest_disappears]"
        ),
    ),
    Mutation(
        name="repo-materialization-package-restore-bypass",
        path="evoom_guard/verifiers/repo_materialization.py",
        before="        if restored != candidate_package:\n",
        after="        if False and restored != candidate_package:\n",
        test=(
            "tests/test_repo_materialization_characterization.py::"
            "test_frozen_repo_materialization_behavior[file_then_patch_and_restore]"
        ),
    ),
    Mutation(
        name="repo-pack-intake-required-pin-bypass",
        path="evoom_guard/verifiers/repo_pack_intake.py",
        before="    if request.expected_pack_sha256 and not request.pack_dir:\n",
        after=(
            "    if False and request.expected_pack_sha256 and "
            "not request.pack_dir:\n"
        ),
        test=(
            "tests/test_repo_pack_intake_characterization.py::"
            "test_frozen_repo_pack_intake_behavior[expected_pin_without_pack]"
        ),
    ),
    Mutation(
        name="repo-pack-intake-reserved-mount-bypass",
        path="evoom_guard/verifiers/repo_pack_intake.py",
        before="    if services.lexists(reserved):\n",
        after="    if False and services.lexists(reserved):\n",
        test=(
            "tests/test_repo_pack_intake_characterization.py::"
            "test_frozen_repo_pack_intake_behavior[reserved_mount_collision]"
        ),
    ),
    Mutation(
        name="repo-pack-intake-invalid-snapshot-catch-bypass",
        path="evoom_guard/verifiers/repo_pack_intake.py",
        before="    except PackManifestError as exc:\n",
        after="    except TypeError as exc:\n",
        test=(
            "tests/test_repo_pack_intake_characterization.py::"
            "test_frozen_repo_pack_intake_behavior[invalid_pack_snapshot]"
        ),
    ),
    Mutation(
        name="repo-pack-intake-digest-pin-bypass",
        path="evoom_guard/verifiers/repo_pack_intake.py",
        before=(
            "    if (\n"
            "        request.expected_pack_sha256\n"
            "        and pack_sha256.lower() != request.expected_pack_sha256\n"
            "    ):\n"
        ),
        after=(
            "    if False and (\n"
            "        request.expected_pack_sha256\n"
            "        and pack_sha256.lower() != request.expected_pack_sha256\n"
            "    ):\n"
        ),
        test=(
            "tests/test_repo_pack_intake_characterization.py::"
            "test_frozen_repo_pack_intake_behavior[digest_mismatch]"
        ),
    ),
    Mutation(
        name="repo-pack-intake-sticky-identity-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "            if pack_identity is not None:\n"
            "                # Once accepted, bind every later early-return "
            "artifact to the\n"
        ),
        after=(
            "            if False and pack_identity is not None:\n"
            "                # Once accepted, bind every later early-return "
            "artifact to the\n"
        ),
        test=(
            "tests/test_repo_pack_intake_characterization.py::"
            "test_frozen_repo_pack_intake_behavior[valid_identity_sticky_evidence]"
        ),
    ),
    Mutation(
        name="repo-pack-intake-live-snapshot-seam-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                    snapshot_pack=lambda source, destination: "
            "snapshot_pack(\n"
            "                        source, destination\n"
            "                    ),\n"
        ),
        after="                    snapshot_pack=snapshot_pack,\n",
        test=(
            "tests/test_repo_pack_intake_characterization.py::"
            "test_repo_verifier_resolves_pack_operation_seams_at_each_use"
        ),
    ),
    Mutation(
        name="repo-pack-intake-workspace-cleanup-binding-bypass",
        path="evoom_guard/workspace/repository_lifetime.py",
        before=(
            "        pack_root = create_workspace(prefix=prefix)\n"
            "        self.pack_root = pack_root\n"
            "        return pack_root\n"
        ),
        after=(
            "        pack_root = create_workspace(prefix=prefix)\n"
            "        return pack_root\n"
        ),
        test=(
            "tests/test_repo_pack_intake_characterization.py::"
            "test_unexpected_snapshot_failure_preserves_workspace_for_final_cleanup"
        ),
    ),
    Mutation(
        name="repo-setup-no-command-guard-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "            if setup_cmd_raw:\n"
            "                setup_outcome = execute_repo_setup(\n"
        ),
        after=(
            "            if True:\n"
            "                setup_outcome = execute_repo_setup(\n"
        ),
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_no_setup_command_performs_no_setup_specific_attribute_lookups"
        ),
    ),
    Mutation(
        name="repo-setup-string-tokenization-bypass",
        path="evoom_guard/verifiers/repo_setup.py",
        before="    if isinstance(setup_cmd_raw, str):\n",
        after="    if False and isinstance(setup_cmd_raw, str):\n",
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_setup_command_precedence_and_token_normalization_are_frozen"
        ),
    ),
    Mutation(
        name="repo-setup-container-placement-bypass",
        path="evoom_guard/verifiers/repo_setup.py",
        before=(
            "    if setup_in_container:\n"
            "        setup_isolation: str | None = services.requested_isolation()\n"
        ),
        after=(
            "    if False and setup_in_container:\n"
            "        setup_isolation: str | None = services.requested_isolation()\n"
        ),
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_frozen_repo_setup_behavior[docker_exit_125]"
        ),
    ),
    Mutation(
        name="repo-setup-pre-snapshot-fail-closed-bypass",
        path="evoom_guard/verifiers/repo_setup.py",
        before=(
            "    except SetupFidelityError as exc:\n"
            "        return _terminal(\n"
            "            request,\n"
            '            diagnostics=f"setup fidelity snapshot failed: {exc}",\n'
        ),
        after=(
            "    except TypeError as exc:\n"
            "        return _terminal(\n"
            "            request,\n"
            '            diagnostics=f"setup fidelity snapshot failed: {exc}",\n'
        ),
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_frozen_repo_setup_behavior[pre_snapshot_error]"
        ),
    ),
    Mutation(
        name="repo-setup-docker-timeout-start-proof-bypass",
        path="evoom_guard/verifiers/repo_setup.py",
        before=(
            "        delivered = services.requested_isolation() "
            'if exc.container_started else "not_run"\n'
        ),
        after='        delivered = "not_run"\n',
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_frozen_repo_setup_behavior[docker_timeout_started]"
        ),
    ),
    Mutation(
        name="repo-setup-docker-output-classification-bypass",
        path="evoom_guard/verifiers/repo_setup.py",
        before=(
            "        docker_failure = isinstance(exc, DockerRunOutputLimit)\n"
        ),
        after="        docker_failure = False\n",
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_frozen_repo_setup_behavior[docker_output_limit_unstarted]"
        ),
    ),
    Mutation(
        name="repo-setup-docker-containment-classification-bypass",
        path="evoom_guard/verifiers/repo_setup.py",
        before=(
            "        docker_failure = isinstance(exc, DockerRunContainmentError)\n"
        ),
        after="        docker_failure = False\n",
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_frozen_repo_setup_behavior[docker_containment_unstarted]"
        ),
    ),
    Mutation(
        name="repo-setup-docker-exit-125-bypass",
        path="evoom_guard/verifiers/repo_setup.py",
        before="    if setup_in_container and r_setup.returncode == 125:\n",
        after=(
            "    if False and setup_in_container "
            "and r_setup.returncode == 125:\n"
        ),
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_frozen_repo_setup_behavior[docker_exit_125]"
        ),
    ),
    Mutation(
        name="repo-setup-nonzero-failure-bypass",
        path="evoom_guard/verifiers/repo_setup.py",
        before="    if r_setup.returncode != 0:\n",
        after="    if False and r_setup.returncode != 0:\n",
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_frozen_repo_setup_behavior[host_nonzero]"
        ),
    ),
    Mutation(
        name="repo-setup-post-snapshot-fail-closed-bypass",
        path="evoom_guard/verifiers/repo_setup.py",
        before=(
            "    except SetupFidelityError as exc:\n"
            "        return _terminal(\n"
            "            request,\n"
            '            diagnostics=f"setup fidelity verification failed: {exc}",\n'
        ),
        after=(
            "    except TypeError as exc:\n"
            "        return _terminal(\n"
            "            request,\n"
            '            diagnostics=f"setup fidelity verification failed: {exc}",\n'
        ),
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_frozen_repo_setup_behavior[post_snapshot_error]"
        ),
    ),
    Mutation(
        name="repo-setup-fidelity-change-bypass",
        path="evoom_guard/verifiers/repo_setup.py",
        before="    if setup_changes:\n",
        after="    if False and setup_changes:\n",
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_frozen_repo_setup_behavior[fidelity_change]"
        ),
    ),
    Mutation(
        name="repo-setup-live-pre-snapshot-seam-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                        capture_setup_before=lambda: cast(\n"
            "                            Any, _setup_fidelity_snapshot\n"
            "                        ),\n"
        ),
        after=(
            "                        capture_setup_before=(\n"
            "                            lambda operation=cast(\n"
            "                                Any, _setup_fidelity_snapshot\n"
            "                            ): operation\n"
            "                        ),\n"
        ),
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_repo_verifier_resolves_host_setup_seams_at_each_operation"
        ),
    ),
    Mutation(
        name="repo-setup-live-trust-provider-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                        trust_setup_on_host=lambda: "
            "self.trust_setup_on_host,\n"
        ),
        after=(
            "                        trust_setup_on_host=(lambda "
            "value=self.trust_setup_on_host: value),\n"
        ),
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_token_normalization_can_change_container_setup_trust"
        ),
    ),
    Mutation(
        name="repo-setup-live-output-globs-provider-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                        setup_output_globs=lambda: "
            "self.setup_output_globs,\n"
        ),
        after=(
            "                        setup_output_globs=(lambda "
            "value=self.setup_output_globs: value),\n"
        ),
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_host_resolver_can_change_setup_output_globs_before_snapshot"
        ),
    ),
    Mutation(
        name="repo-setup-live-timeout-provider-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before="                        timeout=lambda: self.timeout,\n",
        after=(
            "                        timeout=(lambda "
            "value=self.timeout: value),\n"
        ),
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_pre_snapshot_can_change_timeout_but_not_effective_strict_policy"
        ),
    ),
    Mutation(
        name="repo-setup-effective-strict-provider-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                        strict_harness=lambda: "
            "strict_harness,\n"
        ),
        after=(
            "                        strict_harness=lambda: False,\n"
        ),
        test=(
            "tests/test_strict_harness.py::"
            "test_problem_strict_harness_reaches_every_repo_host_phase"
        ),
    ),
    Mutation(
        name="repo-setup-live-isolation-provider-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                        requested_isolation=lambda: self.isolation,\n"
        ),
        after=(
            "                        requested_isolation=(lambda "
            "value=self.isolation: value),\n"
        ),
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_docker_runner_can_change_isolation_before_timeout_evidence"
        ),
    ),
    Mutation(
        name="repo-setup-live-network-provider-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                        docker_network=lambda: self.docker_network,\n"
        ),
        after=(
            "                        docker_network=(lambda "
            "value=self.docker_network: value),\n"
        ),
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_docker_exit_125_uses_live_network_and_runtime_fields"
        ),
    ),
    Mutation(
        name="repo-setup-live-runtime-provider-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                        docker_runtime=lambda: self.docker_runtime,\n"
        ),
        after=(
            "                        docker_runtime=(lambda "
            "value=self.docker_runtime: value),\n"
        ),
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_docker_exit_125_uses_live_network_and_runtime_fields"
        ),
    ),
    Mutation(
        name="repo-setup-live-host-runner-seam-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                        run_host_setup=lambda: cast(\n"
            "                            Any, _run_bounded_subprocess\n"
            "                        ),\n"
        ),
        after=(
            "                        run_host_setup=(\n"
            "                            lambda operation=cast(\n"
            "                                Any, _run_bounded_subprocess\n"
            "                            ): operation\n"
            "                        ),\n"
        ),
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_repo_verifier_resolves_host_setup_seams_at_each_operation"
        ),
    ),
    Mutation(
        name="repo-setup-live-docker-builder-seam-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                        build_docker_command=lambda: cast(\n"
            "                            Any, self._docker_command\n"
            "                        ),\n"
        ),
        after=(
            "                        build_docker_command=(\n"
            "                            lambda operation=cast(\n"
            "                                Any, self._docker_command\n"
            "                            ): operation\n"
            "                        ),\n"
        ),
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_repo_verifier_resolves_docker_setup_methods_at_each_operation"
        ),
    ),
    Mutation(
        name="repo-setup-live-evidence-seam-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                        phase_isolation_evidence=lambda: (\n"
            "                            self._phase_isolation_evidence\n"
            "                        ),\n"
        ),
        after=(
            "                        phase_isolation_evidence=(\n"
            "                            lambda operation="
            "self._phase_isolation_evidence: operation\n"
            "                        ),\n"
        ),
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_repo_verifier_resolves_docker_setup_methods_at_each_operation"
        ),
    ),
    Mutation(
        name="repo-setup-live-diagnostics-seam-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                        distill_diagnostics=lambda: "
            "distill_diagnostics,\n"
        ),
        after=(
            "                        distill_diagnostics=(lambda "
            "operation=distill_diagnostics: operation),\n"
        ),
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_repo_verifier_resolves_docker_setup_methods_at_each_operation"
        ),
    ),
    Mutation(
        name="strict-harness-exit-only-bypass",
        path="evoom_guard/verifiers/repo_phase_contracts.py",
        before=(
            "    if strict_harness and (evidence.junit is None or "
            "evidence.junit.total <= 0):\n"
        ),
        after=(
            "    if False and strict_harness and (evidence.junit is None or "
            "evidence.junit.total <= 0):\n"
        ),
        test=(
            "tests/test_strict_harness.py::"
            "test_strict_harness_zero_test_guard_cannot_be_disabled"
        ),
    ),
    Mutation(
        name="junit-exit-disagreement-bypass",
        path="evoom_guard/verifiers/junit_oracle.py",
        before="    if has_failures and returncode == 0:\n        return True\n",
        after="    if False and has_failures and returncode == 0:\n        return True\n",
        test=(
            "tests/test_repo_verifier_characterization.py::"
            "test_frozen_repo_verifier_behavior_and_evidence[junit_tamper]"
        ),
    ),
    Mutation(
        name="junit-doctype-filter-bypass",
        path="evoom_guard/verifiers/junit_oracle.py",
        before='    if "<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text:\n        return None\n',
        after=(
            '    if False and ("<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text):\n'
            "        return None\n"
        ),
        test="tests/test_junit_hardening.py::test_rejects_doctype_billion_laughs_without_expanding",
    ),
    Mutation(
        name="subprocess-cleanup-requirement-validation-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "        if type(self.require_process_group_cleanup_proof) is not bool:\n"
        ),
        after=(
            "        if False and type(self.require_process_group_cleanup_proof) "
            "is not bool:\n"
        ),
        test=(
            "tests/test_execution_process.py::"
            "test_typed_request_rejects_non_boolean_cleanup_requirement"
        ),
    ),
    Mutation(
        name="subprocess-process-group-cleanup-preflight-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "    if request.require_process_group_cleanup_proof and (\n"
            '        os.name != "posix" or not callable(getattr(os, "killpg", None))\n'
            "    ):\n"
        ),
        after=(
            "    if False and request.require_process_group_cleanup_proof and (\n"
            '        os.name != "posix" or not callable(getattr(os, "killpg", None))\n'
            "    ):\n"
        ),
        test=(
            "tests/test_execution_process.py::"
            "test_required_process_group_cleanup_proof_refuses_before_popen"
        ),
    ),
    Mutation(
        name="subprocess-process-group-platform-preflight-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "    if request.require_process_group_cleanup_proof and (\n"
            '        os.name != "posix" or not callable(getattr(os, "killpg", None))\n'
            "    ):\n"
        ),
        after=(
            "    if request.require_process_group_cleanup_proof and (\n"
            '        False or not callable(getattr(os, "killpg", None))\n'
            "    ):\n"
        ),
        test=(
            "tests/test_execution_process.py::"
            "test_required_process_group_cleanup_proof_refuses_before_popen"
        ),
    ),
    Mutation(
        name="subprocess-process-group-killpg-preflight-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "    if request.require_process_group_cleanup_proof and (\n"
            '        os.name != "posix" or not callable(getattr(os, "killpg", None))\n'
            "    ):\n"
        ),
        after=(
            "    if request.require_process_group_cleanup_proof and (\n"
            '        os.name != "posix" or False\n'
            "    ):\n"
        ),
        test=(
            "tests/test_execution_process.py::"
            "test_required_process_group_cleanup_proof_refuses_before_popen"
        ),
    ),
    Mutation(
        name="subprocess-process-group-cleanup-facade-forward-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "        require_process_group_cleanup_proof="
            "require_process_group_cleanup_proof,\n"
        ),
        after="        require_process_group_cleanup_proof=False,\n",
        test=(
            "tests/test_execution_process.py::"
            "test_public_facade_forwards_process_group_cleanup_proof_requirement"
        ),
    ),
    Mutation(
        name="repo-subprocess-group-proof-facade-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "        require_process_group_cleanup_proof=(\n"
            "            require_process_group_cleanup_proof\n"
            "        ),\n"
        ),
        after="        require_process_group_cleanup_proof=False,\n",
        test=(
            "tests/test_execution_process.py::"
            "test_repo_verifier_facade_forwards_process_group_cleanup_proof_requirement"
        ),
    ),
    Mutation(
        name="strict-setup-process-group-proof-bypass",
        path="evoom_guard/verifiers/repo_setup.py",
        before=(
            "                require_process_group_cleanup_proof="
            "services.strict_harness(),\n"
        ),
        after="                require_process_group_cleanup_proof=False,\n",
        test=(
            "tests/test_strict_harness.py::"
            "test_repo_verifier_strict_harness_requires_group_proof_for_every_host_phase"
        ),
    ),
    Mutation(
        name="strict-suite-process-group-proof-bypass",
        path="evoom_guard/verifiers/repo_suite.py",
        before=(
            "                require_process_group_cleanup_proof="
            "(request.strict_harness),\n"
        ),
        after="                require_process_group_cleanup_proof=False,\n",
        test=(
            "tests/test_strict_harness.py::"
            "test_repo_verifier_strict_harness_requires_group_proof_for_every_host_phase"
        ),
    ),
    Mutation(
        name="repo-suite-docker-timeout-start-proof-bypass",
        path="evoom_guard/verifiers/repo_suite.py",
        before=(
            "        if exc.container_started:\n"
            "            trace.execution_state = \"started_incomplete\"\n"
        ),
        after=(
            "        if True:\n"
            "            trace.execution_state = \"started_incomplete\"\n"
        ),
        test=(
            "tests/test_repo_suite_characterization.py::"
            "test_frozen_repo_suite_behavior[docker_timeout_unstarted]"
        ),
    ),
    Mutation(
        name="repo-suite-docker-output-classification-bypass",
        path="evoom_guard/verifiers/repo_suite.py",
        before="        docker_failure = isinstance(exc, DockerRunOutputLimit)\n",
        after="        docker_failure = False\n",
        test=(
            "tests/test_repo_suite_characterization.py::"
            "test_frozen_repo_suite_behavior[docker_output_limit_started]"
        ),
    ),
    Mutation(
        name="repo-suite-docker-containment-classification-bypass",
        path="evoom_guard/verifiers/repo_suite.py",
        before="        docker_failure = isinstance(exc, DockerRunContainmentError)\n",
        after="        docker_failure = False\n",
        test=(
            "tests/test_repo_suite_characterization.py::"
            "test_frozen_repo_suite_behavior[docker_containment_started]"
        ),
    ),
    Mutation(
        name="repo-suite-docker-not-found-classification-bypass",
        path="evoom_guard/verifiers/repo_suite.py",
        before=(
            '                "but the docker CLI was not found"\n'
            "                if request.container_mode\n"
            "                else f\"test command not found: {base_command[0]!r}\"\n"
            "            ),\n"
            "            artifact={\n"
            '                "files_changed": list(request.files_changed),\n'
            "                \"outcome\": (\n"
            "                    \"isolation_unavailable\"\n"
            "                    if request.container_mode\n"
            "                    else \"test_command_unavailable\"\n"
            "                ),\n"
        ),
        after=(
            '                "but the docker CLI was not found"\n'
            "                if request.container_mode\n"
            "                else f\"test command not found: {base_command[0]!r}\"\n"
            "            ),\n"
            "            artifact={\n"
            '                "files_changed": list(request.files_changed),\n'
            '                "outcome": "test_command_unavailable",\n'
        ),
        test=(
            "tests/test_repo_suite_characterization.py::"
            "test_frozen_repo_suite_behavior[docker_not_found]"
        ),
    ),
    Mutation(
        name="repo-suite-docker-exit-125-bypass",
        path="evoom_guard/verifiers/repo_suite.py",
        before="    if request.container_mode and process.returncode == 125:\n",
        after=(
            "    if False and request.container_mode and process.returncode == 125:\n"
        ),
        test=(
            "tests/test_repo_suite_characterization.py::"
            "test_frozen_repo_suite_behavior[docker_exit_125]"
        ),
    ),
    Mutation(
        name="repo-suite-host-report-owner-bypass",
        path="evoom_guard/verifiers/repo_suite.py",
        before=(
            "            report_path = os.path.join(\n"
            "                request.workdir,\n"
            "                \"judge-result.xml\",\n"
            "            )\n"
        ),
        after=(
            "            report_path = os.path.join(\n"
            "                request.candidate_copy,\n"
            "                \"judge-result.xml\",\n"
            "            )\n"
        ),
        test=(
            "tests/test_repo_suite_characterization.py::"
            "test_completed_branch_order_and_junit_ownership_are_frozen"
        ),
    ),
    Mutation(
        name="repo-suite-terminal-return-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "            if suite_execution.terminal_result is not None:\n"
            "                return suite_execution.terminal_result\n"
        ),
        after=(
            "            if False and suite_execution.terminal_result is not None:\n"
            "                return suite_execution.terminal_result\n"
        ),
        test=(
            "tests/test_repo_suite_characterization.py::"
            "test_terminal_suite_failure_never_starts_the_pack"
        ),
    ),
    Mutation(
        name="repo-suite-host-runner-live-binding-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                    run_host_suite=lambda: cast(\n"
            "                        Any,\n"
            "                        _run_bounded_subprocess,\n"
            "                    ),\n"
        ),
        after=(
            "                    run_host_suite=(\n"
            "                        lambda provider=_run_bounded_subprocess: cast(\n"
            "                            Any,\n"
            "                            provider,\n"
            "                        )\n"
            "                    ),\n"
        ),
        test=(
            "tests/test_repo_suite_characterization.py::"
            "test_suite_dependencies_are_resolved_live_in_historical_order"
        ),
    ),
    Mutation(
        name="repo-suite-docker-runner-live-binding-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                    run_docker_suite=lambda: cast(\n"
            "                        Any,\n"
            "                        self._run_docker,\n"
            "                    ),\n"
        ),
        after=(
            "                    run_docker_suite=(\n"
            "                        lambda provider=self._run_docker: cast(\n"
            "                            Any,\n"
            "                            provider,\n"
            "                        )\n"
            "                    ),\n"
        ),
        test=(
            "tests/test_repo_suite_characterization.py::"
            "test_container_runner_and_trace_builder_are_resolved_live"
        ),
    ),
    Mutation(
        name="strict-pack-process-group-proof-bypass",
        path="evoom_guard/verifiers/repo_pack.py",
        before=(
            "                require_process_group_cleanup_proof="
            "(request.strict_harness),\n"
        ),
        after="                require_process_group_cleanup_proof=False,\n",
        test=(
            "tests/test_strict_harness.py::"
            "test_repo_verifier_strict_harness_requires_group_proof_for_every_host_phase"
        ),
    ),
    Mutation(
        name="repo-pack-docker-timeout-start-proof-bypass",
        path="evoom_guard/verifiers/repo_pack.py",
        before=(
            "        if exc.container_started:\n"
            "            trace.execution_state = \"started_incomplete\"\n"
        ),
        after=(
            "        if True:\n"
            "            trace.execution_state = \"started_incomplete\"\n"
        ),
        test=(
            "tests/test_repo_pack_characterization.py::"
            "test_frozen_repo_pack_behavior[docker_timeout_unstarted]"
        ),
    ),
    Mutation(
        name="repo-pack-docker-output-classification-bypass",
        path="evoom_guard/verifiers/repo_pack.py",
        before="        docker_failure = isinstance(exc, DockerRunOutputLimit)\n",
        after="        docker_failure = False\n",
        test=(
            "tests/test_repo_pack_characterization.py::"
            "test_frozen_repo_pack_behavior[docker_output_limit_started]"
        ),
    ),
    Mutation(
        name="repo-pack-docker-containment-classification-bypass",
        path="evoom_guard/verifiers/repo_pack.py",
        before=(
            "        docker_failure = isinstance(\n"
            "            exc,\n"
            "            DockerRunContainmentError,\n"
            "        )\n"
        ),
        after="        docker_failure = False\n",
        test=(
            "tests/test_repo_pack_characterization.py::"
            "test_frozen_repo_pack_behavior[docker_containment_started]"
        ),
    ),
    Mutation(
        name="repo-pack-docker-exit-125-bypass",
        path="evoom_guard/verifiers/repo_pack.py",
        before="    if request.container_mode and process.returncode == 125:\n",
        after=(
            "    if False and request.container_mode and "
            "process.returncode == 125:\n"
        ),
        test=(
            "tests/test_repo_pack_characterization.py::"
            "test_frozen_repo_pack_behavior[docker_exit_125]"
        ),
    ),
    Mutation(
        name="repo-pack-host-report-owner-bypass",
        path="evoom_guard/verifiers/repo_pack.py",
        before=(
            "            report_path = os.path.join(\n"
            "                pack_phase,\n"
            "                \"judge-result.xml\",\n"
            "            )\n"
        ),
        after=(
            "            report_path = os.path.join(\n"
            "                request.candidate_copy,\n"
            "                \"judge-result.xml\",\n"
            "            )\n"
        ),
        test=(
            "tests/test_repo_pack_characterization.py::"
            "test_host_command_order_and_strict_cleanup_are_frozen"
        ),
    ),
    Mutation(
        name="repo-pack-outcome-exclusivity-bypass",
        path="evoom_guard/verifiers/repo_pack.py",
        before=(
            "        if (self.terminal_result is None) == "
            "(self.completed is None):\n"
        ),
        after=(
            "        if self.terminal_result is None and "
            "self.completed is None:\n"
        ),
        test=(
            "tests/test_repo_pack_characterization.py::"
            "test_repo_pack_outcome_rejects_both_branches"
        ),
    ),
    Mutation(
        name="repo-pack-terminal-return-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                if pack_execution.terminal_result is not None:\n"
            "                    return pack_execution.terminal_result\n"
        ),
        after=(
            "                if False and "
            "pack_execution.terminal_result is not None:\n"
            "                    return pack_execution.terminal_result\n"
        ),
        test=(
            "tests/test_repo_pack_characterization.py::"
            "test_frozen_repo_pack_behavior[host_timeout]"
        ),
    ),
    Mutation(
        name="repo-pack-host-runner-live-binding-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                    run_host_pack=lambda: cast(\n"
            "                        Any, _run_bounded_subprocess\n"
            "                    ),\n"
        ),
        after=(
            "                    run_host_pack=(\n"
            "                        lambda provider=_run_bounded_subprocess: "
            "cast(Any, provider)\n"
            "                    ),\n"
        ),
        test=(
            "tests/test_repo_pack_characterization.py::"
            "test_host_pack_dependencies_are_resolved_live_in_order"
        ),
    ),
    Mutation(
        name="repo-pack-docker-runner-live-binding-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                    run_docker_pack=lambda: cast(\n"
            "                        Any, self._run_docker\n"
            "                    ),\n"
        ),
        after=(
            "                    run_docker_pack=(\n"
            "                        lambda provider=self._run_docker: "
            "cast(Any, provider)\n"
            "                    ),\n"
        ),
        test=(
            "tests/test_repo_pack_characterization.py::"
            "test_container_pack_runner_and_trace_builder_are_live[docker]"
        ),
    ),
    Mutation(
        name="repo-pack-parser-live-binding-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                        parse_xml=lambda: cast(Any, parse_junit_xml),\n"
        ),
        after=(
            "                        parse_xml=(\n"
            "                            lambda provider=parse_junit_xml: "
            "cast(Any, provider)\n"
            "                        ),\n"
        ),
        test=(
            "tests/test_repo_pack_characterization.py::"
            "test_host_pack_dependencies_are_resolved_live_in_order"
        ),
    ),
    Mutation(
        name="repo-pack-evaluator-live-binding-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before="                        evaluate_phase=lambda: evaluate_pack_phase,\n",
        after=(
            "                        evaluate_phase=(\n"
            "                            lambda provider=evaluate_pack_phase: "
            "provider\n"
            "                        ),\n"
        ),
        test=(
            "tests/test_repo_pack_characterization.py::"
            "test_host_pack_dependencies_are_resolved_live_in_order"
        ),
    ),
    Mutation(
        name="repo-pack-junit-digest-bypass",
        path="evoom_guard/verifiers/repo_pack.py",
        before=(
            "    junit_sha256 = hashlib.sha256("
            "junit_text.encode(\"utf-8\")).hexdigest() if junit_text else None\n"
        ),
        after=(
            "    junit_sha256 = hashlib.sha256(b\"\").hexdigest() "
            "if junit_text else None\n"
        ),
        test=(
            "tests/test_repo_pack_characterization.py::"
            "test_frozen_repo_pack_behavior[host_pass_strict]"
        ),
    ),
    Mutation(
        name="repo-pack-pre-execution-snapshot-bypass",
        path="evoom_guard/verifiers/repo_pack_continuity.py",
        before=(
            "        return self._verify(\n"
            "            checkpoint=\"before_execution\",\n"
            "            expected_phase=\"accepted\",\n"
            "            delivered_phase=\"pre_execution_verified\",\n"
            "            diagnostics_prefix=\"verifier pack was changed "
            "before execution\",\n"
            "        )\n"
        ),
        after="        return None\n",
        test=(
            "tests/test_repo_pack_continuity_characterization.py::"
            "test_frozen_repo_pack_continuity_behavior"
            "[pre_execution_drift]"
        ),
    ),
    Mutation(
        name="repo-pack-post-execution-snapshot-bypass",
        path="evoom_guard/verifiers/repo_pack_continuity.py",
        before=(
            "        return self._verify(\n"
            "            checkpoint=\"after_execution\",\n"
            "            expected_phase=\"pre_execution_verified\",\n"
            "            delivered_phase=\"delivered\",\n"
            "            diagnostics_prefix=\"verifier pack changed while "
            "executing\",\n"
            "        )\n"
        ),
        after="        return None\n",
        test=(
            "tests/test_repo_pack_continuity_characterization.py::"
            "test_frozen_repo_pack_continuity_behavior"
            "[post_execution_drift]"
        ),
    ),
    Mutation(
        name="repo-pack-continuity-live-provider-binding-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                        verify_snapshot=lambda: "
            "verify_pack_snapshot,\n"
        ),
        after=(
            "                        verify_snapshot=(\n"
            "                            lambda provider=verify_pack_snapshot: "
            "provider\n"
            "                        ),\n"
        ),
        test=(
            "tests/test_repo_pack_continuity_owner.py::"
            "test_facade_injects_a_live_provider_at_both_checkpoints"
        ),
    ),
    Mutation(
        name="repo-pack-continuity-checkpoint-skip-bypass",
        path="evoom_guard/verifiers/repo_pack_continuity.py",
        before=(
            "            expected_phase=\"pre_execution_verified\",\n"
        ),
        after="            expected_phase=\"accepted\",\n",
        test=(
            "tests/test_repo_pack_continuity_owner.py::"
            "test_after_execution_cannot_skip_the_pre_execution_checkpoint"
        ),
    ),
    Mutation(
        name="repo-pack-continuity-sticky-failure-bypass",
        path="evoom_guard/verifiers/repo_pack_continuity.py",
        before="        if self.failure is not None:\n",
        after="        if False and self.failure is not None:\n",
        test=(
            "tests/test_repo_pack_continuity_owner.py::"
            "test_pre_execution_snapshot_failure_is_typed_and_sticky"
        ),
    ),
    Mutation(
        name="repo-pack-continuity-provider-terminal-bypass",
        path="evoom_guard/verifiers/repo_pack_continuity.py",
        before="            self.provider_failure = exc\n",
        after="            self.provider_failure = None\n",
        test=(
            "tests/test_repo_pack_continuity_owner.py::"
            "test_unexpected_provider_failure_is_re_raised_and_terminal"
        ),
    ),
    Mutation(
        name="repo-pack-continuity-identity-deepcopy-bypass",
        path="evoom_guard/verifiers/repo_pack_continuity.py",
        before=(
            "        frozen = MappingProxyType("
            "copy.deepcopy(dict(self.manifest)))\n"
        ),
        after=(
            "        frozen = MappingProxyType(dict(self.manifest))\n"
        ),
        test=(
            "tests/test_repo_pack_continuity_owner.py::"
            "test_accepted_identity_is_an_immutable_isolated_snapshot"
        ),
    ),
    Mutation(
        name="repo-result-pack-identity-deepcopy-bypass",
        path="evoom_guard/verifiers/repo_result.py",
        before=(
            "        frozen = MappingProxyType("
            "copy.deepcopy(dict(self.manifest)))\n"
        ),
        after="        frozen = MappingProxyType(dict(self.manifest))\n",
        test=(
            "tests/test_repo_result_owner.py::"
            "test_pack_identity_is_sticky_and_defensively_owned"
        ),
    ),
    Mutation(
        name="repo-result-sticky-pack-identity-bypass",
        path="evoom_guard/verifiers/repo_result.py",
        before="        if self.pack_identity is not None:\n",
        after="        if False and self.pack_identity is not None:\n",
        test=(
            "tests/test_repo_result_owner.py::"
            "test_pack_identity_is_sticky_and_defensively_owned"
        ),
    ),
    Mutation(
        name="repo-result-sticky-repo-phase-bypass",
        path="evoom_guard/verifiers/repo_result.py",
        before="        if self.repo_suite_phase is not None:\n",
        after="        if False and self.repo_suite_phase is not None:\n",
        test=(
            "tests/test_repo_result_owner.py::"
            "test_repo_phase_sticky_projection_does_not_invent_a_clean_verdict"
        ),
    ),
    Mutation(
        name="repo-result-explicit-pack-presence-overwrite",
        path="evoom_guard/verifiers/repo_result.py",
        before=(
            "        result.artifact.setdefault(\n"
            "            \"verifier_pack_present\",\n"
            "            verifier_pack_present,\n"
            "        )\n"
        ),
        after=(
            "        result.artifact[\"verifier_pack_present\"] = "
            "verifier_pack_present\n"
        ),
        test=(
            "tests/test_repo_result_owner.py::"
            "test_finalization_preserves_overwrite_order_and_explicit_presence"
        ),
    ),
    Mutation(
        name="repo-result-pack-junit-presence-bypass",
        path="evoom_guard/verifiers/repo_result.py",
        before="    if request.pack_configured:\n",
        after="    if True:\n",
        test=(
            "tests/test_repo_result_owner.py::"
            "test_no_pack_final_artifact_keeps_nullable_fields_but_omits_pack_junit"
        ),
    ),
    Mutation(
        name="repo-result-facade-pack-binding-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before="                result_projection.bind_pack_identity(\n",
        after="                RepoResultProjection().bind_pack_identity(\n",
        test=(
            "tests/test_repo_result_characterization.py::"
            "test_frozen_repo_result_projection[pack_command_unavailable]"
        ),
    ),
    Mutation(
        name="repo-result-facade-repo-phase-binding-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                result_projection.bind_repo_suite_phase("
            "repo_phase)\n"
        ),
        after=(
            "                RepoResultProjection().bind_repo_suite_phase("
            "repo_phase)\n"
        ),
        test=(
            "tests/test_repo_result_characterization.py::"
            "test_frozen_repo_result_projection[pack_command_unavailable]"
        ),
    ),
    Mutation(
        name="repo-runtime-required-capture-guard-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before="            if runtime_continuity.required:\n",
        after="            if False and runtime_continuity.required:\n",
        test=(
            "tests/test_repo_runtime_continuity_owner.py::"
            "test_facade_injects_live_capture_and_verify_providers"
        ),
    ),
    Mutation(
        name="repo-runtime-capture-provider-live-binding-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                    capture_identity=lambda: "
            "capture_runtime_identity,\n"
        ),
        after=(
            "                    capture_identity=(\n"
            "                        lambda provider=capture_runtime_identity: "
            "provider\n"
            "                    ),\n"
        ),
        test=(
            "tests/test_repo_runtime_continuity_owner.py::"
            "test_facade_injects_live_capture_and_verify_providers"
        ),
    ),
    Mutation(
        name="repo-runtime-verify-provider-live-binding-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                    verify_identity=lambda: "
            "verify_runtime_identity,\n"
        ),
        after=(
            "                    verify_identity=(\n"
            "                        lambda provider=verify_runtime_identity: "
            "provider\n"
            "                    ),\n"
        ),
        test=(
            "tests/test_repo_runtime_continuity_owner.py::"
            "test_facade_injects_live_capture_and_verify_providers"
        ),
    ),
    Mutation(
        name="repo-runtime-irrelevant-host-trust-lookup",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                    trust_setup_on_host=(\n"
            "                        self.trust_setup_on_host\n"
            "                        if pack_dir and container_mode "
            "and bool(setup_cmd_raw)\n"
            "                        else False\n"
            "                    ),\n"
        ),
        after=(
            "                    trust_setup_on_host="
            "self.trust_setup_on_host,\n"
        ),
        test=(
            "tests/test_repo_setup_characterization.py::"
            "test_no_setup_command_performs_no_setup_specific_attribute_lookups"
        ),
    ),
    Mutation(
        name="repo-runtime-suite-drift-bypass",
        path="evoom_guard/verifiers/repo_runtime_continuity.py",
        before=(
            "        if changes:\n"
            "            return self._record_failure(\n"
            "                RepoRuntimeContinuityFailure(\n"
            "                    kind=\"suite_drift\",\n"
        ),
        after=(
            "        if False and changes:\n"
            "            return self._record_failure(\n"
            "                RepoRuntimeContinuityFailure(\n"
            "                    kind=\"suite_drift\",\n"
        ),
        test=(
            "tests/test_repo_runtime_continuity_owner.py::"
            "test_suite_drift_is_phase_specific_and_keeps_all_changes"
        ),
    ),
    Mutation(
        name="repo-pack-post-execution-runtime-drift-bypass",
        path="evoom_guard/verifiers/repo_runtime_continuity.py",
        before=(
            "        if changes:\n"
            "            return self._record_failure(\n"
            "                RepoRuntimeContinuityFailure(\n"
            "                    kind=\"pack_drift\",\n"
        ),
        after=(
            "        if False and changes:\n"
            "            return self._record_failure(\n"
            "                RepoRuntimeContinuityFailure(\n"
            "                    kind=\"pack_drift\",\n"
        ),
        test=(
            "tests/test_repo_pack_characterization.py::"
            "test_pack_or_runtime_drift_precedes_junit_read"
            "[runtime_drift_after_execution]"
        ),
    ),
    Mutation(
        name="repo-runtime-final-continuity-bypass",
        path="evoom_guard/verifiers/repo_runtime_continuity.py",
        before=(
            "        self.continuity = self.delivery\n"
            "        self.phase = \"delivered\"\n"
            "        return None\n"
        ),
        after=(
            "        self.phase = \"delivered\"\n"
            "        return None\n"
        ),
        test=(
            "tests/test_repo_runtime_continuity_owner.py::"
            "test_capture_suite_and_pack_accumulate_elapsed_and_finalize_continuity"
        ),
    ),
    Mutation(
        name="repo-runtime-elapsed-accumulation-bypass",
        path="evoom_guard/verifiers/repo_runtime_continuity.py",
        before=(
            "            self.elapsed_ms += observed.elapsed_ms\n"
            "        except RuntimeIdentityError as exc:\n"
            "            return None, RepoRuntimeContinuityFailure(\n"
        ),
        after=(
            "            self.elapsed_ms = observed.elapsed_ms\n"
            "        except RuntimeIdentityError as exc:\n"
            "            return None, RepoRuntimeContinuityFailure(\n"
        ),
        test=(
            "tests/test_repo_runtime_continuity_owner.py::"
            "test_capture_suite_and_pack_accumulate_elapsed_and_finalize_continuity"
        ),
    ),
    Mutation(
        name="repo-runtime-host-setup-overclaim",
        path="evoom_guard/verifiers/repo_runtime_continuity.py",
        before=(
            "            if self.request.container_mode\n"
            "            and not (\n"
            "                self.request.setup_configured\n"
            "                and self.request.trust_setup_on_host\n"
            "            )\n"
        ),
        after="            if self.request.container_mode\n",
        test=(
            "tests/test_repo_runtime_continuity_owner.py::"
            "test_delivery_never_overclaims_host_setup"
        ),
    ),
    Mutation(
        name="repo-runtime-suite-checkpoint-bypass",
        path="evoom_guard/verifiers/repo_runtime_continuity.py",
        before=(
            "        self._require_phase("
            "\"suite_verified\", \"verify after the verifier pack\")\n"
        ),
        after=(
            "        self._require_phase("
            "\"captured\", \"verify after the verifier pack\")\n"
        ),
        test=(
            "tests/test_repo_runtime_continuity_owner.py::"
            "test_pack_verification_cannot_skip_the_suite_checkpoint"
        ),
    ),
    Mutation(
        name="repo-runtime-sticky-failure-bypass",
        path="evoom_guard/verifiers/repo_runtime_continuity.py",
        before=(
            "        if self.failure is not None:\n"
            "            return self.failure\n"
            "        self._require_phase("
            "\"suite_verified\", \"verify after the verifier pack\")\n"
        ),
        after=(
            "        if False and self.failure is not None:\n"
            "            return self.failure\n"
            "        self._require_phase("
            "\"suite_verified\", \"verify after the verifier pack\")\n"
        ),
        test=(
            "tests/test_repo_runtime_continuity_owner.py::"
            "test_suite_failure_is_sticky_and_cannot_be_recovered_by_pack_check"
        ),
    ),
    Mutation(
        name="strict-baseline-setup-group-proof-bypass",
        path="evoom_guard/verifiers/repo_baseline.py",
        before=(
            "                    timeout=request.timeout,\n"
            "                    preexec_fn=(\n"
            "                        verifier._limits()\n"
            "                        if services.platform_name_provider() == \"posix\"\n"
            "                        else None\n"
            "                    ),\n"
            "                    require_process_group_cleanup_proof=(\n"
            "                        request.strict_harness\n"
            "                    ),\n"
        ),
        after=(
            "                    timeout=request.timeout,\n"
            "                    preexec_fn=(\n"
            "                        verifier._limits()\n"
            "                        if services.platform_name_provider() == \"posix\"\n"
            "                        else None\n"
            "                    ),\n"
            "                    require_process_group_cleanup_proof=False,\n"
        ),
        test=(
            "tests/test_strict_harness.py::"
            "test_strict_baseline_requires_group_proof_for_every_host_phase"
        ),
    ),
    Mutation(
        name="strict-baseline-suite-group-proof-bypass",
        path="evoom_guard/verifiers/repo_baseline.py",
        before=(
            "                preexec_fn=(\n"
            "                    verifier._limits()\n"
            "                    if services.platform_name_provider() == \"posix\"\n"
            "                    else None\n"
            "                ),\n"
            "                timeout=request.timeout,\n"
            "                require_process_group_cleanup_proof=(\n"
            "                    request.strict_harness\n"
            "                ),\n"
        ),
        after=(
            "                preexec_fn=(\n"
            "                    verifier._limits()\n"
            "                    if services.platform_name_provider() == \"posix\"\n"
            "                    else None\n"
            "                ),\n"
            "                timeout=request.timeout,\n"
            "                require_process_group_cleanup_proof=False,\n"
        ),
        test=(
            "tests/test_strict_harness.py::"
            "test_strict_baseline_requires_group_proof_for_every_host_phase"
        ),
    ),
    Mutation(
        name="repo-baseline-owned-allocation-bypass",
        path="evoom_guard/verifiers/repo_baseline.py",
        before=(
            "    workdir = _repository_workspace.allocate_owned_workspace(\n"
            "        prefix=\"evo_baseline_\",\n"
            "        create_workspace=services.workspace_factory_provider(),\n"
            "    )\n"
        ),
        after=(
            "    workdir = services.workspace_factory_provider()(\n"
            "        prefix=\"evo_baseline_\"\n"
            "    )\n"
        ),
        test=(
            "tests/test_repo_baseline_characterization.py::"
            "test_baseline_effect_order_trust_boundary_and_cleanup_are_frozen"
        ),
    ),
    Mutation(
        name="repo-baseline-active-primary-cleanup-bypass",
        path="evoom_guard/verifiers/repo_baseline.py",
        before="            primary=cleanup_primary,\n",
        after="            primary=None,\n",
        test=(
            "tests/test_repo_baseline_cross_commit_characterization.py::"
            "test_baseline_cleanup_failure_preserves_an_active_primary"
        ),
    ),
    Mutation(
        name="repo-baseline-caller-ambient-primary-bypass",
        path="evoom_guard/verifiers/repo_baseline.py",
        before="            primary=cleanup_primary,\n",
        after=(
            "            primary=__import__(\"sys\").exc_info()[1],\n"
        ),
        test=(
            "tests/test_repo_baseline_cross_commit_characterization.py::"
            "test_baseline_cleanup_ignores_callers_ambient_exception"
        ),
    ),
    Mutation(
        name="repo-baseline-command-alias-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "            repository_path=repo_path,\n"
            "            test_command=test_command,\n"
            "            setup_command=setup_command,\n"
        ),
        after=(
            "            repository_path=repo_path,\n"
            "            test_command=(\n"
            "                list(test_command) if test_command is not None else None\n"
            "            ),\n"
            "            setup_command=(\n"
            "                list(setup_command) if setup_command is not None else None\n"
            "            ),\n"
        ),
        test=(
            "tests/test_repo_baseline_cross_commit_characterization.py::"
            "test_baseline_commands_keep_caller_lists_live_until_historical_use"
        ),
    ),
    Mutation(
        name="repo-baseline-path-provider-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "            path_join_provider=lambda: cast(Any, os.path.join),\n"
        ),
        after=(
            "            path_join_provider=(\n"
            "                lambda join=cast(Any, os.path.join): join\n"
            "            ),\n"
        ),
        test=(
            "tests/test_repo_baseline_cross_commit_characterization.py::"
            "test_baseline_uses_guard_os_path_and_platform_at_each_historical_site"
        ),
    ),
    Mutation(
        name="repo-baseline-platform-provider-snapshot",
        path="evoom_guard/guard.py",
        before="            platform_name_provider=lambda: os.name,\n",
        after=(
            "            platform_name_provider=(\n"
            "                lambda platform_name=os.name: platform_name\n"
            "            ),\n"
        ),
        test=(
            "tests/test_repo_baseline_cross_commit_characterization.py::"
            "test_baseline_uses_guard_os_path_and_platform_at_each_historical_site"
        ),
    ),
    Mutation(
        name="repo-baseline-os-error-provider-snapshot",
        path="evoom_guard/guard.py",
        before="            os_error_provider=lambda: OSError,\n",
        after=(
            "            os_error_provider=(\n"
            "                lambda error=OSError: error\n"
            "            ),\n"
        ),
        test=(
            "tests/test_repo_baseline_cross_commit_characterization.py::"
            "test_baseline_resolves_operational_exception_matchers_at_catch_time"
        ),
    ),
    Mutation(
        name="repo-baseline-containment-error-provider-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "            containment_error_provider=(\n"
            "                lambda: _SubprocessContainmentError\n"
            "            ),\n"
        ),
        after=(
            "            containment_error_provider=(\n"
            "                lambda error=_SubprocessContainmentError: error\n"
            "            ),\n"
        ),
        test=(
            "tests/test_repo_baseline_cross_commit_characterization.py::"
            "test_baseline_resolves_operational_exception_matchers_at_catch_time"
        ),
    ),
    Mutation(
        name="repo-baseline-output-limit-error-provider-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "            output_limit_error_provider=(\n"
            "                lambda: _SubprocessOutputLimitExceeded\n"
            "            ),\n"
        ),
        after=(
            "            output_limit_error_provider=(\n"
            "                lambda error=_SubprocessOutputLimitExceeded: error\n"
            "            ),\n"
        ),
        test=(
            "tests/test_repo_baseline_cross_commit_characterization.py::"
            "test_baseline_resolves_operational_exception_matchers_at_catch_time"
        ),
    ),
    Mutation(
        name="repo-baseline-timeout-error-provider-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "            timeout_error_provider=lambda: "
            "subprocess.TimeoutExpired,\n"
        ),
        after=(
            "            timeout_error_provider=(\n"
            "                lambda error=subprocess.TimeoutExpired: error\n"
            "            ),\n"
        ),
        test=(
            "tests/test_repo_baseline_cross_commit_characterization.py::"
            "test_baseline_resolves_operational_exception_matchers_at_catch_time"
        ),
    ),
    Mutation(
        name="repo-baseline-setup-fidelity-error-live-rebinding",
        path="evoom_guard/guard.py",
        before=(
            "            setup_fidelity_error_provider="
            "lambda: SetupFidelityError,\n"
        ),
        after=(
            "            setup_fidelity_error_provider=lambda: getattr(\n"
            "                __import__(\n"
            "                    \"evoom_guard.verifiers.repo_verifier\",\n"
            "                    fromlist=[\"SetupFidelityError\"],\n"
            "                ),\n"
            "                \"SetupFidelityError\",\n"
            "            ),\n"
        ),
        test=(
            "tests/test_repo_baseline_cross_commit_characterization.py::"
            "test_baseline_snapshots_setup_fidelity_error_at_facade_entry"
        ),
    ),
    Mutation(
        name="subprocess-required-process-group-launch-bypass",
        path="evoom_guard/execution/process.py",
        before="        **process_group_popen_kwargs(),\n",
        after=(
            "        **({} if request.require_process_group_cleanup_proof "
            "else process_group_popen_kwargs()),\n"
        ),
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_execute_passes_the_process_group_contract_to_popen"
        ),
    ),
    Mutation(
        name="subprocess-reader-start-cleanup-bypass",
        path="evoom_guard/execution/process.py",
        before="        if process is not None:\n",
        after="        if False and process is not None:\n",
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_reader_start_failure_cleans_tree_and_preserves_primary"
        ),
    ),
    Mutation(
        name="subprocess-reader-start-tracking-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "            reader_start_attempts.append(reader)\n"
            "            reader.start()\n"
        ),
        after="            reader.start()\n",
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_reader_start_failure_cleans_tree_and_preserves_primary"
        ),
    ),
    Mutation(
        name="subprocess-reader-safe-close-proof-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "        safe_to_close = index >= len(stopped) or stopped[index]\n"
        ),
        after="        safe_to_close = True\n",
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_attempted_reader_without_join_proof_never_closes_its_pipe"
        ),
    ),
    Mutation(
        name="subprocess-live-reader-synchronous-close",
        path="evoom_guard/execution/process.py",
        before=(
            "    del streams  # Retained for the historical compatibility signature.\n"
            "    for reader in readers:\n"
        ),
        after=(
            "    for stream in streams:\n"
            "        stream.close()\n"
            "    for reader in readers:\n"
        ),
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_live_reader_pipe_is_never_closed_synchronously"
        ),
    ),
    Mutation(
        name="subprocess-reader-start-primary-exception-mask",
        path="evoom_guard/execution/process.py",
        before=(
            "                    tree_cleanup_result = "
            "_terminate_process_tree(process, limits)\n"
            "                except BaseException as cleanup_error:\n"
        ),
        after=(
            "                    tree_cleanup_result = "
            "_terminate_process_tree(process, limits)\n"
            "                except Exception as cleanup_error:\n"
        ),
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_reader_start_primary_survives_cleanup_baseexceptions"
        ),
    ),
    Mutation(
        name="subprocess-reader-join-primary-exception-mask",
        path="evoom_guard/execution/process.py",
        before=(
            "                    reader_cleanup_result = "
            "_join_attempted_pipe_readers(\n"
            "                        reader_start_attempts,\n"
            "                        streams,\n"
            "                        limits.reader_join_seconds,\n"
            "                    )\n"
            "                except BaseException as cleanup_error:\n"
        ),
        after=(
            "                    reader_cleanup_result = "
            "_join_attempted_pipe_readers(\n"
            "                        reader_start_attempts,\n"
            "                        streams,\n"
            "                        limits.reader_join_seconds,\n"
            "                    )\n"
            "                except Exception as cleanup_error:\n"
        ),
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_post_start_baseexception_cleans_even_completed_tree_without_masking"
        ),
    ),
    Mutation(
        name="subprocess-abort-tree-exact-proof-bypass",
        path="evoom_guard/execution/process.py",
        before="                    if tree_cleanup_result is True:\n",
        after="                    if tree_cleanup_result:\n",
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_abort_cleanup_single_outcomes_are_observable"
        ),
    ),
    Mutation(
        name="subprocess-abort-tree-raised-observability-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "                except BaseException as cleanup_error:\n"
            "                    _note_abort_cleanup_failure(\n"
            "                        primary,\n"
            '                        "Managed subprocess-tree abort cleanup raised while "\n'
            '                        "preserving the primary exception: "\n'
            "                        + _abort_cleanup_exception_summary(cleanup_error),\n"
            "                    )\n"
        ),
        after=(
            "                except BaseException as cleanup_error:\n"
            "                    pass\n"
        ),
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_abort_cleanup_single_outcomes_are_observable"
        ),
    ),
    Mutation(
        name="subprocess-abort-reader-exact-proof-bypass",
        path="evoom_guard/execution/process.py",
        before="                    if reader_cleanup_result is True:\n",
        after="                    if reader_cleanup_result:\n",
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_abort_cleanup_single_outcomes_are_observable"
        ),
    ),
    Mutation(
        name="subprocess-abort-reader-raised-observability-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "                except BaseException as cleanup_error:\n"
            "                    _note_abort_cleanup_failure(\n"
            "                        primary,\n"
            '                        "Managed subprocess output-reader abort cleanup raised "\n'
            '                        "while preserving the primary exception: "\n'
            "                        + _abort_cleanup_exception_summary(cleanup_error),\n"
            "                    )\n"
        ),
        after=(
            "                except BaseException as cleanup_error:\n"
            "                    pass\n"
        ),
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_abort_cleanup_single_outcomes_are_observable"
        ),
    ),
    Mutation(
        name="subprocess-abort-second-cleanup-stage-bypass",
        path="evoom_guard/execution/process.py",
        before="            if not reader_cleanup_proven:\n",
        after=(
            "            if tree_cleanup_proven and not reader_cleanup_proven:\n"
        ),
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_abort_cleanup_preserves_two_failures_and_runs_both_stages"
        ),
    ),
    Mutation(
        name="subprocess-abort-note-legacy-fallback-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "    try:\n"
            '        namespace = object.__getattribute__(primary, "__dict__")\n'
            '        notes = namespace.get("__notes__")\n'
            "        if type(notes) is list:\n"
            "            notes.append(note)\n"
            "        else:\n"
            '            namespace["__notes__"] = [note]\n'
            "    except BaseException:\n"
            "        pass\n"
        ),
        after="    return\n",
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_abort_cleanup_note_uses_safe_legacy_fallback"
        ),
    ),
    Mutation(
        name="subprocess-tree-cleanup-proof-state-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "            tree_cleanup_proven = True\n"
            "            if not join_pipe_readers("
            "readers, streams, limits.reader_join_seconds):\n"
        ),
        after=(
            "            if not join_pipe_readers("
            "readers, streams, limits.reader_join_seconds):\n"
        ),
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_post_poll_overflow_stops_before_normal_reader_join"
        ),
    ),
    Mutation(
        name="subprocess-reader-cleanup-proof-state-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "            reader_cleanup_proven = True\n"
            "\n"
            "        # Re-read the clock after process and reader startup"
        ),
        after="\n        # Re-read the clock after process and reader startup",
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_post_poll_overflow_stops_before_normal_reader_join"
        ),
    ),
    Mutation(
        name="subprocess-output-cap-bypass",
        path="evoom_guard/execution/process.py",
        before="                self._exceeded = True\n",
        after="                self._exceeded = False\n",
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_bounded_output_marks_any_truncated_bytes_as_exceeded"
        ),
    ),
    Mutation(
        name="subprocess-live-output-check-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "        while process.poll() is None:\n"
            "            if capture.exceeded:\n"
            '                stop_and_prove("subprocess output limit reached")\n'
        ),
        after=(
            "        while process.poll() is None:\n"
            "            if False and capture.exceeded:\n"
            '                stop_and_prove("subprocess output limit reached")\n'
        ),
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_live_output_overflow_is_stopped_before_process_completion"
        ),
    ),
    Mutation(
        name="subprocess-post-poll-output-check-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "        if capture.exceeded:\n"
            '            stop_and_prove("subprocess output limit reached")\n'
            "            raise ProcessOutputLimitExceeded(limits.max_output_bytes)\n"
            "        if not join_pipe_readers("
            "readers, streams, limits.reader_join_seconds):\n"
        ),
        after=(
            "        if False and capture.exceeded:\n"
            '            stop_and_prove("subprocess output limit reached")\n'
            "            raise ProcessOutputLimitExceeded(limits.max_output_bytes)\n"
            "        if not join_pipe_readers("
            "readers, streams, limits.reader_join_seconds):\n"
        ),
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_post_poll_overflow_stops_before_normal_reader_join"
        ),
    ),
    Mutation(
        name="subprocess-post-join-output-check-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "        if capture.exceeded:\n"
            '            stop_and_prove("subprocess output limit reached")\n'
            "            raise ProcessOutputLimitExceeded(limits.max_output_bytes)\n"
            '        if os.name == "posix":\n'
        ),
        after=(
            "        if False and capture.exceeded:\n"
            '            stop_and_prove("subprocess output limit reached")\n'
            "            raise ProcessOutputLimitExceeded(limits.max_output_bytes)\n"
            '        if os.name == "posix":\n'
        ),
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_post_join_overflow_is_not_returned_as_success"
        ),
    ),
    Mutation(
        name="subprocess-deadline-check-bypass",
        path="evoom_guard/execution/process.py",
        before="            if time.monotonic() >= deadline:\n",
        after="            if False and time.monotonic() >= deadline:\n",
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_deadline_interrupts_a_self_terminating_process"
        ),
    ),
    Mutation(
        name="subprocess-cleanup-proof-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "            if not _terminate_process_tree(process, limits):\n"
            "                raise ProcessContainmentError("
            'f"{reason}; could not prove subprocess-tree cleanup")\n'
        ),
        after=(
            "            if False and not _terminate_process_tree(process, limits):\n"
            "                raise ProcessContainmentError("
            'f"{reason}; could not prove subprocess-tree cleanup")\n'
        ),
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_cleanup_failure_preempts_the_triggering_error"
        ),
    ),
    Mutation(
        name="subprocess-group-kwargs-use-bypass",
        path="evoom_guard/execution/process.py",
        before="        **process_group_popen_kwargs(),\n",
        after="        **{},\n",
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_execute_passes_the_process_group_contract_to_popen"
        ),
    ),
    Mutation(
        name="subprocess-posix-group-contract-bypass",
        path="evoom_guard/execution/process.py",
        before='        return {"start_new_session": True}\n',
        after='        return {"start_new_session": False}\n',
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_posix_process_group_contract"
        ),
    ),
    Mutation(
        name="subprocess-windows-group-contract-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            '        return {"creationflags": '
            'int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))}\n'
        ),
        after='        return {"creationflags": 0}\n',
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_windows_process_group_contract"
        ),
    ),
    Mutation(
        name="diff-coverage-isolated-launch-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "        interpreter,\n"
            "        *interpreter_options,\n"
            '        "-I",\n'
            '        "-c",\n'
            "        _TRUSTED_COVERAGE_LAUNCHER,\n"
            '        "run",\n'
        ),
        after=(
            "        interpreter,\n"
            "        *interpreter_options,\n"
            '        "-c",\n'
            "        _TRUSTED_COVERAGE_LAUNCHER,\n"
            '        "run",\n'
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_candidate_coverage_module_and_config_cannot_disable_measurement"
        ),
    ),
    Mutation(
        name="diff-coverage-repository-config-bypass",
        path="evoom_guard/evidence.py",
        before=(
            '        "run",\n'
            '        f"--rcfile={os.devnull}",\n'
        ),
        after=(
            '        "run",\n'
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_candidate_coverage_module_and_config_cannot_disable_measurement"
        ),
    ),
    Mutation(
        name="diff-coverage-report-isolated-launch-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "        interpreter,\n"
            "        *interpreter_options,\n"
            '        "-I",\n'
            '        "-c",\n'
            "        _TRUSTED_COVERAGE_LAUNCHER,\n"
            '        "json",\n'
        ),
        after=(
            "        interpreter,\n"
            "        *interpreter_options,\n"
            '        "-c",\n'
            "        _TRUSTED_COVERAGE_LAUNCHER,\n"
            '        "json",\n'
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_commands_use_isolated_python_and_ignore_repo_config"
        ),
    ),
    Mutation(
        name="diff-coverage-report-config-bypass",
        path="evoom_guard/evidence.py",
        before=(
            '        "json",\n'
            '        f"--rcfile={os.devnull}",\n'
        ),
        after='        "json",\n',
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_commands_use_isolated_python_and_ignore_repo_config"
        ),
    ),
    Mutation(
        name="diff-coverage-wrapper-prefix-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "    return [\n"
            "        *prefix,\n"
            "        interpreter,\n"
            "        *interpreter_options,\n"
            '        "-I",\n'
            '        "-c",\n'
            "        _TRUSTED_COVERAGE_LAUNCHER,\n"
            '        "run",\n'
        ),
        after=(
            "    return [\n"
            "        interpreter,\n"
            "        *interpreter_options,\n"
            '        "-I",\n'
            '        "-c",\n'
            "        _TRUSTED_COVERAGE_LAUNCHER,\n"
            '        "run",\n'
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_command_preserves_trusted_interpreter_and_wrapper_prefixes"
        ),
    ),
    Mutation(
        name="diff-coverage-report-environment-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "    return [\n"
            "        *prefix,\n"
            "        interpreter,\n"
            "        *interpreter_options,\n"
            '        "-I",\n'
            '        "-c",\n'
            "        _TRUSTED_COVERAGE_LAUNCHER,\n"
            '        "json",\n'
        ),
        after=(
            "    return [\n"
            "        sys.executable,\n"
            '        "-I",\n'
            '        "-c",\n'
            "        _TRUSTED_COVERAGE_LAUNCHER,\n"
            '        "json",\n'
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_command_preserves_trusted_interpreter_and_wrapper_prefixes"
        ),
    ),
    Mutation(
        name="diff-coverage-owned-allocation-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "    workdir = _repository_workspace.allocate_owned_workspace(\n"
            "        prefix=\"evo_guard_cov_\",\n"
            "        create_workspace=tempfile.mkdtemp,\n"
            "    )\n"
        ),
        after="    workdir = tempfile.mkdtemp(prefix=\"evo_guard_cov_\")\n",
        test=(
            "tests/test_evidence_containment.py::"
            "test_coverage_workspace_cleanup_failure_is_explicitly_unmeasured"
        ),
    ),
    Mutation(
        name="diff-coverage-active-primary-cleanup-bypass",
        path="evoom_guard/evidence.py",
        before="                primary=primary,\n",
        after="                primary=None,\n",
        test=(
            "tests/test_evidence_containment.py::"
            "test_coverage_cleanup_preserves_exact_active_primary_and_notes_secondary"
        ),
    ),
    Mutation(
        name="diff-coverage-success-after-cleanup-failure-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "            cleanup_failure_note = "
            "_coverage_cleanup_failure_note(cleanup_error)\n"
        ),
        after="            cleanup_failure_note = None\n",
        test=(
            "tests/test_evidence_containment.py::"
            "test_successful_coverage_measurement_is_not_returned_when_cleanup_is_unproven"
        ),
    ),
    Mutation(
        name="diff-coverage-hostile-cleanup-diagnostic-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "        + _coverage_cleanup_exception_summary(error)\n"
        ),
        after="        + f\"{type(error).__name__}: {error}\"\n",
        test=(
            "tests/test_evidence_containment.py::"
            "test_coverage_cleanup_hostile_formatting_cannot_replace_unmeasured_result"
        ),
    ),
    Mutation(
        name="diff-coverage-caller-ambient-primary-bypass",
        path="evoom_guard/evidence.py",
        before="        primary = cleanup_primary\n",
        after="        primary = sys.exc_info()[1]\n",
        test=(
            "tests/test_evidence_containment.py::"
            "test_coverage_cleanup_ignores_caller_ambient_exception"
        ),
    ),
    Mutation(
        name="diff-coverage-required-unmeasured-pass-bypass",
        path="evoom_guard/application/decision_gates.py",
        before='    if coverage_evidence.get("measured") is not True:\n',
        after=(
            '    if False and coverage_evidence.get("measured") '
            'is not True:\n'
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_required_coverage_fails_closed_when_measurement_is_unavailable"
        ),
    ),
    Mutation(
        name="diff-coverage-required-clean-run-bypass",
        path="evoom_guard/application/repo_finalization.py",
        before=(
            "            require_passing_suite=(\n"
            "                core_verdict_passed "
            "and request.min_diff_coverage is not None\n"
            "            ),\n"
        ),
        after="            require_passing_suite=False,\n",
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_required_coverage_rejects_a_wrapped_suite_that_does_not_pass"
        ),
    ),
    Mutation(
        name="demonstrated-fix-gate-bypass",
        path="evoom_guard/application/decision_gates.py",
        before=(
            "    if (\n"
            "        require_demonstrated_fix\n"
            "        and decision.verdict == PASS\n"
            '        and baseline_evidence["repair_effect"] != "demonstrated"\n'
            "    ):\n"
        ),
        after=(
            "    if False and (\n"
            "        require_demonstrated_fix\n"
            "        and decision.verdict == PASS\n"
            '        and baseline_evidence["repair_effect"] != "demonstrated"\n'
            "    ):\n"
        ),
        test=(
            "tests/test_decision_gates_application.py::"
            "test_green_baseline_demotes_with_exact_read_order_and_reason"
        ),
    ),
    Mutation(
        name="demonstrated-fix-prior-decision-bypass",
        path="evoom_guard/application/decision_gates.py",
        before=(
            "    if (\n"
            "        require_demonstrated_fix\n"
            "        and decision.verdict == PASS\n"
            '        and baseline_evidence["repair_effect"] != "demonstrated"\n'
            "    ):\n"
        ),
        after=(
            "    if (\n"
            "        require_demonstrated_fix\n"
            '        and baseline_evidence["repair_effect"] != "demonstrated"\n'
            "    ):\n"
        ),
        test=(
            "tests/test_decision_gates_application.py::"
            "test_demonstrated_fix_optional_or_non_pass_returns_identity_without_reads"
        ),
    ),
    Mutation(
        name="demonstrated-fix-effect-comparison-inversion",
        path="evoom_guard/application/decision_gates.py",
        before=(
            '        and baseline_evidence["repair_effect"] != "demonstrated"\n'
        ),
        after=(
            '        and baseline_evidence["repair_effect"] == "demonstrated"\n'
        ),
        test=(
            "tests/test_decision_gates_application.py::"
            "test_demonstrated_repair_effect_preserves_pass_without_verdict_read"
        ),
    ),
    Mutation(
        name="assurance-eager-falsey-shortfall-bypass",
        path="evoom_guard/application/decision_gates.py",
        before=(
            "        if (\n"
            "            shortfall is not None\n"
            "            and execution_state == EXECUTION_COMPLETED\n"
            "            and decision.verdict == PASS\n"
            "        ):\n"
        ),
        after=(
            "        if (\n"
            "            shortfall\n"
            "            and execution_state == EXECUTION_COMPLETED\n"
            "            and decision.verdict == PASS\n"
            "        ):\n"
        ),
        test=(
            "tests/test_decision_gates_application.py::"
            "test_empty_assurance_shortfall_is_still_a_demotion"
        ),
    ),
    Mutation(
        name="assurance-lazy-falsey-shortfall-bypass",
        path="evoom_guard/application/decision_gates.py",
        before=(
            "        if shortfall is not None:\n"
            "            return GuardDecision(\n"
        ),
        after=(
            "        if shortfall:\n"
            "            return GuardDecision(\n"
        ),
        test=(
            "tests/test_decision_gates_application.py::"
            "test_empty_assurance_shortfall_is_still_a_demotion"
        ),
    ),
    Mutation(
        name="assurance-eager-prior-decision-bypass",
        path="evoom_guard/application/decision_gates.py",
        before=(
            "        if (\n"
            "            shortfall is not None\n"
            "            and execution_state == EXECUTION_COMPLETED\n"
            "            and decision.verdict == PASS\n"
            "        ):\n"
        ),
        after=(
            "        if (\n"
            "            shortfall is not None\n"
            "            and execution_state == EXECUTION_COMPLETED\n"
            "        ):\n"
        ),
        test=(
            "tests/test_decision_gates_application.py::"
            "test_blackbox_assurance_gate_preserves_completed_prior_failure"
        ),
    ),
    Mutation(
        name="assurance-lazy-prior-decision-bypass",
        path="evoom_guard/application/decision_gates.py",
        before=(
            "    if (\n"
            "        execution_requested\n"
            "        and execution_state == EXECUTION_COMPLETED\n"
            "        and decision.verdict == PASS\n"
            "    ):\n"
        ),
        after=(
            "    if (\n"
            "        execution_requested\n"
            "        and execution_state == EXECUTION_COMPLETED\n"
            "    ):\n"
        ),
        test=(
            "tests/test_decision_gates_application.py::"
            "test_repo_assurance_gate_is_lazy_until_requested_completed_pass"
        ),
    ),
    Mutation(
        name="assurance-eager-completion-bypass",
        path="evoom_guard/application/decision_gates.py",
        before=(
            "        if (\n"
            "            shortfall is not None\n"
            "            and execution_state == EXECUTION_COMPLETED\n"
            "            and decision.verdict == PASS\n"
            "        ):\n"
        ),
        after=(
            "        if (\n"
            "            shortfall is not None\n"
            "            and decision.verdict == PASS\n"
            "        ):\n"
        ),
        test=(
            "tests/test_decision_gates_application.py::"
            "test_blackbox_assurance_gate_does_not_demote_incomplete_pass"
        ),
    ),
    Mutation(
        name="assurance-lazy-completion-bypass",
        path="evoom_guard/application/decision_gates.py",
        before=(
            "    if (\n"
            "        execution_requested\n"
            "        and execution_state == EXECUTION_COMPLETED\n"
            "        and decision.verdict == PASS\n"
            "    ):\n"
        ),
        after=(
            "    if (\n"
            "        execution_requested\n"
            "        and decision.verdict == PASS\n"
            "    ):\n"
        ),
        test=(
            "tests/test_decision_gates_application.py::"
            "test_repo_assurance_gate_is_lazy_until_requested_completed_pass"
        ),
    ),
    Mutation(
        name="assurance-repo-lazy-mode-inversion",
        path="evoom_guard/application/repo_finalization.py",
        before=(
            "        shortfall_evaluator="
            "services.assurance_shortfall_provider(),\n"
            "        eager_shortfall=False,\n"
        ),
        after=(
            "        shortfall_evaluator="
            "services.assurance_shortfall_provider(),\n"
            "        eager_shortfall=True,\n"
        ),
        test=(
            "tests/test_assurance_decision_gate_characterization.py::"
            "test_repo_gate_is_lazy_and_follows_attestation_and_profile"
        ),
    ),
    Mutation(
        name="assurance-blackbox-eager-mode-inversion",
        path="evoom_guard/application/blackbox_finalization.py",
        before=(
            "        shortfall_evaluator="
            "services.assurance_shortfall_provider(),\n"
            "        eager_shortfall=True,\n"
        ),
        after=(
            "        shortfall_evaluator="
            "services.assurance_shortfall_provider(),\n"
            "        eager_shortfall=False,\n"
        ),
        test=(
            "tests/test_assurance_decision_gate_characterization.py::"
            "test_blackbox_gate_is_eager_but_preserves_prior_decisions"
        ),
    ),
    Mutation(
        name="blackbox-finalization-candidate-invocation-proof-bypass",
        path="evoom_guard/application/blackbox_finalization.py",
        before="    gradeable = bool(result.ran and invocation_observed)\n",
        after="    gradeable = bool(result.ran)\n",
        test=(
            "tests/test_blackbox_composite_contract.py::"
            "test_vacuous_blackbox_pack_is_refused_and_repo_phase_is_not_run"
        ),
    ),
    Mutation(
        name="blackbox-finalization-composite-repo-phase-bypass",
        path="evoom_guard/application/blackbox_finalization.py",
        before=(
            "    if not request.blackbox_only and gradeable and result.passed:\n"
        ),
        after=(
            "    if False and not request.blackbox_only "
            "and gradeable and result.passed:\n"
        ),
        test=(
            "tests/test_blackbox_composite_contract.py::"
            "test_completed_composite_sums_counts_and_uses_weakest_report_channel"
        ),
    ),
    Mutation(
        name="blackbox-finalization-live-profile-provider-snapshot",
        path="evoom_guard/guard.py",
        before="                assurance_builder_provider=lambda: _assurance_profile,\n",
        after=(
            "                assurance_builder_provider=(\n"
            "                    lambda builder=_assurance_profile: builder\n"
            "                ),\n"
        ),
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_finalization_helpers_are_resolved_after_blackbox_cleanup"
        ),
    ),
    Mutation(
        name="blackbox-finalization-live-shortfall-provider-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "                assurance_shortfall_provider=(\n"
            "                    lambda: _assurance_shortfall\n"
            "                ),\n"
        ),
        after=(
            "                assurance_shortfall_provider=(\n"
            "                    lambda evaluator=_assurance_shortfall: "
            "evaluator\n"
            "                ),\n"
        ),
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_finalization_helpers_are_resolved_after_blackbox_cleanup"
        ),
    ),
    Mutation(
        name="blackbox-finalization-live-attestation-provider-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "                attestation_builder_provider=(\n"
            "                    lambda: _build_attestation\n"
            "                ),\n"
        ),
        after=(
            "                attestation_builder_provider=(\n"
            "                    lambda builder=_build_attestation: "
            "builder\n"
            "                ),\n"
        ),
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_finalization_helpers_are_resolved_after_blackbox_cleanup"
        ),
    ),
    Mutation(
        name="blackbox-finalization-live-pipeline-provider-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "                verification_pipeline_provider=(\n"
            "                    lambda: VerificationPipeline\n"
            "                ),\n"
        ),
        after=(
            "                verification_pipeline_provider=(\n"
            "                    lambda pipeline=VerificationPipeline: pipeline\n"
            "                ),\n"
        ),
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_verification_pipeline_lookup_remains_live_at_composition"
        ),
    ),
    Mutation(
        name="blackbox-finalization-live-decision-provider-snapshot",
        path="evoom_guard/guard.py",
        before="                guard_decision_provider=lambda: GuardDecision,\n",
        after=(
            "                guard_decision_provider=(\n"
            "                    lambda decision=GuardDecision: decision\n"
            "                ),\n"
        ),
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_guard_decision_reexport_and_lookup_remain_live_at_composition"
        ),
    ),
    Mutation(
        name="blackbox-finalization-result-factory-provider-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "                guard_result_factory_provider=lambda: GuardResult,\n"
        ),
        after=(
            "                guard_result_factory_provider=(\n"
            "                    lambda factory=GuardResult: factory\n"
            "                ),\n"
        ),
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_guard_result_factory_is_snapshotted_before_final_wire_reads"
        ),
    ),
    Mutation(
        name="blackbox-finalization-guard-result-late-global-lookup",
        path="evoom_guard/guard.py",
        before="            finalization_bx.guard_result_factory(\n",
        after="            GuardResult(\n",
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_guard_result_factory_is_snapshotted_before_final_wire_reads"
        ),
    ),
    Mutation(
        name="blackbox-finalization-decision-projection-order-inversion",
        path="evoom_guard/application/blackbox_finalization.py",
        before=(
            "    final_verdict = decision.verdict\n"
            "    final_reason_code = decision.reason_code\n"
            "    final_reason = decision.reason\n"
        ),
        after=(
            "    final_reason_code = decision.reason_code\n"
            "    final_verdict = decision.verdict\n"
            "    final_reason = decision.reason\n"
        ),
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_guard_result_factory_is_snapshotted_before_final_wire_reads"
        ),
    ),
    Mutation(
        name="blackbox-finalization-pass-decision-reread",
        path="evoom_guard/application/blackbox_finalization.py",
        before=(
            '    passed = final_verdict == decision_symbol("PASS")\n'
        ),
        after='    passed = decision.verdict == decision_symbol("PASS")\n',
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_guard_result_factory_is_snapshotted_before_final_wire_reads"
        ),
    ),
    Mutation(
        name="blackbox-finalization-facade-verdict-reread",
        path="evoom_guard/guard.py",
        before="                verdict=finalization_bx.verdict,\n",
        after="                verdict=finalization_bx.decision.verdict,\n",
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_guard_result_factory_is_snapshotted_before_final_wire_reads"
        ),
    ),
    Mutation(
        name="blackbox-finalization-facade-reason-reread",
        path="evoom_guard/guard.py",
        before="                reason=finalization_bx.reason,\n",
        after="                reason=finalization_bx.decision.reason,\n",
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_guard_result_factory_is_snapshotted_before_final_wire_reads"
        ),
    ),
    Mutation(
        name="blackbox-finalization-facade-reason-code-reread",
        path="evoom_guard/guard.py",
        before="                reason_code=finalization_bx.reason_code,\n",
        after=(
            "                reason_code="
            "finalization_bx.decision.reason_code,\n"
        ),
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_guard_result_factory_is_snapshotted_before_final_wire_reads"
        ),
    ),
    Mutation(
        name="blackbox-finalization-runtime-cast-global-lookup",
        path="evoom_guard/guard.py",
        before=(
            "        return cast(\n"
            '            "GuardResult",\n'
            "            finalization_bx.guard_result_factory(\n"
        ),
        after=(
            "        return cast(\n"
            "            GuardResult,\n"
            "            finalization_bx.guard_result_factory(\n"
        ),
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_attestation_can_delete_guard_result_after_callable_snapshot"
        ),
    ),
    Mutation(
        name="blackbox-finalization-live-pass-symbol-snapshot",
        path="evoom_guard/guard.py",
        before='        "PASS": lambda: PASS,\n',
        after='        "PASS": lambda value=PASS: value,\n',
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_blackbox_decision_vocabulary_remains_live_after_risk_effect"
        ),
    ),
    Mutation(
        name="blackbox-finalization-live-fail-symbol-snapshot",
        path="evoom_guard/guard.py",
        before='        "FAIL": lambda: FAIL,\n',
        after='        "FAIL": lambda value=FAIL: value,\n',
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_blackbox_decision_vocabulary_remains_live_after_risk_effect"
        ),
    ),
    Mutation(
        name="blackbox-finalization-live-error-symbol-snapshot",
        path="evoom_guard/guard.py",
        before='        "ERROR": lambda: ERROR,\n',
        after='        "ERROR": lambda value=ERROR: value,\n',
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_blackbox_decision_vocabulary_remains_live_after_risk_effect"
        ),
    ),
    Mutation(
        name="blackbox-finalization-live-tampered-symbol-snapshot",
        path="evoom_guard/guard.py",
        before='        "TAMPERED": lambda: TAMPERED,\n',
        after='        "TAMPERED": lambda value=TAMPERED: value,\n',
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_blackbox_decision_vocabulary_remains_live_after_risk_effect"
        ),
    ),
    Mutation(
        name="blackbox-finalization-live-pass-reason-snapshot",
        path="evoom_guard/guard.py",
        before=(
            '        "REASON_TESTS_PASSED": lambda: '
            "REASON_TESTS_PASSED,\n"
        ),
        after=(
            '        "REASON_TESTS_PASSED": lambda value='
            "REASON_TESTS_PASSED: value,\n"
        ),
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_blackbox_decision_vocabulary_remains_live_after_risk_effect"
        ),
    ),
    Mutation(
        name="blackbox-finalization-live-timeout-reason-snapshot",
        path="evoom_guard/guard.py",
        before=(
            '        "REASON_TEST_TIMEOUT": lambda: REASON_TEST_TIMEOUT,\n'
        ),
        after=(
            '        "REASON_TEST_TIMEOUT": lambda value='
            "REASON_TEST_TIMEOUT: value,\n"
        ),
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_blackbox_decision_vocabulary_remains_live_after_risk_effect"
        ),
    ),
    Mutation(
        name="blackbox-finalization-live-execution-symbol-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "            lambda: EXECUTION_STARTED_INCOMPLETE\n"
        ),
        after=(
            "            lambda value=EXECUTION_STARTED_INCOMPLETE: value\n"
        ),
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_execution_vocabulary_remains_live_after_composed_repo_effect"
        ),
    ),
    Mutation(
        name="blackbox-finalization-live-outcome-policy-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "                outcome_reason_policy_provider="
            "lambda: _OUTCOME_REASON,\n"
        ),
        after=(
            "                outcome_reason_policy_provider=(\n"
            "                    lambda policy=_OUTCOME_REASON: policy\n"
            "                ),\n"
        ),
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_repo_outcome_policies_remain_live_after_composed_repo_effect"
        ),
    ),
    Mutation(
        name="blackbox-finalization-live-tamper-policy-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "                tamper_outcome_reason_policy_provider=(\n"
            "                    lambda: _TAMPER_OUTCOME_REASON\n"
            "                ),\n"
        ),
        after=(
            "                tamper_outcome_reason_policy_provider=(\n"
            "                    lambda policy=_TAMPER_OUTCOME_REASON: policy\n"
            "                ),\n"
        ),
        test=(
            "tests/test_blackbox_finalization_characterization.py::"
            "test_repo_outcome_policies_remain_live_after_composed_repo_effect"
        ),
    ),
    Mutation(
        name="verification-pipeline-repo-composer-bypass",
        path="evoom_guard/application/pipeline.py",
        before="                has_changes=has_changes,\n",
        after="                has_changes=True,\n",
        test=(
            "tests/test_verification_pipeline.py::"
            "test_no_changes_factory_retains_the_frozen_reason"
        ),
    ),
    Mutation(
        name="verification-pipeline-diff-gate-bypass",
        path="evoom_guard/application/pipeline.py",
        before=(
            "        return VerificationPipeline(\n"
            "            apply_diff_coverage_gate(\n"
            "                self.decision,\n"
            "                coverage_evidence=coverage_evidence,\n"
            "                min_diff_coverage=min_diff_coverage,\n"
            "            )\n"
            "        )\n"
        ),
        after="        return VerificationPipeline(self.decision)\n",
        test=(
            "tests/test_verification_pipeline.py::"
            "test_coverage_failure_remains_authoritative_through_later_lazy_gates"
        ),
    ),
    Mutation(
        name="verification-pipeline-demonstrated-fix-gate-bypass",
        path="evoom_guard/application/pipeline.py",
        before=(
            "        return VerificationPipeline(\n"
            "            apply_demonstrated_fix_gate(\n"
            "                self.decision,\n"
            "                baseline_evidence=baseline_evidence,\n"
            "                require_demonstrated_fix=require_demonstrated_fix,\n"
            "            )\n"
            "        )\n"
        ),
        after="        return VerificationPipeline(self.decision)\n",
        test=(
            "tests/test_verification_pipeline.py::"
            "test_demonstrated_fix_failure_precedes_lazy_assurance"
        ),
    ),
    Mutation(
        name="verification-pipeline-assurance-gate-bypass",
        path="evoom_guard/application/pipeline.py",
        before=(
            "        return VerificationPipeline(\n"
            "            apply_assurance_gate(\n"
            "                self.decision,\n"
            "                assurance=assurance,\n"
            "                execution_state=execution_state,\n"
            "                execution_requested=execution_requested,\n"
            "                require_report_integrity=require_report_integrity,\n"
            "                require_candidate_isolation=require_candidate_isolation,\n"
            "                shortfall_evaluator=shortfall_evaluator,\n"
            "                eager_shortfall=eager_shortfall,\n"
            "            )\n"
            "        )\n"
        ),
        after="        return VerificationPipeline(self.decision)\n",
        test=(
            "tests/test_verification_pipeline.py::"
            "test_assurance_is_the_final_demotion_after_prior_gates_pass"
        ),
    ),
    Mutation(
        name="diff-coverage-cross-drive-path-crash",
        path="evoom_guard/evidence.py",
        before=(
            "    except (OSError, ValueError):\n"
            "        return None\n"
        ),
        after=(
            "    except OSError:\n"
            "        return None\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_external_or_cross_drive_coverage_paths_are_ignored_fail_closed"
        ),
    ),
    Mutation(
        name="diff-coverage-external-path-acceptance",
        path="evoom_guard/evidence.py",
        before="    return normalized if is_safe_relpath(normalized) else None\n",
        after="    return normalized\n",
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_path_normalization_accepts_only_repo_relative_paths"
        ),
    ),
    Mutation(
        name="diff-coverage-baseline-effect-ordering-bypass",
        path="evoom_guard/application/repo_finalization.py",
        before=(
            "        elif (\n"
            '            baseline_info.get("verdict") == "FAIL"\n'
            "            and candidate_suite_passed\n"
            "        ):\n"
        ),
        after=(
            "        elif (\n"
            '            baseline_info.get("verdict") == "FAIL"\n'
            "            and verdict == PASS\n"
            "        ):\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_baseline_effect_survives_a_later_coverage_gate_demotion"
        ),
    ),
    Mutation(
        name="diff-coverage-record-baseline-ordering-bypass",
        path="evoom_guard/record_verifier.py",
        before=(
            "        candidate_suite_passed = "
            "_repo_suite_pass_evidence(record, attestation)\n"
        ),
        after='        candidate_suite_passed = verdict == "PASS"\n',
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_baseline_effect_survives_a_later_coverage_gate_demotion"
        ),
    ),
    Mutation(
        name="repo-pack-baseline-phase-selection-bypass",
        path="evoom_guard/application/repo_finalization.py",
        before=(
            "    candidate_suite_passed = (\n"
            "        repo_suite_pass_value is True\n"
            "        if repo_suite_completed\n"
            "        else core_verdict_passed\n"
            "    )\n"
        ),
        after="    candidate_suite_passed = core_verdict_passed\n",
        test=(
            "tests/test_record_verifier.py::"
            "test_pack_failure_preserves_repo_suite_baseline_effect"
        ),
    ),
    Mutation(
        name="repo-finalization-baseline-after-coverage-bypass",
        path="evoom_guard/application/repo_finalization.py",
        before=(
            "        and candidate_suite_completed\n"
            '        and request.isolation == "subprocess"\n'
        ),
        after=(
            "        and candidate_suite_completed\n"
            "        and verdict == PASS\n"
            '        and request.isolation == "subprocess"\n'
        ),
        test=(
            "tests/test_repo_finalization_characterization.py::"
            "test_coverage_demotion_does_not_skip_baseline"
        ),
    ),
    Mutation(
        name="repo-finalization-live-baseline-provider-snapshot",
        path="evoom_guard/guard.py",
        before="            baseline_runner_provider=lambda: _run_baseline_suite,\n",
        after=(
            "            baseline_runner_provider=(\n"
            "                lambda runner=_run_baseline_suite: runner\n"
            "            ),\n"
        ),
        test=(
            "tests/test_repo_finalization_characterization.py::"
            "test_repo_finalization_preserves_live_provider_lookup"
        ),
    ),
    Mutation(
        name="repo-finalization-live-attestation-provider-snapshot",
        path="evoom_guard/guard.py",
        before="            attestation_builder_provider=lambda: _build_attestation,\n",
        after=(
            "            attestation_builder_provider=(\n"
            "                lambda builder=_build_attestation: builder\n"
            "            ),\n"
        ),
        test=(
            "tests/test_repo_finalization_characterization.py::"
            "test_repo_finalization_preserves_live_provider_lookup"
        ),
    ),
    Mutation(
        name="repo-finalization-live-profile-provider-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "            runtime_assurance_builder_provider="
            "lambda: _assurance_profile,\n"
        ),
        after=(
            "            runtime_assurance_builder_provider=(\n"
            "                lambda builder=_assurance_profile: builder\n"
            "            ),\n"
        ),
        test=(
            "tests/test_repo_finalization_characterization.py::"
            "test_repo_finalization_preserves_live_provider_lookup"
        ),
    ),
    Mutation(
        name="repo-finalization-live-shortfall-provider-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "            assurance_shortfall_provider="
            "lambda: _assurance_shortfall,\n"
        ),
        after=(
            "            assurance_shortfall_provider=(\n"
            "                lambda evaluator=_assurance_shortfall: evaluator\n"
            "            ),\n"
        ),
        test=(
            "tests/test_repo_finalization_characterization.py::"
            "test_repo_finalization_preserves_live_provider_lookup"
        ),
    ),
    Mutation(
        name="repo-finalization-trusted-binding-precedence-bypass",
        path="evoom_guard/application/repo_finalization.py",
        before='            "base_sha": request.base_sha,\n',
        after='            "base_sha": attestation_art.get("base_sha"),\n',
        test=(
            "tests/test_repo_finalization_characterization.py::"
            "test_trusted_context_overrides_raw_artifact_values"
        ),
    ),
    Mutation(
        name="repo-finalization-pack-presence-probe-bypass",
        path="evoom_guard/application/repo_finalization.py",
        before=(
            "            if (\n"
            "                present is None\n"
            "                and request.verification_evidence.outcome "
            '== "pack_invalid"\n'
            "            ):\n"
        ),
        after=(
            "            if False and (\n"
            "                present is None\n"
            "                and request.verification_evidence.outcome "
            '== "pack_invalid"\n'
            "            ):\n"
        ),
        test=(
            "tests/test_repo_finalization_characterization.py::"
            "test_pack_presence_probe_precedes_attestation"
        ),
    ),
    Mutation(
        name="repo-finalization-coverage-identity-copy",
        path="evoom_guard/application/repo_finalization.py",
        before="        diff_coverage=coverage_evidence,\n",
        after=(
            "        diff_coverage=(\n"
            "            dict(coverage_evidence)\n"
            "            if coverage_evidence is not None\n"
            "            else None\n"
            "        ),\n"
        ),
        test=(
            "tests/test_repo_finalization_characterization.py::"
            "test_repo_finalization_preserves_live_provider_lookup"
        ),
    ),
    Mutation(
        name="repo-pack-phase-snapshot-pass-bypass",
        path="evoom_guard/verifiers/repo_result.py",
        before=(
            "            passed=phase.passed "
            "if phase.verdict_source is not None else None,\n"
        ),
        after="            passed=False,\n",
        test=(
            "tests/test_record_verifier.py::"
            "test_pack_failure_preserves_repo_suite_baseline_effect"
        ),
    ),
    Mutation(
        name="repo-pack-record-phase-selection-bypass",
        path="evoom_guard/record_verifier.py",
        before=(
            "        candidate_suite_passed = "
            "_repo_suite_pass_evidence(record, attestation)\n"
        ),
        after=(
            "        candidate_suite_passed = _completed_all_pass_evidence(record)\n"
        ),
        test=(
            "tests/test_record_verifier.py::"
            "test_pack_failure_preserves_repo_suite_baseline_effect"
        ),
    ),
    Mutation(
        name="repo-pack-composite-phase-parity-bypass",
        path="evoom_guard/record_verifier.py",
        before=(
            '                and attestation.get("repo_suite_passed") '
            "is clean_repo_pass\n"
        ),
        after="                and True\n",
        test=(
            "tests/test_record_verifier.py::"
            "test_pack_failure_preserves_repo_suite_baseline_effect"
        ),
    ),
    Mutation(
        name="repo-pack-zero-test-record-rejection",
        path="evoom_guard/record_verifier.py",
        before=(
            "                and pack_total > 0\n"
            "                or completed_zero_test_error\n"
        ),
        after="                and pack_total > 0\n",
        test=(
            "tests/test_record_verifier.py::"
            "test_completed_zero_test_pack_is_a_valid_no_verdict_error"
        ),
    ),
    Mutation(
        name="junit-report-set-content-digest-bypass",
        path="evoom_guard/verifiers/junit_oracle.py",
        before="        digest.update(text_bytes)\n",
        after="        digest.update(b\"\")\n",
        test=(
            "tests/test_adversarial_integrity_boundaries.py::"
            "test_junit_report_set_digest_is_deterministic_and_content_bound"
        ),
    ),
    Mutation(
        name="junit-report-set-format-binding-bypass",
        path="evoom_guard/verifiers/repo_suite.py",
        before=(
            "            junit_digest_format = "
            "services.junit_report_set_digest_format()\n"
        ),
        after="            junit_digest_format = None\n",
        test=(
            "tests/test_adversarial_integrity_boundaries.py::"
            "test_maven_report_set_and_pack_are_both_bound_into_composite_evidence"
        ),
    ),
    Mutation(
        name="repo-suite-junit-directory-fallback-bypass",
        path="evoom_guard/verifiers/repo_suite.py",
        before="    if junit is None:\n",
        after="    if False and junit is None:\n",
        test=(
            "tests/test_repo_suite_characterization.py::"
            "test_frozen_repo_suite_behavior[host_junit_directory_pass]"
        ),
    ),
    Mutation(
        name="repo-suite-junit-file-digest-bypass",
        path="evoom_guard/verifiers/repo_suite.py",
        before="        hashlib.sha256(junit_text.encode(\"utf-8\")).hexdigest()\n",
        after="        hashlib.sha256(b\"\").hexdigest()\n",
        test=(
            "tests/test_repo_suite_characterization.py::"
            "test_frozen_repo_suite_behavior[host_junit_file_pass]"
        ),
    ),
    Mutation(
        name="repo-suite-junit-parser-live-binding-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                    parse_xml=lambda: cast(\n"
            "                        Any,\n"
            "                        parse_junit_xml,\n"
            "                    ),\n"
        ),
        after=(
            "                    parse_xml=(\n"
            "                        lambda provider=parse_junit_xml: cast(\n"
            "                            Any,\n"
            "                            provider,\n"
            "                        )\n"
            "                    ),\n"
        ),
        test=(
            "tests/test_repo_suite_characterization.py::"
            "test_suite_dependencies_are_resolved_live_in_historical_order"
        ),
    ),
    Mutation(
        name="repo-suite-phase-evaluator-live-binding-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before="                    evaluate_phase=lambda: evaluate_repo_phase,\n",
        after=(
            "                    evaluate_phase=(\n"
            "                        lambda provider=evaluate_repo_phase: provider\n"
            "                    ),\n"
        ),
        test=(
            "tests/test_repo_suite_characterization.py::"
            "test_suite_dependencies_are_resolved_live_in_historical_order"
        ),
    ),
    Mutation(
        name="junit-composite-pack-digest-substitution",
        path="evoom_guard/verifiers/repo_phase_contracts.py",
        before="                + pack.junit_sha256\n",
        after="                + repo.junit_sha256\n",
        test=(
            "tests/test_adversarial_integrity_boundaries.py::"
            "test_maven_report_set_and_pack_are_both_bound_into_composite_evidence"
        ),
    ),
    Mutation(
        name="repo-phase-pack-zero-test-bypass",
        path="evoom_guard/verifiers/repo_phase_contracts.py",
        before="    if not tests_total:\n",
        after="    if False and not tests_total:\n",
        test=(
            "tests/test_repo_phase_characterization.py::"
            "test_repo_phase_composition_is_frozen[pack_zero_tests_v2]"
        ),
    ),
    Mutation(
        name="repo-phase-pack-unclean-verdict-bypass",
        path="evoom_guard/verifiers/repo_phase_contracts.py",
        before="    elif verdict_source is None:\n",
        after="    elif False and verdict_source is None:\n",
        test=(
            "tests/test_repo_phase_contracts.py::"
            "test_pack_with_tests_but_no_clean_exit_pair_has_no_verdict"
        ),
    ),
    Mutation(
        name="repo-phase-strict-forwarding-bypass",
        path="evoom_guard/verifiers/repo_suite.py",
        before="        strict_harness=request.strict_harness,\n",
        after="        strict_harness=False,\n",
        test=(
            "tests/test_repo_phase_contracts.py::"
            "test_repo_verifier_forwards_strict_harness_to_phase_contract"
        ),
    ),
    Mutation(
        name="repo-pack-composite-digest-parity-bypass",
        path="evoom_guard/record_verifier.py",
        before=").hexdigest() == cast(str, top_digest)\n",
        after=").hexdigest() == cast(str, top_digest) or True\n",
        test=(
            "tests/test_record_verifier.py::"
            "test_pack_failure_preserves_repo_suite_baseline_effect"
        ),
    ),
    Mutation(
        name="repo-junit-source-format-parity-bypass",
        path="evoom_guard/record_verifier.py",
        before="            and _known_string(junit_format, _JUNIT_PHASE_FORMATS)\n",
        after="            and _known_string(junit_format, _JUNIT_TOP_FORMATS)\n",
        test=(
            "tests/test_record_verifier.py::"
            "test_real_completed_repo_records_are_semantically_valid[False]"
        ),
    ),
    Mutation(
        name="repo-junit-current-missing-identity-bypass",
        path="evoom_guard/record_verifier.py",
        before=(
            "        not _producer_version_at_least(attestation, (4, 0, 2))\n"
        ),
        after="        True\n",
        test=(
            "tests/test_record_verifier.py::"
            "test_real_completed_repo_records_are_semantically_valid[False]"
        ),
    ),
    Mutation(
        name="repo-pack-required-phase-contract-bypass",
        path="evoom_guard/record_verifier.py",
        before=(
            "    elif _requires_repo_phase_evidence(attestation) and not "
            "repo_phase_claimed:\n"
        ),
        after=(
            "    elif False and _requires_repo_phase_evidence(attestation) and not "
            "repo_phase_claimed:\n"
        ),
        test=(
            "tests/test_record_verifier.py::"
            "test_pack_failure_preserves_repo_suite_baseline_effect"
        ),
    ),
    Mutation(
        name="diff-coverage-source-exclusion-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "        if line in excluded_known:\n"
            "            missed.append(line)\n"
            "            source_exclusion_seen = True\n"
        ),
        after=(
            "        if line in excluded_known:\n"
            "            continue\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_inline_no_cover_cannot_remove_changed_statements_from_the_floor"
        ),
    ),
    Mutation(
        name="diff-coverage-inline-docstring-code-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "            if any(\n"
            "                start <= item.start and item.end <= end\n"
            "                for start, end in docstring_spans\n"
            "            ):\n"
            "                continue\n"
        ),
        after=(
            "            if any(\n"
            "                start[0] <= item.start[0] <= end[0]\n"
            "                for start, end in docstring_spans\n"
            "            ):\n"
            "                continue\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_code_after_docstring_on_the_same_line_remains_in_the_floor"
        ),
    ),
    Mutation(
        name="diff-coverage-tokenizer-failure-bypass",
        path="evoom_guard/evidence.py",
        before="        return set(range(1, len(source_lines) + 1))\n",
        after="        return code_lines\n",
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_tokenizer_failure_counts_touched_lines_conservatively"
        ),
    ),
    Mutation(
        name="diff-coverage-unknown-executable-line-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "        else:\n"
            "            # Missing and unknown executable lines both fail conservatively.\n"
            "            # In particular, execution of a multi-line statement's first line\n"
            "            # does not prove a short-circuited continuation was evaluated.\n"
            "            missed.append(line)\n"
        ),
        after=(
            "        else:\n"
            "            continue\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_multiline_statement_continuation_cannot_disappear_from_the_floor"
        ),
    ),
    Mutation(
        name="diff-coverage-unimported-source-classification-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "            executed, missed, _ = _classify_touched_lines(\n"
            "                new_contents.get(path), touched, {}\n"
            "            )\n"
        ),
        after=(
            "            executed, missed = [], sorted(touched)\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_comment_only_change_in_unimported_file_is_not_a_false_gap"
        ),
    ),
    Mutation(
        name="diff-coverage-structured-file-blocks-bypass",
        path="evoom_guard/evidence.py",
        before="        repo_path, candidate, file_blocks=file_blocks\n",
        after="        repo_path, candidate, file_blocks=None\n",
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_structured_file_blocks_are_the_coverage_diff_ground_truth"
        ),
    ),
    Mutation(
        name="diff-coverage-setup-forwarding-bypass",
        path="evoom_guard/application/repo_finalization.py",
        before=(
            "            deleted=tuple(request.safe_deleted_paths),\n"
            "            test_command=request.test_command,\n"
            "            setup_command=request.setup_command,\n"
            "            setup_output_globs=request.setup_output_globs,\n"
        ),
        after=(
            "            deleted=tuple(request.safe_deleted_paths),\n"
            "            test_command=request.test_command,\n"
            "            setup_command=None,\n"
            "            setup_output_globs=request.setup_output_globs,\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_replays_setup_with_the_main_fidelity_policy"
        ),
    ),
    Mutation(
        name="diff-coverage-setup-fidelity-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "    changes = setup_fidelity_changes(before, after)\n"
            "    if changes:\n"
        ),
        after=(
            "    changes = []\n"
            "    if changes:\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_setup_cannot_rewrite_judged_source"
        ),
    ),
    Mutation(
        name="diff-coverage-setup-resource-limit-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "            timeout=timeout,\n"
            "            preexec_fn=preexec_fn,\n"
            "        )\n"
            "        after = setup_fidelity_snapshot(\n"
        ),
        after=(
            "            timeout=timeout,\n"
            "            preexec_fn=None,\n"
            "        )\n"
            "        after = setup_fidelity_snapshot(\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_subprocesses_receive_the_main_resource_limits"
        ),
    ),
    Mutation(
        name="diff-coverage-suite-resource-limit-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "            coverage_run = _run_bounded_subprocess(\n"
            "                wrapped,\n"
            "                cwd=copy,\n"
            "                env=env,\n"
            "                timeout=timeout,\n"
            "                preexec_fn=preexec_fn,\n"
            "            )\n"
        ),
        after=(
            "            coverage_run = _run_bounded_subprocess(\n"
            "                wrapped,\n"
            "                cwd=copy,\n"
            "                env=env,\n"
            "                timeout=timeout,\n"
            "                preexec_fn=None,\n"
            "            )\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_subprocesses_receive_the_main_resource_limits"
        ),
    ),
    Mutation(
        name="diff-coverage-report-resource-limit-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "                timeout=60,\n"
            "                preexec_fn=preexec_fn,\n"
            "            )\n"
        ),
        after=(
            "                timeout=60,\n"
            "                preexec_fn=None,\n"
            "            )\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_subprocesses_receive_the_main_resource_limits"
        ),
    ),
    Mutation(
        name="diff-coverage-memory-policy-forwarding-bypass",
        path="evoom_guard/application/repo_finalization.py",
        before=(
            "            setup_output_globs=request.setup_output_globs,\n"
            "            timeout=request.timeout,\n"
            "            mem_limit_mb=request.mem_limit_mb,\n"
            "            file_blocks=request.file_blocks,\n"
        ),
        after=(
            "            setup_output_globs=request.setup_output_globs,\n"
            "            timeout=request.timeout,\n"
            "            mem_limit_mb=1024,\n"
            "            file_blocks=request.file_blocks,\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_guard_forwards_the_configured_memory_limit_to_coverage"
        ),
    ),
    Mutation(
        name="diff-coverage-exact-ratio-bypass",
        path="evoom_guard/application/decision_gates.py",
        before=(
            "    if isinstance(min_diff_coverage, int):\n"
            "        floor_numerator, floor_denominator = "
            "min_diff_coverage, 1\n"
            "    else:\n"
            "        floor_numerator, floor_denominator = "
            "min_diff_coverage.as_integer_ratio()\n"
            "    coverage_below_floor = (\n"
            "        coverage_total > 0\n"
            "        and 100 * coverage_executed * floor_denominator "
            "< floor_numerator * coverage_total\n"
            "    )\n"
        ),
        after=(
            "    coverage_below_floor = "
            "float(coverage_evidence['percent']) < min_diff_coverage\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_exact_ratio_not_rounded_display_controls_the_floor"
        ),
    ),
    Mutation(
        name="diff-coverage-record-exact-ratio-bypass",
        path="evoom_guard/record_verifier.py",
        before=(
            "    if isinstance(threshold, int):\n"
            "        floor_numerator, floor_denominator = threshold, 1\n"
            "    else:\n"
            "        floor_numerator, floor_denominator = threshold.as_integer_ratio()\n"
            "    return 100 * executed * floor_denominator >= floor_numerator * total\n"
        ),
        after="    return coverage['percent'] >= threshold\n",
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_exact_ratio_not_rounded_display_controls_the_floor"
        ),
    ),
    Mutation(
        name="diff-coverage-record-huge-number-overflow",
        path="evoom_guard/record_verifier.py",
        before=(
            "    if isinstance(value, bool) or not isinstance(value, (int, float)):\n"
            "        return False\n"
            "    return isinstance(value, int) or math.isfinite(value)\n"
        ),
        after=(
            "    return (\n"
            "        isinstance(value, (int, float))\n"
            "        and not isinstance(value, bool)\n"
            "        and math.isfinite(value)\n"
            "    )\n"
        ),
        test=(
            "tests/test_record_verifier.py::"
            "test_effective_policy_requires_all_24_typed_fields"
            "[min-diff-coverage-huge-int]"
        ),
    ),
    Mutation(
        name="diff-coverage-api-floor-implication-bypass",
        path="evoom_guard/application/request_preparation.py",
        before=(
            "    collect_diff_coverage = (\n"
            "        raw.collect_diff_coverage or raw.min_diff_coverage is not None\n"
            "    )\n"
        ),
        after="    collect_diff_coverage = raw.collect_diff_coverage\n",
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_python_api_coverage_floor_implies_measurement"
        ),
    ),
    Mutation(
        name="diff-coverage-floor-validation-bypass",
        path="evoom_guard/application/request_preparation.py",
        before=(
            "    if (\n"
            "        raw.min_diff_coverage is not None\n"
            "        and (\n"
        ),
        after=(
            "    if False and (\n"
            "        raw.min_diff_coverage is not None\n"
            "        and (\n"
        ),
        test=(
            "tests/test_guard.py::MemLimitOptionTests::"
            "test_guard_api_rejects_values_that_cannot_form_a_valid_policy"
        ),
    ),
    Mutation(
        name="diff-coverage-required-shortfall-proof-bypass",
        path="evoom_guard/record_verifier.py",
        before="                (floor_shortfall or coverage_shortfall)\n",
        after="                floor_shortfall\n",
        test=(
            "tests/test_record_verifier.py::"
            "test_required_unmeasured_coverage_record_is_a_valid_assurance_error"
        ),
    ),
    Mutation(
        name="candidate-preflight-unsafe-path-bypass",
        path="evoom_guard/verifiers/candidate_preflight.py",
        before=(
            "        sorted(\n"
            "            path\n"
            "            for path in all_touched\n"
            "            if not services.is_safe_relpath(path)\n"
            "        )\n"
        ),
        after=(
            "        sorted(\n"
            "            path\n"
            "            for path in all_touched\n"
            "            if False and not services.is_safe_relpath(path)\n"
            "        )\n"
        ),
        test=(
            "tests/test_candidate_preflight.py::"
            "test_unsafe_paths_fail_closed_and_never_become_safe_deletions"
        ),
    ),
    Mutation(
        name="candidate-preflight-unsafe-execution-bypass",
        path="evoom_guard/verifiers/candidate_preflight.py",
        before="            and not self.unsafe_paths\n",
        after="            and True\n",
        test=(
            "tests/test_candidate_preflight.py::"
            "test_unsafe_paths_fail_closed_and_never_become_safe_deletions"
        ),
    ),
    Mutation(
        name="candidate-preflight-reserved-pack-bypass",
        path="evoom_guard/verifiers/candidate_preflight.py",
        before=(
            "        if path == verifier_pack_dir or "
            "path.startswith(verifier_pack_dir + \"/\"):\n"
        ),
        after=(
            "        if False and (path == verifier_pack_dir or "
            "path.startswith(verifier_pack_dir + \"/\")):\n"
        ),
        test=(
            "tests/test_candidate_preflight.py::"
            "test_reserved_pack_namespace_is_never_candidate_writable"
        ),
    ),
    Mutation(
        name="candidate-preflight-builtin-allowlist-bypass",
        path="evoom_guard/verifiers/candidate_preflight.py",
        before=(
            "            if not services.is_allowlist_exemptible(\n"
            "                path,\n"
        ),
        after=(
            "            if False and not services.is_allowlist_exemptible(\n"
            "                path,\n"
        ),
        test=(
            "tests/test_candidate_preflight.py::"
            "test_builtin_harness_path_cannot_be_allowlisted"
        ),
    ),
    Mutation(
        name="candidate-preflight-existing-test-as-new",
        path="evoom_guard/verifiers/candidate_preflight.py",
        before="                is_new=path in new_paths,\n",
        after="                is_new=True,\n",
        test=(
            "tests/test_candidate_preflight.py::"
            "test_feature_mode_relaxes_only_a_new_plain_test"
        ),
    ),
    Mutation(
        name="candidate-preflight-local-action-discovery-bypass",
        path="evoom_guard/verifiers/candidate_preflight.py",
        before=(
            "    local_action_dirs = "
            "services.discover_local_action_dirs(request.repo_path)\n"
        ),
        after="    local_action_dirs: tuple[str, ...] = ()\n",
        test=(
            "tests/test_candidate_preflight.py::"
            "test_local_action_helper_is_bound_from_the_base_tree"
        ),
    ),
    Mutation(
        name="candidate-preflight-protected-deletion-bypass",
        path="evoom_guard/verifiers/candidate_preflight.py",
        before=(
            "            if services.is_safe_relpath(path) and "
            "not is_violation(path)\n"
        ),
        after="            if services.is_safe_relpath(path)\n",
        test=(
            "tests/test_candidate_preflight.py::"
            "test_protected_deletion_is_not_in_safe_deletion_set"
        ),
    ),
    Mutation(
        name="candidate-preflight-live-policy-seam-snapshot",
        path="evoom_guard/guard.py",
        before="            is_judge_autoexec=lambda path: is_judge_autoexec(path),\n",
        after="            is_judge_autoexec=is_judge_autoexec,\n",
        test=(
            "tests/test_candidate_preflight.py::"
            "test_guard_adapter_resolves_later_policy_seams_after_discovery"
        ),
    ),
    Mutation(
        name="candidate-preflight-live-pack-namespace-bypass",
        path="evoom_guard/guard.py",
        before="            verifier_pack_dir=lambda: VERIFIER_PACK_DIR,\n",
        after='            verifier_pack_dir=lambda: "evoguard_verifier_pack",\n',
        test=(
            "tests/test_candidate_preflight.py::"
            "test_guard_adapter_reads_reserved_namespace_after_discovery"
        ),
    ),
    Mutation(
        name="cli-parser-live-ref-injection-bypass",
        path="evoom_guard/cli/__init__.py",
        before="        immutable_release_ref_provider=lambda: _immutable_release_ref,\n",
        after=(
            "        immutable_release_ref_provider="
            "lambda: (lambda value: str(value)),\n"
        ),
        test=(
            "tests/test_cli_parser_characterization.py::"
            "test_cli_parser_matches_frozen_characterization"
        ),
    ),
    Mutation(
        name="cli-parser-live-helper-injection-bypass",
        path="evoom_guard/cli/__init__.py",
        before=(
            "        add_github_attestation_policy_arguments=lambda parser: (\n"
            "            _add_github_attestation_policy_arguments(parser)\n"
            "        ),\n"
        ),
        after=(
            "        add_github_attestation_policy_arguments="
            "lambda _parser: None,\n"
        ),
        test=(
            "tests/test_cli_parser_characterization.py::"
            "test_cli_parser_matches_frozen_characterization"
        ),
    ),
    Mutation(
        name="cli-parser-construction-time-helper-rebinding-bypass",
        path="evoom_guard/cli/__init__.py",
        before=(
            "        add_release_artifact_key_registry_arguments=lambda parser: (\n"
            "            _add_release_artifact_key_registry_arguments(parser)\n"
            "        ),\n"
        ),
        after=(
            "        add_release_artifact_key_registry_arguments=(\n"
            "            _add_release_artifact_key_registry_arguments\n"
            "        ),\n"
        ),
        test=(
            "tests/test_cli_parser_characterization.py::"
            "test_cli_parser_resolves_dependencies_at_their_original_call_sites"
        ),
    ),
    Mutation(
        name="cli-parser-construction-time-ref-rebinding-bypass",
        path="evoom_guard/cli/__init__.py",
        before="        immutable_release_ref_provider=lambda: _immutable_release_ref,\n",
        after=(
            "        immutable_release_ref_provider=(\n"
            "            lambda ref=_immutable_release_ref: lambda: ref\n"
            "        )(),\n"
        ),
        test=(
            "tests/test_cli_parser_characterization.py::"
            "test_cli_parser_resolves_dependencies_at_their_original_call_sites"
        ),
    ),
    Mutation(
        name="cli-guard-cli-precedence-bypass",
        path="evoom_guard/cli/guard_command.py",
        before="        if cli_value is not None:\n",
        after="        if False and cli_value is not None:\n",
        test=(
            "tests/test_cli_guard_command_characterization.py::"
            "test_frozen_cli_guard_command_behavior"
            "[patch_cli_precedence_and_outputs]"
        ),
    ),
    Mutation(
        name="cli-guard-diff-routing-bypass",
        path="evoom_guard/cli/guard_command.py",
        before="    if args.diff is not None:\n",
        after="    if False and args.diff is not None:\n",
        test=(
            "tests/test_cli_guard_command_characterization.py::"
            "test_frozen_cli_guard_command_behavior[diff_policy_defaults]"
        ),
    ),
    Mutation(
        name="cli-guard-unverifiable-reason-substitution",
        path="evoom_guard/cli/guard_command.py",
        before="                    reason_code=services.no_verifiable_changes_reason,\n",
        after="                    reason_code=services.invalid_verifier_pack_reason,\n",
        test=(
            "tests/test_cli_guard_command_characterization.py::"
            "test_frozen_cli_guard_command_behavior[dirs_unverifiable]"
        ),
    ),
    Mutation(
        name="cli-guard-digest-without-pack-bypass",
        path="evoom_guard/cli/guard_command.py",
        before="        if not verifier_pack:\n",
        after="        if False and not verifier_pack:\n",
        test=(
            "tests/test_cli_guard_command_characterization.py::"
            "test_frozen_cli_guard_command_behavior[digest_without_pack]"
        ),
    ),
    Mutation(
        name="cli-guard-node-memory-adjustment-bypass",
        path="evoom_guard/cli/guard_command.py",
        before=(
            "        if services.path_is_file("
            "services.join_path(node_root, \"package.json\")):\n"
        ),
        after=(
            "        if False and services.path_is_file("
            "services.join_path(node_root, \"package.json\")):\n"
        ),
        test=(
            "tests/test_cli_guard_command_characterization.py::"
            "test_frozen_cli_guard_command_behavior[node_default_memory]"
        ),
    ),
    Mutation(
        name="cli-guard-signing-without-json-bypass",
        path="evoom_guard/cli/guard_command.py",
        before="    if sign_key and not args.json_out:\n",
        after="    if False and sign_key and not args.json_out:\n",
        test=(
            "tests/test_cli_guard_command_characterization.py::"
            "test_frozen_cli_guard_command_behavior[sign_without_json]"
        ),
    ),
    Mutation(
        name="cli-guard-report-publication-bypass",
        path="evoom_guard/cli/guard_command.py",
        before="        services.write_report(args.report, report)\n",
        after="        pass\n",
        test=(
            "tests/test_cli_guard_command_characterization.py::"
            "test_frozen_cli_guard_command_behavior"
            "[patch_cli_precedence_and_outputs]"
        ),
    ),
    Mutation(
        name="cli-guard-json-publication-bypass",
        path="evoom_guard/cli/guard_command.py",
        before=(
            "    if args.json_out:\n"
            "        services.write_json(result, args.json_out, deleted=deleted)\n"
        ),
        after=(
            "    if False and args.json_out:\n"
            "        services.write_json(result, args.json_out, deleted=deleted)\n"
        ),
        test=(
            "tests/test_cli_guard_command_characterization.py::"
            "test_frozen_cli_guard_command_behavior"
            "[patch_cli_precedence_and_outputs]"
        ),
    ),
    Mutation(
        name="cli-guard-sarif-publication-bypass",
        path="evoom_guard/cli/guard_command.py",
        before="    if args.sarif:\n",
        after="    if False and args.sarif:\n",
        test=(
            "tests/test_cli_guard_command_characterization.py::"
            "test_frozen_cli_guard_command_behavior"
            "[patch_cli_precedence_and_outputs]"
        ),
    ),
    Mutation(
        name="cli-guard-live-config-loader-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "        load_config=lambda path, *, required, out: _load_config(\n"
            "            path, required=required, out=out\n"
            "        ),\n"
        ),
        after="        load_config=_load_config,\n",
        test=(
            "tests/test_cli_guard_command_characterization.py::"
            "test_facade_preserves_entry_snapshot_and_later_global_lookups"
        ),
    ),
    Mutation(
        name="cli-guard-live-read-snapshot",
        path="evoom_guard/cli/__init__.py",
        before="        read_text=lambda path: _read_text(path),\n",
        after="        read_text=_read_text,\n",
        test=(
            "tests/test_cli_guard_command_characterization.py::"
            "test_facade_preserves_entry_snapshot_and_later_global_lookups"
        ),
    ),
    Mutation(
        name="cli-guard-late-signing-provider-snapshot",
        path="evoom_guard/cli/__init__.py",
        before="        sign_file_provider=sign_file_provider,\n",
        after=(
            "        sign_file_provider=(\n"
            "            lambda signer=sign_file_provider(): lambda: signer\n"
            "        )(),\n"
        ),
        test=(
            "tests/test_cli_guard_command_characterization.py::"
            "test_signing_provider_is_resolved_after_json_publication"
        ),
    ),
    Mutation(
        name="cli-record-verdict-signature-gate-bypass",
        path="evoom_guard/cli/record_commands.py",
        before="    if not signature_valid:\n",
        after="    if False and not signature_valid:\n",
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_verify_verdict_rejects_an_invalid_signature_before_context"
        ),
    ),
    Mutation(
        name="cli-record-verdict-late-parser-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "            strict_json_loads_provider=strict_json_loads_provider,\n"
        ),
        after=(
            "            strict_json_loads_provider=(\n"
            "                lambda parser=strict_json_loads_provider(): lambda: parser\n"
            "            )(),\n"
        ),
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_verify_verdict_freezes_signature_provider_then_resolves_json_late"
        ),
    ),
    Mutation(
        name="cli-record-bundle-live-reader-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "        services=_record_command_owner.BundleEvidenceServices(\n"
            "            read_bounded_bytes=lambda path, *, limit, label: "
            "_read_bounded_bytes(\n"
            "                path,\n"
            "                limit=limit,\n"
            "                label=label,\n"
            "            ),\n"
        ),
        after=(
            "        services=_record_command_owner.BundleEvidenceServices(\n"
            "            read_bounded_bytes=_read_bounded_bytes,\n"
        ),
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_bundle_evidence_preserves_validate_then_create_then_report_order"
        ),
    ),
    Mutation(
        name="cli-record-bundle-live-reporter-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "            create_evidence_bundle=create_evidence_bundle,\n"
            "            invalid_input_errors=(EvidenceBundleError,),\n"
            "            operational_errors=(OSError, ValueError, SigningUnavailableError),\n"
            "            machine_report=lambda reporter, value: _machine_report(\n"
            "                reporter,\n"
            "                value,\n"
            "            ),\n"
        ),
        after=(
            "            create_evidence_bundle=create_evidence_bundle,\n"
            "            invalid_input_errors=(EvidenceBundleError,),\n"
            "            operational_errors=(OSError, ValueError, SigningUnavailableError),\n"
            "            machine_report=_machine_report,\n"
        ),
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_bundle_evidence_preserves_validate_then_create_then_report_order"
        ),
    ),
    Mutation(
        name="cli-record-bundle-semantic-gate-bypass",
        path="evoom_guard/cli/record_commands.py",
        before="    if not record_is_valid:\n",
        after="    if False and not record_is_valid:\n",
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_bundle_evidence_rejects_invalid_record_before_creation"
        ),
    ),
    Mutation(
        name="cli-record-finalize-stdin-gate-bypass",
        path="evoom_guard/cli/record_commands.py",
        before='    if args.verdict == "-":\n',
        after='    if False and args.verdict == "-":\n',
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_finalize_record_rejects_stdin_before_any_read"
        ),
    ),
    Mutation(
        name="cli-record-finalize-semantic-gate-bypass",
        path="evoom_guard/cli/record_commands.py",
        before="    if not record_is_semantic:\n",
        after="    if False and not record_is_semantic:\n",
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_finalize_record_rejects_semantically_invalid_object_before_sealing"
        ),
    ),
    Mutation(
        name="cli-record-finalize-require-pass-bypass",
        path="evoom_guard/cli/record_commands.py",
        before="    return 0 if allowed or not args.require_pass else 1\n",
        after="    return 0\n",
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_finalize_record_require_pass_denies_a_finalized_deny"
        ),
    ),
    Mutation(
        name="cli-record-bundle-signature-verification-bypass",
        path="evoom_guard/cli/record_commands.py",
        before=(
            "        services.verify_bundle_signature(\n"
            "            inspected,\n"
            "            trusted_public_key_path=args.trusted_pub,\n"
            "        )\n"
        ),
        after="        pass\n",
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_verify_bundle_fails_closed_at_each_verification_claim[signature]"
        ),
    ),
    Mutation(
        name="cli-record-bundle-context-verification-bypass",
        path="evoom_guard/cli/record_commands.py",
        before=(
            "        services.verify_bundle_context(\n"
            "            inspected,\n"
            "            expected_context=expected_context,\n"
            "        )\n"
        ),
        after="        pass\n",
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_verify_bundle_fails_closed_at_each_verification_claim[context]"
        ),
    ),
    Mutation(
        name="cli-record-bundle-semantic-verification-bypass",
        path="evoom_guard/cli/record_commands.py",
        before="    record_report = services.verify_record(verdict_record)\n",
        after='    record_report = {"ok": True}\n',
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_verify_bundle_fails_closed_at_each_verification_claim[record]"
        ),
    ),
    Mutation(
        name="cli-record-bundle-sign-key-forwarding-bypass",
        path="evoom_guard/cli/record_commands.py",
        before=(
            "        manifest = services.create_evidence_bundle(\n"
            "            args.verdict,\n"
            "            args.out,\n"
            "            context=context,\n"
            "            private_key_path=args.sign_key,\n"
        ),
        after=(
            "        manifest = services.create_evidence_bundle(\n"
            "            args.verdict,\n"
            "            args.out,\n"
            "            context=context,\n"
            "            private_key_path=args.out,\n"
        ),
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_bundle_evidence_preserves_validate_then_create_then_report_order"
        ),
    ),
    Mutation(
        name="cli-record-finalize-sign-key-forwarding-bypass",
        path="evoom_guard/cli/record_commands.py",
        before=(
            "        finalized = services.finalize_evidence_bundle(\n"
            "            args.verdict,\n"
            "            args.out,\n"
            "            expected_context=expected_context,\n"
            "            private_key_path=args.sign_key,\n"
        ),
        after=(
            "        finalized = services.finalize_evidence_bundle(\n"
            "            args.verdict,\n"
            "            args.out,\n"
            "            expected_context=expected_context,\n"
            "            private_key_path=args.out,\n"
        ),
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_finalize_record_preserves_read_verify_finalize_report_order"
        ),
    ),
    Mutation(
        name="cli-record-bundle-trusted-pub-forwarding-bypass",
        path="evoom_guard/cli/record_commands.py",
        before="            trusted_public_key_path=args.trusted_pub,\n",
        after="            trusted_public_key_path=args.bundle,\n",
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_verify_bundle_preserves_entry_snapshots_and_live_reporter"
        ),
    ),
    Mutation(
        name="cli-record-bundle-context-object-gate-bypass",
        path="evoom_guard/cli/record_commands.py",
        before=(
            "    if not isinstance(context, dict):\n"
            "        services.machine_report(\n"
            "            out,\n"
            "            {\n"
            '                "format": report_format,\n'
            '                "ok": False,\n'
        ),
        after=(
            "    if False and not isinstance(context, dict):\n"
            "        services.machine_report(\n"
            "            out,\n"
            "            {\n"
            '                "format": report_format,\n'
            '                "ok": False,\n'
        ),
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_bundle_evidence_rejects_non_object_context_before_creation"
        ),
    ),
    Mutation(
        name="cli-record-material-shape-gate-bypass",
        path="evoom_guard/cli/record_commands.py",
        before="        if not separator or not role or not path:\n",
        after="        if False and (not separator or not role or not path):\n",
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_bundle_evidence_rejects_invalid_material_before_creation"
        ),
    ),
    Mutation(
        name="cli-record-finalize-verdict-object-gate-bypass",
        path="evoom_guard/cli/record_commands.py",
        before=(
            "    if not isinstance(verdict, dict):\n"
            "        services.machine_report(\n"
            "            out,\n"
            "            {\n"
            '                "format": report_format,\n'
            '                "ok": False,\n'
            '                "finalized": False,\n'
        ),
        after=(
            "    if False and not isinstance(verdict, dict):\n"
            "        services.machine_report(\n"
            "            out,\n"
            "            {\n"
            '                "format": report_format,\n'
            '                "ok": False,\n'
            '                "finalized": False,\n'
        ),
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_finalize_record_rejects_non_object_verdict_before_semantic_verification"
        ),
    ),
    Mutation(
        name="cli-record-finalize-context-object-gate-bypass",
        path="evoom_guard/cli/record_commands.py",
        before=(
            "    if not isinstance(expected_context, dict):\n"
            "        services.machine_report(\n"
            "            out,\n"
            "            {\n"
            '                "format": report_format,\n'
            '                "ok": False,\n'
            '                "finalized": False,\n'
        ),
        after=(
            "    if False and not isinstance(expected_context, dict):\n"
            "        services.machine_report(\n"
            "            out,\n"
            "            {\n"
            '                "format": report_format,\n'
            '                "ok": False,\n'
            '                "finalized": False,\n'
        ),
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_finalize_record_rejects_non_object_context_before_sealing"
        ),
    ),
    Mutation(
        name="cli-record-bundle-expected-context-object-gate-bypass",
        path="evoom_guard/cli/record_commands.py",
        before=(
            "    if not isinstance(expected_context, dict):\n"
            "        services.machine_report(\n"
            "            out,\n"
            "            {\n"
            '                "format": report_format,\n'
            '                "ok": False,\n'
            '                "verified": False,\n'
        ),
        after=(
            "    if False and not isinstance(expected_context, dict):\n"
            "        services.machine_report(\n"
            "            out,\n"
            "            {\n"
            '                "format": report_format,\n'
            '                "ok": False,\n'
            '                "verified": False,\n'
        ),
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_verify_bundle_rejects_non_object_expected_context_before_inspection"
        ),
    ),
    Mutation(
        name="cli-record-bundle-require-pass-bypass",
        path="evoom_guard/cli/record_commands.py",
        before="    ok = verified and (pass_gate or not require_pass)\n",
        after="    ok = verified\n",
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_verify_bundle_require_pass_denies_a_semantically_valid_non_pass"
        ),
    ),
    Mutation(
        name="cli-record-bundle-inspection-order-inversion",
        path="evoom_guard/cli/record_commands.py",
        before=(
            "    try:\n"
            "        inspected = services.inspect_evidence_bundle(args.bundle)\n"
            '        claims["canonical_container"] = "pass"\n'
        ),
        after=(
            "    try:\n"
            "        services.verify_bundle_signature(\n"
            "            args.bundle,\n"
            "            trusted_public_key_path=args.trusted_pub,\n"
            "        )\n"
            "        inspected = services.inspect_evidence_bundle(args.bundle)\n"
            '        claims["canonical_container"] = "pass"\n'
        ),
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_verify_bundle_stops_at_failed_container_inspection"
        ),
    ),
    Mutation(
        name="cli-record-finalize-live-reader-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "        services=_record_command_owner.FinalizeRecordServices(\n"
            "            read_bounded_bytes=lambda path, *, limit, label: "
            "_read_bounded_bytes(\n"
            "                path,\n"
            "                limit=limit,\n"
            "                label=label,\n"
            "            ),\n"
        ),
        after=(
            "        services=_record_command_owner.FinalizeRecordServices(\n"
            "            read_bounded_bytes=_read_bounded_bytes,\n"
        ),
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_finalize_record_preserves_entry_snapshots_and_live_facade_seams"
        ),
    ),
    Mutation(
        name="cli-record-finalize-live-reporter-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "            finalize_evidence_bundle=finalize_evidence_bundle,\n"
            "            invalid_input_errors=(EvidenceBundleError,),\n"
            "            operational_errors=(OSError, ValueError, SigningUnavailableError),\n"
            "            machine_report=lambda reporter, value: _machine_report(\n"
            "                reporter,\n"
            "                value,\n"
            "            ),\n"
        ),
        after=(
            "            finalize_evidence_bundle=finalize_evidence_bundle,\n"
            "            invalid_input_errors=(EvidenceBundleError,),\n"
            "            operational_errors=(OSError, ValueError, SigningUnavailableError),\n"
            "            machine_report=_machine_report,\n"
        ),
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_finalize_record_preserves_entry_snapshots_and_live_facade_seams"
        ),
    ),
    Mutation(
        name="cli-record-finalize-entry-provider-made-live",
        path="evoom_guard/cli/__init__.py",
        before="            finalize_evidence_bundle=finalize_evidence_bundle,\n",
        after=(
            "            finalize_evidence_bundle=lambda *call_args, **call_kwargs: (\n"
            "                __import__(\n"
            '                    "evoom_guard.evidence_bundle",\n'
            '                    fromlist=["finalize_evidence_bundle"],\n'
            "                ).finalize_evidence_bundle(*call_args, **call_kwargs)\n"
            "            ),\n"
        ),
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_finalize_record_preserves_entry_snapshots_and_live_facade_seams"
        ),
    ),
    Mutation(
        name="cli-record-verify-bundle-live-reporter-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "            signature_operational_errors=(\n"
            "                OSError,\n"
            "                ValueError,\n"
            "                SigningUnavailableError,\n"
            "            ),\n"
            "            machine_report=lambda reporter, value: _machine_report(\n"
            "                reporter,\n"
            "                value,\n"
            "            ),\n"
        ),
        after=(
            "            signature_operational_errors=(\n"
            "                OSError,\n"
            "                ValueError,\n"
            "                SigningUnavailableError,\n"
            "            ),\n"
            "            machine_report=_machine_report,\n"
        ),
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_verify_bundle_preserves_entry_snapshots_and_live_reporter"
        ),
    ),
    Mutation(
        name="cli-record-bundle-entry-inspector-made-live",
        path="evoom_guard/cli/__init__.py",
        before="            inspect_evidence_bundle=inspect_evidence_bundle,\n",
        after=(
            "            inspect_evidence_bundle=lambda path: __import__(\n"
            '                "evoom_guard.evidence_bundle",\n'
            '                fromlist=["inspect_evidence_bundle"],\n'
            "            ).inspect_evidence_bundle(path),\n"
        ),
        test=(
            "tests/test_cli_record_command_characterization.py::"
            "test_verify_bundle_preserves_entry_snapshots_and_live_reporter"
        ),
    ),
    Mutation(
        name="cli-agent-change-validate-error-exit-bypass",
        path="evoom_guard/cli/agent_change_commands.py",
        before=(
            '                "format": services.proposal_format,\n'
            '                "ok": False,\n'
            '                "status": "ERROR",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 2\n"
            "    services.machine_report(\n"
        ),
        after=(
            '                "format": services.proposal_format,\n'
            '                "ok": False,\n'
            '                "status": "ERROR",\n'
            '                "error": str(exc),\n'
            "            },\n"
            "        )\n"
            "        return 0\n"
            "    services.machine_report(\n"
        ),
        test=(
            "tests/test_cli_agent_change_command_characterization.py::"
            "test_frozen_cli_agent_change_command_behavior[validate_error]"
        ),
    ),
    Mutation(
        name="cli-agent-change-git-pin-bypass",
        path="evoom_guard/cli/agent_change_commands.py",
        before=(
            "        git_executable = services.git_executable_pin(\n"
            "            args.git_executable,\n"
            "            args.git_executable_sha256,\n"
            "        )\n"
            "        bindings = services.derive_bindings(\n"
        ),
        after=(
            "        git_executable = args.git_executable\n"
            "        bindings = services.derive_bindings(\n"
        ),
        test=(
            "tests/test_cli_agent_change_command_characterization.py::"
            "test_frozen_cli_agent_change_command_behavior[derive_success]"
        ),
    ),
    Mutation(
        name="cli-agent-change-authorization-read-order-inversion",
        path="evoom_guard/cli/agent_change_commands.py",
        before=(
            "        source = services.read_external_object(\n"
            "            args.source,\n"
            '            label="authorization source",\n'
            "        )\n"
            "        scope = services.read_external_object(\n"
            "            args.scope,\n"
            '            label="authorization scope",\n'
            "        )\n"
        ),
        after=(
            "        scope = services.read_external_object(\n"
            "            args.scope,\n"
            '            label="authorization scope",\n'
            "        )\n"
            "        source = services.read_external_object(\n"
            "            args.source,\n"
            '            label="authorization source",\n'
            "        )\n"
        ),
        test=(
            "tests/test_cli_agent_change_command_characterization.py::"
            "test_frozen_cli_agent_change_command_behavior"
            "[seal_authorization_success]"
        ),
    ),
    Mutation(
        name="cli-agent-change-seal-deny-exit-bypass",
        path="evoom_guard/cli/agent_change_commands.py",
        before=(
            "        return 1\n"
            "    services.machine_report(\n"
            "        out,\n"
            "        {\n"
            '            "format": services.proposal_format,\n'
            '            "ok": True,\n'
            '            "status": "ALLOW",\n'
            '            "decision": sealed.decision,\n'
        ),
        after=(
            "        return 0\n"
            "    services.machine_report(\n"
            "        out,\n"
            "        {\n"
            '            "format": services.proposal_format,\n'
            '            "ok": True,\n'
            '            "status": "ALLOW",\n'
            '            "decision": sealed.decision,\n'
        ),
        test=(
            "tests/test_cli_agent_change_command_characterization.py::"
            "test_frozen_cli_agent_change_command_behavior[seal_finalized_deny]"
        ),
    ),
    Mutation(
        name="cli-agent-change-verify-deny-exit-bypass",
        path="evoom_guard/cli/agent_change_commands.py",
        before=(
            "        return 1\n"
            "    services.machine_report(\n"
            "        out,\n"
            "        {\n"
            '            "format": services.proposal_format,\n'
            '            "ok": True,\n'
            '            "status": "ALLOW",\n'
            '            "decision": verified.decision,\n'
        ),
        after=(
            "        return 0\n"
            "    services.machine_report(\n"
            "        out,\n"
            "        {\n"
            '            "format": services.proposal_format,\n'
            '            "ok": True,\n'
            '            "status": "ALLOW",\n'
            '            "decision": verified.decision,\n'
        ),
        test=(
            "tests/test_cli_agent_change_command_characterization.py::"
            "test_frozen_cli_agent_change_command_behavior[verify_finalized_deny]"
        ),
    ),
    Mutation(
        name="cli-agent-change-live-reader-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "            read_external_object=lambda path, *, label: "
            "_read_external_finalizer_object(\n"
            "                path, label=label\n"
            "            ),\n"
            "            seal_authorization=seal_agent_change_authorization,\n"
        ),
        after=(
            "            read_external_object=_read_external_finalizer_object,\n"
            "            seal_authorization=seal_agent_change_authorization,\n"
        ),
        test=(
            "tests/test_cli_agent_change_command_characterization.py::"
            "test_authorization_reads_stay_live_but_sealer_snapshots_at_entry"
        ),
    ),
    Mutation(
        name="cli-agent-change-entry-derive-helper-late-bound",
        path="evoom_guard/cli/__init__.py",
        before=(
            "            derive_bindings=(\n"
            "                derive_agent_change_bindings_v2\n"
            '                if args.contract_version == "2"\n'
            "                else derive_agent_change_bindings\n"
            "            ),\n"
        ),
        after=(
            "            derive_bindings=(\n"
            "                derive_agent_change_bindings_v2\n"
            '                if args.contract_version == "2"\n'
            "                else (lambda **kwargs: getattr(\n"
            '                    sys.modules["evoom_guard.finalizer_derivation"],\n'
            '                    "derive_agent_change_bindings",\n'
            "                )(**kwargs))\n"
            "            ),\n"
        ),
        test=(
            "tests/test_cli_agent_change_command_characterization.py::"
            "test_derive_dependencies_snapshot_at_entry_but_reporter_resolves_late"
        ),
    ),
    Mutation(
        name="cli-agent-change-live-reporter-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "            write_bindings=write_agent_change_bindings,\n"
            "            machine_report=lambda report_out, value: _machine_report(\n"
            "                report_out,\n"
            "                value,\n"
            "            ),\n"
        ),
        after=(
            "            write_bindings=write_agent_change_bindings,\n"
            "            machine_report=_machine_report,\n"
        ),
        test=(
            "tests/test_cli_agent_change_command_characterization.py::"
            "test_derive_dependencies_snapshot_at_entry_but_reporter_resolves_late"
        ),
    ),
    Mutation(
        name="cli-agent-change-entry-sealer-late-bound",
        path="evoom_guard/cli/__init__.py",
        before="            seal_authorization=seal_agent_change_authorization,\n",
        after=(
            "            seal_authorization=lambda *positional, **keyword: getattr(\n"
            '                sys.modules["evoom_guard.admission.agent_change"],\n'
            '                "seal_agent_change_authorization",\n'
            "            )(*positional, **keyword),\n"
        ),
        test=(
            "tests/test_cli_agent_change_command_characterization.py::"
            "test_authorization_reads_stay_live_but_sealer_snapshots_at_entry"
        ),
    ),
    Mutation(
        name="cli-trusted-finalizer-derive-source-binding-bypass",
        path="evoom_guard/cli/trusted_finalizer_commands.py",
        before='        "pull_request_number": args.pr_number,\n',
        after='        "pull_request_number": 0,\n',
        test=(
            "tests/test_cli_derive_finalizer_bindings_characterization.py::"
            "test_frozen_cli_derive_finalizer_bindings_behavior[derive_success]"
        ),
    ),
    Mutation(
        name="cli-trusted-finalizer-derive-write-bypass",
        path="evoom_guard/cli/trusted_finalizer_commands.py",
        before=(
            "        output = services.write_bindings(\n"
            "            bindings,\n"
            "            bindings_path=args.out,\n"
            "            force=args.force,\n"
            "        )\n"
        ),
        after="        output = args.out\n",
        test=(
            "tests/test_cli_derive_finalizer_bindings_characterization.py::"
            "test_frozen_cli_derive_finalizer_bindings_behavior[derive_success]"
        ),
    ),
    Mutation(
        name="cli-trusted-finalizer-entry-binding-writer-late-bound",
        path="evoom_guard/cli/__init__.py",
        before="            write_bindings=write_finalizer_bindings,\n",
        after=(
            "            write_bindings=lambda *positional, **keyword: getattr(\n"
            '                sys.modules["evoom_guard.finalizer_derivation"],\n'
            '                "write_finalizer_bindings",\n'
            "            )(*positional, **keyword),\n"
        ),
        test=(
            "tests/test_cli_derive_finalizer_bindings_characterization.py::"
            "test_dependencies_snapshot_at_entry_but_reporter_resolves_late"
        ),
    ),
    Mutation(
        name="cli-trusted-finalizer-semantic-verification-bypass",
        path="evoom_guard/cli/trusted_finalizer_commands.py",
        before=(
            '    report = services.verify_record(record)\n'
            '    if not report["ok"]:\n'
        ),
        after=(
            '    report = {"ok": True, "checks": []}\n'
            '    if not report["ok"]:\n'
        ),
        test=(
            "tests/test_cli_trusted_finalizer_command_characterization.py::"
            "test_frozen_cli_trusted_finalizer_command_behavior"
            "[bindings_semantic_invalid]"
        ),
    ),
    Mutation(
        name="cli-trusted-finalizer-binding-read-order-inversion",
        path="evoom_guard/cli/trusted_finalizer_commands.py",
        before=(
            "        bindings = services.read_bindings(args.bindings)\n"
            "        record = services.read_semantic_record(args.verdict)\n"
        ),
        after=(
            "        record = services.read_semantic_record(args.verdict)\n"
            "        bindings = services.read_bindings(args.bindings)\n"
        ),
        test=(
            "tests/test_cli_trusted_finalizer_command_characterization.py::"
            "test_frozen_cli_trusted_finalizer_command_behavior[bindings_success]"
        ),
    ),
    Mutation(
        name="cli-trusted-finalizer-handoff-read-order-inversion",
        path="evoom_guard/cli/trusted_finalizer_commands.py",
        before=(
            '        source = services.read_external_object(args.source, label="source")\n'
            '        context = services.read_external_object(args.context, label="context")\n'
        ),
        after=(
            '        context = services.read_external_object(args.context, label="context")\n'
            '        source = services.read_external_object(args.source, label="source")\n'
        ),
        test=(
            "tests/test_cli_trusted_finalizer_command_characterization.py::"
            "test_frozen_cli_trusted_finalizer_command_behavior[handoff_success]"
        ),
    ),
    Mutation(
        name="cli-trusted-finalizer-seal-derivation-bypass",
        path="evoom_guard/cli/trusted_finalizer_commands.py",
        before=(
            "        expected_derivation = services.read_bindings(args.expected_derivation).payload\n"
            "        materials = services.parse_materials(args.material)\n"
        ),
        after=(
            "        expected_derivation = None\n"
            "        materials = services.parse_materials(args.material)\n"
        ),
        test=(
            "tests/test_cli_trusted_finalizer_command_characterization.py::"
            "test_frozen_cli_trusted_finalizer_command_behavior[seal_allow]"
        ),
    ),
    Mutation(
        name="trusted-finalizer-strict-derivation-absence-bypass",
        path="evoom_guard/trusted_finalizer.py",
        before=(
            "    if len(derivation_materials) != 1:\n"
            "        raise FinalizerHandoffError(\n"
            "            \"derivation-bound finalized evidence bundle must contain exactly one \"\n"
            "            f\"{FINALIZER_DERIVATION_ROLE!r} material\"\n"
            "        )\n"
        ),
        after=(
            "    if len(derivation_materials) != 1:\n"
            "        return verified  # type: ignore[return-value]\n"
        ),
        test=(
            "tests/test_trusted_finalizer.py::"
            "test_weak_bundle_cannot_pass_strict_verification_but_explicit_legacy_can"
        ),
    ),
    Mutation(
        name="cli-trusted-finalizer-seal-require-pass-bypass",
        path="evoom_guard/cli/trusted_finalizer_commands.py",
        before=(
            "    return 0 if allowed or not args.require_pass else 1\n"
            "\n"
            "\n"
            "def execute_verify_finalized(\n"
        ),
        after=(
            "    return 0\n"
            "\n"
            "\n"
            "def execute_verify_finalized(\n"
        ),
        test=(
            "tests/test_cli_trusted_finalizer_command_characterization.py::"
            "test_frozen_cli_trusted_finalizer_command_behavior[seal_deny_gated]"
        ),
    ),
    Mutation(
        name="cli-trusted-finalizer-verify-require-pass-bypass",
        path="evoom_guard/cli/trusted_finalizer_commands.py",
        before="    ok = allowed or not args.require_pass\n",
        after="    ok = allowed\n",
        test=(
            "tests/test_cli_trusted_finalizer_command_characterization.py::"
            "test_frozen_cli_trusted_finalizer_command_behavior"
            "[verify_deny_ungated]"
        ),
    ),
    Mutation(
        name="cli-trusted-finalizer-live-reader-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "            operational_errors=(OSError,),\n"
            "            read_external_object=lambda object_path, *, label: (\n"
            "                _read_external_finalizer_object(object_path, label=label)\n"
            "            ),\n"
            "            create_handoff=create_finalizer_handoff,\n"
        ),
        after=(
            "            operational_errors=(OSError,),\n"
            "            read_external_object=_read_external_finalizer_object,\n"
            "            create_handoff=create_finalizer_handoff,\n"
        ),
        test=(
            "tests/test_cli_trusted_finalizer_command_characterization.py::"
            "test_handoff_reads_and_path_stay_live_but_creator_snapshots_at_entry"
        ),
    ),
    Mutation(
        name="cli-trusted-finalizer-live-reporter-snapshot",
        path="evoom_guard/cli/__init__.py",
        before=(
            "            context_from_bindings=context_from_verified_bindings,\n"
            "            write_verified_context=write_verified_finalizer_context,\n"
            "            machine_report=lambda report_out, value: _machine_report(\n"
            "                report_out,\n"
            "                value,\n"
            "            ),\n"
        ),
        after=(
            "            context_from_bindings=context_from_verified_bindings,\n"
            "            write_verified_context=write_verified_finalizer_context,\n"
            "            machine_report=_machine_report,\n"
        ),
        test=(
            "tests/test_cli_trusted_finalizer_command_characterization.py::"
            "test_binding_imports_snapshot_but_semantic_reader_and_reporter_stay_live"
        ),
    ),
    Mutation(
        name="cli-trusted-finalizer-entry-sealer-late-bound",
        path="evoom_guard/cli/__init__.py",
        before="            seal_finalizer=seal_finalizer_bundle,\n",
        after=(
            "            seal_finalizer=lambda *positional, **keyword: getattr(\n"
            '                sys.modules["evoom_guard.trusted_finalizer"],\n'
            '                "seal_finalizer_bundle",\n'
            "            )(*positional, **keyword),\n"
        ),
        test=(
            "tests/test_cli_trusted_finalizer_command_characterization.py::"
            "test_seal_imports_snapshot_but_readers_and_material_parser_stay_live"
        ),
    ),
    Mutation(
        name="blackbox-candidate-runtime-scanner-snapshot",
        path="evoom_guard/blackbox.py",
        before=(
            "        services=CandidateExecutionEvidenceServices(\n"
            "            container_ids_provider=lambda: _candidate_container_ids,\n"
            "            sleeper_provider=lambda: time.sleep,\n"
        ),
        after=(
            "        services=CandidateExecutionEvidenceServices(\n"
            "            container_ids_provider=(\n"
            "                lambda scanner=_candidate_container_ids: scanner\n"
            "            ),\n"
            "            sleeper_provider=lambda: time.sleep,\n"
        ),
        test=(
            "tests/test_blackbox_candidate_runtime_characterization.py::"
            "test_retry_observes_live_providers_and_updates_cids_before_sorting"
        ),
    ),
    Mutation(
        name="blackbox-candidate-runtime-sleeper-snapshot",
        path="evoom_guard/blackbox.py",
        before=(
            "        services=CandidateExecutionEvidenceServices(\n"
            "            container_ids_provider=lambda: _candidate_container_ids,\n"
            "            sleeper_provider=lambda: time.sleep,\n"
        ),
        after=(
            "        services=CandidateExecutionEvidenceServices(\n"
            "            container_ids_provider=lambda: _candidate_container_ids,\n"
            "            sleeper_provider=(\n"
            "                lambda sleeper=time.sleep: sleeper\n"
            "            ),\n"
        ),
        test=(
            "tests/test_blackbox_candidate_runtime_characterization.py::"
            "test_retry_observes_live_providers_and_updates_cids_before_sorting"
        ),
    ),
    Mutation(
        name="blackbox-candidate-runtime-scan-before-drain",
        path="evoom_guard/verifiers/blackbox_candidate_runtime.py",
        before=(
            "        launcher_events = (\n"
            "            request.recorder.drain()\n"
            "            if request.recorder is not None\n"
            "            else 0\n"
            "        )\n"
            "        container_ids = services.container_ids_provider()(\n"
            "            request.cidfile_dir\n"
            "        )\n"
        ),
        after=(
            "        container_ids = services.container_ids_provider()(\n"
            "            request.cidfile_dir\n"
            "        )\n"
            "        launcher_events = (\n"
            "            request.recorder.drain()\n"
            "            if request.recorder is not None\n"
            "            else 0\n"
            "        )\n"
        ),
        test=(
            "tests/test_blackbox_candidate_runtime_characterization.py::"
            "test_retry_observes_live_providers_and_updates_cids_before_sorting"
        ),
    ),
    Mutation(
        name="blackbox-candidate-runtime-observed-cid-copy",
        path="evoom_guard/verifiers/blackbox_candidate_runtime.py",
        before=(
            "            request.observed_container_ids.update(container_ids)\n"
            "            container_ids = sorted(request.observed_container_ids)\n"
        ),
        after=(
            "            container_ids = sorted(\n"
            "                set(request.observed_container_ids) | set(container_ids)\n"
            "            )\n"
        ),
        test=(
            "tests/test_blackbox_candidate_runtime_characterization.py::"
            "test_interrupted_observation_keeps_immediate_cid_mutation"
        ),
    ),
    Mutation(
        name="blackbox-candidate-runtime-container-conjunction-bypass",
        path="evoom_guard/verifiers/blackbox_candidate_runtime.py",
        before=(
            "            candidate_invocations = min(\n"
            "                launcher_events,\n"
            "                len(container_ids),\n"
            "            )\n"
        ),
        after="            candidate_invocations = launcher_events\n",
        test=(
            "tests/test_candidate_invocation_evidence.py::"
            "test_docker_invocation_requires_both_launcher_receipt_and_valid_cid"
        ),
    ),
    Mutation(
        name="blackbox-candidate-runtime-kernel-late-binding",
        path="evoom_guard/verifiers/blackbox_candidate_runtime.py",
        before=(
            "    cleanup_kernel = services.cleanup_kernel_provider()\n"
            "    cleanup_request_factory = services.cleanup_request_factory_provider()\n"
            "    known_container_ids = frozenset(request.known_container_ids or ())\n"
        ),
        after=(
            "    cleanup_request_factory = services.cleanup_request_factory_provider()\n"
            "    known_container_ids = frozenset(request.known_container_ids or ())\n"
            "    cleanup_kernel = services.cleanup_kernel_provider()\n"
        ),
        test=(
            "tests/test_blackbox_candidate_runtime_characterization.py::"
            "test_blackbox_candidate_runtime_matches_pre_extraction_vector"
            "[cleanup_live_binding_schedule]"
        ),
    ),
    Mutation(
        name="blackbox-candidate-runtime-known-ids-deferred",
        path="evoom_guard/verifiers/blackbox_candidate_runtime.py",
        before=(
            "    known_container_ids = frozenset(request.known_container_ids or ())\n"
        ),
        after=(
            "    known_container_ids = request.known_container_ids or frozenset()\n"
        ),
        test=(
            "tests/test_blackbox_candidate_runtime_owner.py::"
            "test_cleanup_freezes_known_ids_once_and_preserves_provider_order"
        ),
    ),
    Mutation(
        name="blackbox-candidate-runtime-provider-order-inversion",
        path="evoom_guard/verifiers/blackbox_candidate_runtime.py",
        before=(
            "        control_runner=services.control_runner_provider(),\n"
            "        sleeper=services.sleeper_provider(),\n"
            "        path_exists=services.path_exists_provider(),\n"
        ),
        after=(
            "        sleeper=services.sleeper_provider(),\n"
            "        control_runner=services.control_runner_provider(),\n"
            "        path_exists=services.path_exists_provider(),\n"
        ),
        test=(
            "tests/test_blackbox_candidate_runtime_owner.py::"
            "test_cleanup_freezes_known_ids_once_and_preserves_provider_order"
        ),
    ),
    Mutation(
        name="blackbox-candidate-runtime-scan-error-overcatch",
        path="evoom_guard/verifiers/blackbox_candidate_runtime.py",
        before="        except services.scan_failure_type_provider() as exc:\n",
        after="        except Exception as exc:\n",
        test=(
            "tests/test_blackbox_candidate_runtime_owner.py::"
            "test_scan_adapter_propagates_unclassified_exceptions_by_identity"
        ),
    ),
    Mutation(
        name="blackbox-candidate-runtime-strict-gate-bypass",
        path="evoom_guard/verifiers/blackbox_candidate_runtime.py",
        before="    if request.strict and cleanup.failures:\n",
        after="    if False and request.strict and cleanup.failures:\n",
        test=(
            "tests/test_blackbox_candidate_runtime_owner.py::"
            "test_strict_cleanup_aggregates_failures_once_in_kernel_order"
        ),
    ),
    Mutation(
        name="blackbox-candidate-runtime-failure-order-inversion",
        path="evoom_guard/verifiers/blackbox_candidate_runtime.py",
        before='            + "; ".join(cleanup.failures)\n',
        after='            + "; ".join(reversed(cleanup.failures))\n',
        test=(
            "tests/test_blackbox_candidate_runtime_owner.py::"
            "test_strict_cleanup_aggregates_failures_once_in_kernel_order"
        ),
    ),
    Mutation(
        name="blackbox-pack-outcome-exclusivity-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before="        if (self.terminal is None) == (self.completed is None):\n",
        after="        if False:\n",
        test=(
            "tests/test_blackbox_pack_phase.py::"
            "test_pack_outcome_requires_exactly_one_branch"
        ),
    ),
    Mutation(
        name="blackbox-pack-pre-snapshot-verification-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before=(
            "    started_at = services.perf_counter()\n"
            "    try:\n"
            "        services.verify_snapshot()"
            "(request.pack_snapshot, request.pack_identity)\n"
            "        lifecycle.active = True\n"
        ),
        after=(
            "    started_at = services.perf_counter()\n"
            "    try:\n"
            "        lifecycle.active = True\n"
        ),
        test=(
            "tests/test_blackbox_pack_characterization.py::"
            "test_blackbox_pack_branch_order_identity_and_errors_are_frozen"
            "[pre_snapshot_drift]"
        ),
    ),
    Mutation(
        name="blackbox-pack-active-lifecycle-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before="        lifecycle.active = True\n",
        after="        lifecycle.active = False\n",
        test=(
            "tests/test_blackbox_pack_phase.py::"
            "test_pack_error_from_command_preserves_historical_cleanup_state"
        ),
    ),
    Mutation(
        name="blackbox-pack-started-lifecycle-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before="        lifecycle.started = True\n",
        after="        lifecycle.started = False\n",
        test=(
            "tests/test_blackbox_pack_phase.py::"
            "test_execute_preserves_identity_lookup_timing_and_lifecycle"
        ),
    ),
    Mutation(
        name="blackbox-pack-runner-command-lookup-inversion",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before=(
            "        run_judge = services.run_judge()\n"
            "        command = services.build_command()"
            "(request.pack_snapshot, request.xml_path)\n"
        ),
        after=(
            "        command = services.build_command()"
            "(request.pack_snapshot, request.xml_path)\n"
            "        run_judge = services.run_judge()\n"
        ),
        test=(
            "tests/test_blackbox_pack_phase.py::"
            "test_execute_preserves_identity_lookup_timing_and_lifecycle"
        ),
    ),
    Mutation(
        name="blackbox-pack-judge-cwd-binding-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before="            cwd=request.pack_snapshot,\n",
        after="            cwd=request.xml_path,\n",
        test=(
            "tests/test_blackbox_pack_phase.py::"
            "test_execute_preserves_identity_lookup_timing_and_lifecycle"
        ),
    ),
    Mutation(
        name="blackbox-pack-environment-identity-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before="            env=request.environment,\n",
        after="            env=dict(request.environment),\n",
        test=(
            "tests/test_blackbox_pack_phase.py::"
            "test_execute_preserves_identity_lookup_timing_and_lifecycle"
        ),
    ),
    Mutation(
        name="blackbox-pack-timeout-forwarding-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before="            timeout=request.timeout,\n",
        after="            timeout=request.timeout + 1,\n",
        test=(
            "tests/test_blackbox_pack_phase.py::"
            "test_execute_preserves_identity_lookup_timing_and_lifecycle"
        ),
    ),
    Mutation(
        name="blackbox-pack-normal-active-clear-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before="        lifecycle.active = False\n",
        after="        lifecycle.active = True\n",
        test=(
            "tests/test_blackbox_pack_phase.py::"
            "test_execute_preserves_identity_lookup_timing_and_lifecycle"
        ),
    ),
    Mutation(
        name="blackbox-pack-timeout-classification-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before='            error="timeout",\n',
        after='            error="black-box output limit",\n',
        test=(
            "tests/test_blackbox_pack_characterization.py::"
            "test_blackbox_pack_branch_order_identity_and_errors_are_frozen"
            "[timeout]"
        ),
    ),
    Mutation(
        name="blackbox-pack-output-limit-classification-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before='            error="black-box output limit",\n',
        after='            error="timeout",\n',
        test=(
            "tests/test_blackbox_pack_characterization.py::"
            "test_blackbox_pack_branch_order_identity_and_errors_are_frozen"
            "[output_limit]"
        ),
    ),
    Mutation(
        name="blackbox-pack-cleanup-classification-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before='            error="judge process cleanup failed",\n',
        after='            error="timeout",\n',
        test=(
            "tests/test_blackbox_pack_characterization.py::"
            "test_blackbox_pack_branch_order_identity_and_errors_are_frozen"
            "[judge_cleanup_error]"
        ),
    ),
    Mutation(
        name="blackbox-pack-post-snapshot-verification-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before=(
            "    try:\n"
            "        services.verify_snapshot()"
            "(request.pack_snapshot, request.pack_identity)\n"
            "    except PackManifestError as exc:\n"
        ),
        after=(
            "    try:\n"
            "        pass\n"
            "    except PackManifestError as exc:\n"
        ),
        test=(
            "tests/test_blackbox_pack_characterization.py::"
            "test_blackbox_pack_branch_order_identity_and_errors_are_frozen"
            "[post_snapshot_drift]"
        ),
    ),
    Mutation(
        name="blackbox-pack-report-owner-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before="    xml_text = services.read_report()(completed.xml_path)\n",
        after='    xml_text = services.read_report()("")\n',
        test=(
            "tests/test_blackbox_pack_phase.py::"
            "test_interpretation_binds_raw_report_hash_and_effect_order"
        ),
    ),
    Mutation(
        name="blackbox-pack-raw-report-digest-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before="        junit_sha256 = services.digest_text(xml_text)\n",
        after='        junit_sha256 = services.digest_text(xml_text + " ")\n',
        test=(
            "tests/test_blackbox_pack_phase.py::"
            "test_interpretation_binds_raw_report_hash_and_effect_order"
        ),
    ),
    Mutation(
        name="blackbox-pack-diagnostic-stream-order-inversion",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before=(
            "        completed.process.stdout + "
            '"\\n" + completed.process.stderr\n'
        ),
        after=(
            "        completed.process.stderr + "
            '"\\n" + completed.process.stdout\n'
        ),
        test=(
            "tests/test_blackbox_pack_phase.py::"
            "test_interpretation_binds_raw_report_hash_and_effect_order"
        ),
    ),
    Mutation(
        name="blackbox-pack-zero-test-rejection-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before="    if junit is None or junit.total <= 0:\n",
        after="    if junit is None:\n",
        test=(
            "tests/test_blackbox_pack_characterization.py::"
            "test_blackbox_pack_branch_order_identity_and_errors_are_frozen"
            "[zero_tests]"
        ),
    ),
    Mutation(
        name="blackbox-pack-junit-exit-coherence-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before=(
            "    if (completed.process.returncode == 0 and not junit_all_passed) or (\n"
            "        completed.process.returncode == 1 and junit_all_passed\n"
            "    ):\n"
        ),
        after="    if False:\n",
        test=(
            "tests/test_blackbox_pack_characterization.py::"
            "test_blackbox_pack_branch_order_identity_and_errors_are_frozen"
            "[exit_0_mismatch]"
        ),
    ),
    Mutation(
        name="blackbox-pack-pass-verdict-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before=(
            "    if completed.process.returncode == 0:\n"
            "        return BlackboxPackVerdictFacts(\n"
            "            passed=True,\n"
        ),
        after=(
            "    if completed.process.returncode == 0:\n"
            "        return BlackboxPackVerdictFacts(\n"
            "            passed=False,\n"
        ),
        test=(
            "tests/test_blackbox_pack_characterization.py::"
            "test_blackbox_pack_branch_order_identity_and_errors_are_frozen"
            "[exit_0_pass]"
        ),
    ),
    Mutation(
        name="blackbox-pack-failing-test-gradeability-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before=(
            "    if completed.process.returncode == 1:\n"
            "        return BlackboxPackVerdictFacts(\n"
            "            passed=False,\n"
            "            tests_passed=tests_passed,\n"
            "            tests_total=tests_total,\n"
            "            diagnostics=diagnostics,\n"
            "            ran=True,\n"
        ),
        after=(
            "    if completed.process.returncode == 1:\n"
            "        return BlackboxPackVerdictFacts(\n"
            "            passed=False,\n"
            "            tests_passed=tests_passed,\n"
            "            tests_total=tests_total,\n"
            "            diagnostics=diagnostics,\n"
            "            ran=False,\n"
        ),
        test=(
            "tests/test_blackbox_pack_characterization.py::"
            "test_blackbox_pack_branch_order_identity_and_errors_are_frozen"
            "[exit_1_fail]"
        ),
    ),
    Mutation(
        name="blackbox-pack-non-verdict-exit-bypass",
        path="evoom_guard/verifiers/blackbox_pack.py",
        before="    if completed.process.returncode == 1:\n",
        after="    if completed.process.returncode >= 1:\n",
        test=(
            "tests/test_blackbox_pack_characterization.py::"
            "test_blackbox_pack_branch_order_identity_and_errors_are_frozen"
            "[exit_2_error]"
        ),
    ),
    Mutation(
        name="blackbox-pack-facade-evidence-attachment-bypass",
        path="evoom_guard/blackbox.py",
        before="            if not facts.attach_candidate_evidence:\n",
        after="            if True:\n",
        test=(
            "tests/test_blackbox_pack_characterization.py::"
            "test_blackbox_pack_branch_order_identity_and_errors_are_frozen"
            "[exit_0_pass]"
        ),
    ),
    Mutation(
        name="blackbox-candidate-workspace-owned-allocation-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "    workdir = allocate_owned_workspace(\n"
            '        prefix="evo_blackbox_",\n'
            "        create_workspace=lambda **kwargs: tempfile.mkdtemp(**kwargs),\n"
            "    )\n"
        ),
        after='    workdir = tempfile.mkdtemp(prefix="evo_blackbox_")\n',
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_blackbox_removes_both_nominally_owned_workspaces"
        ),
    ),
    Mutation(
        name="blackbox-pack-workspace-owned-allocation-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "            pack_workdir = "
            "allocate_owned_workspace(\n"
            '                prefix="evo_blackbox_pack_",\n'
            "                create_workspace=lambda **kwargs: "
            "tempfile.mkdtemp(**kwargs),\n"
            "            )\n"
        ),
        after=(
            "            pack_workdir = tempfile.mkdtemp("
            'prefix="evo_blackbox_pack_")\n'
        ),
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_blackbox_removes_both_nominally_owned_workspaces"
        ),
    ),
    Mutation(
        name="blackbox-candidate-workspace-cleanup-bypass",
        path="evoom_guard/blackbox.py",
        before='                    ("candidate workspace", workdir),\n',
        after='                    ("candidate workspace", None),\n',
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_blackbox_removes_both_nominally_owned_workspaces"
        ),
    ),
    Mutation(
        name="blackbox-pack-workspace-cleanup-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            '                    ("verifier-pack snapshot workspace", '
            "pack_workdir),\n"
        ),
        after=(
            '                    ("verifier-pack snapshot workspace", '
            "None),\n"
        ),
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_blackbox_removes_both_nominally_owned_workspaces"
        ),
    ),
    Mutation(
        name="blackbox-workspace-active-primary-cleanup-bypass",
        path="evoom_guard/blackbox.py",
        before="                workspace_primary = observe_cleanup_primary()\n",
        after="                workspace_primary = None\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_workspace_cleanup_failures_are_notes_on_the_exact_active_primary"
        ),
    ),
    Mutation(
        name="blackbox-workspace-cleanup-stage-join-escape",
        path="evoom_guard/blackbox.py",
        before=(
            "        try:\n"
            "            if cidfile_dir is not None:\n"
            "                try:\n"
        ),
        after=(
            "        try:\n"
            "            cidfile_dir = os.path.join("
            "workdir, CANDIDATE_CID_DIRNAME)\n"
            "            if cidfile_dir is not None:\n"
            "                try:\n"
        ),
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_cleanup_stage_reuses_prebound_cid_path_and_attempts_both_owned_roots"
        ),
    ),
    Mutation(
        name="blackbox-workspace-cleanup-baseexception-conversion",
        path="evoom_guard/blackbox.py",
        before="                    if isinstance(first_failure, Exception):\n",
        after="                    if isinstance(first_failure, BaseException):\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_cleanup_keyboard_interrupt_is_visible_and_does_not_skip_pack_root"
        ),
    ),
    Mutation(
        name="blackbox-workspace-cleanup-note-projection-bypass",
        path="evoom_guard/blackbox.py",
        before="        return _cleanup_failure_result_with_notes(exc)\n",
        after="        return exc.result\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_workspace_failures_remain_visible_beneath_reportable_container_failure"
        ),
    ),
    Mutation(
        name="blackbox-workspace-cleanup-reason-mapping-bypass",
        path="evoom_guard/application/blackbox_finalization.py",
        before='            "black-box workspace cleanup failed",\n',
        after="",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_workspace_cleanup_error_maps_to_runtime_cleanup_reason"
        ),
    ),
    Mutation(
        name="blackbox-cleanup-owner-prebind-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "    cleanup_repo_workspaces = "
            "_repository_workspace.cleanup_repo_workspaces\n"
        ),
        after=(
            "    cleanup_repo_workspaces = lambda *args, **kwargs: (\n"
            "        _repository_workspace.cleanup_repo_workspaces("
            "*args, **kwargs)\n"
            "    )\n"
        ),
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_finalization_dependencies_are_bound_before_first_owned_allocation"
            "[return]"
        ),
    ),
    Mutation(
        name="blackbox-cleanup-exc-info-prebind-bypass",
        path="evoom_guard/blackbox.py",
        before="    cleanup_exc_info = sys.exc_info\n",
        after="    cleanup_exc_info = lambda: sys.exc_info()\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_finalization_dependencies_are_bound_before_first_owned_allocation"
            "[return]"
        ),
    ),
    Mutation(
        name="blackbox-cleanup-rmtree-prebind-bypass",
        path="evoom_guard/blackbox.py",
        before="    remove_workspace_tree = shutil.rmtree\n",
        after="    remove_workspace_tree = lambda path: shutil.rmtree(path)\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_finalization_dependencies_are_bound_before_first_owned_allocation"
            "[return]"
        ),
    ),
    Mutation(
        name="blackbox-cleanup-path-prebind-bypass",
        path="evoom_guard/blackbox.py",
        before="    join_path = os.path.join\n",
        after="    join_path = lambda *parts: os.path.join(*parts)\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_finalization_dependencies_are_bound_before_first_owned_allocation"
            "[return]"
        ),
    ),
    Mutation(
        name="blackbox-cleanup-cid-dirname-prebind-bypass",
        path="evoom_guard/blackbox.py",
        before="        cidfile_dir = join_path(workdir, candidate_cid_dirname)\n",
        after="        cidfile_dir = join_path(workdir, CANDIDATE_CID_DIRNAME)\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_finalization_dependencies_are_bound_before_first_owned_allocation"
            "[return]"
        ),
    ),
    Mutation(
        name="blackbox-container-cleanup-provider-prebind-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "    cleanup_candidate_containers_provider = "
            "_cleanup_candidate_containers\n"
        ),
        after=(
            "    cleanup_candidate_containers_provider = "
            "lambda *args, **kwargs: _cleanup_candidate_containers("
            "*args, **kwargs)\n"
        ),
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_finalization_dependencies_are_bound_before_first_owned_allocation"
            "[return]"
        ),
    ),
    Mutation(
        name="blackbox-cleanup-exc-info-deferred-primary-bypass",
        path="evoom_guard/blackbox.py",
        before="            deferred_primary = exc_info_error\n",
        after="            deferred_primary = None\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_exc_info_call_failure_is_deferred_until_both_roots_are_cleaned"
        ),
    ),
    Mutation(
        name="blackbox-cleanup-ambient-primary-adoption-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "            if observed_primary is ambient_primary:\n"
            "                return None\n"
        ),
        after="            if False:\n                return None\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_outer_handled_exception_is_not_adopted_as_the_cleanup_primary"
            "[container]"
        ),
    ),
    Mutation(
        name="blackbox-cleanup-path-absence-prebind-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "    workspace_path_absent = "
            "_repository_workspace.repository_path_absent\n"
        ),
        after=(
            "    workspace_path_absent = lambda path: "
            "_repository_workspace.repository_path_absent(path)\n"
        ),
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_finalization_dependencies_are_bound_before_first_owned_allocation"
            "[return]"
        ),
    ),
    Mutation(
        name="blackbox-recorder-stale-primary-bypass",
        path="evoom_guard/blackbox.py",
        before="            recorder_primary = observe_cleanup_primary()\n",
        after="            recorder_primary = container_primary\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_recorder_close_cannot_replace_container_cleanup_failure"
        ),
    ),
    Mutation(
        name="blackbox-recorder-close-live-lookup-bypass",
        path="evoom_guard/blackbox.py",
        before="                        invocation_recorder_close()\n",
        after="                        invocation_recorder.close()\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_recorder_close_method_is_bound_before_candidate_execution"
        ),
    ),
    Mutation(
        name="blackbox-cleanup-hostile-string-baseexception-bypass",
        path="evoom_guard/blackbox.py",
        before="    except BaseException as stringify_error:\n",
        after="    except Exception as stringify_error:\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_hostile_container_cleanup_stringification_returns_bounded_failure"
        ),
    ),
    Mutation(
        name="blackbox-cleanup-hostile-note-string-bypass",
        path="evoom_guard/blackbox.py",
        before="    except BaseException as stringify_error:\n",
        after="    except Exception as stringify_error:\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_hostile_and_excess_cleanup_notes_are_projected_safely"
        ),
    ),
    Mutation(
        name="blackbox-cleanup-hostile-str-subclass-normalization-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "            if type(rendered) is not str:\n"
            "                rendered = str.__str__(rendered)\n"
        ),
        after="",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_cleanup_text_normalizes_hostile_str_subclass_before_bounding"
        ),
    ),
    Mutation(
        name="blackbox-cleanup-note-callback-baseexception-bypass",
        path="evoom_guard/blackbox.py",
        before="    except BaseException as report_error:\n",
        after="    except Exception as report_error:\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_active_primary_receives_safe_container_and_recorder_cleanup_notes"
        ),
    ),
    Mutation(
        name="blackbox-cleanup-note-python310-storage-bypass",
        path="evoom_guard/blackbox.py",
        before='                primary.__dict__["__notes__"] = [fallback]\n',
        after="                pass\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_cleanup_note_callback_fallback_supports_python310_notes_storage"
        ),
    ),
    Mutation(
        name="blackbox-cleanup-note-count-bound-bypass",
        path="evoom_guard/blackbox.py",
        before="    if len(notes) > _MAX_BLACKBOX_CLEANUP_NOTES:\n",
        after="    if False:\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_hostile_and_excess_cleanup_notes_are_projected_safely"
        ),
    ),
    Mutation(
        name="blackbox-container-cleanup-active-primary-bypass",
        path="evoom_guard/blackbox.py",
        before="                    if container_primary is not None:\n",
        after="                    if False:\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_active_primary_receives_safe_container_and_recorder_cleanup_notes"
        ),
    ),
    Mutation(
        name="blackbox-workspace-owner-active-primary-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "                if workspace_failures and "
            "workspace_primary is not None:\n"
        ),
        after="                if False:\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_active_primary_survives_hostile_workspace_cleanup_reporting"
        ),
    ),
    Mutation(
        name="blackbox-workspace-owner-safe-note-adapter-bypass",
        path="evoom_guard/blackbox.py",
        before="                            note_failure=discard_owner_note,\n",
        after="                            note_failure=note_cleanup_failure,\n",
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_workspace_owner_projects_each_cleanup_note_exactly_once"
        ),
    ),
    Mutation(
        name="blackbox-workspace-secondary-hostile-formatting-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "                    for workspace_label, failure in "
            "workspace_failures[1:]:\n"
            "                        _report_blackbox_cleanup_secondary(\n"
            "                            first_failure,\n"
            "                            workspace_label,\n"
            "                            failure,\n"
            "                            note_failure=note_cleanup_failure,\n"
            "                        )\n"
        ),
        after=(
            "                    for workspace_label, failure in "
            "workspace_failures[1:]:\n"
            "                        note_cleanup_failure(\n"
            "                            first_failure,\n"
            "                            f\"Blackbox {workspace_label} cleanup "
            "failed: {failure}\",\n"
            "                        )\n"
        ),
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_two_hostile_workspace_failures_preserve_the_first_and_both_attempts"
        ),
    ),
    Mutation(
        name="blackbox-secondary-cleanup-label-bypass",
        path="evoom_guard/blackbox.py",
        before='        "secondary cleanup",\n',
        after='        "workspace cleanup",\n',
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_recorder_close_cannot_replace_container_cleanup_failure"
        ),
    ),
    Mutation(
        name="blackbox-container-cleanup-evidence-redrain-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "                            cleanup_result = "
            "_retain_pending_candidate_evidence(\n"
            "                                cleanup_result,\n"
            "                                pending_result,\n"
            "                            )\n"
            "                        control_failure = "
            "_BlackboxCleanupFailure(cleanup_result)\n"
        ),
        after=(
            "                            cleanup_result = "
            "_attach_candidate_execution_evidence(\n"
            "                                cleanup_result,\n"
            "                                recorder=invocation_recorder,\n"
            "                                cidfile_dir=cidfile_dir,\n"
            "                                observed_container_ids="
            "observed_candidate_container_ids,\n"
            "                            )\n"
            "                        control_failure = "
            "_BlackboxCleanupFailure(cleanup_result)\n"
        ),
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_cleanup_results_reuse_evidence_without_a_second_live_drain"
            "[container]"
        ),
    ),
    Mutation(
        name="blackbox-workspace-cleanup-evidence-redrain-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "                        cleanup_result = "
            "_retain_pending_candidate_evidence(\n"
            "                            cleanup_result,\n"
            "                            pending_result,\n"
            "                        )\n"
            "                        control_failure = "
            "_BlackboxCleanupFailure(cleanup_result)\n"
        ),
        after=(
            "                        cleanup_result = "
            "_attach_candidate_execution_evidence(\n"
            "                            cleanup_result,\n"
            "                            recorder=invocation_recorder,\n"
            "                            cidfile_dir=cidfile_dir,\n"
            "                            observed_container_ids="
            "observed_candidate_container_ids,\n"
            "                        )\n"
            "                        control_failure = "
            "_BlackboxCleanupFailure(cleanup_result)\n"
        ),
        test=(
            "tests/test_blackbox_workspace_cleanup.py::"
            "test_cleanup_results_reuse_evidence_without_a_second_live_drain"
            "[workspace]"
        ),
    ),
    Mutation(
        name="guard-request-isolation-validation-bypass",
        path="evoom_guard/application/request_preparation.py",
        before="    validate_isolation_mode(raw.isolation)\n",
        after="    str(raw.isolation)\n",
        test=(
            "tests/test_guard_request_preparation.py::"
            "test_preparation_rejects_unknown_isolation_before_any_provider"
        ),
    ),
    Mutation(
        name="docker-image-canonical-identity-validation-bypass",
        path="evoom_guard/isolation/docker.py",
        before=(
            "    if type(value) is not str or "
            "_DOCKER_IMAGE_ID.fullmatch(value) is None:\n"
        ),
        after="    if False:\n",
        test=(
            "tests/test_isolation_docker.py::"
            "test_image_resolution_rejects_noncanonical_inspection_output"
        ),
    ),
    Mutation(
        name="repo-docker-image-cross-verification-cache-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before='        image = str(self.docker_image or "")\n',
        after=(
            "        if self._resolved_docker_image:\n"
            "            return self._resolved_docker_image\n"
            '        image = str(self.docker_image or "")\n'
        ),
        test=(
            "tests/test_isolation_docker.py::"
            "test_repo_image_facade_preserves_pull_order"
        ),
    ),
    Mutation(
        name="repo-docker-context-local-image-priority-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "            str(active_image or self._resolved_docker_image "
            "or self.docker_image)\n"
        ),
        after="            str(self._resolved_docker_image or self.docker_image)\n",
        test=(
            "tests/test_isolation_docker.py::"
            "test_repo_docker_command_prefers_context_local_image_identity"
        ),
    ),
    Mutation(
        name="diff-verification-empty-preflight-bypass",
        path="evoom_guard/application/diff_verification.py",
        before='    if not (diff_text or "").strip():\n',
        after="    if False:\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_preflight_failures_allocate_nothing"
        ),
    ),
    Mutation(
        name="diff-verification-binary-preflight-bypass",
        path="evoom_guard/application/diff_verification.py",
        before="    if services.binary_diff_provider()(diff_text):\n",
        after="    if False:\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_preflight_failures_allocate_nothing"
        ),
    ),
    Mutation(
        name="diff-verification-unsafe-path-filter-bypass",
        path="evoom_guard/application/diff_verification.py",
        before="            if not services.safe_relpath_provider()(path)\n",
        after="            if False\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_preflight_failures_allocate_nothing"
        ),
    ),
    Mutation(
        name="diff-verification-pack-trust-preflight-bypass",
        path="evoom_guard/application/diff_verification.py",
        before="    if pack_trust_problem:\n",
        after="    if False:\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_preflight_failures_allocate_nothing"
        ),
    ),
    Mutation(
        name="diff-verification-repository-copy-bypass",
        path="evoom_guard/application/diff_verification.py",
        before=(
            "        services.copy_repo_tree_provider()(request.head_dir, base)\n"
        ),
        after="        None\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_success_serializes_and_forwards_every_historical_input"
        ),
    ),
    Mutation(
        name="diff-verification-diff-write-bypass",
        path="evoom_guard/application/diff_verification.py",
        before="        services.diff_writer_provider()(diff_file, diff_text)\n",
        after="        None\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_success_serializes_and_forwards_every_historical_input"
        ),
    ),
    Mutation(
        name="diff-verification-reverse-apply-gate-bypass",
        path="evoom_guard/application/diff_verification.py",
        before=(
            "        if not services.reverse_apply_provider()(base, diff_file):\n"
        ),
        after="        if False:\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_reverse_apply_failure_still_cleans_up"
        ),
    ),
    Mutation(
        name="diff-verification-unverifiable-path-catch-bypass",
        path="evoom_guard/application/diff_verification.py",
        before=(
            "        except services.unverifiable_errors_provider() as exc:\n"
        ),
        after="        except () as exc:\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_unverifiable_paths_are_fail_closed_after_reconstruction"
        ),
    ),
    Mutation(
        name="diff-verification-empty-reconstruction-gate-bypass",
        path="evoom_guard/application/diff_verification.py",
        before="        if not file_blocks and not deleted:\n",
        after="        if False:\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_empty_reconstruction_does_not_invoke_guard"
        ),
    ),
    Mutation(
        name="diff-verification-candidate-end-marker-corruption",
        path="evoom_guard/application/diff_verification.py",
        before=(
            '            f"<<<FILE: {relative_path}>>>\\n{new_content}\\n'
            '<<<END FILE>>>"\n'
        ),
        after=(
            '            f"<<<FILE: {relative_path}>>>\\n{new_content}\\n'
            '<<<END EDIT>>>"\n'
        ),
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_success_serializes_and_forwards_every_historical_input"
        ),
    ),
    Mutation(
        name="diff-verification-guard-provider-call-bypass",
        path="evoom_guard/application/diff_verification.py",
        before="        run_guard = services.guard_provider()\n",
        after="        run_guard = services.guard_provider\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_success_serializes_and_forwards_every_historical_input"
        ),
    ),
    Mutation(
        name="diff-verification-explicit-base-sha-priority-bypass",
        path="evoom_guard/application/diff_verification.py",
        before=(
            "            base_sha=options.base_sha\n"
            "            or services.diff_base_sha_provider()(diff_text),\n"
        ),
        after=(
            "            base_sha=services.diff_base_sha_provider()(diff_text),\n"
        ),
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_explicit_revision_identity_short_circuits_diff_parsers"
        ),
    ),
    Mutation(
        name="diff-verification-explicit-head-sha-priority-bypass",
        path="evoom_guard/application/diff_verification.py",
        before=(
            "            head_sha=options.head_sha\n"
            "            or services.diff_head_sha_provider()(diff_text),\n"
        ),
        after=(
            "            head_sha=services.diff_head_sha_provider()(diff_text),\n"
        ),
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_explicit_revision_identity_short_circuits_diff_parsers"
        ),
    ),
    Mutation(
        name="diff-verification-deletion-forwarding-bypass",
        path="evoom_guard/application/diff_verification.py",
        before="            deleted=tuple(deleted),\n",
        after="            deleted=(),\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_success_serializes_and_forwards_every_historical_input"
        ),
    ),
    Mutation(
        name="diff-verification-coverage-forwarding-bypass",
        path="evoom_guard/application/diff_verification.py",
        before="            diff_coverage=options.diff_coverage,\n",
        after="            diff_coverage=False,\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_success_serializes_and_forwards_every_historical_input"
        ),
    ),
    Mutation(
        name="diff-verification-baseline-forwarding-bypass",
        path="evoom_guard/application/diff_verification.py",
        before="            baseline_evidence=options.baseline_evidence,\n",
        after="            baseline_evidence=False,\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_success_serializes_and_forwards_every_historical_input"
        ),
    ),
    Mutation(
        name="diff-verification-file-block-forwarding-bypass",
        path="evoom_guard/application/diff_verification.py",
        before="            file_blocks=file_blocks,\n",
        after="            file_blocks={},\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_success_serializes_and_forwards_every_historical_input"
        ),
    ),
    Mutation(
        name="diff-verification-source-annotation-bypass",
        path="evoom_guard/application/diff_verification.py",
        before='        result.source = "diff"\n',
        after="        result.source = None\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_success_serializes_and_forwards_every_historical_input"
        ),
    ),
    Mutation(
        name="diff-verification-reconstruction-annotation-bypass",
        path="evoom_guard/application/diff_verification.py",
        before='        result.base_reconstruction = "ok"\n',
        after="        result.base_reconstruction = None\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_success_serializes_and_forwards_every_historical_input"
        ),
    ),
    Mutation(
        name="diff-verification-workspace-cleanup-bypass",
        path="evoom_guard/application/diff_verification.py",
        before=(
            "        cleanup_workspace(\n"
            "            workdir,\n"
            "            primary=cleanup_primary,\n"
            "        )\n"
        ),
        after="        None\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_success_serializes_and_forwards_every_historical_input"
        ),
    ),
    Mutation(
        name="diff-verification-cleanup-provider-preallocation-order-bypass",
        path="evoom_guard/application/diff_verification.py",
        before=(
            "    cleanup_workspace = services.cleanup_workspace_provider()\n"
            "    workdir = services.workspace_factory_provider()("
            "prefix=\"evo_guard_diff_\")\n"
        ),
        after=(
            "    workdir = services.workspace_factory_provider()("
            "prefix=\"evo_guard_diff_\")\n"
            "    cleanup_workspace = services.cleanup_workspace_provider()\n"
        ),
        test=(
            "tests/test_diff_verification_application.py::"
            "test_cleanup_provider_lookup_failure_precedes_workspace_factory"
        ),
    ),
    Mutation(
        name="diff-verification-active-primary-cleanup-bypass",
        path="evoom_guard/application/diff_verification.py",
        before="            primary=cleanup_primary,\n",
        after="            primary=None,\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_active_primary_survives_cleanup_failure_with_diagnostic_note"
        ),
    ),
    Mutation(
        name="diff-verification-caller-ambient-primary-bypass",
        path="evoom_guard/application/diff_verification.py",
        before="            primary=cleanup_primary,\n",
        after="            primary=__import__(\"sys\").exc_info()[1],\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_cleanup_does_not_use_callers_ambient_exception_as_primary"
        ),
    ),
    Mutation(
        name="diff-verification-owned-allocation-bypass",
        path="evoom_guard/guard.py",
        before=(
            "            workspace_factory_provider="
            "lambda: _allocate_diff_workspace,\n"
        ),
        after="            workspace_factory_provider=lambda: tempfile.mkdtemp,\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_success_serializes_and_forwards_every_historical_input"
        ),
    ),
    Mutation(
        name="diff-verification-reverse-provider-snapshot",
        path="evoom_guard/guard.py",
        before="            reverse_apply_provider=lambda: _reverse_apply,\n",
        after=(
            "            reverse_apply_provider="
            "(lambda operation=_reverse_apply: operation),\n"
        ),
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_live_provider_rebinding_is_preserved"
        ),
    ),
    Mutation(
        name="diff-verification-block-provider-snapshot",
        path="evoom_guard/guard.py",
        before="            blocks_from_dirs_provider=lambda: blocks_from_dirs,\n",
        after=(
            "            blocks_from_dirs_provider="
            "(lambda operation=blocks_from_dirs: operation),\n"
        ),
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_live_provider_rebinding_is_preserved"
        ),
    ),
    Mutation(
        name="diff-verification-guard-provider-snapshot",
        path="evoom_guard/guard.py",
        before="            guard_provider=lambda: guard,\n",
        after="            guard_provider=(lambda operation=guard: operation),\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_live_provider_rebinding_is_preserved"
        ),
    ),
    Mutation(
        name="diff-verification-base-sha-provider-snapshot",
        path="evoom_guard/guard.py",
        before="            diff_base_sha_provider=lambda: _diff_base_sha,\n",
        after=(
            "            diff_base_sha_provider="
            "(lambda operation=_diff_base_sha: operation),\n"
        ),
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_live_provider_rebinding_is_preserved"
        ),
    ),
    Mutation(
        name="diff-verification-head-sha-provider-snapshot",
        path="evoom_guard/guard.py",
        before="            diff_head_sha_provider=lambda: _diff_head_sha,\n",
        after=(
            "            diff_head_sha_provider="
            "(lambda operation=_diff_head_sha: operation),\n"
        ),
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_live_provider_rebinding_is_preserved"
        ),
    ),
    Mutation(
        name="diff-verification-binary-reason-provider-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "            binary_patch_reason_code_provider="
            "lambda: REASON_BINARY_PATCH,\n"
        ),
        after=(
            "            binary_patch_reason_code_provider=(\n"
            "                lambda value=REASON_BINARY_PATCH: value\n"
            "            ),\n"
        ),
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_preflight_reason_code_is_looked_up_after_branch_detection"
        ),
    ),
    Mutation(
        name="diff-verification-reverse-reason-provider-snapshot",
        path="evoom_guard/guard.py",
        before=(
            "            reverse_apply_failed_reason_code_provider=(\n"
            "                lambda: REASON_REVERSE_APPLY_FAILED\n"
            "            ),\n"
        ),
        after=(
            "            reverse_apply_failed_reason_code_provider=(\n"
            "                lambda value=REASON_REVERSE_APPLY_FAILED: value\n"
            "            ),\n"
        ),
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_reconstruction_reason_code_is_looked_up_after_runtime_effect"
        ),
    ),
    Mutation(
        name="diff-verification-eager-result-class-lookup",
        path="evoom_guard/guard.py",
        before="        DiffVerificationServices(\n",
        after="        DiffVerificationServices[GuardResult](\n",
        test=(
            "tests/test_diff_verification_characterization.py::"
            "test_facade_does_not_resolve_guard_result_before_diff_preflight"
        ),
    ),
)


def _module_name(path: str) -> str:
    """Return the import name for one mutated Python source path."""

    module = path.removesuffix(".py").replace("/", ".")
    if module.endswith(".__init__"):
        module = module.removesuffix(".__init__")
    if not module.startswith("evoom_guard."):
        raise RuntimeError(f"mutation path is outside the package: {path}")
    return module


def _apply_mutation(overlay: Path, mutation: Mutation) -> None:
    target = overlay / mutation.path
    source = target.read_text(encoding="utf-8")
    count = source.count(mutation.before)
    if count != 1:
        raise RuntimeError(
            f"{mutation.name}: expected one mutation site in {mutation.path}, found {count}"
        )
    target.write_text(
        source.replace(mutation.before, mutation.after, 1),
        encoding="utf-8",
        newline="\n",
    )


def _watchdog_popen_kwargs() -> dict[str, Any]:
    """Create a gate-owned process-tree boundary independent of mutated code."""

    if os.name == "posix":
        return {"start_new_session": True}
    if os.name == "nt":
        creation_flag = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        if creation_flag == 0:
            raise RuntimeError("watchdog process-group support is unavailable on Windows")
        return {"creationflags": creation_flag}
    raise RuntimeError(f"watchdog containment is unsupported on host: {os.name}")


def _stop_watchdog_tree(process: subprocess.Popen[str]) -> None:
    """Stop a timed-out pytest process and members of its inherited boundary."""

    cleanup_error: str | None = None
    if os.name == "posix":
        killpg = getattr(os, "killpg", None)
        if not callable(killpg):
            cleanup_error = "killpg is unavailable"
        else:
            try:
                killpg(
                    process.pid,
                    getattr(signal, "SIGKILL", signal.SIGTERM),
                )
            except ProcessLookupError:
                pass
            except OSError as exc:
                cleanup_error = f"killpg failed: {exc}"
    elif os.name == "nt":
        try:
            killed = subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            cleanup_error = f"taskkill failed: {exc}"
        else:
            # A departed Windows root does not prove that descendants are gone;
            # taskkill must positively accept the /T cleanup request.
            if killed.returncode != 0:
                cleanup_error = f"taskkill exited {killed.returncode}"
    else:  # pragma: no cover - rejected before launch
        cleanup_error = f"unsupported watchdog host: {os.name}"

    if process.poll() is None:
        try:
            process.kill()
        except OSError as exc:
            cleanup_error = cleanup_error or f"direct kill failed: {exc}"
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        cleanup_error = cleanup_error or "watchdog tree retained inherited pipes"
    if process.poll() is None:
        cleanup_error = cleanup_error or "watchdog root did not exit"
    if cleanup_error is not None:
        raise RuntimeError(cleanup_error)


def _run_overlay_test(
    overlay: Path, mutation: Mutation, timeout: float
) -> subprocess.CompletedProcess[str]:
    """Run one focused test and prove it imported the requested overlay module."""

    module_name = _module_name(mutation.path)
    expected_path = str((overlay / mutation.path).resolve())
    process_temp = (overlay / ".process-tmp").resolve()
    process_temp.mkdir(exist_ok=True)
    pytest_args = [
        "-p",
        "no:cacheprovider",
        "--basetemp",
        str((overlay / ".pytest-tmp").resolve()),
        mutation.test,
        "-q",
    ]
    bootstrap = (
        "import importlib, pathlib, sys; "
        f"sys.path.insert(0, {str(overlay)!r}); "
        f"mutated = importlib.import_module({module_name!r}); "
        "loaded = pathlib.Path(mutated.__file__).resolve(); "
        f"expected = pathlib.Path({expected_path!r}).resolve(); "
        "assert loaded == expected, (loaded, expected); "
        "import pytest; "
        f"raise SystemExit(pytest.main({pytest_args!r}))"
    )
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.update(
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONHASHSEED="0",
        TMPDIR=str(process_temp),
        TEMP=str(process_temp),
        TMP=str(process_temp),
    )
    process = subprocess.Popen(
        [sys.executable, "-c", bootstrap],
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **_watchdog_popen_kwargs(),
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _stop_watchdog_tree(process)
        raise
    return subprocess.CompletedProcess(
        process.args,
        process.returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _run_mutant(mutation: Mutation, timeout: float) -> tuple[str, str]:
    with tempfile.TemporaryDirectory(prefix="evoguard-mutant-") as temp:
        overlay = Path(temp)
        shutil.copytree(
            ROOT / "evoom_guard",
            overlay / "evoom_guard",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        try:
            control = _run_overlay_test(overlay, mutation, timeout)
        except subprocess.TimeoutExpired:
            return "infrastructure-error", f"control exceeded {timeout:g}s"
        control_output = (control.stdout + "\n" + control.stderr).strip()
        if control.returncode != 0:
            return (
                "infrastructure-error",
                f"control pytest exit {control.returncode}\n{control_output}",
            )

        _apply_mutation(overlay, mutation)
        try:
            completed = _run_overlay_test(overlay, mutation, timeout)
        except subprocess.TimeoutExpired:
            return "infrastructure-error", f"mutant exceeded {timeout:g}s"

    output = (completed.stdout + "\n" + completed.stderr).strip()
    if completed.returncode == 1:
        return "killed", output
    if completed.returncode == 0:
        return "survived", output
    return "infrastructure-error", f"pytest exit {completed.returncode}\n{output}"


def _classify_mutant(mutation: Mutation, timeout: float) -> tuple[str, str]:
    """Run one mutant and fail closed on any ordinary worker exception."""

    try:
        return _run_mutant(mutation, timeout)
    except Exception as exc:
        return "infrastructure-error", f"{type(exc).__name__}: {exc}"


def _run_selected(
    selected: list[Mutation], timeout: float, workers: int
) -> list[tuple[str, str]]:
    """Run selected mutants with bounded workers and stable inventory order."""

    if workers == 1:
        return [_classify_mutant(mutation, timeout) for mutation in selected]

    with ThreadPoolExecutor(
        max_workers=workers,
        thread_name_prefix="evoguard-mutant",
    ) as executor:
        futures = [
            executor.submit(_classify_mutant, mutation, timeout)
            for mutation in selected
        ]
        return [future.result() for future in futures]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="per-mutant timeout in seconds (default: 20)",
    )
    parser.add_argument(
        "--mutation",
        action="append",
        default=[],
        help="run only this mutation name (repeatable)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="bounded parallel workers (default: 1; maximum: 8)",
    )
    args = parser.parse_args()
    if not 1 <= args.timeout <= 120:
        parser.error("--timeout must be between 1 and 120 seconds")
    if not 1 <= args.workers <= MAX_WORKERS:
        parser.error(f"--workers must be between 1 and {MAX_WORKERS}")

    requested = set(args.mutation)
    known = {mutation.name for mutation in MUTATIONS}
    unknown = requested - known
    if unknown:
        parser.error("unknown mutation(s): " + ", ".join(sorted(unknown)))
    selected = [m for m in MUTATIONS if not requested or m.name in requested]

    results = _run_selected(selected, args.timeout, args.workers)
    failures: list[str] = []
    for mutation, (status, detail) in zip(selected, results, strict=True):
        print(f"{status.upper():20} {mutation.name}")
        if status != "killed":
            failures.append(f"{mutation.name}: {status}\n{detail}")

    if failures:
        print("\nMutation gate failed:\n" + "\n\n".join(failures), file=sys.stderr)
        return 1
    print(f"\nReviewed security mutants: {len(selected)}/{len(selected)} killed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
