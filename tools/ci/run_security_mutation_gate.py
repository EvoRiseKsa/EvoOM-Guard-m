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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Mutation:
    name: str
    path: str
    before: str
    after: str
    test: str


MUTATIONS = (
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
            "            failures.append((label, exc))\n"
        ),
        after=(
            "        except BaseException as exc:\n"
            "            failures.append((label, exc)); break\n"
        ),
        test=(
            "tests/test_repository_workspace_owner.py::"
            "test_repository_workspace_cleanup_attempts_every_path_and_preserves_primary"
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
            "    if raw.expect_verifier_pack_sha256 and "
            "not raw.verifier_pack_path:\n"
        ),
        after=(
            "    if False and raw.expect_verifier_pack_sha256 and "
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
        before="            candidate_input_provider=lambda: CandidateInput,\n",
        after=(
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
        before="            source_identity_provider=lambda: SourceIdentity,\n",
        after=(
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
            "            effective_policy_provider="
            "lambda: _build_effective_policy_contract,\n"
        ),
        after=(
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
            "            effective_policy_payload_provider="
            "lambda: _effective_policy_payload,\n"
        ),
        after=(
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
        before="            guard_request_provider=lambda: GuardRequest,\n",
        after=(
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
            "                process_group_terminator(process)\n"
            "            except BaseException:\n"
            "                # An active primary exception must not be replaced by cleanup.\n"
        ),
        after=(
            "                pass\n"
            "            except BaseException:\n"
            "                # An active primary exception must not be replaced by cleanup.\n"
        ),
        test=(
            "tests/test_blackbox_judge_reader_start.py::"
            "test_reader_start_failure_cleans_group_handles_pipes_and_preserves_primary"
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
            "                pipe_join(reader_start_attempts, streams)\n"
            "            except BaseException:\n"
            "                pass\n"
        ),
        after=(
            "                pipe_join(reader_start_attempts, streams)\n"
            "            except BaseException:\n"
            "                raise\n"
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
            "                process_group_terminator(process)\n"
            "            except BaseException:\n"
            "                # An active primary exception must not be replaced by cleanup.\n"
        ),
        after=(
            "                process_group_terminator(process)\n"
            "            except Exception:\n"
            "                # An active primary exception must not be replaced by cleanup.\n"
        ),
        test=(
            "tests/test_blackbox_judge_reader_start.py::"
            "test_reader_start_primary_survives_every_cleanup_baseexception"
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
        before=(
            "            except BaseException:\n"
            "                pass\n"
            "        raise\n"
            "\n"
            "\n"
            "__all__ = [\n"
        ),
        after=(
            "            except BaseException:\n"
            "                pass\n"
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
        before="            remove_tree(path)\n",
        after=(
            "            try:\n"
            "                remove_tree(path)\n"
            "            except BaseException:\n"
            "                continue\n"
        ),
        test=(
            "tests/test_repo_verifier_cleanup_priority.py::"
            "test_workspace_cleanup_failure_is_visible_after_pending_result"
        ),
    ),
    Mutation(
        name="repo-workspace-cleanup-primary-mask",
        path="evoom_guard/verifiers/repo_verifier.py",
        before="                primary=sys.exc_info()[1],\n",
        after="                primary=None,\n",
        test=(
            "tests/test_repo_verifier_cleanup_priority.py::"
            "test_workspace_cleanup_baseexception_cannot_mask_primary"
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
            "            if not _terminate_git_process_tree(process):\n"
        ),
        after=(
            "        if interrupted:\n"
            "            if False and not _terminate_git_process_tree(process):\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_timeout_uses_bounded_kill_reap_and_reader_join"
        ),
    ),
    Mutation(
        name="finalizer-git-posix-post-completion-proof-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            '            if os.name == "posix":\n'
            "                if not _terminate_git_process_tree(process):\n"
        ),
        after=(
            '            if False and os.name == "posix":\n'
            "                if not _terminate_git_process_tree(process):\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_posix_success_proves_post_completion_group_cleanup"
        ),
    ),
    Mutation(
        name="finalizer-git-post-poll-primary-suppression",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "                raise\n"
            '            if os.name == "posix":\n'
        ),
        after=(
            "                pass\n"
            '            if os.name == "posix":\n'
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_post_poll_wait_baseexception_remains_authoritative"
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
            "    except BaseException:\n"
            "        # Preserve the active exception while attempting bounded cleanup.\n"
        ),
        after=(
            "    except Exception:\n"
            "        # Preserve the active exception while attempting bounded cleanup.\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_reader_start_failure_kills_and_reaps_git_without_masking_primary"
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
            "                if not _terminate_gh_process_tree(process):\n"
        ),
        after=(
            "            if not root_exited_on_windows:\n"
            "                if False and not _terminate_gh_process_tree(process):\n"
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
            "                if not _terminate_gh_process_tree(process):\n"
        ),
        after=(
            "            if False and os.name == \"posix\":\n"
            "                if not _terminate_gh_process_tree(process):\n"
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
            "    except BaseException:\n"
            "        # Preserve the active exception while attempting bounded cleanup.\n"
        ),
        after=(
            "    except Exception:\n"
            "        # Preserve the active exception while attempting bounded cleanup.\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_reader_start_failure_cleans_child_without_masking_primary"
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
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                pack_workdir = tempfile.mkdtemp(prefix=prefix)\n"
            "                return pack_workdir\n"
        ),
        after="                return tempfile.mkdtemp(prefix=prefix)\n",
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
            "        delivered = (\n"
            "            services.requested_isolation()\n"
            "            if exc.container_started\n"
            '            else "not_run"\n'
            "        )\n"
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
            "                require_process_group_cleanup_proof=(\n"
            "                    request.strict_harness\n"
            "                ),\n"
        ),
        after=(
            "                require_process_group_cleanup_proof=(\n"
            "                    False\n"
            "                ),\n"
        ),
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
            "                \"outcome\": (\n"
            "                    \"isolation_unavailable\"\n"
            "                    if request.container_mode\n"
            "                    else \"test_command_unavailable\"\n"
            "                ),\n"
        ),
        after="                \"outcome\": \"test_command_unavailable\",\n",
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
        path="evoom_guard/guard.py",
        before=(
            "                    env=setup_env,\n"
            "                    timeout=timeout,\n"
            "                    preexec_fn=rv._limits() if os.name == \"posix\" else None,\n"
            "                    require_process_group_cleanup_proof=strict_harness,\n"
        ),
        after=(
            "                    env=setup_env,\n"
            "                    timeout=timeout,\n"
            "                    preexec_fn=rv._limits() if os.name == \"posix\" else None,\n"
            "                    require_process_group_cleanup_proof=False,\n"
        ),
        test=(
            "tests/test_strict_harness.py::"
            "test_strict_baseline_requires_group_proof_for_every_host_phase"
        ),
    ),
    Mutation(
        name="strict-baseline-suite-group-proof-bypass",
        path="evoom_guard/guard.py",
        before=(
            "                env=run_env,\n"
            "                preexec_fn=rv._limits() if os.name == \"posix\" else None,\n"
            "                timeout=timeout,\n"
            "                require_process_group_cleanup_proof=strict_harness,\n"
        ),
        after=(
            "                env=run_env,\n"
            "                preexec_fn=rv._limits() if os.name == \"posix\" else None,\n"
            "                timeout=timeout,\n"
            "                require_process_group_cleanup_proof=False,\n"
        ),
        test=(
            "tests/test_strict_harness.py::"
            "test_strict_baseline_requires_group_proof_for_every_host_phase"
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
            "                except BaseException:\n"
            "                    pass\n"
            "            if not reader_cleanup_proven:\n"
        ),
        after=(
            "                except Exception:\n"
            "                    pass\n"
            "            if not reader_cleanup_proven:\n"
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
            "                except BaseException:\n"
            "                    pass\n"
            "        raise\n"
        ),
        after=(
            "                except Exception:\n"
            "                    pass\n"
            "        raise\n"
        ),
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_post_start_baseexception_cleans_even_completed_tree_without_masking"
        ),
    ),
    Mutation(
        name="subprocess-tree-cleanup-proof-state-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "            tree_cleanup_proven = True\n"
            "            if not join_pipe_readers(\n"
        ),
        after="            if not join_pipe_readers(\n",
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
            "        deadline = time.monotonic()"
        ),
        after="\n        deadline = time.monotonic()",
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
            "        if not join_pipe_readers(\n"
        ),
        after=(
            "        if False and capture.exceeded:\n"
            '            stop_and_prove("subprocess output limit reached")\n'
            "            raise ProcessOutputLimitExceeded(limits.max_output_bytes)\n"
            "        if not join_pipe_readers(\n"
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
            "                raise ProcessContainmentError(\n"
            '                    f"{reason}; could not prove subprocess-tree cleanup"\n'
            "                )\n"
        ),
        after=(
            "            if False and not _terminate_process_tree(process, limits):\n"
            "                raise ProcessContainmentError(\n"
            '                    f"{reason}; could not prove subprocess-tree cleanup"\n'
            "                )\n"
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
        before='                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)\n',
        after="                0\n",
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
        path="evoom_guard/guard.py",
        before=(
            "            shortfall_evaluator=_assurance_shortfall,\n"
            "            eager_shortfall=True,\n"
        ),
        after=(
            "            shortfall_evaluator=_assurance_shortfall,\n"
            "            eager_shortfall=False,\n"
        ),
        test=(
            "tests/test_assurance_decision_gate_characterization.py::"
            "test_blackbox_gate_is_eager_but_preserves_prior_decisions"
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
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                    repo_suite_passed=(\n"
            "                        passed if verdict_source is not None else None\n"
            "                    ),\n"
        ),
        after="                    repo_suite_passed=False,\n",
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
            "            junit_digest_format = (\n"
            "                services.junit_report_set_digest_format()\n"
            "            )\n"
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
        before="        if not args.json_out:\n",
        after="        if False and not args.json_out:\n",
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
        before="            derive_bindings=derive_agent_change_bindings,\n",
        after=(
            "            derive_bindings=lambda **kwargs: getattr(\n"
            '                sys.modules["evoom_guard.finalizer_derivation"],\n'
            '                "derive_agent_change_bindings",\n'
            "            )(**kwargs),\n"
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
            "        expected_derivation = (\n"
            "            services.read_bindings(args.expected_derivation).payload\n"
            "            if args.expected_derivation is not None\n"
            "            else None\n"
            "        )\n"
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
    bootstrap = (
        "import importlib, pathlib, sys; "
        f"sys.path.insert(0, {str(overlay)!r}); "
        f"mutated = importlib.import_module({module_name!r}); "
        "loaded = pathlib.Path(mutated.__file__).resolve(); "
        f"expected = pathlib.Path({expected_path!r}).resolve(); "
        "assert loaded == expected, (loaded, expected); "
        "import pytest; "
        f"raise SystemExit(pytest.main([{mutation.test!r}, '-q']))"
    )
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONHASHSEED="0")
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
    args = parser.parse_args()
    if not 1 <= args.timeout <= 120:
        parser.error("--timeout must be between 1 and 120 seconds")

    requested = set(args.mutation)
    known = {mutation.name for mutation in MUTATIONS}
    unknown = requested - known
    if unknown:
        parser.error("unknown mutation(s): " + ", ".join(sorted(unknown)))
    selected = [m for m in MUTATIONS if not requested or m.name in requested]

    failures: list[str] = []
    for mutation in selected:
        try:
            status, detail = _run_mutant(mutation, args.timeout)
        except (OSError, RuntimeError) as exc:
            status, detail = "infrastructure-error", str(exc)
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
