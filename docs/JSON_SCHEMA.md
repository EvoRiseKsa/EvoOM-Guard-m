<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
  Maintained and released by Mana Alharbi (مانع الحربي).
-->

# EvoGuard JSON contract

`evo-guard guard --json <path>` writes one JSON object describing the verdict.
Integrations should read this surface instead of parsing the human Markdown
report. Pin `schema_version`, then key decisions off `verdict` and
`reason_code`.

## Stability rules

- `schema_version` is bumped when a shape, enumerated value, or existing field's
  security meaning changes incompatibly. Schema 1.10 makes static pre-gate
  outcomes distinguish requested runtime policy from assurance actually
  delivered: no-run axes are explicit and an unevaluated pack is not described
  as verified or present.
- Verdict names (`PASS`, `REJECTED`, `FAIL`, `ERROR`, `TAMPERED`) are frozen.
- A shipped `reason_code` is never renamed or repurposed. Consumers must still
  handle a future unknown code as the generic enclosing verdict.
- Human `reason` and `diagnostics` text may change. Do **not** parse them.
- Additive nullable fields may appear within a schema version; ignore fields an
  older consumer does not understand.

## Example (`PASS`)

```json
{
  "schema_version": "1.10",
  "tool": "evoguard",
  "tool_version": "3.4.3",
  "verdict": "PASS",
  "passed": true,
  "exit_code": 0,
  "reason_code": "tests_passed",
  "reason": "all repo tests pass and the patch leaves the test harness untouched",
  "files_changed": ["calc.py"],
  "protected_violations": [],
  "risk_level": "low",
  "risk_score": 0.07,
  "tests_passed": 2,
  "tests_total": 2,
  "test_command_ran": true,
  "verdict_source": "junit+exit",
  "source": "diff",
  "base_reconstruction": "ok",
  "diagnostics": ""
}
```

When a base-to-head change deletes files, `deleted` lists them. Deletions are
gated since schema 1.1: deleting source changes the verified tree, while
deleting a protected test/config/CI/auto-exec path is `REJECTED`.

## Top-level fields

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | Contract version; pin this in strict integrations. |
| `tool` | string | Always `"evoguard"`. |
| `tool_version` | string | `evoom_guard.__version__`. |
| `verdict` | string | `PASS` \| `REJECTED` \| `FAIL` \| `ERROR` \| `TAMPERED`. |
| `passed` | bool | `true` only for `PASS`. |
| `exit_code` | int | `0` for `PASS`, `1` for every other verdict. Invalid CLI usage exits `2` and may write no verdict. |
| `reason_code` | string | Stable machine cause; see the table below. |
| `reason` | string | Human explanation; do not parse. |
| `files_changed` | string[] | Repo-relative paths added or modified by the candidate. |
| `deleted` | string[] | Repo-relative deleted paths when supplied by a diff/base-head run. |
| `protected_violations` | string[] | Protected harness paths the patch tried to change. |
| `risk_level` | string | `low` \| `medium` \| `high`. |
| `risk_score` | number | Blast-radius score in `0..1`. |
| `tests_passed` / `tests_total` | int \| null | Judge-owned counts; with a repo-native pack these are the composed repo + pack totals. |
| `test_command_ran` | bool | Whether a test command actually executed; false for a pre-gate refusal. |
| `verdict_source` | string \| null | `junit+exit`, `exit`, `blackbox`, `composite:repo+verifier-pack`, or `null`. |
| `source` | string \| null | `diff` \| `base/head` \| `edit blocks`. |
| `base_reconstruction` | string \| null | `ok` \| `failed` for `--diff`. |
| `diagnostics` | string | Truncated failure essence (at most 2000 characters). |
| `diff_coverage` | object \| null | Changed-line evidence; `executed` is explicitly not the same as asserted. |
| `baseline` | object \| null | Optional pristine-base suite result and `repair_effect`; see below. |
| `assurance` | object | What boundary/integrity levels were actually delivered. |
| `attestation` | object \| null | Digests, policy, revision, runtime, and pack context bound to this verdict. |

Structured `junit+exit` adapters cover pytest, `node --test`, vitest, jest,
gotestsum, RSpec, mocha, and Maven/Surefire. `exit` is a coarser custom-command
verdict. `composite:repo+verifier-pack` means the repo command and a separate
mandatory pytest pack phase were both composed.

## Assurance object (schema 1.10)

Important fields are:

- `harness_integrity`: currently `pre_gate_enforced`.
- `report_integrity`: `same_process_candidate_writable` for repo-native runs,
  `external_process_isolated` when the black-box judge runs, or
  `not_applicable_static_gate` when the diff pre-gate decides the result before
  any report channel exists.
- `candidate_isolation`: the effective delivered boundary, or `not_run` for a
  static pre-gate result. If container setup
  is explicitly moved to the host, this becomes `subprocess` even when the suite
  itself ran in Docker/gVisor.
- `suite_isolation`: the boundary used for the suite, or `not_run` when the diff
  static gate stopped the run before any suite started.
- `setup_isolation`: `null`, `subprocess`, `docker`, `gvisor`,
  `subprocess_host_opt_in`, or `unavailable` as applicable.
- `runtime_continuity`: `not_applicable` when no repo-native pack execution
  occurred (including a static gate);
  `unavailable` if the initial identity could not be captured; `incomplete` if
  execution stopped before all required boundary checks; `verification_failed`
  if a later identity could not be reproduced or differed; otherwise
  `snapshot_boundary_checked` for subprocess comparisons, or
  `read_only_enforced` when Docker/gVisor suite and pack mounts enforced the
  accepted runtime tree read-only. The stronger value is not claimed when a
  configured setup command actually ran through `trust_setup_on_host`, because
  that host process may outlive setup.
- On a static gate only, `verifier_pack.configured` is true when policy supplied
  a pack path and `verifier_pack.present` is `null` because that path was not
  opened. Runtime profiles retain the pre-1.10 pack fields; observed pack
  identity belongs in the attestation.
- `verifier_pack.integrity`: `verified_snapshot_read_only` for a container pack
  mount or `verified_snapshot_pre_post` for a host snapshot checked before and
  after execution; `not_evaluated_static_gate` when execution was pre-gated.
- `verifier_pack.secrecy`: records whether black-box/container execution kept
  the pack unmounted from the candidate. Repo-native pack code remains readable
  in the shared judge process; `not_evaluated_static_gate` makes no secrecy
  claim.
- `overall_profile`: includes `static_gate`, `repo_native_same_process`,
  `isolated_repo_native`, `mixed_host_setup_repo_native`, and
  `black_box_external_judge`.

These axes are independent. A read-only Docker candidate tree protects host
state but does not fix the repo-native same-process report-forgery boundary.
For `static_gate`, the requested mode and isolation remain solely in
`attestation.effective_policy`; they are policy context, not delivered evidence.

## Attestation object (schema 1.10)

Core context binding includes:

- `created_utc`, `guard_version`, `mode`, `candidate_sha256`, `deleted_paths`,
  and `test_command`.
- A black-box request stopped by the diff pre-gate keeps `mode: blackbox` and
  `effective_policy.mode/blackbox` unchanged. This records the requested policy;
  the `static_gate` assurance object still states that no black-box judge ran.
- `effective_policy` and `policy_sha256`. The policy includes every material
  knob, including `expect_verifier_pack_sha256`, `trust_setup_on_host`, and
  `setup_output_globs`. Those globs exclude content from setup validation only;
  they do not exclude it from post-setup runtime continuity.
- `base_sha`, `head_sha`, `base_tree_sha`, `head_tree_sha`, `policy_id`, and
  `policy_version` when supplied.
- `isolation_evidence` (`requested`, `delivered`, `image_digest`, `network`,
  `runtime`) for delivered container runs, including repo-native Docker/gVisor.
- Black-box composition fields `deleted_paths_applied`, `repo_suite_passed`, and
  `repo_suite_junit_sha256`.
- For repo-native pack composition, `runtime_tree_sha256`,
  `runtime_tree_digest_format: EVOGUARD_RUNTIME_TREE_V1`,
  `runtime_tree_entries`, `runtime_tree_bytes`,
  `runtime_identity_elapsed_ms`, and `runtime_continuity` describe the complete
  accepted post-setup runtime tree and the strength of continuity actually
  enforced.

### JUnit identity

- `junit_sha256` is the report/content digest.
- `junit_digest_format: JUNIT_XML_SHA256` means SHA-256 over one JUnit XML text.
- `junit_digest_format: EVOGUARD_JUNIT_COMPOSITE_V1` means SHA-256 over the
  unambiguous UTF-8 framing
  `repo\0<repo XML>\0verifier-pack\0<pack XML>`.

Do not compare `junit_sha256` values without also checking
`junit_digest_format`.

For a directory-producing adapter such as Maven/Surefire, `parse_junit_dir`
accepts the set only when every `*.xml` entry is a readable regular file and
parses under the same size/DTD/entity rules as a single report. Any symlink,
special, unreadable, malformed, oversized, or DTD/entity-bearing sibling makes
the directory yield no clean JUnit verdict; valid siblings are not counted
partially.

### Runtime-tree identity

`EVOGUARD_RUNTIME_TREE_V1` is distinct from both `EVOGUARD_PACK_V2` and the
candidate source digest. It binds the post-setup tree that repo-suite and pack
phases consume, including outputs created by setup. Its assurance meaning is
carried by `runtime_continuity`: subprocess boundary snapshots detect persistent
drift but cannot exclude a mutate/restore action between observations;
`read_only_enforced` describes delivered Docker/gVisor read-only mounts and is
not emitted for host-setup opt-in.

### Verifier-pack identity

- `verifier_pack_sha256` is the **observed accepted snapshot** identity.
- `verifier_pack_digest_format` is `EVOGUARD_PACK_V2`.
- `verifier_pack_manifest` is the canonical optional `pack.json` record.
- `verifier_pack_tests_passed` / `verifier_pack_tests_total` are counts from the
  mandatory pack phase, separate from the composed top-level totals.
- The expected pin is not a duplicate attestation field; it is recorded in
  `effective_policy.expect_verifier_pack_sha256` and therefore in
  `policy_sha256`.

V2 is a portable content/tree identity over typed directory/file paths,
lengths, and bytes. It rejects symlinks and special files. It does not bind
timestamps or filesystem permission metadata. Pre-3.4 pack digests use a
different algorithm and must be recomputed with `pack-doctor`.

## Baseline object

When requested, `baseline` records `verdict` (`PASS`, `FAIL`, or
`NO_CLEAN_VERDICT`), counts, `repair_effect` (`demonstrated`,
`not_demonstrated`, or `unmeasured`), `scope`, and a human `note`. If setup
cannot be proven faithful it may also contain `setup_fidelity` and
`setup_fidelity_changes`; this makes the baseline unclean rather than silently
comparing a different tree. Its scope remains `repo_suite_only`: a pack is
candidate-only and is not run on the pristine baseline.

## Verdict and `reason_code`

| Verdict | `reason_code` | Meaning |
|---|---|---|
| `PASS` | `tests_passed` | Required repo/pack phases passed and the harness gate passed. |
| `REJECTED` | `protected_harness_edit` | Patch edits/deletes a protected test, config, CI, or auto-exec path. |
| `FAIL` | `tests_failed` | A required test phase genuinely failed. |
| `FAIL` / `ERROR` | `no_test_verdict` | No clean test verdict was available (collection/usage/judge error). |
| `TAMPERED` | `junit_exit_mismatch` | Process exit and judge-owned JUnit disagree. |
| `TAMPERED` | `verifier_pack_snapshot_changed` | Accepted pack snapshot changed before or during execution. |
| `TAMPERED` | `candidate_tree_changed_during_run` | The prepared candidate runtime tree changed across the repo-suite/pack transition. |
| `ERROR` | `verifier_pack_identity_mismatch` | Expected V2 digest differs from the accepted snapshot; checked before candidate execution. |
| `ERROR` | `verifier_pack_invalid` | Pack contract/tree is malformed, empty, unreadable, symlinked, special, or unstable. |
| `ERROR` | `test_command_unavailable` | Required test/pack interpreter or executable is unavailable. |
| `ERROR` | `policy_requirement_unsupported` | Selected judge cannot enforce a requested gate; it is not silently dropped. |
| `ERROR` | `assurance_requirement_not_met` | Delivered assurance/isolation is below the required floor or unavailable. |
| `ERROR` | `setup_timeout` | Setup timed out. |
| `ERROR` | `setup_failed` | Setup failed or changed judged paths outside trusted output exceptions. |
| `FAIL` / `ERROR` | `test_timeout` | A required test phase timed out; exact verdict reflects the judge path. |
| `FAIL` | `diff_coverage_below_threshold` | Measured changed-line coverage is below the requested gate. |
| `FAIL` | `fix_not_demonstrated` | Required before/after repair effect was not demonstrated. |
| `ERROR` | `no_parseable_edits` | No edit blocks could be parsed. |
| `ERROR` | `unsafe_path` | Absolute, `..`, or repo-escape path. |
| `ERROR` | `patch_apply_failed` | A patch anchor did not match. |
| `ERROR` | `empty_diff` | `--diff` input was empty. |
| `ERROR` | `binary_patch` | Binary diff refused. |
| `ERROR` | `reverse_apply_failed` | Diff did not reverse-apply to reconstruct the base. |
| `ERROR` | `no_verifiable_changes` | Input reconstructed but contained no verifiable source change. |

## Added in 1.9 → 1.10

- Static diff-gate outcomes now report `overall_profile: static_gate`,
  `candidate_isolation/suite_isolation: not_run`, and
  `report_integrity: not_applicable_static_gate`.
- Configured verifier packs stopped before evaluation use
  `configured: true`, `present: null`, and explicit
  `not_evaluated_static_gate` integrity/secrecy values.
- Static black-box refusals preserve the requested attestation mode and complete
  effective policy without claiming that the judge, pack, or container ran.
- Runtime assurance floors no longer overwrite an already-final static
  pre-gate verdict.

## Added in 1.8 → 1.9

- Descriptor-bound POSIX workspace operations and explicit non-atomic Windows
  fallback semantics.
- All-or-nothing directory JUnit validation.
- `EVOGUARD_RUNTIME_TREE_V1`, its attestation metrics, and delivered
  `runtime_continuity` assurance.

## Added in 1.7 → 1.8

- Canonical V2 pack identity and fail-closed expected digest pin.
- Separate mandatory repo + pack verdict source and pack-specific counts.
- Pre/post accepted-pack and candidate-tree fidelity outcomes with distinct
  tamper reason codes; pack validation and missing-command failures also receive
  distinct reason codes.
- Explicit JUnit digest formats, including composite framing.
- Setup/suite isolation split, host-setup downgrade, pack integrity labels, and
  repo-native container isolation evidence.
- Effective policy binds the expected pack identity and trusted setup-output
  contract.

## Earlier contract milestones

- **1.7:** complete `effective_policy` became the input to `policy_sha256`;
  unsupported gates fail closed; baseline scope became explicit.
- **1.6:** baseline differential evidence, `fix_not_demonstrated`, exact
  commit/tree binding, protected policy identity, and context-aware
  `verify-verdict` checks.
- **1.5:** delivered black-box candidate isolation and composite repo + external
  black-box verdict evidence.
- **1.4:** attestation mode and fail-closed assurance floors.
- **1.3:** assurance object and the explicit
  `same_process_candidate_writable` limit.
- **1.2:** diff coverage, attestation, and named test/setup timeout/failure
  causes.
- **1.1:** deletion-aware verified trees and protected-deletion gating.

## `evo-guard doctor`

`evo-guard doctor --json` reports environment support and does not read a patch.
It exits `0` when supported and `1` otherwise.

```json
{
  "tool": "evoguard",
  "version": "3.4.3",
  "platform": "linux-x86_64",
  "python": "3.11.15",
  "git": true,
  "patch": true,
  "supported": true
}
```
