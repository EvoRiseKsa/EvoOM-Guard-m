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
  security meaning changes incompatibly. Schema 1.11 (EvoGuard v3.4.4) adds an
  explicit execution state machine and derives runtime assurance from observed
  execution, pack, and isolation evidence rather than requested policy.
- Verdict names (`PASS`, `REJECTED`, `FAIL`, `ERROR`, `TAMPERED`) are frozen.
- A shipped `reason_code` is never renamed or repurposed. Consumers must still
  handle a future unknown code as the generic enclosing verdict.
- Human `reason` and `diagnostics` text may change. Do **not** parse them.
- Additive nullable fields may appear within a schema version; ignore fields an
  older consumer does not understand.
- A schema's `$id` remains on the immutable `v3.8.0` tag while its contract is
  unchanged. It identifies the schema shape, not the newer runtime that carries
  that same shape, so external resolvers retain a reachable stable reference.

## Release Source Finalizer contracts

The protected-`main` release-source path is intentionally not a PR evidence
context. Its closed-world schemas are
[`release-source-context-1.schema.json`](../evoom_guard/schemas/release-source-context-1.schema.json)
and
[`release-source-handoff-1.schema.json`](../evoom_guard/schemas/release-source-handoff-1.schema.json).
They are validated semantically by the separate Release Source Finalizer and do
not change the frozen PR `evidence-context-1` contract. See
[RELEASE_SOURCE_FINALIZER.md](RELEASE_SOURCE_FINALIZER.md) for its trust and
bootstrap boundaries.

The current v4.2.0 source also defines the distinct, closed-world
[`release-source-admission-2.schema.json`](../evoom_guard/schemas/release-source-admission-2.schema.json)
for `EVOGUARD_RELEASE_SOURCE_ADMISSION_V2`. Its signed manifest includes the
full A/B/C identities and replay selectors, evidence descriptors, provider
policy/output bindings, Git and GitHub CLI SHA-256 pins, provider POSIX UID/GID,
the exact cross-domain key registry, and the V2 authentication domain. These
embedded values are claims; the detached verifier requires their source,
policy, toolchain, isolation, and public-key expectations from outside the
bundle. See [RELEASE_SOURCE_ADMISSION_V2.md](RELEASE_SOURCE_ADMISSION_V2.md).

## Example (`PASS`)

Schema 1.11 was introduced in EvoGuard v3.4.4 and remains the current verdict
contract.

A machine-readable structural schema is available at
[`evoom_guard/schemas/verdict-record-1.11.schema.json`](../evoom_guard/schemas/verdict-record-1.11.schema.json).
It defines the complete 24-field `effective_policy`, SHA/timestamp shapes,
assurance and verifier-pack enums, and nested required fields. Use
`evo-guard verify-record verdict.json` for reason-to-verdict/lifecycle mappings,
source/channel binding, policy digest recomputation, and other cross-field
semantic checks that JSON Schema cannot express; see
[RECORD_VERIFICATION.md](RECORD_VERIFICATION.md).

```json
{
  "schema_version": "1.11",
  "tool": "evoguard",
  "tool_version": "4.2.0",
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
  "execution_state": "completed",
  "execution_phase": "repo_suite",
  "verdict_source": "junit+exit",
  "isolation": "subprocess",
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
| `tests_passed` / `tests_total` | int \| null | Judge-owned counts; completed composite repo+pack or black-box+repo verdicts contain summed phase totals. Incomplete composites use `null` rather than presenting a partial total as complete. |
| `test_command_ran` | bool | Whether a test/judge process actually started. It remains `true` when that process times out or otherwise ends without a clean verdict. |
| `execution_state` | string | `static_gate` \| `not_started` \| `started_incomplete` \| `completed`; see below. |
| `execution_phase` | string | Furthest or decisive phase, such as `pre_gate`, `preflight`, `setup`, `runtime_verification`, `repo_suite`, `verifier_pack`, or `blackbox_pack`. Treat future values as additive detail. |
| `verdict_source` | string \| null | `junit+exit`, `exit`, `blackbox`, `composite:repo+verifier-pack`, `composite:blackbox+repo`, or `null`. |
| `isolation` | string | Effective boundary for an observed trusted-verifier launcher/runtime invocation (`subprocess`, `docker`, or `gvisor`), or `not_run` when that invocation was not observed. It is not standalone proof of argv semantics or successful candidate logic; requested/prepared isolation is policy/context only. |
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
mandatory pytest pack phase were both composed; `composite:blackbox+repo`
means the observed external candidate protocol phase and repo-native suite were
both required and completed.

## Execution state (schema 1.11)

`execution_state` is independent of the verdict. It answers how far execution
actually progressed:

| State | Meaning |
|---|---|
| `static_gate` | The diff/static gate decided the result before runtime evaluation. |
| `not_started` | Runtime evaluation was requested but stopped during preflight before a test/judge process started. |
| `started_incomplete` | A setup, test, or judge process started, but the required execution sequence did not complete (for example a timeout). |
| `completed` | The required process returned and the relevant post-execution checks ran. This does not imply `PASS`; a completed run can still be `FAIL`, `ERROR`, or `TAMPERED`. |

`test_command_ran` is the narrower process-start fact. Thus a suite timeout has
`test_command_ran: true`, `execution_state: started_incomplete`, and may have
`verdict_source: null`: process start is not the same as clean verdict evidence.
`execution_phase` records the furthest/decisive phase so preflight, setup,
repo-suite, pack, and black-box failures remain distinguishable.

Requested mode and isolation are policy context and remain in
`attestation.effective_policy`. Top-level `isolation` and assurance isolation
axes describe delivered execution only; when no suite/test process started they
are `not_run`.

## Assurance object (schema 1.11)

Important fields are:

- `harness_integrity`: currently `pre_gate_enforced`.
- `execution_state` and `execution_phase`: mirror the top-level state and phase.
- `report_integrity`: `same_process_candidate_writable` for a started
  repo-native run (including the overall default black-box composite),
  `external_process_isolated` when the only executed report channel so far is
  the black-box judge (completed black-box-only, or a non-PASS/short-circuit
  before the repo channel starts),
  `not_applicable_static_gate` when the diff gate decides the result, or
  `not_applicable_not_run` when runtime preflight stops before tests start.
- `candidate_isolation`: the effective boundary associated with observed
  verifier/launcher evidence, or `not_run` when none was observed. Black-box
  evidence requires a judge-owned
  `$EVOGUARD_EXEC` receipt and, for Docker/gVisor, a runtime-written valid CID;
  this proves the launcher/runtime path, while the trusted pack supplies argv
  semantics and output assertions. Preparation alone is insufficient. If container setup
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
- `verifier_pack` separates policy and evidence with the fields documented
  below. A configured path alone never proves presence, identity, execution, or
  secrecy.
- `overall_profile`: includes `static_gate`, `preflight`,
  `execution_incomplete_before_tests`, `execution_incomplete`,
  `repo_native_same_process`, `isolated_repo_native`,
  `mixed_host_setup_repo_native`, `black_box_external_judge`, and
  `composite_blackbox_repo_native`. `blackbox_composite_short_circuit` means a
  required phase stopped the pipeline before the repo-native report channel
  started; `repo_native_suite` states that lifecycle explicitly.

These axes are independent. A read-only Docker candidate tree protects host
state but does not fix the repo-native same-process report-forgery boundary.
For `static_gate`, the requested mode and isolation remain solely in
`attestation.effective_policy`; they are policy context, not delivered evidence.

For `not_started`, the profile is `preflight`, isolation axes are `not_run`, and
report integrity is `not_applicable_not_run`. A started-but-incomplete setup
before tests uses `execution_incomplete_before_tests`; a started suite/judge
that does not finish uses `execution_incomplete`. None of these profiles implies
a clean verdict source.

### Verifier-pack assurance fields

When a pack is configured, `assurance.verifier_pack` contains:

| Field | Meaning |
|---|---|
| `configured` | Policy supplied a pack path. This is not evidence that the path exists. |
| `present` | `true`/`false` when checked, or `null` when the static gate did not inspect it. |
| `integrity` | Observed snapshot state; see the state list below. |
| `identity_verified` | `true` only when the accepted snapshot identity is established, `false` for an identity mismatch/change, otherwise `null`. |
| `execution_state` | Pack-specific `static_gate`, `not_started`, `started_incomplete`, or `completed`. |
| `secrecy` | Delivered reachability, or an explicit not-evaluated state when pack execution did not start. |
| `snapshot_sha256` | Accepted observed `EVOGUARD_PACK_V2` digest, or `null` if no snapshot was accepted. |

The `integrity` values preserve the exact lifecycle boundary:

- `not_evaluated_static_gate`: static policy stopped before the pack path was
  opened.
- `not_evaluated_missing`: the configured path was checked and missing.
- `invalid`: the path existed but the pack contract/tree was invalid.
- `snapshot_identity_mismatch`: a valid observed snapshot did not match the
  required digest.
- `verified_snapshot_pre_execution`: an accepted snapshot exists, but pack
  execution or the post-execution check did not complete.
- `verified_snapshot_pre_post`: host/subprocess snapshot checks completed before
  and after execution. Black-box packs use this mechanism even when the
  candidate is containerized, because the judge executes its private snapshot
  on the host.
- `verified_snapshot_read_only`: container execution completed with the
  accepted repo-native pack snapshot mounted read-only.
- `snapshot_changed`: the accepted snapshot changed before/during the required
  execution sequence.
- `not_evaluated`: no snapshot evidence was established for another preflight
  path.

Corresponding secrecy values include `not_evaluated_static_gate`,
`not_evaluated_no_execution`, `readable_in_judge_process`,
`not_evaluated_no_candidate_execution`, `reachable_same_host`, and
`unmounted_from_candidate`. A pre-execution snapshot does not by itself
establish secrecy.

## Attestation object (schema 1.11)

Core context binding includes:

- `created_utc`, `guard_version`, `mode`, `candidate_sha256`, `deleted_paths`,
  and `test_command`.
- `execution_state`, `execution_phase`, and `test_command_started` bind progress
  to the verdict. `delivered_isolation` is the primary suite/runner phase;
  `effective_candidate_isolation` is the end-to-end boundary after any host
  setup downgrade and matches top-level/assurance `candidate_isolation`. For black-box
  runs, `candidate_invocations` and
  `candidate_launcher_invocation_observed` bind the judge-owned launcher/CID
  receipts; they prove the boundary invocation, while the trusted pack defines
  and checks the candidate command's semantics. Only zero/non-zero and the
  boolean are security-relevant; `candidate_invocations` is diagnostic and may
  be inflated after the first subprocess receipt by code under the same user.
  Always combine report integrity with `verdict`, `execution_state`, and
  `repo_suite_state`; an incomplete/short-circuited profile is not a completed
  end-to-end PASS guarantee. Pack phase
  facts are also bound as `verifier_pack_present`, `verifier_pack_started`, and
  `verifier_pack_completed`.
- A black-box request stopped by the diff pre-gate keeps `mode: blackbox` and
  `effective_policy.mode/blackbox` unchanged. This records the requested policy;
  the `static_gate` assurance object still states that no black-box judge ran.
- `effective_policy` and `policy_sha256`. The policy includes every material
  knob, including `expect_verifier_pack_sha256`, `trust_setup_on_host`, and
  `setup_output_globs`. Those globs exclude content from setup validation only;
  they do not exclude it from post-setup runtime continuity.
- `base_sha`, `head_sha`, `base_tree_sha`, `head_tree_sha`, `policy_id`, and
  `policy_version` when supplied.
- `isolation_evidence` records requested, prepared, and observed delivery facts.
  The phase-specific `setup_isolation_evidence`,
  `repo_suite_isolation_evidence`, `verifier_pack_isolation_evidence`, and
  `blackbox_pack_isolation_evidence` prevent a later phase failure from erasing
  or overstating an earlier phase. A Docker client timeout claims start only
  when `docker inspect` independently returns a non-zero `StartedAt`.
- Phase-composition fields `deleted_paths_applied`, `repo_suite_started`,
  `repo_suite_completed`, `repo_suite_state`, `repo_suite_passed`,
  `repo_suite_tests_passed`, `repo_suite_tests_total`,
  `repo_suite_verdict_source`, `repo_suite_returncode`, and
  `repo_suite_junit_sha256` / `repo_suite_junit_digest_format`. Black-box lifecycle states include
  `not_required_blackbox_only`, `required_not_run_short_circuit`,
  `required_not_started`, `required_started_incomplete`, and
  `composed_completed`. Repo-native pack composition uses
  `repo_phase_completed`; `repo_suite_passed` is `null` without a clean source.
  For a clean repo+pack composite produced by v4.0.2 or later, `verify-record`
  requires the explicit repo counts to equal the top-level counts minus the pack
  counts and requires the boolean to agree with those counts, the phase source,
  return code, and JUnit component identity. Older records remain verifiable
  under their shipped, less expressive contract.
- For repo-native pack composition, `runtime_tree_sha256`,
  `runtime_tree_digest_format: EVOGUARD_RUNTIME_TREE_V1`,
  `runtime_tree_entries`, `runtime_tree_bytes`,
  `runtime_identity_elapsed_ms`, and `runtime_continuity` describe the complete
  accepted post-setup runtime tree and the strength of continuity actually
  enforced.

### JUnit identity

- `junit_sha256` is the report/content digest.
- `junit_digest_format: JUNIT_XML_SHA256` means SHA-256 over one JUnit XML text.
- `junit_digest_format: EVOGUARD_JUNIT_REPORT_SET_V1` means SHA-256 over the
  accepted report set in sorted filename order. The UTF-8 domain label
  `EVOGUARD_JUNIT_REPORT_SET_V1\0` is followed by each UTF-8 filename and XML
  document, both prefixed by an unsigned 64-bit big-endian byte length.
- `junit_digest_format: EVOGUARD_JUNIT_COMPOSITE_V1` means SHA-256 over the
  raw-XML UTF-8 framing `repo\0<repo XML>\0verifier-pack\0<pack XML>`. It is
  retained for pre-v4.0.2 structured records and current exit-only repo commands,
  which have no repo JUnit component digest to place in V2.
- `junit_digest_format: EVOGUARD_JUNIT_COMPOSITE_V2` means SHA-256 over the
  labelled UTF-8 framing
  `EVOGUARD_JUNIT_COMPOSITE_V2\0repo\0<repo format>\0<repo digest>`
  `\0verifier-pack\0JUNIT_XML_SHA256\0<pack digest>`. From v4.0.2 it is used for
  every structured repo+pack JUnit composite, whether the repo component is one
  XML document or a Maven/Surefire report set. This lets `verify-record`
  recompute the top identity from the two attested component identities.
- `verifier_pack_junit_sha256` / `verifier_pack_junit_digest_format` bind the
  pack-phase JUnit component used by V2. They are distinct from the verifier-pack
  source snapshot identity (`verifier_pack_sha256` / `EVOGUARD_PACK_V2`).

Do not compare `junit_sha256` values without also checking
`junit_digest_format`.

For a directory-producing adapter such as Maven/Surefire, the report-set parser
accepts the set only when every `*.xml` entry is a readable regular file and
parses under the same size/DTD/entity rules as a single report. Any symlink,
special, unreadable, malformed, oversized, or DTD/entity-bearing sibling makes
the directory yield no clean JUnit verdict; valid siblings are not counted
partially. Accepted sets carry `EVOGUARD_JUNIT_REPORT_SET_V1`, so their identity
is bound even when the runner emits multiple files.

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

## Diff-coverage object

Measured evidence contains `measured: true`, `percent`, aggregate `executed`
and `total` counts, per-Python-file `executed`/`missed` line arrays,
`unmeasured_files`, and the non-assertion `caveat`. Unmeasured evidence contains
`measured: false` and a non-empty `note`; the subprocess collector also retains
`unmeasured_files` and `caveat`, while unsupported execution modes emit the
minimal two-field form. `verify-record` reconciles per-file totals and the
producer percentage and enforces `min_diff_coverage` against a `PASS` or
`diff_coverage_below_threshold` reason. If the threshold is configured but the
collector reports `measured: false`, the producer emits `ERROR` with
`assurance_requirement_not_met`; the verifier requires that explicit
unmeasured evidence and completed all-pass suite evidence for that reason.
Per-file arrays identify changed physical source lines. A line is `executed`
only with direct physical-line coverage evidence. Source-excluded, continuation,
and otherwise unknown executable lines are `missed`, while comments, blanks,
and docstrings remain outside the denominator. Code sharing a physical line
with a docstring remains measurable, and lexer failure is conservative. The
producer's one-decimal `percent` is a display value; policy comparison and
record verification use the exact `executed/total` ratio.

The `caveat` is load-bearing: repo-native candidate code and `coverage.py`
share one Python process. A candidate can stop tracing or mutate the live
`CoverageData`, including fabricating executed lines. Isolated collector startup
and an empty rcfile prevent repository module/config shadowing but do not
authenticate runtime coverage state. `verify-record` proves the record's
internal arithmetic and policy consistency; it cannot convert candidate-writable
coverage data into adversarial integrity evidence. Treat the threshold as a
non-hostile-code quality signal, not an admission authority for an untrusted PR.

## Baseline object

When requested, `baseline` records `verdict` (`PASS`, `FAIL`, or
`NO_CLEAN_VERDICT`), counts, `repair_effect` (`demonstrated`,
`not_demonstrated`, or `unmeasured`), `scope`, and a human `note`. If setup
cannot be proven faithful it may also contain `setup_fidelity` and
`setup_fidelity_changes`; this makes the baseline unclean rather than silently
comparing a different tree. Its scope remains `repo_suite_only`: a pack is
candidate-only and is not run on the pristine baseline.
`repair_effect` is derived from the pristine baseline and candidate repo-suite
results before later evidence gates change the composite verdict. Consequently,
a baseline `FAIL` plus an all-pass candidate suite remains `demonstrated` even
when the final verdict is demoted by a coverage requirement. `verify-record`
enforces that ordering as well as binding `require_demonstrated_fix` to the
recorded effect; changing only the human-facing label cannot make a failed gate
internally consistent.
For repo-native verifier-pack composition, the candidate side of this comparison
is the separately recorded repo phase, not the combined repo+pack verdict.

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
| `ERROR` | `verifier_pack_required` | Black-box mode was requested without configuring a verifier pack. |
| `ERROR` | `verifier_pack_not_found` | The configured verifier-pack path was checked and does not exist. |
| `ERROR` | `candidate_not_exercised` | A black-box pack completed without an observed `$EVOGUARD_EXEC` candidate invocation; constant tests/direct legacy target access are not a gradeable black-box verdict. |
| `ERROR` | `runtime_cleanup_failed` | The judge process group or a candidate container could not be proven absent after execution; a pending PASS/FAIL is invalidated fail-closed. |
| `ERROR` | `test_command_unavailable` | Required test/pack interpreter or executable is unavailable. |
| `ERROR` | `policy_requirement_unsupported` | Selected judge cannot enforce a requested gate; it is not silently dropped. |
| `ERROR` | `assurance_requirement_not_met` | Delivered assurance/isolation is below the required floor, or required changed-line coverage is explicitly unavailable. |
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

## Added in 1.10 → 1.11 (v3.4.4)

- Top-level `execution_state` and `execution_phase` distinguish static gates,
  preflight stops, incomplete runs, and completed execution.
- `test_command_ran` now means process start, not availability of a clean
  `verdict_source`; it remains true on timeout.
- Preflight/no-run assurance uses `overall_profile: preflight`, isolation
  `not_run`, and `report_integrity: not_applicable_not_run` instead of projecting
  requested policy into delivered evidence.
- Verifier-pack assurance now separates configuration, observed presence,
  accepted identity, execution progress, secrecy, and pre/post snapshot state.
- Assurance floors are evaluated against delivered evidence only for a completed
  `PASS`. They do not replace a static, preflight, timeout/incomplete, pack, or
  isolation failure with a less specific cause.
- `runtime_cleanup_failed` identifies a completed judge whose pending verdict was
  invalidated because process/container absence could not be proven.

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
  "version": "4.2.0",
  "platform": "linux-x86_64",
  "python": "3.11.15",
  "git": true,
  "patch": true,
  "supported": true
}
```
