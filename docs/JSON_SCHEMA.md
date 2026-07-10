<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
  Sole owner & author: Mana Alharbi (مانع الحربي).
-->

# EvoGuard JSON contract

`evo-guard guard --json <path>` writes a single JSON object describing the verdict.
This is the **stable machine surface** that every integration (an IDE extension, a
Claude Code hook, the GitHub Action) is expected to read — instead of parsing the
human Markdown report. Pin on `schema_version`; key off `verdict` and `reason_code`.

## Stability rules

* `schema_version` is bumped on any **breaking** change to this shape, the verdict
  names, or the `reason_code` vocabulary.
* Verdict names (`PASS`, `REJECTED`, `FAIL`, `ERROR`, `TAMPERED`) are **frozen**.
* A `reason_code` value, once shipped, is **never renamed or repurposed**. New
  codes may be **added** without a `schema_version` bump (treat an unknown code as
  the generic verdict).
* The human `reason` / `diagnostics` strings may change at any time — **do not**
  parse them.

## Example (`PASS`)

```json
{
  "schema_version": "1.2",
  "tool": "evoguard",
  "tool_version": "1.8.0",
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

When the change deletes files (from a base→head diff), an extra `deleted` array
lists them. Deletions are **gated** as of `schema_version` `1.1`: a deleted
*source* file is applied to the verified tree (so the verdict matches the merge),
while deleting a protected harness file (a test, its config, the gate's CI, or an
auto-exec file) drives `REJECTED`. (Before `1.1` this array was named
`deleted_not_gated`, when deletions were ungated.)

## Fields

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | Contract version. Pin on this. |
| `diff_coverage` | object \| null | Changed-line coverage evidence (`--diff-coverage`): `measured`, `percent`, `executed`, `total`, per-file `executed`/`missed` lines, `caveat` ("executed is not asserted"). `null` when not requested. |
| `attestation` | object \| null | Context binding for the (optionally signed) verdict: `candidate_sha256`, `policy_sha256`, `junit_sha256`, `verifier_pack_sha256`, `verifier_pack_manifest` (optional `pack.json` id/version), `created_utc`, `guard_version`, `test_command`, `deleted_paths`. |
| `tool` | string | Always `"evoguard"`. |
| `tool_version` | string | `evoom_guard.__version__`. |
| `verdict` | string | `PASS` \| `REJECTED` \| `FAIL` \| `ERROR` \| `TAMPERED`. |
| `passed` | bool | `true` only for `PASS`. |
| `exit_code` | int | `0` for `PASS`, `1` for every other verdict. (Invalid CLI usage exits `2` and writes no JSON.) |
| `reason_code` | string | Stable cause code — see below. |
| `reason` | string | Human explanation. **Do not parse.** |
| `files_changed` | string[] | Repo-relative paths the candidate adds/modifies. |
| `protected_violations` | string[] | Harness paths the patch tried to edit (drives `REJECTED`). |
| `risk_level` | string | `low` \| `medium` \| `high` blast radius. |
| `risk_score` | float | `0..1` blast-radius score. |
| `tests_passed` / `tests_total` | int \| null | Judge-owned JUnit counts; `null` when no suite ran. |
| `test_command_ran` | bool | Whether the test command actually executed (false for pre-gate `REJECTED` / unsafe / unparseable). |
| `verdict_source` | string \| null | `junit+exit` (hardened — pytest, `node --test`, vitest, jest, `gotestsum` (Go), `rspec` (Ruby), mocha, or Maven) \| `exit` (custom runner) \| `null`. |
| `source` | string \| null | How the candidate was supplied: `diff` \| `base/head` \| `edit blocks`. |
| `base_reconstruction` | string \| null | `ok` \| `failed` (only for `--diff`). |
| `diagnostics` | string | Truncated failure essence (≤ 2000 chars). |

## Verdict ⟷ reason_code

| `verdict` | `reason_code` | When |
|---|---|---|
| `PASS` | `tests_passed` | Suite passed; harness untouched. |
| `REJECTED` | `protected_harness_edit` | Patch edits a test / config / auto-exec file. |
| `FAIL` | `tests_failed` | Suite ran and genuinely failed. |
| `FAIL` | `no_test_verdict` | Suite produced no clean verdict (collection/usage error). |
| `TAMPERED` | `junit_exit_mismatch` | Exit code and JUnit report disagree (a desync/forced-exit signature). |
| `ERROR` | `no_parseable_edits` | No `<<<FILE>>>` / `<<<PATCH>>>` blocks. |
| `ERROR` | `unsafe_path` | Absolute / `..` / repo-escape path (edit-block or diff). |
| `ERROR` | `patch_apply_failed` | A `<<<PATCH>>>` anchor did not match. |
| `ERROR` | `empty_diff` | `--diff` input was empty/whitespace. |
| `ERROR` | `binary_patch` | `--diff` contained a binary change. |
| `ERROR` | `reverse_apply_failed` | `--diff` did not reverse-apply (stale base). |
| `ERROR` | `no_verifiable_changes` | `--diff` reconstructed but changed no verifiable source. |

## `evo-guard doctor`

`evo-guard doctor --json` reports the environment EvoGuard needs (it does **not** read a
patch). Exit code is `0` when supported, `1` otherwise.

```json
{
  "tool": "evoguard",
  "version": "1.1.0",
  "platform": "linux-x86_64",
  "python": "3.11.15",
  "git": true,
  "patch": true,
  "supported": true
}
```


## 1.2 additions

- New reason codes: `test_timeout`, `setup_timeout`, `setup_failed` (a run that timed out or whose setup failed is no longer mislabelled `patch_apply_failed`), and `diff_coverage_below_threshold` — a PASS-quality run gated to `FAIL` because the measured changed-line coverage fell below `--min-diff-coverage`.
- New top-level fields `diff_coverage` and `attestation` (additive; `null` when absent).
