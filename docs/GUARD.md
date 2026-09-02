<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# EvoOM Guard — evidence-bound change verification

> A CI gate that evaluates one explicit policy question about an untrusted code change —
> produced by a human, bot, supplier, or the motivating case, an **AI agent**:
> **did the change satisfy the selected judge without manipulating its evidence?**
> It is model-free; authorship is not an input to the decision.

## Why

Frontier agents have been observed **editing or skipping their own tests** to make
a suite pass, and self-modifying coding agents have **faked test logs** (documented
in the public literature). A patch-review gate designed to block the documented
harness-editing paths is therefore a real need as agent-authored PRs become common.
EvoOM Guard addresses those modelled paths: the candidate is judged by the
**repository's own tests**, the verdict is read from a **judge-owned JUnit
report + the process exit code** (never scraped from the patch's stdout), and a
candidate edit or deletion targeting a conventionally recognized judge path, an
exact base-owned `harness_inputs` path, or an ancestor of that path is rejected
before the suite runs. Platform-ambiguous candidate spellings are unsafe, and
existing filesystem aliases are checked where the host can compare identity.

Before spending a real attempt on an unfamiliar repository, post-`v4.6.0`
source builds provide `evo-guard preflight`. It statically checks trusted policy,
launcher portability, and common runtime-write hazards without applying a patch
or running candidate code. It cannot produce `PASS` and does not weaken the
runtime identity check. See [`PREFLIGHT.md`](PREFLIGHT.md).

## What it checks

| Verdict | Meaning |
|---|---|
| ✅ `PASS` | the selected repository judge passed, and the patch did not edit or delete a path covered by the active harness policy |
| ⛔ `REJECTED` | the patch edits **or deletes** an effective-policy protected path — blocked before the suite runs |
| ❌ `FAIL` | the patch applied and the suite ran, but tests fail (also: a suite timeout, or a PASS demoted below `--min-diff-coverage`) |
| 🚨 `TAMPERED` | the process exit code and judge-owned JUnit disagree, or an accepted candidate/pack identity later differs at an enforced materialization/runtime checkpoint |
| ⚠️ `ERROR` | no trustworthy verdict could be produced: the patch did not apply / no parseable edits, an unsafe path, the initial trusted harness identity could not be bound, setup failed/timed out, requested isolation was unavailable, or an assurance floor was unmet |

> **What `REJECTED` does — and does not — mean.** `REJECTED` is a *policy trip*:
> the change touched a path the current harness-protection policy protects. That
> is the right default for an AI-generated patch, but it is **not by itself proof
> of intent to cheat** — a legitimate dependency bump that edits `pom.xml`, or a
> real build/wrapper fix, trips the same rule. Review a genuinely intended
> protected-path change through a separate trusted policy-maintenance workflow.

> **Security policy:** `--allow` applies only to adopter-defined extra `--protected`
> globs. It cannot exempt built-in tests, configuration, CI (including local
> `action.yml` / `action.yaml` manifests), or judge auto-exec
> paths. Use a reviewed policy-maintenance workflow for those changes.

The verdict and its stable `reason_code` are emitted as JSON for integrations — see
[`JSON_SCHEMA.md`](JSON_SCHEMA.md).

A Guard result also carries a **blast radius** (`low`/`medium`/`high`) from the
files and lines represented by the materialized change and any protected-path
hit, plus the **verdict source** (`junit+exit` for the hardened path). Failures
that happen before a complete change can be represented can retain the
compatibility `low`/`0.0` default; that is not a claim that the rejected input
was small. The published JSON keys remain `risk_level`/`risk_score` for
compatibility; they are not a vulnerability, maliciousness, correctness, or
production-readiness probability. See the exact V1 input contract and direct
raw-diff limitations in [`BLAST_RADIUS.md`](BLAST_RADIUS.md).

A forged `9999 passed` printed by the patch's own code **cannot** flip the verdict —
the score comes from the structured JUnit report, cross-checked against the exit
code.

## Install

<!-- BEGIN EVOGUARD_PROJECT_STATUS:GUARD_CURRENT_RELEASE -->
> **Release availability.** [`v4.8.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.8.0) is the latest maintained immutable
> consumer release selected by the protected source tree. For strict CI, pin
> commit `07e361cb9a75cc1822cd905ca65df42235b3b910` rather than a tag. Its direct record is not an
> A-through-H ledger or independent review.

EvoOM Guard is not published to PyPI. Obtain it from this repository.

**GitHub Action:**

```yaml
- uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
  with:
    fetch-depth: 0
    persist-credentials: false
- uses: EvoRiseKsa/EvoOM-Guard-m@v4.8.0
```

**CLI:**

```bash
pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m.git@v4.8.0"
pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m.git@07e361cb9a75cc1822cd905ca65df42235b3b910"
evo-guard guard --diff - --no-config --test-command "python -m pytest -q" < pr.diff
```

Pin the full commit for the strictest source identity. The maintained
immutable tag is the named consumer release. Do not use `@main` for a gate
you depend on.
<!-- END EVOGUARD_PROJECT_STATUS:GUARD_CURRENT_RELEASE -->

## CLI

```bash
# Easiest: pipe a normal git diff from your working tree (the head checkout).
# Guard reverse-applies it to reconstruct the base, then verifies — zero setup.
git diff main...HEAD | evo-guard guard --diff - --no-config --test-command "python -m pytest -q"
evo-guard guard --diff pr.diff --no-config --report report.md --json guard.json

# Verify a candidate in EvoOM Guard's edit-block format against a repo:
evo-guard guard path/to/repo --patch candidate.txt
echo "<<<FILE: src/x.py>>> … <<<END FILE>>>" | evo-guard guard path/to/repo --patch -

# Verify a PR by diffing two explicit checkouts:
evo-guard guard --base path/to/base --head path/to/head --test-command "python -m pytest -q"
```

`evo-guard guard` prints a Markdown report and exits **0 only on `PASS`**, non-zero
otherwise — drop it straight into any CI step.

- **`--diff <file|->`** (lowest friction): a `base...HEAD` unified diff, verified
  against the current checkout (the optional `<repo>` arg, else cwd) by
  **reverse-applying** it to reconstruct the base. So `git diff … | evo-guard guard --diff -`
  works straight from your tree — no second checkout, no worktree. Needs `git`
  (or `patch`) on the runner.
- **`--base/--head`** diffs two explicit trees into the block format.
- **`--patch`** takes the EvoOM Guard edit-block format directly.

Added/modified files are verified, and **deletions are gated too** (since schema
1.1): deleting an effective-policy protected path is `REJECTED` exactly like
editing it, while a deleted *source* file is applied to the verified copy so the
verdict matches the real merge. `--json` writes the machine-readable verdict.
The report shows the `Input` (`diff` / `base/head` / `edit blocks`) and, for
`--diff`, the `Base reconstruction` (`ok` / `failed`).

### Changed-line coverage: `--diff-coverage` / `--min-diff-coverage`

> **Version boundary:** published `v4.0.2` and later include these options together with
> fail-closed unavailable-measurement behavior, isolated collector startup,
> exact-ratio comparison, conservative physical-line denominator,
> setup/resource forwarding, and the explicit candidate-writable caveat below.

Optional `--diff-coverage` runs the pytest suite once more (and replays a
configured setup once) and records which changed Python statements executed. It
remains evidence only. A configured
`--min-diff-coverage` is a requirement: measured coverage below the threshold
is `FAIL diff_coverage_below_threshold`; an unavailable measurement is `ERROR
assurance_requirement_not_met`, never `PASS`.

The coverage subprocess starts in Python isolated mode, imports the installed
collector before adding the candidate root for project imports, and uses an
explicit empty coverage rcfile. Candidate `coverage.py`/`coverage/` modules and
repository `.coveragerc` or `pyproject.toml` coverage settings therefore do not
select or configure the judge collector. Both the run and report commands use
these protections. Trusted interpreter/wrapper prefixes are preserved (for
example `venv/python -m pytest` or `uv run pytest`); `coverage` must be installed
in that selected Python environment or required measurement fails closed.
Configured setup is replayed under the same `setup_output_globs` fidelity
policy. Wall/output/cleanup bounds apply to setup, run, and report, and the main
suite's POSIX CPU/address-space limits are forwarded.

Token/AST classification removes comments, blanks, and the docstring expression
itself, but retains executable code sharing a docstring's physical line. Lexer
failure treats affected physical lines as potentially executable/missed. Every
remaining changed physical code line needs direct coverage evidence to count as
executed; continuation/unknown lines and source `pragma: no cover` exclusions
count as missed. The gate compares the exact `executed/total` ratio; `percent`
is rounded to one decimal for display only. Structured
`file_blocks` are the ground truth for base/head and diff inputs, including
files containing literal edit-block marker text. This is hardening, not a new
sandbox: repo-native
candidate tests and coverage still execute inside the same judged Python
process. Candidate code can call `Coverage.current()`, stop tracing, or mutate
the live `CoverageData` to report unexecuted lines as executed. The isolated
launcher and empty rcfile block repository module/config shadowing only; they do
not authenticate runtime coverage state. `min_diff_coverage` is therefore a
quality gate for non-hostile code, not an adversarial acceptance control. For
untrusted PR admission, keep this signal advisory and require independently
produced external verifier/finalizer evidence. “Executed” also does not mean
“asserted”. Conservative physical-line
classification can therefore create false negatives on continuations that
coverage does not name directly. Use the stronger black-box/
external verifier architecture for an external-process evidence boundary.
Coverage entries for imports outside the throwaway repository are ignored;
changed repository files still remain in the denominator as missed when no
matching in-repository entry exists. This includes cross-drive absolute paths
on Windows and prevents an external helper from aborting record production.

In a quiescent tree, base/head derivation rejects symlinks, Windows junctions
and other reparse objects instead of traversing them. Each regular-file
comparison/read is bound to the object, type, mode, link count, size and path
timestamps captured by its `lstat`. POSIX requires `O_NOFOLLOW` and
`O_NONBLOCK`; the latter makes a
regular-to-FIFO swap fail without hanging at `open`. Windows verifies the
opened handle and current path before and after the bounded operation. Drift
is an unverifiable input error, not an accepted partial candidate. This is a
**per-file stability check**, not an atomic whole-tree snapshot: Guard does not
claim that every path in a mutable base/head directory existed at one common
instant, and Windows cannot make the check atomic against an attacker that
swaps and restores a name entirely between observations. Derive from a
quiescent checkout and bind trusted Git object IDs in the finalizer when
revision identity is an admission requirement.

### Differential evidence: `--baseline-evidence` (opt-in)

"All tests pass on head" does not by itself show the change **fixed** anything —
the base may already have been green. With `--baseline-evidence`, Guard also
runs the suite on the **pristine base** (same judge, policy and environment) and
reports `repair_effect`:

| Baseline | Candidate | `repair_effect` |
|---|---|---|
| ❌ FAIL | ✅ PASS | **demonstrated** — counterfactual evidence the change repaired the measured behaviour |
| ✅ PASS | ✅ PASS | not_demonstrated (nothing to repair — normal for feature PRs) |
| no clean verdict | — | unmeasured |

Evidence only by default. `--require-demonstrated-fix` turns it into a gate: a
PASS whose repair effect is not demonstrated becomes **FAIL**
(`fix_not_demonstrated`). Use that gate **only for agent "fix" PRs** — ordinary
feature PRs start from a green base and would fail it by design. Subprocess
judge only; one extra suite run. **Fail-closed:** requesting the gate (or
`--min-diff-coverage`) together with `--blackbox` / `--isolation docker|gvisor`
is an ERROR (`policy_requirement_unsupported`) — a requirement the judge cannot
enforce is refused, never silently dropped; an evidence-only request in those
modes attaches an explicit *unmeasured* record instead. The measured baseline
also records `scope: repo_suite_only` — a verifier pack (if any) is exercised
only on the candidate run.
`repair_effect` describes the candidate suite transition itself. If that suite
passes after a failing baseline, the effect remains `demonstrated` even when a
separate later gate (for example required changed-line coverage) makes the final
composite verdict non-PASS.
With a repo-native verifier pack, Guard records the candidate repo phase before
composing the pack result. A pack failure therefore still leaves an auditable
base-FAIL to candidate-repo-PASS transition; the attestation carries the repo
counts/source/return code and `verify-record` reconciles them with the composite
totals. A detached verdict signature, when configured, covers that attestation.

### Suite continuity: `--require-suite-continuity` (opt-in, trusted repos)

By default the whole-tree runtime-continuity check — capture the fully prepared
candidate tree, then reject any modification observed after the suite runs — is
active only when a verifier pack makes the tree a judged input. A plain
`subprocess` + JUnit run has no such check: it relies on the judge-owned report
and the exit code.

`--require-suite-continuity` opts a pack-less run into the same after-suite tree
check. If the repository suite rewrites the prepared tree while it runs, the
verdict is `TAMPERED` (`candidate_tree_changed`) instead of a pass. It is off by
default and intended for **trusted repositories** whose suite is expected never
to write into the tree.

Because the check compares the exact tree before and after the suite, ordinary
incidental writes are themselves reported as tampering. The trusted test command
must therefore suppress them — disable bytecode with `-B` (or
`PYTHONDONTWRITEBYTECODE`) and pytest's cache with `-p no:cacheprovider`:

```bash
git diff main...HEAD | evo-guard guard --diff - --no-config \
  --require-suite-continuity \
  --test-command "python -I -B -m pytest -p no:cacheprovider -q"
```

This is not a policy field: like `--sign-key`, it is a trusted-local control and
is never taken from candidate-controlled workflow input on a pull request.

### Assertion liveness: `--require-assert-liveness` (opt-in, pytest)

Candidate-imported source can monkeypatch the test framework's assertion methods
(`unittest.TestCase.assertEqual → no-op`) at import time, so a genuinely broken
suite *honestly* reports all-pass — nothing for the report/exit tamper check to
catch (reward-hacking catalog row 11b / threat-model class D).

`--require-assert-liveness` closes this for a **pytest** run. The gate installs a
judge-owned pytest plugin and an assertion-liveness canary into a `.evoguard/`
directory inside the prepared copy, puts that directory on `PYTHONPATH`, and loads
the plugin with `-p assert_liveness_plugin`. The plugin **adds** the canary to
whatever the command already collects — it never replaces the repository's own
`testpaths`, so the real suite still runs — and the canary runs in the same
session, the only place the monkeypatch is active. The canary probes the neutable
assertion methods and enforces with a bare `assert` (a statement the candidate
cannot rebind), so a neutered run cannot be a false `PASS`.

When the judge-owned canary node itself fails in the report, the assertion
machinery was neutered, so the report's *passes* cannot be trusted either — this is
tamper, not an honest test failure. The run is graded **`TAMPERED`** with the
distinct reason code **`assertion_liveness_failed`** (not a plain
`FAIL`/`tests_failed`). A *genuine* break with the flag — live assertions, canary
passes — stays a plain `FAIL`, so the two are never conflated.

```bash
git diff main...HEAD | evo-guard guard --diff - --no-config \
  --require-assert-liveness \
  --test-command "python -m pytest -q"
```

- **pytest-only.** A non-pytest test command with the flag set is refused
  (`ERROR`) before any suite runs — a requested security control never silently
  no-ops.
- **Tamper-resistance.** Under `--isolation docker` the copy mounts read-only, so
  the plugin and canary cannot be rewritten or deleted at runtime; the default
  same-process profile catches the demonstrated naive neuter but is not immune to a
  canary-aware in-process rewrite (the same in-process boundary as report forgery).
- Like `--require-suite-continuity`, this is a trusted-local control, not a policy
  field, and is never taken from candidate-controlled workflow input.

### `--diff` safety (for untrusted PRs)

`--diff` has only the candidate checkout available, so it deliberately refuses
to infer `.evoguard.json` from cwd. Pass a trusted, absolute `--config` file
materialized from the base revision, or explicitly use `--no-config`. The
Marketplace Action performs this materialization automatically from the verified
PR base commit.

When a direct `--diff` run uses a verifier pack, the pack must be outside the
candidate checkout and its `EVOGUARD_PACK_V2` SHA-256 must be pinned with
`--expect-verifier-pack-sha256`. A pack resolved from the candidate tree, or a
pack without a pin, is an `ERROR` before candidate code runs. This prevents a
patch from supplying the judge that is meant to evaluate it.

- **The real working tree is never modified.** Guard reverse-applies the diff to a
  throwaway *copy*; `head_dir`/cwd is only ever read.
- **Unsafe paths are refused, not applied.** A diff that targets an absolute path,
  a `..` escape, or anything outside the repo root returns a clear `ERROR` *before*
  any apply (checked up front, on top of `git apply`'s own unsafe-path guard and the
  verifier's relpath gate).
- **Binary patches are not supported** — a diff containing a binary file change
  (`GIT binary patch` / `Binary files … differ`) returns a clear `ERROR`. Guard
  verifies text source changes only.
- A diff that does not reverse-apply (a stale base) returns `ERROR` with
  `Base reconstruction: failed`.

## GitHub Action

<!-- BEGIN EVOGUARD_PROJECT_STATUS:GUARD_ACTION_EXAMPLE -->
A composite action ships at the repository root
([`action.yml`](../action.yml)). Copy
[`examples/evoguard.yml`](../examples/evoguard.yml) to
`.github/workflows/evoguard.yml` in the repository you want to protect:

```yaml
- uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
  with:
    fetch-depth: 0
    persist-credentials: false
- uses: EvoRiseKsa/EvoOM-Guard-m@v4.8.0
  with:
    comment: "false"
    fail-on: "any-non-pass"
```
<!-- END EVOGUARD_PROJECT_STATUS:GUARD_ACTION_EXAMPLE -->

> ⚠️ **`fail-on: rejected-only` is unavailable on `pull_request` runs.** The
> Action requires `any-non-pass` there because `rejected-only` would leave a
> `FAIL` (tests genuinely failing), `TAMPERED` signature, or `ERROR` **green**.
> It is available only for a trusted non-PR invocation where a maintainer
> deliberately wants a narrow harness-integrity report.

### Hardening profiles: `evo-guard init --profile`

`evo-guard init` scaffolds the workflow and a trusted `.evoguard.json`. By
default it writes the minimal `local` (subprocess) policy. `--profile` scaffolds
a container-isolated policy instead:

```bash
evo-guard init --ref v4.7.1 --profile hostile \
  --test-command "python -I -B -m pytest -q -p no:cacheprovider"
```

| `--profile` | Isolation | Policy adds |
|---|---|---|
| `local` (default) | subprocess | nothing beyond `test_command` |
| `protected` | `docker` | network-less container, `require_candidate_isolation: docker`, `strict_harness` |
| `hostile` | `gvisor` | network-less gVisor guest kernel, `require_candidate_isolation: gvisor`, `strict_harness` |

The generated `protected`/`hostile` policy loads as written but leaves
`docker_image` as an explicit placeholder you must replace with a digest-pinned
image; the judge fails closed until you do. These profiles deliver real
container isolation without the full **operating profile** contract — that
additionally requires an independent verifier pack (`blackbox_only`,
`require_report_integrity: external_process_isolated`, and
`operating_profile`). See [Operating profiles](OPERATING_PROFILES.md).

### Pull-request policy source (security-critical)

A `pull_request` workflow file is part of the candidate merge result. Its
`with:` values must therefore not choose the judge. On a PR, the Action takes
the following steps instead:

1. Resolves the event's base SHA and materializes
   `$BASE:.evoguard.json` into a temporary file.
2. Runs Guard with that materialized base policy. A missing policy is an empty
   policy; a present but unreadable, malformed, or invalid one fails closed.
3. Ignores candidate workflow inputs that shape the judge (`test-command`, path
   rules, feature mode, setup/isolation, black-box, coverage, limits, and
   assurance floors). `base-ref` may not replace the event base SHA and
   `fail-on` must be `any-non-pass`.

Only settings represented in the protected policy can take effect in a PR; a
`with:` value never substitutes for a missing policy field.

### Explicit repository-local harness inputs

The built-in policy recognizes conventional tests, runner/build configuration,
CI and auto-executed judge paths. A custom repository-local wrapper or helper is
ambiguous: the same `python src/cli.py` token could be the program under test or
part of the judge. Guard therefore does not guess. Put every repository-owned
judge wrapper/helper in the verified base `.evoguard.json`:

```json
{
  "test_command": ["sh", "ci/run-tests.sh"],
  "harness_inputs": [
    "ci/lib/assertions.sh",
    "ci/run-tests.sh"
  ]
}
```

Entries are exact, normalized, repository-relative regular base files. They
cannot be directories, globs, absolute/escaping paths, symlinks, or reparse
points. Cross-platform canonicalization also rejects Windows
trailing-dot/space segments, reserved device names (`CON`, `NUL`, `COM1`, and
their equivalents), and DOS 8.3-style `~N` spellings. `allow` cannot exempt an
edit/deletion of a declared file or any ancestor. For already-existing
candidate paths, admission compares filesystem object identity with each
declared file and ancestor where available and fails closed when an existing
trusted target cannot be compared. On `pull_request`, `harness_inputs` is
base-policy-only: the Action exposes no candidate-controlled input for it.

Guard captures each declared base file's type, mode, and SHA-256 identity before
candidate copy/materialization and compares the materialized tree with that
trusted snapshot before candidate code runs. Repo-native paths repeat the
comparison at their documented setup/suite checkpoints. The black-box runner
receives the same explicit declaration and repeats the comparison after
candidate/pack execution, including in `--blackbox-only`. An observed
materialization or post-execution difference is `TAMPERED` /
`candidate_tree_changed_during_run`.

The first trusted-source binding is a different case: if Guard cannot establish
that reference before materialization, it returns `ERROR` /
`assurance_requirement_not_met`. No candidate copy or candidate code existed at
that point, so the failure is not labelled candidate tampering.

These are observation checkpoints, not continuous monitoring. In host
`subprocess` isolation the candidate and judge share the host filesystem, so a
temporary mutation restored before the next snapshot can escape observation.
Require delivered Docker/gVisor isolation when a read-only candidate mount is
part of the threat model.

Guard does not analyze `test_command`, `sh -c`, package scripts, imports,
`source`, Make includes, globs, environment-selected paths, or dynamic loading
to derive a transitive execution graph. List every repository-owned file on
which the judge relies. Apart from the narrow documented discovery of helper
directories for literal local Actions referenced by verified base workflows,
no transitive helper discovery is claimed. External command paths are
toolchain/image evidence, not repository `harness_inputs`; use an immutable
image or digest-pinned external verifier pack when that identity matters.

### Strict harness profile

Set `"strict_harness": true` in the protected base policy when the verification
lane must protect the documented additional execution-environment manifests. In
that mode, dependency manifests/locks and compiler/project configuration (for example
`requirements*.txt`, `uv.lock`, `package.json`, `tsconfig*.json`, `go.mod`, and
`Cargo.toml`) are non-exemptible protected paths. It also rejects a nominally
successful command unless a non-empty structured JUnit verdict is available.
Before the repository suite starts, Guard asks the live public runner-adapter
facade whether that command can be instrumented. If not, strict mode returns
`ERROR` / `assurance_requirement_not_met` without running the suite. If an
adapter matches, the existing post-run checks still reject a missing, empty,
malformed, or exit-code-inconsistent report; adapter recognition alone cannot
establish `PASS`. For example, a raw `python -c ...` command has no structured
runner adapter: it is refused in the preflight phase with
`test_command_started: false`, rather than executed and later classified as
`no_test_verdict`.
For host-subprocess execution it additionally requires positive POSIX
process-group cleanup capability for setup, repository-suite, verifier-pack,
and pristine-baseline commands. An unsupported host refuses the strict request
before candidate execution. Docker/gVisor execution instead relies on the
separate container lifecycle and absence proof.

This is deliberately **not** the default: dependency or build-system upgrades
need a separately reviewed maintenance path. It expands a finite protected-path
set; it does not discover every execution dependency or turn a same-process
repo-native judge into an external isolation boundary. A managed process group
is lifecycle containment, not filesystem, network, credential, or
report-integrity isolation. Use the black-box profile when that stronger
boundary is required.

For the narrower structured-evidence floor without strict harness's additional
path and process-lifecycle controls, pass
`--require-structured-verdict` to `evo-guard guard` (or
`require_structured_verdict=True` to the Python API). This direct opt-in defaults
off for compatibility with custom commands that intentionally use exit-code-only
grading. It is a no-op with `--blackbox-only`, because that mode does not run the
repository suite; the external verifier-pack report remains mandatory there.
Run `evo-guard preflight . --strict` first to surface the same live adapter
decision without executing candidate code.

Put the policy in the base branch, for example:

```json
{
  "test_command": ["python", "-m", "pytest", "-q"],
  "timeout": 180,
  "strict_harness": true
}
```

For a verifier pack, both fields live in the same base policy and the path is a
safe repository-relative directory:

```json
{
  "test_command": ["python", "-m", "pytest", "-q"],
  "verifier_pack": "security/evoguard-pack",
  "expect_verifier_pack_sha256": "<64-hex-EVOGUARD_PACK_V2-digest>"
}
```

The Action archives that directory from the verified base commit into a runner
temporary directory, then passes only the staged copy to Guard. It never accepts
a candidate-checkout pack for a PR. The pin is mandatory when a pack is set;
missing/invalid policy data or a conflicting pack input fails closed. A matching
`with:` pack value is not an alternate policy source.

This protects policy *after the workflow starts*. It cannot make a workflow run
if a PR removes, replaces, or disables that workflow. Require the Guard workflow
or status check in your repository ruleset/branch protection and protect
`.github/workflows/` with appropriate review/CODEOWNERS controls. Keep
untrusted code on `pull_request`; do not checkout a candidate with secrets under
`pull_request_target` to work around workflow protection. See
[`REPOSITORY_PROTECTION.md`](REPOSITORY_PROTECTION.md) for the concrete GitHub
controls and their remaining limits.

It writes the report to the **job summary**, exposes a `verdict` output, and
fails the step per `fail-on`. It deliberately refuses in-job PR commenting so
candidate execution never shares `pull-requests: write`; use a separate
metadata-only reporting job if a comment is required. To gate only machine-made
PRs, add `if: github.event.pull_request.user.type == 'Bot'` to the job.

### Minimal workflow with a natural `git diff` (no action needed)

If you prefer no composite action, the `--diff` mode is a two-line gate:

<!-- BEGIN EVOGUARD_PROJECT_STATUS:GUARD_NO_ACTION_EXAMPLE -->
```yaml
- uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
  with:
    fetch-depth: 0
    persist-credentials: false
- run: pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m.git@v4.8.0"
- run: |
    BASE="${{ github.event.pull_request.base.sha }}"
    git fetch --no-tags origin "$BASE"
    git show "$BASE:.evoguard.json" > "$RUNNER_TEMP/evoguard-base-policy.json" \
      || printf '{}\n' > "$RUNNER_TEMP/evoguard-base-policy.json"
    git diff "$BASE...HEAD" | evo-guard guard --diff - \
      --config "$RUNNER_TEMP/evoguard-base-policy.json" \
      --report "$GITHUB_STEP_SUMMARY"
```
<!-- END EVOGUARD_PROJECT_STATUS:GUARD_NO_ACTION_EXAMPLE -->

`evo-guard guard` returns a non-zero exit on anything but `PASS`, so the step fails the
check automatically. The test command belongs in the materialized base policy;
putting it as a literal CLI flag in a `pull_request` workflow would let the
candidate edit the judge. This no-action pattern has the same deployment
prerequisite as the composite Action: branch/ruleset protection must ensure the
workflow itself cannot be removed or replaced to bypass the check.

## External black-box judge & assurance policy

**`v4.7.1` release contract:** for a named, fail-closed combination of these
controls, use
`--operating-profile local|protected|hostile`. The profile is included in the
effective policy and its digest only when explicitly selected. `protected`
requires a pinned black-box-only verifier inside Docker/gVisor with no candidate
network; `hostile` requires gVisor and an active memory limit. See
[`OPERATING_PROFILES.md`](OPERATING_PROFILES.md) for the exact contract and key
custody rules. Confirm the exact immutable `v4.7.1` artifact before consumer
use. Its detached-maintainer-signed, same-owner direct record binds the exact
postpublication readback, not the delivered isolation facts of a particular
run or an independent review; see
[`RELEASE_STATUS.md`](RELEASE_STATUS.md).

The default judge runs the candidate in the **same process** as the report writer,
so deliberate in-process source can forge the report (`report_integrity:
same_process_candidate_writable`). The following controls add independent checks
or require a stronger boundary:

- `--verifier-pack <dir>` — org-owned tests/invariants the patch cannot modify.
  Repo-native verification runs the repo suite and then the accepted snapshot as
  a separate mandatory pytest phase; both must pass. The pack is not copied into
  the candidate tree, so a narrowed/custom repo command cannot silently omit it.
- `--expect-verifier-pack-sha256 <digest>` — require the accepted
  `EVOGUARD_PACK_V2` content/tree identity (from `pack-doctor --json`) before any
  candidate code runs. A mismatch is `ERROR verifier_pack_identity_mismatch`.
  For Action PRs, set this together with `verifier_pack` in the verified base
  `.evoguard.json`; Action `with:` values do not establish this policy.
- `--blackbox` — after static effective-policy protected-path admission passes, an external phase comes
  from the **judge's own pytest** over the pack, which never imports the
  candidate. That phase is
  `report_integrity: external_process_isolated`; the default **composite** also
  requires the repo's own suite and therefore reports the weaker repo-native
  channel overall.
  `--blackbox-only` skips the repo suite for pure-CLI/service targets. The
  black-box runner still captures declared `harness_inputs` from the trusted
  source before materialization, checks the materialized copy before execution,
  and checks it after candidate/pack execution. Failure of the initial
  trusted-source binding is `ERROR` / `assurance_requirement_not_met` before
  materialization and is not attributed to the candidate. A materialized-copy
  mismatch or persistent post-execution drift is `TAMPERED` /
  `candidate_tree_changed_during_run`; only the repo-native setup/suite
  checkpoints are absent. With
  `--isolation docker`, the observed launcher boundary is a real, network-less,
  read-only container with the pack unmounted. A judge-owned launcher receipt
  and runtime CID establish use of that boundary; the trusted pack's assertions
  establish the intended candidate behaviour. Preparation or a constant pack is
  not evidence. A pack that never calls `$EVOGUARD_EXEC` is
  `ERROR candidate_not_exercised`, and a missing daemon/image is never a
  mislabelled `docker`.
- `--require-report-integrity` / `--require-candidate-isolation` — fail-closed
  floors: a completed run that would otherwise pass but delivered a weaker
  boundary returns `ERROR` (`assurance_requirement_not_met`), never a silently
  downgraded `PASS`.

A diff pre-gate refusal is earlier than every runtime claim. It reports
`overall_profile: static_gate`, `candidate_isolation/suite_isolation: not_run`,
and `report_integrity: not_applicable_static_gate`; a configured pack is marked
unevaluated. Requested Docker/gVisor/black-box settings remain in the effective
policy only. Runtime assurance floors do not overwrite the original static
`REJECTED`/`ERROR` reason because no runtime verdict exists to rank.

Schema 1.11 introduced that rule across the whole execution lifecycle, and
schema 1.12 preserves it. Every JSON, Markdown, SARIF, and attested result
records `execution_state` as one of:

- `static_gate` — the static diff gate decided the result;
- `not_started` — runtime preflight stopped before a test/judge process started;
- `started_incomplete` — setup/test/judge execution started but the required
  sequence did not finish (including timeout);
- `completed` — required execution returned and post-execution checks ran.

`execution_phase` records the furthest or decisive phase. `test_command_ran`
means process start, not clean verdict availability: on a suite/judge timeout it
is `true` while `verdict_source` may remain `null`; setup-only timeout leaves it
false. When no suite/test starts, top-level
and assurance isolation are `not_run`; requested isolation remains only in
`attestation.effective_policy`. Preflight assurance reports
`overall_profile: preflight` and
`report_integrity: not_applicable_not_run`; incomplete execution uses an
explicit incomplete profile. Assurance floors are applied to a completed
`PASS`, not used to erase a more specific static, preflight, timeout/incomplete,
pack, tamper, or isolation cause.

The accepted pack lives in a judge-owned snapshot outside the candidate tree and
its `HOME` and is checked immediately before and after execution. Persistent
snapshot drift is `TAMPERED verifier_pack_snapshot_changed`; persistent prepared
candidate-runtime drift across the repo/pack phases is
`TAMPERED candidate_tree_changed_during_run`. In host subprocess mode these are
pre/post observations, **not** an OS sandbox or secrecy guarantee. Repo-native
setup, suite, and pack subprocesses receive separate judge-owned home/temp/cache
directories outside the candidate copy. This reduces incidental writes but does
not exempt any in-tree cache, temporary file, or build output from runtime
identity. Python `-I`/`-E` may ignore `PYTHON*` environment settings; use the
static `preflight` command and an explicit `-B` where it reports that risk.
Repo-native pack pytest may import candidate code and retains
`report_integrity: same_process_candidate_writable`; only black-box mode moves
the verdict producer outside the candidate process.

Pack assurance also follows actual lifecycle evidence. Its object independently
records `configured`, `present`, `integrity`, `identity_verified`, pack
`execution_state`, `secrecy`, and observed `snapshot_sha256`. This distinguishes
a missing path, an invalid pack, an expected-digest mismatch, an accepted
pre-execution snapshot, a completed pre/post or read-only verification, and a
changed snapshot. A policy path alone proves only `configured: true`.

The attestation identifies both digest algorithms. Pack content uses
`verifier_pack_digest_format: EVOGUARD_PACK_V2`. A single JUnit document uses
`junit_digest_format: JUNIT_XML_SHA256`. `EVOGUARD_JUNIT_COMPOSITE_V1` names the
raw-XML framing used by legacy structured records and retained for exit-only repo
commands. Structured repo+pack results from v4.0.2 use
`EVOGUARD_JUNIT_COMPOSITE_V2`, which binds labelled component formats and digests
and can be recomputed by `verify-record`. Maven/Surefire directories use
`EVOGUARD_JUNIT_REPORT_SET_V1` as their repo component. Check the format field
whenever comparing a stored digest.

See [`START_HERE.md`](START_HERE.md) to pick a path, [`BLACKBOX.md`](BLACKBOX.md)
for the judge, and [`ASSURANCE.md`](ASSURANCE.md) for what each level proves.

## Trust boundary (honest)

By default Guard runs the repo's suite in a **subprocess** with rlimits and a
timeout. That is appropriate for **trusted** repositories — your own code, gating a
patch — and is **not** a general security sandbox: it does not confine filesystem or
network access. For **untrusted** code (e.g. fork PRs), treat this like any other
code-execution gate: run it where the patch's code cannot reach your secrets, and
isolate the runner. Guard never claims the subprocess is a sandbox.

**Optional containerised judge** — `--isolation docker --docker-image <img>` runs
the suite inside a short-lived container with the configured network (default
`none`), a read-only root filesystem, all capabilities dropped,
`no-new-privileges`, and CPU/PID/memory/open-file limits. During suite execution
the candidate tree is mounted `/work:ro`; `/tmp` is a writable tmpfs and `/out`
is a separate writable judge-report mount. This protects the host/tree boundary,
but it does **not** make the repo-native report unforgeable: candidate code,
tests, and the JUnit writer still share a process. A Docker container also shares
the host kernel, so it is defence in depth for semi-trusted code, not a complete
hostile-code boundary.

Isolation mode admission is closed: only `subprocess`, `docker`, and `gvisor`
are accepted, and an unknown value is rejected before provider lookup,
workspace creation, or process launch. For Docker/gVisor, image inspection must
return a canonical immutable `sha256:` plus 64-lowercase-hex image ID. A tag,
short digest, malformed digest, or CLI-looking value never reaches the container
run argv.

**Setup boundary and tree fidelity (3.4).** An optional `setup_command` runs
before the suite. Under Docker/gVisor it now runs **inside the requested boundary
by default**. The configured image is freshly resolved at the start of each
verification; its canonical immutable ID is kept judgment-local and used by the
separate setup, suite, and pack containers with the same network, runtime, and
resource policy. A reused or concurrent verifier does not share that pin with
another judgment. Setup alone receives `/work:rw` and no report mount; suite
and pack phases receive the candidate tree read-only, and the pack snapshot is
`/verifier-pack:ro`.

This proves validation and consistent use of the judge-selected image ID. It is
not runtime attestation and does not independently prove the daemon, host
kernel, OCI runtime, or actually executed image.

This has practical consequences:

- The image must contain the setup tool and, when using a verifier pack, Python
  and pytest. The default `--docker-network none` blocks package registries, so
  prefer dependencies baked into the image or an offline cache.
- Guard compares pre-existing file/directory/symlink/special entries and
  permission bits before and after setup, subject to the documented output
  policy. Only **new** conventional dependency/build outputs are ignored by
  default. `setup_output_globs` in the protected `.evoguard.json` adds trusted
  exceptions to the general fidelity scan; keep them narrow. They never exempt
  declared `harness_inputs` or their ancestors. In this repo-native setup path,
  the trusted-base snapshot is captured before candidate materialization,
  checked against the materialized tree, and checked again at the enforced
  observation points. Other matching paths are included in repo/pack runtime
  continuity after setup.
- `--trust-setup-on-host` is an explicit compatibility escape hatch. It uses a
  restricted host environment, records
  `setup_isolation: subprocess_host_opt_in`, and lowers effective
  `candidate_isolation` to
  `subprocess`; a required Docker/gVisor assurance floor therefore refuses it.
- `setup_command` is not supported with `--blackbox` today. The combination is
  `ERROR policy_requirement_unsupported`, never a silently skipped setup.

**Filesystem containment.** On POSIX, Guard's protected workspace reads,
writes, and deletions are relative to held directory descriptors and refuse
symlink traversal (`O_NOFOLLOW`). The operation stays bound even if a path name
is swapped concurrently. On Windows, stdlib provides no atomic descriptor-
relative equivalent; Guard rejects symlink/junction parents and checks parent/
file identity before and after each operation. Treat the Windows boundary as
best effort rather than an atomic containment guarantee.

**Runtime continuity for repo-native packs.** After setup, Guard identifies the
runtime tree as `EVOGUARD_RUNTIME_TREE_V1`, including setup-created dependencies
and build outputs. Relative symlinks are accepted only when their resolved
targets remain inside that tree; absolute, escaping, or dangling symlinks fail
closed (`python -m venv --copies` avoids absolute interpreter links). The scan
is bounded to 500,000 entries, 128 MiB of canonical path bytes, 32 GiB of
logical bytes, and 8 GiB per regular file. Its 120-second deadline is checked
between filesystem calls and cannot preempt a hung kernel call; use an outer
job timeout for untrusted/network filesystems. Subprocess execution reports
`snapshot_boundary_checked`:
phase-boundary drift is detected, but a lingering process can theoretically
mutate and restore bytes between observations. The same observation-point
boundary applies to exact harness-input snapshots: equality at the checkpoints
is not a continuous immutability claim. Docker/gVisor reports
`read_only_enforced` only when setup remained inside the requested container;
if a configured setup command ran through `--trust-setup-on-host`, Guard does
not make that stronger claim because the host process could survive into later
phases. `setup_output_globs` never remove content from this runtime-continuity
identity. Failure states remain explicit: `unavailable` means no initial
identity was accepted, `incomplete` means execution stopped before every
boundary was checked, and `verification_failed` means a later identity could
not be reproduced or differed.

**Directory JUnit is all-or-nothing.** Maven/Surefire-style report directories
are rejected as a whole if any `*.xml` entry is symlinked, special, unreadable,
malformed, oversized, or contains a DTD/ENTITY. A clean sibling cannot mask a
missing or hostile piece of the report set. Every accepted filename and XML
document is bound under `EVOGUARD_JUNIT_REPORT_SET_V1` in deterministic sorted
order.

For untrusted/public input prefer **`--isolation gvisor`** — the same judge
through the gVisor `runsc` runtime (a
user-space guest kernel, no `/dev/kvm`), a separate-kernel boundary; a Firecracker
microVM backend is designed in `docs/VM_ISOLATION.md`. The image must carry the
repo's test runner (e.g. `node:22-slim` for `node --test`).

## What it is and is not

- **It is** a policy-bound **verification gate** with regression-tested controls
  for the documented reward-hacking paths.
- **It is not** a generator, a fixer, or an agent. It does not write the patch; it
  judges one.
