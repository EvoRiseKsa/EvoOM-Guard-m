<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
  Maintained and released by Mana Alharbi (مانع الحربي).
-->

# EvoGuard — an AI patch verification gate

> A CI gate that answers one objective question about a code change — produced by
> a human or, the motivating case, an **AI agent**: **does this patch fix the code
> *without gaming the tests*?** It is a thin, model-free composition of the project's
> reward-hack-resistant judge and its patch risk scorer.

## Why

Frontier agents have been observed **editing or skipping their own tests** to make
a suite pass, and self-modifying coding agents have **faked test logs** (documented
in the public literature). A patch-review gate the patch itself **can't game by
hacking the harness** is therefore a real need as agent-authored PRs become common. EvoGuard provides
it: the candidate is judged by the **repository's own tests**, the verdict is read
from a **judge-owned JUnit report + the process exit code** (never scraped from the
patch's stdout), and **any edit to the tests or their configuration is rejected**
before the suite runs.

## What it checks

| Verdict | Meaning |
|---|---|
| ✅ `PASS` | the repo's tests pass **and** the patch left the test harness untouched |
| ⛔ `REJECTED` | the patch edits **or deletes** the tests, their configuration, the gate's CI, or an auto-executed file (`sitecustomize.py`, `*.pth`, `Makefile`, …) — blocked before the suite runs |
| ❌ `FAIL` | the patch applied and the suite ran, but tests fail (also: a suite timeout, or a PASS demoted below `--min-diff-coverage`) |
| 🚨 `TAMPERED` | the process exit code and the judge-owned JUnit report disagree — a desync/forced-exit signature; never read as a pass |
| ⚠️ `ERROR` | no trustworthy verdict could be produced: the patch did not apply / no parseable edits, an unsafe path, a failed or timed-out setup command, a requested isolation that could not be delivered, or an unmet `--require-*` assurance floor |

> **What `REJECTED` does — and does not — mean.** `REJECTED` is a *policy trip*:
> the change touched a path the current harness-protection policy protects. That
> is the right default for an AI-generated patch, but it is **not by itself proof
> of intent to cheat** — a legitimate dependency bump that edits `pom.xml`, or a
> real build fix in a `Makefile`, trips the same rule. When a protected edit is
> genuinely intended, review it like any harness change and exempt it explicitly
> with `--allow <glob>` (a deliberate, reviewed baseline — see
> [`ADOPTION.md`](ADOPTION.md)).

The verdict and its stable `reason_code` are emitted as JSON for integrations — see
[`JSON_SCHEMA.md`](JSON_SCHEMA.md).

Every run also reports a **blast-radius risk** (`low`/`medium`/`high`) from the
files and lines touched and any protected-path hit, and the **verdict source**
(`junit+exit` for the hardened path).

A forged `9999 passed` printed by the patch's own code **cannot** flip the verdict —
the score comes from the structured JUnit report, cross-checked against the exit
code.

## Install

There are two ways to get Guard, depending on where you run it. EvoGuard is
proprietary and is **not published to PyPI** (`pip install evoom-guard` will not find
it) — both paths install it **from this repository**.

**In GitHub Actions — nothing to install.** Reference the composite action; the
runner fetches it and `pip install`s EvoGuard itself, so the only line your
workflow adds is the `uses:` (plus a full-history checkout):

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }                 # Guard needs the base commit to diff
- uses: EvoRiseKsa/EvoOM-Guard-m@v3.4.2   # a release tag; @<sha> is strictest, @main is latest
```

**As a CLI — install the `evo-guard` command from the repo** (the stdlib-only core has
no third-party dependencies, so this is a fast, clean install — no clone needed):

```bash
pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m.git@v3.4.2"   # a release tag — recommended
pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m.git@<sha>"    # the strictest, immutable pin
evo-guard guard --diff - --test-command "python -m pytest -q" < pr.diff
```

> **Pinning.** Guard is a verification *gate*, so pin the version you run rather
> than tracking a moving branch — both for the `uses:` action ref and the `git+`
> pip URL:
> - **`@v3.4.2`** — a release tag. The recommended pin and the right choice for
>   trying Guard out: a real, named version rather than whatever is on `main`.
> - **`@<sha>`** — a full commit SHA. The **strictest, immutable** pin (a tag can
>   in principle be moved); best for CI, where the gate you run should be the exact
>   code you reviewed.
> - **`@main`** — always the latest, unreviewed code. Fine for a quick look, not
>   for a gate you depend on.
>
> If the repository is private, the usual GitHub access applies — a
> token-authenticated `git+https://…@<token>…` URL for `pip`, and repo read access
> for the `uses:` reference.

## CLI

```bash
# Easiest: pipe a normal git diff from your working tree (the head checkout).
# Guard reverse-applies it to reconstruct the base, then verifies — zero setup.
git diff main...HEAD | evo-guard guard --diff - --test-command "python -m pytest -q"
evo-guard guard --diff pr.diff --report report.md --json guard.json

# Verify a candidate in EvoGuard's edit-block format against a repo:
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
- **`--patch`** takes the EvoGuard edit-block format directly.

Added/modified files are verified, and **deletions are gated too** (since schema
1.1): deleting a protected harness file — a test, its config, the gate's CI — is
`REJECTED` exactly like editing it (removing a check is as much a hack as
rewriting one), while a deleted *source* file is applied to the verified copy so
the verdict matches the real merge. `--json` writes the machine-readable verdict.
The report shows the `Input` (`diff` / `base/head` / `edit blocks`) and, for
`--diff`, the `Base reconstruction` (`ok` / `failed`).

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

### `--diff` safety (for untrusted PRs)

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

A composite action ships at the repo root ([`action.yml`](../action.yml)), used as
`EvoRiseKsa/EvoOM-Guard-m@v3.4.2`. Copy [`examples/evoguard.yml`](../examples/evoguard.yml) to
`.github/workflows/evoguard.yml` in the repo you want to protect:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }            # Guard needs the base commit to diff
- uses: EvoRiseKsa/EvoOM-Guard-m@v3.4.2   # pin a release (@<sha> strictest, @main latest)
  with:
    comment: "true"                   # post the verdict as a PR comment
    fail-on: "any-non-pass"           # or "rejected-only" — see the warning below
```

> ⚠️ **`fail-on: rejected-only` is a harness-integrity gate, not a correctness
> gate.** With it, only `REJECTED` fails the step — a `FAIL` (tests genuinely
> failing), a `TAMPERED` signature, and an `ERROR` all leave the check **green**.
> Use it only when another required check already runs the suite and you want
> Guard to gate *only* harness edits; otherwise keep the default `any-non-pass`.

It writes the report to the **job summary**, posts it as a **PR comment**, exposes a
`verdict` output, and fails the step per `fail-on`. To gate only machine-made PRs,
add `if: github.event.pull_request.user.type == 'Bot'` to the job.

### Minimal workflow with a natural `git diff` (no action needed)

If you prefer no composite action, the `--diff` mode is a two-line gate:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }                       # Guard needs the base to diff
- run: pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m.git@v3.4.2"   # see Install; @<sha> strictest for CI
- run: |
    BASE="origin/${{ github.event.pull_request.base.ref }}"
    git fetch --no-tags origin "${{ github.event.pull_request.base.ref }}"
    git diff "$BASE...HEAD" | evo-guard guard --diff - --test-command "python -m pytest -q" --report "$GITHUB_STEP_SUMMARY"
```

`evo-guard guard` returns a non-zero exit on anything but `PASS`, so the step fails the
check automatically.

## External black-box judge & assurance policy

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
- `--blackbox` — the verdict comes from the **judge's own pytest** over the pack,
  which never imports the candidate (`report_integrity: external_process_isolated`).
  It is **composite** by default: the repo's own suite **and** the pack must pass.
  `--blackbox-only` skips the repo suite for pure-CLI/service targets. With
  `--isolation docker`, the candidate runs in a real, network-less, read-only
  container with the pack unmounted; `candidate_isolation` reflects what was
  **delivered** — a missing daemon/image is `ERROR`, never a mislabelled `docker`.
- `--require-report-integrity` / `--require-candidate-isolation` — fail-closed
  floors: a run weaker than required returns `ERROR`
  (`assurance_requirement_not_met`), never a silently downgraded `PASS`.

The accepted pack lives in a judge-owned snapshot outside the candidate tree and
its `HOME` and is checked immediately before and after execution. Persistent
snapshot drift is `TAMPERED verifier_pack_snapshot_changed`; persistent prepared
candidate-runtime drift across the repo/pack phases is
`TAMPERED candidate_tree_changed_during_run`. In host subprocess mode these are
pre/post observations, **not** an OS sandbox or secrecy guarantee. Repo-native
pack pytest may import candidate code and retains
`report_integrity: same_process_candidate_writable`; only black-box mode moves
the verdict producer outside the candidate process.

The attestation identifies both digest algorithms. Pack content uses
`verifier_pack_digest_format: EVOGUARD_PACK_V2`. A single JUnit document uses
`junit_digest_format: JUNIT_XML_SHA256`; a repo-native repo+pack result uses
`EVOGUARD_JUNIT_COMPOSITE_V1`, which frames and hashes both XML documents. Check
the format field whenever comparing a stored digest.

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

**Setup boundary and tree fidelity (3.4).** An optional `setup_command` runs
before the suite. Under Docker/gVisor it now runs **inside the requested boundary
by default**, in a separate container using the same resolved image ID,
network, runtime, and resource policy as the later suite/pack containers. Setup
alone receives `/work:rw` and no report mount; suite and pack phases receive the
candidate tree read-only, and the pack snapshot is `/verifier-pack:ro`.

This has practical consequences:

- The image must contain the setup tool and, when using a verifier pack, Python
  and pytest. The default `--docker-network none` blocks package registries, so
  prefer dependencies baked into the image or an offline cache.
- Guard compares every pre-existing file/directory/symlink/special entry and
  permission bit before and after setup. Only **new** conventional dependency/
  build outputs are ignored by default. `setup_output_globs` in the protected
  `.evoguard.json` adds trusted exceptions; never include source, tests, policy,
  or harness paths. These exceptions apply to setup validation only: after
  setup, matching paths are included in repo/pack runtime continuity.
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
mutate and restore bytes between observations. Docker/gVisor reports
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
missing or hostile piece of the report set.

For untrusted/public input prefer **`--isolation gvisor`** — the same judge
through the gVisor `runsc` runtime (a
user-space guest kernel, no `/dev/kvm`), a separate-kernel boundary; a Firecracker
microVM backend is designed in `docs/VM_ISOLATION.md`. The image must carry the
repo's test runner (e.g. `node:22-slim` for `node --test`).

## What it is and is not

- **It is** an objective, reward-hack-resistant **verification gate**.
- **It is not** a generator, a fixer, or an agent. It does not write the patch; it
  judges one.
