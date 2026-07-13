<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# EvoOM Guard

[![CI](https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/workflows/ci.yml/badge.svg)](https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/workflows/ci.yml)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-EvoOM%20Guard-B93A2B?logo=github)](https://github.com/marketplace/actions/evoom-guard)
[![Release](https://img.shields.io/github/v/release/EvoRiseKsa/EvoOM-Guard-m?color=1E7B4F)](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/latest)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: Source-available](https://img.shields.io/badge/license-source--available-lightgrey)](LICENSE)

**Independent, evidence-bound verification for untrusted software changes — with
AI-generated patches as the primary use case.**

Guard asks one deliberately narrow question: did this change satisfy the selected
judge without manipulating the evidence used to decide? It does not infer who
wrote the change, and a `PASS` is never a claim of complete software correctness.

> **New here? → [`docs/START_HERE.md`](docs/START_HERE.md)** picks your path in 30
> seconds (Basic Guard · Black-box CLI · + container isolation), with a decision
> table and a complete runnable example. Start there instead of reading this whole page.
>
> **See it run on an external target repo → [`evoom-guard-demo`](https://github.com/EvoRiseKsa/evoom-guard-demo)**:
> an honest fix passes, test tampering is rejected, a fake `9999 passed` on stdout
> still fails, and black-box report forgery is caught — all with the published release.
>
> **See it judge a real historical bug → [`docs/CASE-STUDY.md`](docs/CASE-STUDY.md)**:
> charset-normalizer's real `TypeError`-on-comparison bug (≤3.3.2, fixed upstream in
> 3.4.0) — the genuine fix earns `PASS` with `repair_effect: demonstrated`, the
> test-silencing variant is `REJECTED` before a single test runs, and the do-nothing
> patch `FAIL`s. Reproducible from hash-pinned PyPI sdists.

AI coding agents have learned an ugly trick: when they can't fix the code, they
"fix" the tests. Delete the failing assertion, add a pytest `addopts = "-k
passing"` deselect, print a fake `9999 passed` to stdout, or drop a
`sitecustomize.py` that forces exit 0. The suite goes green; nothing was fixed.

Guard closes that hole with two mechanisms:

1. **Protected harness paths are rejected before execution** (a robust
   guarantee). Any edit — or **deletion** — of the tests, their configuration
   (`pyproject.toml`, `pytest.ini`, `vitest.config.*`, `Makefile`, CI workflows,
   …), or an auto-executed file (`sitecustomize.py`, `*.pth`) is **REJECTED
   before the suite even runs**. This is a *static* check on the patch's file
   list, so runtime code cannot undo it. `package.json` is dual-purpose, so instead of
   blocking it wholesale, its test-harness fields are restored from the pristine
   original.
2. **The result is judge-owned, not scraped from stdout.** Tests run against a
   throwaway copy, and the verdict is read from a **judge-owned JUnit report +
   the process exit code** — never from stdout. A patch that prints `9999
   passed` moves nothing, and an exit-code ⟷ report disagreement is its own
   **`TAMPERED`** verdict. This blocks the reward-hacks agents do **in
   practice** (harness edits/deletions, config deselects, stdout forgery — all
   caught, with adversarial tests in `tests/` and the
   [catalogue](docs/REWARD_HACKING_CATALOG.md)).

> **Honest boundary — read this.** By default, mechanism 2 is *not* unforgeable.
> Your tests and the report writer run in the **same process** as the code under
> test, so a patch that deliberately writes process-level forgery into source (an
> `atexit` hook that overwrites the report and calls `os._exit(0)`) *can* fake a
> `PASS`. Guard ships an adversarial test that proves this, and every verdict
> carries an **`assurance` profile** naming its `report_integrity` as
> `same_process_candidate_writable`. The container isolation modes protect the
> host, **not** the report. `--blackbox` adds a judge-owned external channel in
> which the same forgery is caught; use `--blackbox-only` when every required
> report channel must be external. The default composite still includes the
> weaker repo-native channel.
> See [`docs/ASSURANCE.md`](docs/ASSURANCE.md).

### Add an external report channel: `--blackbox`

For targets with a process/protocol boundary (a CLI, an HTTP service, a
DB-backed program), the black-box phase is produced by **its own pytest over
judge-owned tests that never import your code** — so candidate code cannot
forge that phase's report from inside the run:

```bash
evo-guard guard ./repo --patch candidate.txt \
    --verifier-pack examples/blackbox-pack --blackbox
```

The pack invokes the candidate across a process boundary (via `$EVOGUARD_EXEC`,
which runs it under the delivered isolation) and asserts on its outputs.
For `--blackbox-only`, that completed judge yields
`report_integrity: external_process_isolated`; in the default composite mode the
overall profile honestly reports the weaker repo-native report channel. The
*identical* `atexit`+`os._exit` forgery that
fakes a `PASS` under the default judge yields the correct `FAIL` (proven in
`tests/test_blackbox.py`). A protected-harness refusal is decided earlier: it
reports `static_gate`, `candidate_isolation: not_run`, and
`report_integrity: not_applicable_static_gate` instead of claiming that the
requested judge or container ran. Runtime preflight failures are separately
`not_started` with `report_integrity: not_applicable_not_run`; a suite/judge
timeout is `started_incomplete`, has `test_command_ran: true`, and may still have
`verdict_source: null`. Three properties make a completed execution verdict a
real guarantee, not a label:

- **Boundary evidence is observed, not requested.** `candidate_isolation`
  changes from `not_run` only after the judge observes a trusted-pack call to
  `$EVOGUARD_EXEC` (and, for containers, a runtime-written CID). This proves the
  launcher/runtime path was invoked; the trusted pack remains responsible for
  checking the command's semantics and outputs. A missing daemon/image fails
  before execution; a pack that never invokes the launcher is refused as
  `candidate_not_exercised` even without a floor — never a vacuous `PASS` or a
  result mislabelled `docker`. A pending verdict is also refused as
  `runtime_cleanup_failed` if the judge process group or a candidate container
  cannot be proven absent after execution. In a container the repo copy is mounted
  **read-only** and
  the pack is **not mounted into the candidate at all** (proven against a real
  daemon in CI, where a malicious candidate fails to write the host, open the
  network, or reach the pack).
- **The verdict is composite.** By default the repo's own suite **and** the
  external pack must both pass — a green pack can never mask an internal
  regression. Pure-CLI/service targets with no in-repo suite pass
  `--blackbox-only`.
- **Fail-closed policy.** `--require-report-integrity` / `--require-candidate-isolation`
  turn the `assurance` profile into a contract: a completed `PASS` weaker than
  required is refused, never silently downgraded. The floor does not erase a
  more specific static, preflight, timeout/incomplete, pack, tamper, or isolation
  cause.

Pack assurance is evidence-based too: `configured`, observed `present`,
`integrity`, `identity_verified`, pack `execution_state`, delivered `secrecy`,
and observed `snapshot_sha256` distinguish missing, invalid, mismatched,
accepted-before-execution, verified pre/post or read-only, and changed snapshots.
A configured path alone is not reported as a verified pack.

See [`docs/BLACKBOX.md`](docs/BLACKBOX.md) and [`docs/ASSURANCE.md`](docs/ASSURANCE.md).

Structured, judge-owned verdicts (`junit+exit`) cover **eight runners**:
pytest, `node --test`, vitest, jest, gotestsum (Go), rspec (Ruby), mocha, and
Maven/Surefire (Java). Any other test command is graded by exit code — still
never by stdout.

The **core runtime has zero Python dependencies** — 3.10+ standard library only
(plus `git`/`patch` on the host). Ed25519 signing and diff-coverage are optional
extras (`cryptography`, `coverage`).

**Release-artifact scope.** The zipapp builder fixes archive entry order,
timestamps, and modes, so repeated builds are deterministic when the source
bytes and Python/OS/ZIP-zlib toolchain are equivalent. This is **not** a claim
that independent Windows and Linux builds are bit-identical; checkout line
endings and platform/toolchain details can legitimately change the SHA-256.
Release reruns have a separate, stronger immutability rule: an asset already
attached to a tag is byte-compared and is never replaced—different bytes make
the workflow fail closed.

## Try it in two minutes

```bash
pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m@v3.5.0"   # a released tag; pin a SHA for strictest CI

# From the branch you want checked (the diff is reverse-applied to a throwaway
# copy — your working tree is never modified):
git diff main...HEAD | evo-guard guard --diff - --test-command "python -m pytest -q"
```

You get a PR-ready Markdown report and a CI-friendly exit code:

| Verdict | Meaning | Exit |
|---|---|---|
| ✅ `PASS` | the repo's tests pass **and** the patch left the protected harness untouched | 0 |
| ⛔ `REJECTED` | the patch edits or deletes the tests, their config, CI, or an auto-executed file — blocked before the suite runs. A *policy trip*, not proof of intent: a legitimate config/dependency change trips it too — review and exempt with `--allow` | 1 |
| ❌ `FAIL` | the patch applied and the suite ran, but tests fail | 1 |
| 🚨 `TAMPERED` | the exit code and JUnit disagree, or the judged candidate/pack snapshot changed during execution | 1 |
| ⚠️ `ERROR` | verification could not safely complete — a stale/unsafe/binary diff (refused, never applied), a timeout, a setup failure, required isolation unavailable, or an unmet `--require-*` assurance floor | 1 |

Every run can also emit a machine-readable JSON record (`--json`) with a stable
`schema_version` and a fixed `reason_code` for the verdict's cause, plus an
explicit `execution_state` (`static_gate`, `not_started`,
`started_incomplete`, or `completed`) and `execution_phase`. In schema 1.11,
`test_command_ran` means the test/judge process started, so it remains true on a
test/judge timeout even when no clean `verdict_source` exists. Requested policy
remains in the attestation; no-run isolation is reported as `not_run`. It can
also emit a
SARIF 2.1.0 report (`--sarif`) for GitHub code scanning — see
[`docs/JSON_SCHEMA.md`](docs/JSON_SCHEMA.md).

## In CI (GitHub Actions)

The fastest path — scaffold the workflow from inside your repo:

```bash
evo-guard init --test-command "python -m pytest -q"
```

or drop the composite action in yourself:

```yaml
permissions:
  contents: read
  pull-requests: write   # only if comment: "true"

steps:
  - uses: actions/checkout@v4
    with: { fetch-depth: 0 }          # Guard needs the base commit to diff
  - uses: EvoRiseKsa/EvoOM-Guard-m@v3.5.0   # a release tag (pin a SHA for strictest CI)
    with:
      test-command: "python -m pytest -q"
      comment: "true"                 # upserts ONE sticky PR comment per PR
```

The step fails on any non-`PASS` verdict. (`fail-on: rejected-only` gates ONLY
harness integrity — with it, `FAIL`/`TAMPERED`/`ERROR` leave the check **green**;
use it only when another required check already runs the suite.) The report also lands in the job summary. Further
inputs: `verifier-pack`, `expect-verifier-pack-sha256`,
`blackbox`/`blackbox-only`, `require-report-integrity`,
`require-candidate-isolation`, `isolation`/`docker-image`/`docker-network`,
`trust-setup-on-host`,
`sarif`, `allow`, `allow-new-tests`, `timeout`, `mem-limit` — see
[`action.yml`](action.yml) and [`docs/ADOPTION.md`](docs/ADOPTION.md).

## Other input shapes & useful flags

```bash
# Two checkouts (what the Action does internally):
evo-guard guard --base ./base-checkout --head ./head-checkout --test-command "python -m pytest -q"

# An agent's edit blocks (<<<FILE: path>>> ... <<<END FILE>>> /
# <<<PATCH: path>>> <<<SEARCH>>> ... <<<REPLACE>>> ... <<<END PATCH>>>):
evo-guard guard ./repo --patch candidate.txt

# Useful flags:
#   --protected "src/billing/*"   extra globs the patch may not touch
#   --allow "docs/pytest.ini"     baseline allowlist (never auto-exec/unsafe paths)
#   --allow-new-tests             feature mode: NEW test files allowed; edits to
#                                 existing tests/config stay rejected
#   --isolation docker|gvisor     run the suite in a network-less, read-only
#                                 container (needs --docker-image + a daemon)
#   --verifier-pack /secure/pack  org-owned tests the patch cannot modify
#   --expect-verifier-pack-sha256 <64-hex>  require its EVOGUARD_PACK_V2 identity
#   --blackbox                    external isolated judge (needs --verifier-pack):
#                                 verdict from the judge's own process; composite
#                                 with the repo suite. --blackbox-only skips it.
#   --require-report-integrity external_process_isolated   fail-closed floor;
#                                 requires --blackbox-only because the default
#                                 composite includes the weaker repo-native channel
#   --require-candidate-isolation docker                   fail-closed floor
#   --timeout 300                 per-run suite timeout (seconds)
#   --json out.json --report out.md --sarif out.sarif

# Environment checkup / workflow scaffolding / version:
evo-guard doctor
evo-guard init --test-command "npm test"
evo-guard version
```

Project defaults can live in a `.evoguard.json` at the repo root (itself a
protected file — a patch cannot edit its own gate). Python API:
`from evoom_guard.guard import guard, guard_from_diff, render_report`.

### Setup and container phases in 3.4

`setup_command` prepares the throwaway candidate tree before judgment. With
`--isolation docker` or `gvisor`, setup runs **inside the resolved container
image by default**, with the workspace writable; the repo suite and a configured
verifier-pack phase then run in separate containers with the candidate tree
**read-only**. The same resolved image ID is used for all phases. The default
network is `none`, so bake dependencies into the image, use an available cache,
or deliberately configure a network.

Setup is checked before and after: changing judged source or harness files is an
error. Conventional new dependency/build outputs are allowed, and repositories
can declare additional exceptions with `setup_output_globs` in
`.evoguard.json`. Those globs are **trusted policy**: a broad pattern excludes
matching paths from the fidelity check, so keep them narrow and review the
protected config. They affect setup validation only; a repo-native pack's
post-setup runtime identity still includes those paths.
`trust_setup_on_host: true` is a compatibility escape hatch
for container modes; it is recorded and reduces effective candidate isolation
to `subprocess`.

## Signed verdicts and portable evidence

With the `sign` extra, the judge can sign every JSON verdict with an Ed25519
key, making post-run record modification detectable — a `FAIL` cannot be quietly
edited into a `PASS` without invalidating the signature:

```bash
evo-guard keygen                                   # once: the judge's identity
evo-guard guard ... --json v.json --sign-key evoguard-signing.pem
evo-guard verify-verdict v.json --pub evoguard-signing.pub   # offline; exit 0/1
```

See [`docs/SIGNED_VERDICTS.md`](docs/SIGNED_VERDICTS.md).

For one machine-consumable result that combines canonical bytes, an external
trust key, replay-resistant repository/run/revision context, and schema-1.11
semantic verification, create an authenticated evidence bundle in a trusted
post-run finalizer:

```bash
evo-guard verify-record v.json
evo-guard bundle-evidence v.json --out evidence.evb \
  --context context.json --sign-key evoguard-signing.pem
evo-guard verify-bundle evidence.evb \
  --trusted-pub evoguard-signing.pub --expect-context expected-context.json
```

`VERIFIED` authenticates the enclosed record and its exact context; it does not
mean the enclosed verdict is `PASS` or that all software behavior is correct.
Add `--require-pass` when this command is the merge/deploy gate.
The private key must never be available to the candidate job. See
[`docs/EVIDENCE_BUNDLES.md`](docs/EVIDENCE_BUNDLES.md) and
[`docs/RECORD_VERIFICATION.md`](docs/RECORD_VERIFICATION.md).

## Evidence beyond "the tests passed"

**Baseline differential evidence** (`--baseline-evidence`, v3.3): the suite also
runs on the **pristine base** — `repair_effect: demonstrated` only when the base
*fails* and the candidate *passes* under the same judge. "All tests pass on
head" alone never showed the change fixed anything. `--require-demonstrated-fix`
turns it into a gate for agent "fix" PRs (an undemonstrated PASS becomes FAIL,
`fix_not_demonstrated`); a gate the selected judge cannot enforce is an ERROR
(`policy_requirement_unsupported`), never silently dropped.

A green suite is one signal, not a proof. Guard can now attach two more
independent pieces of evidence to every verdict:

```bash
# Which changed lines did the suite actually EXECUTE? (one extra suite run,
# needs the 'cov' extra). Evidence by default; --min-diff-coverage makes it a gate:
evo-guard guard . --diff - --diff-coverage --min-diff-coverage 80

# Judge-owned tests the PATCH CANNOT MODIFY (org invariants, integration
# checks) — injected at judgment time and run as a separate mandatory phase:
evo-guard pack-doctor /secure/org-pack
# Copy the reported "pack sha256" into this protected policy/CI value:
evo-guard guard . --diff - --verifier-pack /secure/org-pack \
  --expect-verifier-pack-sha256 "$PACK_SHA256"
```

- A `PASS` whose changed lines were never executed is a **hollow pass** — the
  report shows exactly which lines the suite never reached, and the optional
  threshold flips it to `FAIL` (`diff_coverage_below_threshold`). Honest limit,
  stated in the output itself: *executed is not asserted* — coverage is a floor
  of scrutiny, not proof of correctness.
- A patch overfitted to the visible tests fails the **Independent Verifier
  Pack** — org-owned checks injected at judgment time that the **patch cannot
  include or modify**. In 3.4, Guard snapshots the pack outside the candidate
  tree, verifies its framed `EVOGUARD_PACK_V2` digest, then runs it as a
  **separate mandatory phase**: repo suite and pack must both pass, and a pack
  that collects zero tests cannot produce `PASS`. `--expect-verifier-pack-sha256`
  pins the exact accepted identity and the attestation records the digest,
  manifest and pack test counts. Honest scope: a repo-native pack still shares
  the judge process with imported candidate code, so it is not a secrecy
  boundary. For runtime separation, use black-box mode with delivered
  Docker/gVisor isolation (the pack is not mounted into the candidate at all).
  See [`docs/VERIFIER_PACKS.md`](docs/VERIFIER_PACKS.md).
- Every verdict now carries an **attestation block** (candidate/policy/report
  digests, timestamp, versions) — so a signed verdict is bound to *what* was
  judged, under *which* policy, not just to its own bytes.

## What Guard honestly is (and is not)

- The verdict comes from **running your repo's own test suite** in a subprocess
  with a wall-clock timeout and, on POSIX, CPU/memory rlimits, against a
  throwaway copy. Your working tree is never modified.
- The default subprocess judge is **not a security sandbox**. Guard is built to
  gate patches to **trusted repositories** (your own code). For semi-trusted
  code, use `--isolation docker` or `gvisor` (network-less, read-only
  container) — see [`docs/VM_ISOLATION.md`](docs/VM_ISOLATION.md).
- Resistance is **tested against specific forgery classes** (stdout forgery,
  planted/oversized/entity-bomb reports, harness edits *and deletions*,
  auto-exec files, path escapes — see the adversarial tests and
  [`docs/REWARD_HACKING_CATALOG.md`](docs/REWARD_HACKING_CATALOG.md)), not
  claimed as absolute immunity.
- **The default judge's result is forgeable by deliberate in-process code** (the
  honest boundary above): it is trustworthy against the common cheats, not
  against a patch that writes report-forgery into source. The black-box phase
  comes from a process the candidate never runs in and closes that channel;
  `--blackbox-only` is required to remove the weaker repo-native channel from
  the end-to-end verdict. Read the `assurance` profile's `report_integrity`
  field on every verdict — [`docs/ASSURANCE.md`](docs/ASSURANCE.md).
- The shell-free `$EVOGUARD_EXEC` launcher used by every black-box isolation
  mode has a **POSIX executable contract**. Native Windows therefore fails
  closed before subprocess, Docker, or gVisor delivery; run black-box mode
  under Linux/GitHub Actions or WSL. This is separate from ordinary repo-native
  Guard execution on Windows.
- Custom (non-adapter) test commands are graded by exit code only — still not
  stdout-forgeable, but with a coarser gradient (and, like every runner today,
  in-process-forgeable).
- **`ModuleNotFoundError` under the judge?** Prefer `python -m pytest` over bare
  `pytest` in `--test-command`: the `-m` form puts the repo copy's root on
  `sys.path` (exactly like the default command), so top-level packages import
  without a `conftest.py` or an installed package.

## Docs

| Doc | What it covers |
|---|---|
| [`docs/START_HERE.md`](docs/START_HERE.md) | **Start here** — pick your path (Basic / Black-box CLI / container isolation) with a decision table |
| [`examples/blackbox-cli/`](examples/blackbox-cli/) | A complete runnable example: honest → PASS, cheat → REJECTED, regression → FAIL |
| [`evoom-guard-demo`](https://github.com/EvoRiseKsa/evoom-guard-demo) | External-repository demonstration (a separate target repo under the same account — not third-party validation): four scenarios reproduced with the published release |
| [`docs/ADOPTION.md`](docs/ADOPTION.md) | Turn it on in one command; what each verdict means |
| [`docs/GUARD.md`](docs/GUARD.md) | The full CLI/API guide and safety model |
| [`docs/REWARD_HACKING_CATALOG.md`](docs/REWARD_HACKING_CATALOG.md) | The catalogue of agent reward-hacks Guard catches |
| [`docs/PROOFS.md`](docs/PROOFS.md) | Reproducible demonstration runs and an adversarial benchmark (documented cases → expected verdicts) |
| [`docs/CASE-STUDY.md`](docs/CASE-STUDY.md) | A real upstream bug (charset-normalizer #537): honest fix → PASS `demonstrated`; tamper → REJECTED; fake → FAIL — from hash-pinned sdists |
| [`docs/SIGNED_VERDICTS.md`](docs/SIGNED_VERDICTS.md) | Ed25519-signed verdicts: tamper-evident evidence, offline verification |
| [`docs/VERIFIER_PACKS.md`](docs/VERIFIER_PACKS.md) | Independent Verifier Packs: org-owned, patch-immutable invariants (and their honest runtime limits) |
| [`docs/ASSURANCE.md`](docs/ASSURANCE.md) | The `assurance` profile: what a PASS proves, what it doesn't, and why |
| [`docs/BLACKBOX.md`](docs/BLACKBOX.md) | The `--blackbox` external judge: closing same-process report forgery |
| [`ROADMAP.md`](ROADMAP.md) | Shipped capabilities, current limits, and general future direction |
| [`docs/JSON_SCHEMA.md`](docs/JSON_SCHEMA.md) | The stable JSON verdict contract (`schema_version`, `reason_code`) |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Module map and design decisions |
| [`docs/VM_ISOLATION.md`](docs/VM_ISOLATION.md) | The docker/gVisor isolation modes and their threat model |
| [`docs/FEATURE_MODE.md`](docs/FEATURE_MODE.md) | `--allow-new-tests`: gating feature work that adds tests |
| [`adversarial/README.md`](adversarial/README.md) | Executable adversarial corpus: enforced controls, known gaps, documented exceptions, and the environment-labelled security baseline |

## Where this comes from

Guard is the extracted verification core of **EvoOM**, a verification-first
measurement platform for code-generating models, built on one rule: *no result
is accepted without traceable evidence — never trust a model's opinion of its
own output.* Versions 1.1–1.8 of this gate were developed in an internal
repository (EvoGuard); v2.0.0 consolidated that engine here — see
[`CHANGELOG.md`](CHANGELOG.md).

## Feedback

If you tried it, [tell us what happened](../../issues/new?template=guard-report.md) —
pass, fail, wrong verdict, or install trouble. Two minutes, and it directly
shapes whether this tool grows.

## License

Source-available: **free to use** (including commercially, in your own CI);
**no redistribution or resale**. See [LICENSE](LICENSE).
