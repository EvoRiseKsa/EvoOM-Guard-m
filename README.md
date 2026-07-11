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

**An AI patch verification gate: does this patch fix the code — *without gaming the tests*?**

> **New here? → [`docs/START_HERE.md`](docs/START_HERE.md)** picks your path in 30
> seconds (Basic Guard · Black-box CLI · + container isolation), with a decision
> table and a complete runnable example. Start there instead of reading this whole page.
>
> **See it run on a repo it doesn't own → [`evoom-guard-demo`](https://github.com/EvoRiseKsa/evoom-guard-demo)**:
> an honest fix passes, test tampering is rejected, a fake `9999 passed` on stdout
> still fails, and black-box report forgery is caught — all with the published release.

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
> host, **not** the report. **The fix ships as `--blackbox`** (below): the
> verdict then comes from the judge's own process and the same forgery is caught.
> See [`docs/ASSURANCE.md`](docs/ASSURANCE.md).

### Close the forgery hole: `--blackbox` (external isolated judge)

For targets with a process/protocol boundary (a CLI, an HTTP service, a
DB-backed program), the black-box judge produces the verdict from **its own
pytest over judge-owned tests that never import your code** — so a patch cannot
forge the report from inside the run:

```bash
evo-guard guard ./repo --patch candidate.txt \
    --verifier-pack examples/blackbox-pack --blackbox
```

The pack invokes the candidate across a process boundary (via `$EVOGUARD_EXEC`,
which runs it under the delivered isolation) and asserts on its outputs.
`report_integrity` becomes `external_process_isolated`, and the *identical*
`atexit`+`os._exit` forgery that fakes a `PASS` under the default judge yields
the correct `FAIL` (proven in `tests/test_blackbox.py`). Three properties make
this a real guarantee, not a label:

- **Isolation is *delivered*, not requested.** `candidate_isolation` reports what
  actually ran. Ask for `--isolation docker` with no daemon or a missing image
  and Guard returns `ERROR` (`assurance_requirement_not_met`) — never a `PASS`
  mislabelled `docker`. In a container the repo copy is mounted **read-only** and
  the pack is **not mounted into the candidate at all** (proven against a real
  daemon in CI, where a malicious candidate fails to write the host, open the
  network, or reach the pack).
- **The verdict is composite.** By default the repo's own suite **and** the
  external pack must both pass — a green pack can never mask an internal
  regression. Pure-CLI/service targets with no in-repo suite pass
  `--blackbox-only`.
- **Fail-closed policy.** `--require-report-integrity` / `--require-candidate-isolation`
  turn the `assurance` profile into a contract: a run weaker than you required is
  refused, never silently downgraded.

See [`docs/BLACKBOX.md`](docs/BLACKBOX.md) and [`docs/ASSURANCE.md`](docs/ASSURANCE.md).

Structured, judge-owned verdicts (`junit+exit`) cover **eight runners**:
pytest, `node --test`, vitest, jest, gotestsum (Go), rspec (Ruby), mocha, and
Maven/Surefire (Java). Any other test command is graded by exit code — still
never by stdout.

The **core runtime has zero Python dependencies** — 3.10+ standard library only
(plus `git`/`patch` on the host). Ed25519 signing and diff-coverage are optional
extras (`cryptography`, `coverage`).

## Try it in two minutes

```bash
pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m@v3.2.2"   # a released tag; pin a SHA for strictest CI

# From the branch you want checked (the diff is reverse-applied to a throwaway
# copy — your working tree is never modified):
git diff main...HEAD | evo-guard guard --diff - --test-command "python -m pytest -q"
```

You get a PR-ready Markdown report and a CI-friendly exit code:

| Verdict | Meaning | Exit |
|---|---|---|
| ✅ `PASS` | the repo's tests pass **and** the patch left the protected harness untouched | 0 |
| ⛔ `REJECTED` | the patch edits or deletes the tests, their config, CI, or an auto-executed file — a reward-hack, rejected before the suite runs | 1 |
| ❌ `FAIL` | the patch applied and the suite ran, but tests fail | 1 |
| 🚨 `TAMPERED` | the process exit code and the judge-owned JUnit report disagree — a forgery signature | 1 |
| ⚠️ `ERROR` | verification could not safely complete — a stale/unsafe/binary diff (refused, never applied), a timeout, a setup failure, required isolation unavailable, or an unmet `--require-*` assurance floor | 1 |

Every run can also emit a machine-readable JSON record (`--json`) with a stable
`schema_version` and a fixed `reason_code` for the verdict's cause, plus a
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
  - uses: EvoRiseKsa/EvoOM-Guard-m@v3.2.2   # a release tag (pin a SHA for strictest CI)
    with:
      test-command: "python -m pytest -q"
      comment: "true"                 # upserts ONE sticky PR comment per PR
```

The step fails on any non-`PASS` verdict (set `fail-on: rejected-only` to gate
only on reward-hacks). The report also lands in the job summary. Further
inputs: `verifier-pack`, `blackbox`/`blackbox-only`, `require-report-integrity`,
`require-candidate-isolation`, `isolation`/`docker-image`/`docker-network`,
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
#   --blackbox                    external isolated judge (needs --verifier-pack):
#                                 verdict from the judge's own process; composite
#                                 with the repo suite. --blackbox-only skips it.
#   --require-report-integrity external_process_isolated   fail-closed floor
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

## Signed verdicts (optional)

With the `sign` extra, the judge can sign every JSON verdict with an Ed25519
key, making the *record* as tamper-evident as the *run* — a `FAIL` cannot be
quietly edited into a `PASS` in some artifact bucket:

```bash
evo-guard keygen                                   # once: the judge's identity
evo-guard guard ... --json v.json --sign-key evoguard-signing.pem
evo-guard verify-verdict v.json --pub evoguard-signing.pub   # offline; exit 0/1
```

See [`docs/SIGNED_VERDICTS.md`](docs/SIGNED_VERDICTS.md).

## Evidence beyond "the tests passed"

A green suite is one signal, not a proof. Guard can now attach two more
independent pieces of evidence to every verdict:

```bash
# Which changed lines did the suite actually EXECUTE? (one extra suite run,
# needs the 'cov' extra). Evidence by default; --min-diff-coverage makes it a gate:
evo-guard guard . --diff - --diff-coverage --min-diff-coverage 80

# Judge-owned tests the PATCH CANNOT MODIFY (org invariants, integration
# checks) — injected at judgment time, collected with the suite:
evo-guard guard . --diff - --verifier-pack /secure/org-pack
```

- A `PASS` whose changed lines were never executed is a **hollow pass** — the
  report shows exactly which lines the suite never reached, and the optional
  threshold flips it to `FAIL` (`diff_coverage_below_threshold`). Honest limit,
  stated in the output itself: *executed is not asserted* — coverage is a floor
  of scrutiny, not proof of correctness.
- A patch overfitted to the visible tests fails the **Independent Verifier
  Pack** — org-owned checks injected at judgment time that the **patch cannot
  include or modify** (a diff touching the pack mount is `REJECTED`). Honest
  scope: in repo-native mode the pack is copied into the candidate tree and runs
  in the same process and filesystem, so **runtime code is not isolated from it**
  — it is an integrity control against *patch* overfitting, not a runtime-tamper
  or secrecy guarantee. For runtime separation, use black-box mode with delivered
  Docker/gVisor isolation (the pack is not mounted into the candidate at all).
  See [`docs/VERIFIER_PACKS.md`](docs/VERIFIER_PACKS.md).
- Every verdict now carries an **attestation block** (candidate/policy/report
  digests, timestamp, versions) — so a signed verdict is bound to *what* was
  judged, under *which* policy, not just to its own bytes.

## What Guard honestly is (and is not)

- The verdict comes from **running your repo's own test suite** in a subprocess
  with CPU/memory rlimits and a timeout, against a throwaway copy. Your working
  tree is never modified.
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
  against a patch that writes report-forgery into source. The external isolated
  judge (`--blackbox`) closes this — its verdict comes from a process the
  candidate never runs in. Read the `assurance` profile's `report_integrity`
  field on every verdict — [`docs/ASSURANCE.md`](docs/ASSURANCE.md).
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
| [`evoom-guard-demo`](https://github.com/EvoRiseKsa/evoom-guard-demo) | An independent repo the tool doesn't own — four scenarios proven with the published release |
| [`docs/ADOPTION.md`](docs/ADOPTION.md) | Turn it on in one command; what each verdict means |
| [`docs/GUARD.md`](docs/GUARD.md) | The full CLI/API guide and safety model |
| [`docs/REWARD_HACKING_CATALOG.md`](docs/REWARD_HACKING_CATALOG.md) | The catalogue of agent reward-hacks Guard catches |
| [`docs/PROOFS.md`](docs/PROOFS.md) | Live proof runs: a real repo, and a hard ungameable benchmark (cheat → REJECTED; honest → PASS) |
| [`docs/SIGNED_VERDICTS.md`](docs/SIGNED_VERDICTS.md) | Ed25519-signed verdicts: tamper-evident evidence, offline verification |
| [`docs/VERIFIER_PACKS.md`](docs/VERIFIER_PACKS.md) | Independent Verifier Packs: org-owned, patch-immutable invariants (and their honest runtime limits) |
| [`docs/ASSURANCE.md`](docs/ASSURANCE.md) | The `assurance` profile: what a PASS proves, what it doesn't, and why |
| [`docs/BLACKBOX.md`](docs/BLACKBOX.md) | The `--blackbox` external judge: closing same-process report forgery |
| [`ROADMAP.md`](ROADMAP.md) | Shipped capabilities, current limits, and general future direction |
| [`docs/JSON_SCHEMA.md`](docs/JSON_SCHEMA.md) | The stable JSON verdict contract (`schema_version`, `reason_code`) |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Module map and design decisions |
| [`docs/VM_ISOLATION.md`](docs/VM_ISOLATION.md) | The docker/gVisor isolation modes and their threat model |
| [`docs/FEATURE_MODE.md`](docs/FEATURE_MODE.md) | `--allow-new-tests`: gating feature work that adds tests |

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
