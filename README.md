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

AI coding agents have learned an ugly trick: when they can't fix the code, they
"fix" the tests. Delete the failing assertion, add a pytest `addopts = "-k
passing"` deselect, print a fake `9999 passed` to stdout, or drop a
`sitecustomize.py` that forces exit 0. The suite goes green; nothing was fixed.

Guard closes that hole with two mechanisms:

1. **The harness is untouchable.** Any edit — or **deletion** — of the tests,
   their configuration (`pyproject.toml`, `pytest.ini`, `vitest.config.*`,
   `Makefile`, CI workflows, …), or an auto-executed file (`sitecustomize.py`,
   `*.pth`) is **REJECTED before the suite even runs**. `package.json` is
   dual-purpose, so instead of blocking it wholesale, its test-harness fields are
   restored from the pristine original.
2. **The verdict cannot be forged.** Tests run against a throwaway copy of your
   repo, and the verdict is read from a **judge-owned JUnit report + the process
   exit code** — never scraped from stdout. A patch that prints `9999 passed`,
   or plants a fake report, moves nothing — and an exit-code ⟷ report
   disagreement is surfaced as its own **`TAMPERED`** verdict, never read as a
   pass. (There are adversarial tests for exactly these attacks in `tests/`;
   the catalogue of covered reward-hacks is
   [`docs/REWARD_HACKING_CATALOG.md`](docs/REWARD_HACKING_CATALOG.md).)

Structured, forgery-resistant verdicts (`junit+exit`) cover **eight runners**:
pytest, `node --test`, vitest, jest, gotestsum (Go), rspec (Ruby), mocha, and
Maven/Surefire (Java). Any other test command is graded by exit code — still
never by stdout.

Zero dependencies — Python 3.10+ standard library only (plus `git`/`patch` on
the host).

## Try it in two minutes

```bash
pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m@main"   # pin a tag/SHA in CI

# From the branch you want checked (the diff is reverse-applied to a throwaway
# copy — your working tree is never modified):
git diff main...HEAD | evo-guard guard --diff - --test-command "pytest -q"
```

You get a PR-ready Markdown report and a CI-friendly exit code:

| Verdict | Meaning | Exit |
|---|---|---|
| ✅ `PASS` | the repo's tests pass **and** the patch left the test harness untouched | 0 |
| ⛔ `REJECTED` | the patch edits or deletes the tests, their config, CI, or an auto-executed file — a reward-hack, rejected before the suite runs | 1 |
| ❌ `FAIL` | the patch applied and the suite ran, but tests fail | 1 |
| 🚨 `TAMPERED` | the process exit code and the judge-owned JUnit report disagree — a forgery signature | 1 |
| ⚠️ `ERROR` | the patch did not apply — e.g. a stale base, or an unsafe / binary diff (refused, never applied) | 1 |

Every run can also emit a machine-readable JSON record (`--json`) with a stable
`schema_version` and a fixed `reason_code` for the verdict's cause, plus a
SARIF 2.1.0 report (`--sarif`) for GitHub code scanning — see
[`docs/JSON_SCHEMA.md`](docs/JSON_SCHEMA.md).

## In CI (GitHub Actions)

The fastest path — scaffold the workflow from inside your repo:

```bash
evo-guard init --test-command "pytest -q"
```

or drop the composite action in yourself:

```yaml
permissions:
  contents: read
  pull-requests: write   # only if comment: "true"

steps:
  - uses: actions/checkout@v4
    with: { fetch-depth: 0 }          # Guard needs the base commit to diff
  - uses: EvoRiseKsa/EvoOM-Guard-m@main   # pin a release tag or SHA (strictest)
    with:
      test-command: "pytest -q"
      comment: "true"                 # upserts ONE sticky PR comment per PR
```

The step fails on any non-`PASS` verdict (set `fail-on: rejected-only` to gate
only on reward-hacks). The report also lands in the job summary. Further
inputs: `isolation`/`docker-image`/`docker-network`, `sarif`, `allow`,
`allow-new-tests`, `timeout`, `mem-limit` — see [`action.yml`](action.yml) and
[`docs/ADOPTION.md`](docs/ADOPTION.md).

## Other input shapes & useful flags

```bash
# Two checkouts (what the Action does internally):
evo-guard guard --base ./base-checkout --head ./head-checkout --test-command "pytest -q"

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
- Custom (non-adapter) test commands are graded by exit code only — still not
  stdout-forgeable, but with a coarser gradient.

## Docs

| Doc | What it covers |
|---|---|
| [`docs/ADOPTION.md`](docs/ADOPTION.md) | Turn it on in one command; what each verdict means |
| [`docs/GUARD.md`](docs/GUARD.md) | The full CLI/API guide and safety model |
| [`docs/REWARD_HACKING_CATALOG.md`](docs/REWARD_HACKING_CATALOG.md) | The catalogue of agent reward-hacks Guard catches |
| [`docs/PROOFS.md`](docs/PROOFS.md) | Live proof runs: a real repo, and a hard ungameable benchmark (cheat → REJECTED; honest → PASS) |
| [`docs/SIGNED_VERDICTS.md`](docs/SIGNED_VERDICTS.md) | Ed25519-signed verdicts: tamper-evident evidence, offline verification |
| [`ROADMAP.md`](ROADMAP.md) | Where this is heading: the patch gate inside an agent-governance fabric |
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
