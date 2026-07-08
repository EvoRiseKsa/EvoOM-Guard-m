<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# EvoOM Guard

**An AI patch verification gate: does this patch fix the code — *without gaming the tests*?**

AI coding agents have learned an ugly trick: when they can't fix the code, they
"fix" the tests. Delete the failing assertion, add a pytest `addopts = "-k
passing"` deselect, print a fake `9999 passed` to stdout, or drop a
`sitecustomize.py` that forces exit 0. The suite goes green; nothing was fixed.

Guard closes that hole with two mechanisms:

1. **The harness is untouchable.** Any edit to the tests, their configuration
   (`pyproject.toml`, `pytest.ini`, `vitest.config.*`, `Makefile`, …), or an
   auto-executed file (`sitecustomize.py`, `*.pth`) is **REJECTED before the
   suite even runs**. `package.json` is dual-purpose, so instead of blocking it
   wholesale, its test-harness fields are restored from the pristine original.
2. **The verdict cannot be forged.** Tests run against a throwaway copy of your
   repo, and the verdict is read from a **judge-owned JUnit report + the process
   exit code** — never scraped from stdout. A patch that prints `9999 passed`,
   or plants a fake `judge-result.xml`, moves nothing (there are adversarial
   tests for exactly these attacks in `tests/`).

Zero dependencies — Python 3.10+ standard library only.

## Try it in two minutes

```bash
pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m@v0.1.0"

# From the branch you want checked (the diff is reverse-applied to a throwaway
# copy — your working tree is never modified):
git diff main...HEAD | evo-guard --diff - --test-command "pytest -q"
```

You get a PR-ready Markdown report and a CI-friendly exit code:

| Verdict | Meaning | Exit |
|---|---|---|
| ✅ `PASS` | the repo's tests pass **and** the patch left the test harness untouched | 0 |
| ⛔ `REJECTED` | the patch edits the tests, their config, or an auto-executed file — a reward-hack, rejected before the suite runs | 1 |
| ❌ `FAIL` | the patch applied and the suite ran, but tests fail | 1 |
| ⚠️ `ERROR` | the patch did not apply — e.g. a stale base, or an unsafe / binary diff (refused, never applied) | 1 |

## In CI (GitHub Actions)

```yaml
permissions:
  contents: read
  pull-requests: write   # only if comment: "true"

steps:
  - uses: actions/checkout@v4
    with: { fetch-depth: 0 }          # Guard needs the base commit to diff
  - uses: EvoRiseKsa/EvoOM-Guard-m@v0.1.0   # pin a release; @main is latest
    with:
      test-command: "pytest -q"
      comment: "true"                 # posts the verdict as a PR comment
```

The step fails on any non-`PASS` verdict (set `fail-on: rejected-only` to gate
only on reward-hacks). The report also lands in the job summary.

## Other input shapes

```bash
# Two checkouts (what the Action does internally):
evo-guard --base ./base-checkout --head ./head-checkout --test-command "pytest -q"

# An agent's edit blocks (<<<FILE: path>>> ... <<<END FILE>>> /
# <<<PATCH: path>>> <<<SEARCH>>> ... <<<REPLACE>>> ... <<<END PATCH>>>):
evo-guard ./repo --patch candidate.txt

# Useful flags:
#   --protected "src/billing/*"   extra globs the patch may not touch
#   --timeout 300                 per-run suite timeout (seconds)
#   --json out.json --report out.md
```

Python API: `from evoom_guard import guard, guard_from_diff, render_report`.

## What Guard honestly is (and is not)

- The verdict comes from **running your repo's own test suite** in a subprocess
  with CPU/memory rlimits and a timeout, against a throwaway copy. Your working
  tree is never modified.
- That subprocess is **not a security sandbox**. Guard is built to gate patches
  to **trusted repositories** (your own code). Do not point it at untrusted
  code you wouldn't run locally.
- Resistance is **tested against specific forgery classes** (stdout forgery,
  planted reports, harness edits, auto-exec files, path escapes — see the
  adversarial tests), not claimed as absolute immunity.
- Custom (non-pytest) test commands are graded by exit code only — still not
  stdout-forgeable, but with a coarser gradient.

## Where this comes from

Guard is the extracted verification core of **EvoOM**, a verification-first
measurement platform for code-generating models, built on one rule: *no result
is accepted without traceable evidence — never trust a model's opinion of its
own output.*

## Feedback

If you tried it, [tell us what happened](../../issues/new?template=guard-report.md) —
pass, fail, wrong verdict, or install trouble. Two minutes, and it directly
shapes whether this tool grows.

## License

Source-available: **free to use** (including commercially, in your own CI);
**no redistribution or resale**. See [LICENSE](LICENSE).
