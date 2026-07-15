<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
  Maintained and released by Mana Alharbi (مانع الحربي).
-->

# Feature mode — adding new tests safely (`allow_new_tests`)

By default EvoGuard rejects **any** change to a test file before the suite runs:
that's the harness-edit pre-gate, and it is what makes a *bug-fix* verdict
trustworthy (fix the source under test, never the test that judges it). The
side effect is that a PR which **legitimately adds a new feature with its own new
tests** can't pass — and you can't add an untested function either (a coverage
gate would fail). The "clean → PASS" demo had to be a doc-only change for exactly
this reason.

**Feature mode** is a narrow, opt-in relaxation for that case.

## What it does

When enabled, a changed path that is protected **only because it is a test file**
is allowed **if it is brand-new** to the repo. Everything else stays rejected.

| Change | Strict (default) | Feature mode (`allow_new_tests`) |
|---|---|---|
| Add a **new** test file (`tests/test_x.py`, `*.test.ts` …) | ⛔ REJECTED | ✅ allowed |
| **Edit / delete an existing** test | ⛔ REJECTED | ⛔ REJECTED |
| Edit test/build **config** or a **lock file** (`pyproject.toml`, `pytest.ini`, `pnpm-lock.yaml`, `.evoguard.json` …) | ⛔ REJECTED | ⛔ REJECTED |
| Add/edit an **auto-exec** judge file (`conftest.py`, `sitecustomize.py`, `*.pth`, `Makefile` …) | ⛔ REJECTED | ⛔ REJECTED |
| Edit a **CI / gate** file (`.github/workflows/**`, local `action.yml` / `action.yaml`) | ⛔ REJECTED | ⛔ REJECTED |
| Touch a path matched by a caller **`protected`** glob | ⛔ REJECTED | ⛔ REJECTED |

So a feature PR can ship its **own new tests**, but it can never weaken or delete
an existing assertion, swap the config, or plant an auto-exec file.

## How to enable

Per repo, in `.evoguard.json` (recommended):

```json
{ "allow_new_tests": true }
```

Or per run: `evo-guard guard … --allow-new-tests`. It is **off by default**.

## Threat analysis (read before enabling)

Feature mode is **strictly weaker** than strict mode, by design. The honest
residual risk:

- **New test code executes in the judge process.** A new `test_*.py` is imported
  (and a new `*.test.ts` is collected) when the suite runs, so its module/
  collection-time code runs alongside the real tests. A *hostile* new test could,
  in principle, monkeypatch or shadow a module so other tests pass falsely — i.e.
  mask a broken source change. EvoGuard does **not** sandbox this.
- What feature mode still guarantees: **existing** tests are byte-for-byte the
  originals (any edit/deletion is rejected), and the config / auto-exec / CI /
  lock files are untouched. So an attacker can only act through *added* test code,
  not by quietly rewriting the existing harness.

**Therefore:** feature mode is for **trusted / semi-trusted authors** (e.g. your
own coding agent adding features), paired with **human review of the added
tests** — not for untrusted or public fork PRs. For untrusted code, keep strict
mode (default) and add isolation (`--isolation docker`/`gvisor`, both shipping;
a stronger microVM-class judge is on the roadmap). For untrusted *behaviour*, the
external black-box judge (`--blackbox`) produces a judge-owned verdict the code
under test cannot forge in-process, with delivered, fail-closed isolation. The
`*.test.ts` reward-hack in `REWARD_HACKING_CATALOG.md` — weakening an
**existing** assertion — stays blocked in both modes.

## Recommendation

- **Default / untrusted input:** leave it off (strict).
- **Trusted feature work that should add tests:** turn it on per repo, and review
  the added tests like any other code. Combine with a CI rule that routes such PRs
  to human review (the gate proves the *existing* harness is intact; a human
  vouches the *new* tests are honest).
