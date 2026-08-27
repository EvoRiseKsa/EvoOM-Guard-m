<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# EvoOM Guard — threat model and profile-defense matrix

This document states, in one place, **what EvoOM Guard defends, in which profile,
and what it does not** — the attacker model, the reward-hack technique classes, and
which operating profile closes each class. It is the consolidated view behind the
technique-by-technique [reward-hacking catalog](REWARD_HACKING_CATALOG.md), the
[assurance](ASSURANCE.md) trust boundaries, and the [operating
profiles](OPERATING_PROFILES.md). For the self-contained, reproducible proofs of
the invariants below — fuzzing, mechanical efficacy, mutation, metamorphic, none
of which need an external reviewer — see [self-contained proof](SELF_PROOF.md).

## The narrow question

EvoOM Guard answers exactly one question:

> Did *this exact change* satisfy the *selected judge* without editing, deleting,
> or neutering an evidence path the active policy protects?

It does **not** decide whether an accepted change is correct, secure, complete,
well-tested, or safe to deploy. A change that passes a weak suite is a `PASS`.

## Attacker model

The adversary is the **author of the candidate change** — a coding agent or a
human — who wants a `PASS` without honestly satisfying the judge. The adversary
may:

- write arbitrary edits to any file the policy does not protect, including source
  files that the test suite imports;
- run arbitrary code inside the test process (imports, fixtures, plugins,
  `conftest`, auto-executed hooks);
- print anything to stdout/stderr and set any process exit code;
- attempt path tricks (normalization, case, unicode, symlinks) to reach a
  protected path.

The adversary does **not** control: the judge's policy, the judge-owned JUnit
report path, a judge-owned verifier pack, signing keys, the isolation runtime, or
the final admission step. If any of those is candidate-controlled, the tool cannot
compensate — that is a deployment failure, not a gate failure.

## What is judge-owned vs candidate-controlled

| Surface | Owner | Notes |
|---|---|---|
| Protected-path policy | judge | Built-ins + declared `harness_inputs`; `allow` cannot waive them. |
| JUnit report **path** | judge | Written outside the candidate tree; the verdict reads it, never stdout. |
| Process exit code | shared | The candidate process sets it; reconciled against the report. |
| The test process | **shared** | Candidate-imported code runs *inside* it — the root of the in-process class below. |
| Verifier pack (`--blackbox`) | judge | The judge's own tests, independent of the candidate's suite. |
| Isolation boundary (`--isolation`) | judge | Effective only when the verdict records the requested isolation was delivered. |

## Technique classes and where each is closed

Each class below is tied to the catalog rows that encode it as a regression test.

### A. Judging-file tamper (protected-path) — **closed by default**

Rewrite/delete a test, deselect via `pytest.ini`/`pyproject.toml`, plant a
`conftest.py`/`sitecustomize.py`/`*.pth`, or neuter the CI that runs the gate.
All are edits to a **protected path**, rejected *before any suite runs*
(`test_command_ran: false`). Catalog rows 3–9, 9b. Independently re-verified in
this repository's audit: **29/29 distinct path-trick and plant attempts blocked**
(case/unicode/normalization/symlink/dir-diff/allowlist-exemption), zero bypass.

### B. Verdict-channel forgery — **closed by default**

Print a fake `"9999 passed"` (row 10) — the verdict is read from the judge-owned
JUnit report, not stdout. Desync the exit code and the report (`atexit`/`os._exit`
after failures, row 11) — the two trusted signals disagree and the run is
`TAMPERED`.

### C. In-process report+exit **co-forgery** — boundary by default, closed by the hardened profile

In the default same-process profile the candidate shares the process that writes
the report. Candidate-imported code can overwrite the judge-owned JUnit report
*and* force `exit 0` together, so both trusted channels agree on a false `PASS`.
This is the **documented** boundary in catalog row **11a**
(`report_integrity: same_process_candidate_writable`), pinned by
`tests/test_report_integrity.py`. It is closed by an external judge-owned verifier
pack under `--blackbox-only` with `--isolation`
(`report_integrity: external_process_isolated`).

### D. Assertion-neutering — boundary for any candidate-imported suite, closed by a judge-owned pack

Candidate-imported code monkeypatches the test framework's assertion methods (e.g.
`unittest.TestCase.assertEqual → no-op`) at import time, so the repo's own suite
*honestly* reports all-pass with a truthful report and `exit 0` — nothing for the
tamper detector to catch. Verified in this repository's audit: a genuinely broken
change (`minimize_patch` disabled → control `FAIL 23/27`) becomes `PASS 27/27,
tamper=None` once the assertions are neutered. This is the same **in-process**
root cause as class C and is *not* removed by process isolation alone, because the
monkeypatch runs inside whatever process executes the candidate-imported suite. It
**is** closed today by a **judge-owned verifier pack** whose assertions are
independent of candidate-imported modules: a pack that asserts with bare `assert`
statements cannot be neutered by monkeypatching `unittest`/`pytest` assertion
methods, because `assert` is a language statement, not a callable the candidate can
rebind. A repo-native **assertion-liveness canary** ships for this, two ways:

- **Auto-injected** with `guard --require-assert-liveness` (pytest-only). The gate
  installs a judge-owned pytest plugin and the canary into a `.evoguard/` directory
  inside the prepared copy, puts it on `PYTHONPATH`, and loads it with
  `-p assert_liveness_plugin`. The plugin *adds* the canary to whatever the command
  already collects (it never replaces `testpaths`, so the repository suite still
  runs), and the canary runs in the same session — the only place the monkeypatch is
  active. Under `--isolation docker` the copy mounts read-only, so the plugin and
  canary are untamperable at runtime; the default subprocess profile catches the
  demonstrated naive neuter but is not immune to a canary-aware in-process rewrite. A
  non-pytest command with the flag set is refused (`ERROR`) before any suite runs,
  rather than silently skipping the control.
- **Manually**, by appending the judge-owned
  [`benchmarks/self_proof/assert_liveness_canary.py`](../benchmarks/self_proof/assert_liveness_canary.py)
  to your own pytest command (useful outside the gate).

The canary probes the neutable `unittest.TestCase` assertion methods and enforces
with a bare `assert`, so a neutered run fails instead of yielding a false `PASS`.
Verified end-to-end through the real gate by
[`benchmarks/self_proof/assert_liveness.py`](../benchmarks/self_proof/assert_liveness.py)
(neuter without the canary → false `PASS`; with it → `FAIL`) and by
`tests/test_report_integrity.py` (the flag turns the neuter into a `FAIL`, keeps an
honest suite passing, does not suppress the repository suite, and refuses a
non-pytest command). See catalog row 11b.

### E. Mid-run mutation of a protected judging file — boundary by default, closed by continuity

Candidate-imported code rewrites a *protected* judging file on disk *during*
collection/execution. The protected-path gate is a **pre-execution** static check,
so a file that is pristine at gate time but rewritten mid-run is not caught by that
gate alone. Verified in the audit: a candidate that edits only an allowed source
file rewrites a protected test at collection time and turns `FAIL` into a wrong
`PASS`. It is closed by **after-suite tree-continuity** — a verifier pack, or the
opt-in `--require-suite-continuity`, which re-verifies the judged tree's identity
after the suite and rejects `suite_drift`. Catalog rows 9e–9f (declared
`harness_inputs`) and row 11c. (The pack-less `--require-suite-continuity` path
tolerates benign runner bookkeeping — `__pycache__/`, `.pytest_cache/`, `*.pyc`,
linter caches, coverage temp — so real runner cache churn is not mistaken for
drift, while any change to a judged source / test / config file still trips it;
the verifier-pack path keeps the strict exact-tree identity.)

## Profile-defense matrix

| Technique class | Default (`guard`, subprocess) | Hardened (`--blackbox-only --isolation`, judge-owned pack, continuity) |
|---|---|---|
| A. Judging-file tamper | ✅ rejected pre-execution | ✅ rejected pre-execution |
| B. Verdict-channel forgery | ✅ `FAIL`/`TAMPERED` | ✅ `FAIL`/`TAMPERED` |
| C. Report+exit co-forgery | ⚠️ boundary (`known_gap`) | ✅ external report, isolated |
| D. Assertion-neutering | ⚠️ boundary; ✅ with `--require-assert-liveness` (auto-injected canary) | ✅ judge-owned pack (bare `assert`) or `--require-assert-liveness` under docker |
| E. Mid-run protected-file rewrite | ⚠️ boundary (continuity off) | ✅ `suite_drift` / continuity |

A default `PASS` therefore carries `report_integrity:
same_process_candidate_writable` and **must not be read as tamper-proof**. It is a
correct, useful verdict for cooperative CI on trusted authors; it is not a
sandbox for hostile code.

## Adoption guidance

- **Trusted authors, internal CI:** the default profile blocks classes A and B —
  the bulk of accidental and casual reward-hacking — at ~300 ms, before the suite
  runs. This is the common case.
- **Untrusted / fork / agent-authored changes:** gate with a **judge-owned
  verifier pack** under `--blackbox-only` and `--isolation docker` (or `gvisor`),
  and enable continuity. This closes classes C, D, and E. See
  [BLACKBOX.md](BLACKBOX.md), [VERIFIER_PACKS.md](VERIFIER_PACKS.md), and
  [ISOLATION_CONFORMANCE.md](ISOLATION_CONFORMANCE.md).
- **Hostile code / untrusted kernel surface:** container isolation is defence in
  depth, not a complete boundary; use VM-class isolation
  ([VM_ISOLATION.md](VM_ISOLATION.md)).
- Keep the base policy, workflow, verifier pack, keys, and admission step outside
  candidate control ([REPOSITORY_PROTECTION.md](REPOSITORY_PROTECTION.md)).

## Non-claims

- **Resistant, not immune.** The classes above are the *modelled* vectors; a novel
  vector the model does not cover could exist.
- EvoOM Guard does not judge test quality, author intent, or general correctness.
- It does not discover a complete transitive harness graph; declare repository
  wrappers/helpers as `harness_inputs`.
- Runners outside the eight structured adapters grade on the **exit code alone**
  today (no structured counts / tamper check) — see
  [RUNNER_CONFORMANCE.md](RUNNER_CONFORMANCE.md).
- Same-owner demonstrations are reproducible operational evidence, **not**
  independent validation — see [INDEPENDENT_EVALUATION.md](INDEPENDENT_EVALUATION.md).
