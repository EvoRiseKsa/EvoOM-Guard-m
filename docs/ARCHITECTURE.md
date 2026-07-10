<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
  Sole owner & author: Mana Alharbi (مانع الحربي).
-->

# EvoGuard — architecture

A map of the codebase for anyone reading or extending it. The core is **stdlib-only**;
the whole gate is a thin, model-free composition of a reward-hack-resistant judge and
a blast-radius scorer.

## One-paragraph mental model

Given a code change, EvoGuard applies it to a **throwaway copy** of the repo, runs
the repo's **own test suite** in that copy, and reads the verdict from a **JUnit
report the judge owns** (a path *outside* the copy) plus the **process exit code** —
never from the candidate's stdout. Before running anything, it **rejects** any change
that touches the tests, their config, the gate's CI, a lock file, or an auto-exec
file. The result is one verdict (`PASS` / `REJECTED` / `FAIL` / `TAMPERED` / `ERROR`),
an exit code, a JSON record, a Markdown report, and an optional SARIF document.

## Module map (`evoom_guard/`)

| Module | Responsibility |
|---|---|
| `contracts.py` | The `Verifier` Protocol + `VerdictResult` / `Problem` — the domain-agnostic interface. |
| `verifiers/repo_verifier.py` | **The engine.** Parse blocks, the harness-edit **pre-gate**, copy + apply + delete, run the suite (subprocess/docker/gvisor) with rlimits + timeout, read the judge-owned JUnit, grade, and detect tamper. |
| `verifiers/grading.py` | The pure score gradient (`fraction_score`). |
| `adapters.py` | Per-runner report wiring (`RunnerAdapter` + `instrument_command`). One class per runner; the engine stays runner-agnostic. |
| `guard.py` | **Orchestration.** `guard()` / `guard_from_diff()` / `candidate_from_dirs()`, the verdict mapping, and the report renderers (Markdown / JSON / SARIF). |
| `patch_applier.py` | `apply_patch` — unique-anchor search/replace for `<<<PATCH>>>` blocks. |
| `patchmin.py` | Pure, model-free helpers: delta-debugging (`minimize_patch`) + blast-radius `risk_score`. |
| `cli.py` | The `evo-guard` command: `guard` / `doctor` / `init` / `version`, `.evoguard.json` loading, flag↔config precedence. |

## Data flow (a `--diff` run)

```
git diff ─► guard_from_diff(head_dir, diff_text)
  │   reject empty / binary / unsafe-path diffs up front (clear ERROR, no apply)
  │   copy head → base ; reverse-apply the diff to reconstruct "base"
  ▼
candidate_from_dirs(base, head) ─► <<<FILE>>> blocks (add/modify) + deleted[]
  ▼
guard(base, candidate, deleted=…)
  │   pre-gate: unsafe path → ERROR ; protected edit OR protected deletion → REJECTED
  ▼
RepoVerifier.verify(candidate, problem)
  │   copytree(base) → copy   (original never touched)
  │   apply FILE/PATCH blocks ; apply safe deletions ; restore package.json harness fields
  │   (optional setup_command on host) 
  │   instrument_command → splice a judge-owned JUnit reporter (per adapter)
  │   run suite: subprocess (rlimits+timeout) | docker | gvisor(runsc)
  │   read judge-owned judge-result.xml + exit code
  ▼
grade_repo_run + detect_tamper ─► VerdictResult
  ▼
GuardResult ─► verdict + exit code + JSON + Markdown + SARIF
```

## The two invariants that make it reward-hack-resistant

1. **Judge-owned verdict.** The structured report is written to a path *outside* the
   repo copy and read back by the judge; the candidate (confined to relative paths
   inside the copy) cannot pre-plant or overwrite it. The verdict comes from that
   report + the exit code, **never** from candidate stdout — so a forged `"N passed"`
   does nothing. An exit-code/report disagreement is surfaced as `TAMPERED`.
2. **Harness-edit pre-gate.** Any edit *or deletion* of a test, its config, a lock
   file, the gate's CI, or an auto-exec file (`sitecustomize.py`, `*.pth`, `Makefile`,
   …) is `REJECTED` before the suite runs. See `is_protected*` / `is_judge_autoexec`
   in `repo_verifier.py`.

## How to extend it

- **Add a test runner:** write a `RunnerAdapter` in `adapters.py` (a `matches` +
  `instrument` pair that wires a JUnit reporter to an **absolute, judge-owned** path)
  and append it to `_INNER_ADAPTERS`. Add its config/lock files to `_PROTECTED_CONFIG`.
  A runner whose only machine-readable output is stdout does **not** qualify (stdout
  is forgeable) — leave it on exit-code grading. A runner that emits **one file per
  test class** (Maven Surefire) points its reports directory at `<report_path>.d`;
  the verifier falls back to `parse_junit_dir` to merge them. Add adapter unit tests
  in `tests/test_adapters.py`.
- **Add an isolation backend:** extend `RepoVerifier` (`_docker_command` / `_run_docker`
  are the pattern) and keep the pre-gate running *before* any sandbox starts.
- **Never read the verdict from stdout**, and **keep the core dependency-free** —
  third-party needs live in the runner image or the adapter, not the core.

## Trust boundary (short)

The default `subprocess` judge (rlimits + timeout) is for **trusted** repos, not a
sandbox. `--isolation docker` adds network/filesystem confinement (shares the host
kernel); `--isolation gvisor` adds a separate user-space guest kernel for untrusted
code. A Firecracker microVM backend is designed (issue #51) but not built. See
[`GUARD.md`](GUARD.md) and [`VM_ISOLATION.md`](VM_ISOLATION.md).
