<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
  Maintained and released by Mana Alharbi (مانع الحربي).
-->

# EvoGuard — architecture

A map of the codebase for anyone reading or extending it. The core is **stdlib-only**;
the whole gate is a thin, model-free composition of a policy-bound judge and a
blast-radius scorer.

## One-paragraph mental model

Given a code change, EvoGuard applies it to a **throwaway copy** of the repo, runs
the repo's **own test suite** in that copy, and reads the verdict from a **JUnit
report the judge owns** (a path *outside* the copy) plus the **process exit code** —
never from the candidate's stdout. Before running anything, it **rejects** any change
that touches the tests, their config, the gate's CI, a lock file, or an auto-exec
file. If an Independent Verifier Pack is configured, Guard snapshots and identifies
it outside the candidate tree, then requires a **separate pack phase** as well as the
repo suite; merely copying a pack or collecting zero pack tests is never enough. The
result is one verdict (`PASS` / `REJECTED` / `FAIL` / `TAMPERED` / `ERROR`), an exit
code, a JSON record, a Markdown report, and an optional SARIF document. Separate
offline consumers can validate the record's internal semantics or authenticate a
canonical evidence envelope against external key and run-context inputs.

## Module map (`evoom_guard/`)

| Module | Responsibility |
|---|---|
| `contracts.py` | The `Verifier` Protocol + `VerdictResult` / `Problem` — the domain-agnostic interface. |
| `verifiers/repo_verifier.py` | **The engine.** Parse blocks, the harness-edit **pre-gate**, copy + apply + delete, run setup/suite/pack phases (subprocess/docker/gvisor) with a timeout and POSIX rlimits where available, read the judge-owned JUnit, grade, and detect drift/tamper. |
| `workspace.py` | Contained workspace I/O: atomic descriptor-relative/no-follow operations on POSIX; reparse rejection plus pre/post parent/object identity checks as a non-atomic Windows fallback. |
| `runtime_identity.py` | Canonical post-setup runtime-tree identity (`EVOGUARD_RUNTIME_TREE_V1`), including setup-created outputs. |
| `verifiers/fidelity.py` | Setup-fidelity snapshots and drift details; setup output exceptions are scoped to this validation step. |
| `verifiers/junit_oracle.py` | Hardened JUnit parsing/grading. Directory report sets fail closed if any XML sibling is untrusted or invalid. |
| `pack_manifest.py` | The canonical pack contract: strict `pack.json`, regular-file-only inventory, framed `EVOGUARD_PACK_V2` digest, verified snapshots, and pack test discovery. |
| `candidate_runner.py` | The shell-free `$EVOGUARD_EXEC` launcher and delivered-isolation evidence for black-box candidates. |
| `verifiers/grading.py` | The pure score gradient (`fraction_score`). |
| `adapters.py` | Per-runner report wiring (`RunnerAdapter` + `instrument_command`). One class per runner; the engine stays runner-agnostic. |
| `guard.py` | **Orchestration.** `guard()` / `guard_from_diff()` / `candidate_from_dirs()`, the verdict mapping, and the report renderers (Markdown / JSON / SARIF). |
| `patch_applier.py` | `apply_patch` — unique-anchor search/replace for `<<<PATCH>>>` blocks. |
| `patchmin.py` | Pure, model-free helpers: delta-debugging (`minimize_patch`) + blast-radius `risk_score`. |
| `record_verifier.py` | Bounded, strict schema-1.11 structural and cross-field validation. It checks consistency of recorded claims; it does not rerun the judged change. |
| `strict_json.py` | Shared fail-closed JSON decoding limits for offline record and bundle consumers (duplicates, numbers, nesting, and Unicode). |
| `evidence_bundle.py` | Canonical, bounded evidence envelopes: exact verdict/material bytes, manifest digests, Ed25519 authentication, and exact external context binding. Structural inspection does not imply authentication. |
| `schemas/` | Packaged JSON Schema 2020-12 contracts for verdict records, evidence contexts, and evidence manifests; shipped in both wheel and zipapp artifacts. |
| `signing.py` | Optional Ed25519 byte/file signatures and stable DER-SPKI key identities. `cryptography` remains a lazy `sign` extra, not a core dependency. |
| `cli.py` | The `evo-guard` command: execution (`guard`), offline verification (`verify-verdict`, `verify-record`, `verify-bundle`), bundle creation, pack/environment diagnostics, initialization, and version reporting. It also owns `.evoguard.json` loading and flag↔config precedence. |

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
  │   snapshot + identify verifier pack outside candidate tree (when configured)
  │   optional setup_command:
  │     subprocess mode → host subprocess (temporary HOME/minimal env; not sandboxed)
  │     docker/gvisor → writable setup container by default; verify setup fidelity
  │   if a repo-native pack is configured: identify the complete post-setup
  │     runtime tree (including setup-created outputs) as EVOGUARD_RUNTIME_TREE_V1
  │   instrument_command → splice a judge-owned JUnit reporter (per adapter)
  │   run repo suite: subprocess (POSIX rlimits + timeout) | docker | gvisor(runsc)
  │   if pack configured: run it as a separate mandatory pytest phase
  │   container suite + pack mounts are read-only; verify candidate/pack snapshots
  │   read judge-owned report(s) + exit code(s), compose both phases
  │     directory JUnit: any invalid/symlink/special XML invalidates the whole set
  ▼
grade_repo_run + detect_tamper ─► VerdictResult
  ▼
GuardResult ─► verdict + exit code + JSON + Markdown + SARIF

exact verdict bytes ─► verify-record ─► structural/cross-field report
exact verdict + trusted context/key ─► bundle-evidence ─► canonical .evb
.evb + external public key/context ─► verify-bundle ─► authenticated semantic result
```

## The two invariants that make it reward-hack-resistant

1. **Judge-owned verdict path.** The structured report is written to a path *outside*
   the repo copy, so a patch cannot pre-plant it through an edit block. The verdict
   comes from that report + the exit code, **never** from candidate stdout — so a
   forged `"N passed"` does nothing. An exit-code/report disagreement is surfaced as
   `TAMPERED`. Repo-native code still shares the reporter process and therefore has
   `report_integrity: same_process_candidate_writable`; black-box mode is the stronger
   external-process boundary.
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
  the verifier falls back to `parse_junit_dir` to merge them. The directory is one
  evidence set: an unreadable, malformed, oversized, DTD/entity-bearing,
  symlinked, or special XML sibling invalidates the whole set. Add adapter unit
  tests in `tests/test_adapters.py`.
- **Add an isolation backend:** extend `RepoVerifier` (`_docker_command` / `_run_docker`
  are the pattern) and keep the pre-gate running *before* any sandbox starts.
- **Change pack behavior in one place:** extend `pack_manifest.py`; every consumer
  must use the same manifest parser, V2 identity, snapshot verification and non-zero
  test requirement.
- **Never read the verdict from stdout**, and **keep the core dependency-free** —
  third-party needs live in the runner image or the adapter, not the core.

## Trust boundary (short)

The default `subprocess` judge uses a wall timeout everywhere and CPU/memory rlimits
on POSIX; it is for **trusted** repos, not a sandbox. Every black-box isolation
mode uses the same POSIX executable launcher and fails closed on native Windows
before subprocess, Docker, or gVisor delivery (use Linux/GitHub Actions or WSL).
`--isolation docker` runs setup inside the
resolved image by default, then runs suite and pack containers against read-only
mounts; `gvisor` adds a separate user-space guest kernel. Explicit
`setup_output_globs` are trusted policy exceptions to setup-fidelity checks, not
to the post-setup runtime identity. Subprocess continuity is a boundary snapshot
check, while Docker/gVisor can claim read-only enforcement only without host
setup opt-in. POSIX workspace operations are descriptor-relative/no-follow;
Windows performs best-effort pre/post identity checks because stdlib lacks an
atomic equivalent. `trust_setup_on_host` deliberately weakens effective
isolation. A Firecracker
microVM backend is documented as a future design but is not built. See
[`GUARD.md`](GUARD.md) and [`VM_ISOLATION.md`](VM_ISOLATION.md).
