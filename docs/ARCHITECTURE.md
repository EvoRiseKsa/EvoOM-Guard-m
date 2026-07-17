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
| `verdict_contract_v1_11.py` | Frozen, stdlib-only schema-1.11 vocabulary: verdicts, lifecycle states, reason compatibility, policy keys, and required record sections. It contains no producer or verifier algorithm. |
| `guard.py` | **Producer orchestration.** `guard()` / `guard_from_diff()` / `candidate_from_dirs()`, independent outcome selection, assurance/attestation construction, and report renderers (Markdown / JSON / SARIF). It re-exports the established schema-1.11 constants for compatibility. |
| `patch_applier.py` | `apply_patch` — unique-anchor search/replace for `<<<PATCH>>>` blocks. |
| `patchmin.py` | Pure, model-free helpers: delta-debugging (`minimize_patch`) + blast-radius `risk_score`. |
| `record_verifier.py` | Public bounded schema-1.11 semantic-verification API and ordered claim-family orchestration. It checks consistency of recorded claims; it does not rerun the judged change. |
| `record_verification/` | Internal verifier components extracted incrementally behind the public API. `report.py` owns the stable report envelope and independent schema-support pin; `isolation.py` owns isolation-parity checks. |
| `strict_json.py` | Shared fail-closed JSON decoding limits for offline record and bundle consumers (duplicates, numbers, nesting, and Unicode). |
| `evidence_bundle.py` | Canonical, bounded evidence envelopes: exact verdict/material bytes, manifest digests, Ed25519 authentication, and exact external context binding. Structural inspection does not imply authentication. |
| `finalizer_derivation.py` | No-checkout raw-Git reader and canonical `EVOGUARD_FINALIZER_GIT_BINDINGS_V1` derivation for candidate text, ordered deletions, effective policy, and verifier-pack identity. It compares those results with an untrusted verdict before finalizer signing. |
| `artifact_admission.py` | Narrow detached-signature `.eab` records that bind one regular file's SHA-256 and size to an externally verified Trusted Finalizer `ALLOW`. It deliberately does not implement build provenance, OCI, publication, or deployment claims. |
| `artifact_digest_admission.py` | Unreleased opt-in V2 records that bind one exact generic or OCI manifest-or-index SHA-256 digest plus opaque provenance-reference bytes to an externally verified Trusted Finalizer `ALLOW`. It does not parse or verify provenance, OCI registry state, build, publication, or deployment semantics. |
| `github_attestation.py` | Unreleased protected-boundary adapter that freezes one artifact, invokes a constrained `gh attestation verify` pinned to one repository, signer workflow/digest, source ref/digest, GitHub Actions OIDC issuer, SLSA predicate, and hosted runners, retains a canonical receipt/raw output, and can bind that receipt through V2. GitHub CLI performs cryptographic attestation verification; EvoGuard does not parse untrusted predicate data or independently recreate GitHub/Sigstore verification. |
| `schemas/` | Packaged JSON Schema 2020-12 contracts for verdict records, evidence contexts/manifests, and artifact bindings; shipped in both wheel and zipapp artifacts. |
| `signing.py` | Optional Ed25519 byte/file signatures and stable DER-SPKI key identities. `cryptography` remains a lazy `sign` extra, not a core dependency. |
| `cli.py` | The `evo-guard` command: execution (`guard`), offline verification (`verify-verdict`, `verify-record`, `verify-bundle`), bundle creation, pack/environment diagnostics, initialization, and version reporting. It owns trusted `.evoguard.json` loading and flag/config precedence: base for `--base/--head`, repo for edit blocks, and an explicit external policy (or `--no-config`) for `--diff`. |

## Contract ownership and independence

The shared contract is deliberately **data, not a shared decision engine**. The
producer and semantic verifier may use the same immutable names and compatibility
table, but they must not call the same lifecycle, policy-digest, assurance, or
admission implementation. Otherwise one defect could make both sides agree on a
false claim. Compatibility is guarded by an external frozen fixture that is not
generated from the contract module.

```text
frozen vocabulary ─┬─► producer logic ─► verdict record
                   └─► independent semantic checks ─► verification report

external golden fixture ─► compares vocabulary + schema + producer API + verifier output
```

The record's major claim families have intentionally bounded meanings:

| Claim family | Producer evidence | What offline verification establishes | What it does not establish |
|---|---|---|---|
| Subject identity | Candidate/tree/revision digests observed by the judge | Field shape, parity, and documented digest relationships inside the record/bundle | That an external repository currently has those bytes unless supplied and re-hashed |
| Policy binding | Complete `effective_policy` plus canonical `policy_sha256` | Recomputed policy digest and policy↔runtime consistency | That the policy was organizationally approved |
| Execution lifecycle | Phase/state receipts repeated across result, assurance, and attestation | Cross-field consistency for `static_gate`, `not_started`, `started_incomplete`, or `completed` | That execution occurred merely because JSON says it did; authentication/runtime evidence remain separate |
| Isolation delivery | Observed launcher/container receipts and effective boundary | Consistency of top-level, assurance, attestation, and invocation semantics | Independent remote attestation of the host, kernel, or container runtime |
| Report integrity | Judge-owned report channel, exit code, and report digests | Verdict/count/source consistency and impossible-combination rejection | Quality or completeness of the tests themselves |
| Verifier-pack identity | Manifest, snapshot digest, phase receipts, and counts | Pack identity/count/lifecycle consistency; bundle verification can re-hash enclosed material | Secrecy of a same-host pack or correctness of its assertions |
| Admission | Verdict, reason code, counts, source, and assurance | The frozen reason/verdict/lifecycle truth table and related cross-field rules | Complete software correctness, absence of vulnerabilities, or author intent |

JSON Schema remains an independent structural publication; semantic verification
remains code; signature/context verification remains a third boundary. None is a
substitute for the others.

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
