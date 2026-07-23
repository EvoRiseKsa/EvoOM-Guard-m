# Refactor architecture overview (execution alignment roadmap v1.0)

This folder is the implementation backbone for the staged refactor decision:
keep the project in the current repository and reorganize incrementally using
strict behavior-preserving PR slices.

## Execution posture

- The current public implementation and tests remain the source of record.
- Behavior-preserving `R1`/`R2` slices carry `no-behavior-change`. Any `R3`
  semantic change is isolated from mechanical work and requires an explicit
  invariant, threat model, adversarial coverage, compatibility note, and
  rollback plan.
- The work is split into explicit stages so each stage can be merged safely:
  0) stable baseline lock
  1) architectural documentation
  2) test characterization and equivalence
  3) domain models
  4) execution primitives
  5) policy and candidate/workspace splitting
  6) repo verifier extraction
  7) blackbox extraction
  8) pipeline orchestration
  9) CLI extraction
  10) evidence and finalizer domains
  11) action/release engineering
  12) strict quality gates
  13) docs and delivery packaging
  14) post-foundation functional roadmap

## Core architecture idea

- `domain` owns request, lifecycle, verdict and assurance models.
- `execution` owns scheduling/observability primitives.
- `isolation` owns containment and transport of runtime evidence.
- `verifiers` owns executor orchestration and report interpretation.
- `application` owns pipeline and policy/assurance composition.
- `api` / `cli` / `integrations` own compatibility boundaries.

## Current implementation position and next step

The process, Docker, candidate-boundary, invocation-transport, and typed
judge-process kernels have been extracted behind characterized compatibility
surfaces. PR #123 completed the `execution/judge.py` slice; PR #133 extracted
pure repository/pack phase contracts into
`verifiers/repo_phase_contracts.py`. Host-command resolution now belongs to
`execution/command.py`, while Guard consumes public setup-fidelity and harness
policy contracts directly instead of verifier-private compatibility seams.

The first `domain/verification.py` slice owns dependency-free JUnit and
repository/pack phase contracts behind exact legacy aliases. A dedicated
strict-Mypy gate protects that package. `domain/verdict.py` separately owns
generic verdict/lifecycle/reason semantics; schema-1.11 policy and wire fields
remain in their versioned contract. `domain/policy.py` now owns the immutable
effective-policy value, while `policy/effective.py` owns canonical construction,
payload projection, and digesting; the finalizer no longer imports Guard's
private policy builder. Broader request, assurance, and evidence domain models
remain pending. The first `candidate/` slice now owns the
dependency-free edit grammar and pure patch transform behind exact legacy
aliases; candidate materialization remains pending while existing contained
workspace effects retain their established implementation.
`RepoVerifier` still owns effectful subprocess,
container, filesystem, runtime-identity, and trace operations.
`blackbox.py` still owns command construction, report interpretation,
verdict/evidence composition, and remaining pack/CID responsibilities.
The flat workspace module has been migrated atomically into the classified
`workspace/` package without splitting its security-sensitive globals.
Internal workspace decomposition and the `application` verification pipeline
remain pending.

The immediate structural priority is to continue Stage 3 only with
dependency-closed contracts, followed by small characterized slices for those
remaining RepoVerifier and black-box responsibilities. Each slice must retain
the existing contract, mutation, differential, and architectural-boundary
gates.
