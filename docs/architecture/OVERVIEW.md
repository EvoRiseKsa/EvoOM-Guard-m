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
private policy builder. `domain/request.py` now captures an owned repository,
candidate, source, policy, pack, and coverage snapshot behind the unchanged
public `guard()` signature; operational values are derived from that request.
`domain/execution.py` now owns immutable execution and isolation snapshots,
while `verifiers/repo_execution.py` owns the mutable verifier-local builder
and exact projection to the existing artifact keys. Pack identity and
repository-phase evidence stay separate instead of being mislabeled as
lifecycle state. `domain/evidence.py` now owns the immutable repo-native
verification aggregate, and `verifiers/repo_evidence.py` is the sole adapter
from verifier artifact facts to that aggregate and back to the unchanged
attestation fields. The repo-native decision, lifecycle, assurance, and result
paths no longer inspect the raw artifact mapping. `domain/decision.py` now owns
the immutable core `GuardDecision`, and `application/repo_decision.py` owns the
pure repo-native twelve-branch composer. Guard delegates that initial decision
while retaining later demotions in their characterized order.
`application/decision_gates.py` now owns the first post-decision gate: exact
changed-line coverage evaluation. Guard still owns collection and invokes the
pure gate at the historical point before demonstrated-fix and assurance. The
same application module owns demonstrated-fix demotion from already prepared
baseline evidence; Guard retains baseline execution, repair-effect
classification, and repo-suite scope. It also owns final delivered-assurance
demotion. Guard supplies the already constructed profile and preserves the
historical black-box eager versus repo-native lazy evaluation modes, including
their different access and exception order.
`domain/assurance.py` now owns immutable
delivered-assurance and verifier-pack values, while
`application/assurance.py` owns pure profile construction and floor
evaluation. Guard keeps exact private compatibility aliases and the frozen
pre-extraction assurance vector proves unchanged schema-1.11 payloads and
diagnostics. This completes the dependency-closed Stage 3 contracts; it does
not complete Stage 8 orchestration. `application/attestation.py` now owns pure
assembly of the established 57-key attestation. Guard retains the historical
private signature and supplies live clock, version, candidate-digest,
policy-digest, and pack-digest-format providers, retaining its historical
candidate-hashing seam. A frozen pre-extraction vector protects key order,
null presence, clock count, and reference-versus-copy behavior; focused tests
freeze the complete provider and artifact-lookup sequence.
The first
`candidate/` slice now owns the
dependency-free edit grammar and pure patch transform behind exact legacy
aliases; candidate materialization remains pending while existing contained
workspace effects retain their established implementation.
`RepoVerifier` still owns effectful subprocess, container, filesystem, and
runtime-identity operations; it records lifecycle changes through the typed
builder rather than mutating an untyped trace dictionary.
`blackbox.py` still owns command construction, report interpretation,
verdict/evidence composition, and remaining pack/CID responsibilities.
The flat workspace module has been migrated atomically into the classified
`workspace/` package without splitting its security-sensitive globals.
Internal workspace decomposition and the complete `application` verification
pipeline remain pending.

The immediate structural priority is the next Stage 8 slice: introduce a
bounded `VerificationPipeline` facade over the extracted decision composers
without moving effect, profile, or attestation timing. Small RepoVerifier and
black-box responsibility slices can continue independently where their effect
boundaries are already characterized. Every slice must retain the existing
contract, mutation, differential, and
architectural-boundary gates.
