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

## Immediate next step

The black-box extraction track is active within the Stage 4+ implementation
section of `REFACTOR_PROGRAM.md`. The current slice moves the typed
judge-process lifecycle to `execution/judge.py` while preserving `blackbox.py`
as the compatibility, command-construction, report-interpretation, and
evidence-composition surface. The next black-box slices may separate pack,
CID, and evidence responsibilities only after the existing contract, mutation,
and differential gates remain unchanged.
