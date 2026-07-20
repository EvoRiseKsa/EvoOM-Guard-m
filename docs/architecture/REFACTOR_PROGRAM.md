# Refactor program (execution file)

## Objective

Lock the baseline and refactor incrementally from monolith modules into stable typed
domains without changing runtime behavior, so we can execute higher-confidence
hardening later (Artifact-Bound Admission, stronger organization policy, etc.).

## Stage 0: Baseline hardening (current)

- Merge / continue PR #102 (`v4.0.1` immutable reference lock and `init --ref` behavior).
- Create baseline artifact set under `tests/baseline/v4.0.1/` for command/help, verdicts,
  reports, sarif, bundles, signature-vectors, pack-digests, manifest.
- Add `BASELINE_MANIFEST.json` with:
  - commit SHA
  - release tag
  - `.pyz` SHA-256
  - schema version
  - command inventory
  - action inputs/outputs
  - evidence format versions
  - test count
  - benchmark digest
- Add release gate checklist:
  - branch ruleset
  - required checks
  - code-owner review
  - stale approval dismiss
  - environment review rules
  - immutable release and attestation evidence

## Stage 1: Architecture documents

- Add docs in `docs/architecture/*` and `docs/adr/*` (8 architecture ADRs minimum).
- Add AST import boundary test.
- Add PR workflow standard for no-behavior-change refactors.

## Stage 2: Characterization and equivalence

- Golden vectors for verdict/reason/lifecycle
- Differential harness between old/new harness
- Fuzz/property suites for malformed inputs and tamper vectors
- Mutation security gates for assurance-sensitive logic

## Stage 3: Domain modeling

- Split core contracts (`GuardRequest`, `ExecutionPhaseResult`, `VerificationEvidence`,
  `GuardDecision`) into `domain/` models.
- Add mypy strict baseline for `domain/`.

## Stage 4+: Execution and verifier extraction

- Extract bounded execution/process modules and process-tree cleanup.
- Extract `candidate/` and `workspace/` domains.
- Split `repo_verifier.py` into phase modules.
- Split `blackbox.py` into invocation/pack/CID/evidence modules.
- Build `application` pipeline (`VerificationPipeline`, `VerdictComposer`,
  `AssuranceEvaluator`, `AttestationBuilder`) and shadow-mode differential.

## Later stages (9+): CLI/application split, evidence/finalizer domains, Action/release hardening, QA gates

- Split CLI parser/registry and command modules while preserving entrypoint compatibility.
- Extract evidence primitives and finalizer/admission domain packages.
- Expand action scripts, offline mode, release ledger and SBOM assets.
- Add strict type/architecture/mutation gates and external red-team stage.
- Finalize artifact-bound admission after stable core + external evidence.

## Completion criteria per stage

1. All new modules have unit + integration coverage.
2. Golden/differential and mutation gates for the stage are green.
3. No behavior regressions in existing verdict/reason/canonical outputs.
4. PR labeled `no-behavior-change` unless migration scope is explicit and documented.

