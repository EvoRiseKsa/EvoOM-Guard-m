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

- Frozen `RepoVerifier` behavioral/evidence vectors, reproduced by
  `python tools/ci/capture_repo_verifier_characterization.py` and reviewed before
  any explicit `--write` update.
- Differential seam between the compatibility facade and the frozen pre-refactor
  outcomes; wall-clock duration is the only normalized field.
- Split, reviewable `BlackboxResult` contract/preflight/judge/evidence-cleanup
  vectors, checked by `python tools/ci/capture_blackbox_characterization.py`.
  Replacement is explicit through `--write`; only temporary paths, the current
  interpreter path, invocation tokens, container IDs, and elapsed fields are
  normalized.
- Fuzz/property suites for malformed inputs and tamper vectors
- A bounded deterministic mutation gate for assurance-sensitive logic:
  `python tools/ci/run_security_mutation_gate.py`. Every reviewed mutant must be
  killed by an assertion; timeouts and test infrastructure errors fail closed.

## Stage 3: Domain modeling

- Split core contracts (`GuardRequest`, `ExecutionPhaseResult`, `VerificationEvidence`,
  `GuardDecision`) into `domain/` models.
- Add mypy strict baseline for `domain/`.

## Stage 4+: Execution and verifier extraction

- Extract bounded execution/process modules and process-tree cleanup.
- Extract typed Docker control/image-identity and container-cleanup contracts,
  retaining policy/evidence composition and compatibility facades in callers.
- Extract candidate-boundary preparation into `isolation/candidate.py` behind
  the characterized `candidate_runner.py` compatibility surface.
- Extract the black-box invocation-receipt transport into
  `isolation/invocation.py`, retaining evidence composition in `blackbox.py`.
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
4. `R1`/behavior-preserving `R2` PRs carry `no-behavior-change`; `R3`/`R4`
   PRs instead document the changed invariant, threat model, compatibility,
   adversarial coverage, and rollback.
