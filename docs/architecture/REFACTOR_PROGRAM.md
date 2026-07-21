# Refactor program (execution file)

## Objective

Lock the baseline and refactor incrementally from monolith modules into stable typed
domains without changing runtime behavior, so we can execute higher-confidence
hardening later (Artifact-Bound Admission, stronger organization policy, etc.).

## Stage 0: Baseline hardening (completed)

- PR #102 merged the `v4.0.1` immutable reference lock and corrected `init --ref` behavior.
- The baseline artifact set under `tests/baseline/v4.0.1/` covers command/help, verdicts,
  reports, sarif, bundles, signature-vectors, pack-digests, manifest.
- `BASELINE_MANIFEST.json` records:
  - commit SHA
  - release tag
  - `.pyz` SHA-256
  - schema version
  - command inventory
  - action inputs/outputs
  - evidence format versions
  - test count
  - benchmark digest
- The release gate checklist covers:
  - branch ruleset
  - required checks
  - code-owner review
  - stale approval dismiss
  - environment review rules
  - immutable release and attestation evidence

PR #134 added the bounded `v4.0.2` release ledger. That newer ledger records
release identity and provenance only; it is deliberately not a copied or newly
captured behavioral baseline.

## Stage 1: Architecture documents (completed)

- Add docs in `docs/architecture/*` and `docs/adr/*` (8 architecture ADRs minimum).
- Add AST import boundary test.
- Add PR workflow standard for no-behavior-change refactors.

## Stage 2: Characterization and equivalence (completed)

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

The merged characterization and gate slices include PRs #109, #114, #115,
#122, and #132. The capture tools require explicit `--write` for reviewed
baseline replacement.

## Stage 3: Domain modeling (pending)

- Split core contracts (`GuardRequest`, `ExecutionPhaseResult`, `VerificationEvidence`,
  `GuardDecision`) into `domain/` models.
- Add mypy strict baseline for `domain/`.

There is no `evoom_guard/domain/` package or strict domain-only mypy baseline
yet.

## Stage 4+: Execution and verifier extraction (partially completed)

- Bounded process execution and cleanup were extracted in PR #112 and hardened
  by later lifecycle changes.
- Typed Docker control/image-identity and container-cleanup contracts were
  extracted in PR #117,
  retaining policy/evidence composition and compatibility facades in callers.
- Candidate-boundary preparation was extracted in PR #118 into
  `isolation/candidate.py` behind
  the characterized `candidate_runner.py` compatibility surface.
- The black-box invocation-receipt transport was extracted in PR #120 into
  `isolation/invocation.py`, retaining evidence composition in `blackbox.py`.
- The typed black-box judge-process lifecycle was extracted in PR #123 into
  `execution/judge.py`, retaining command construction, compatibility seams,
  report interpretation, evidence composition, and verdict policy in
  `blackbox.py`.
- Pure repository/pack interpretation and composition were extracted in PR
  #133 into the
  typed `verifiers/repo_phase_contracts.py` module behind frozen vectors; keep
  subprocess, container, filesystem, runtime-identity, and trace effects in
  `RepoVerifier` until their own characterization slices exist.
- Pending: extract `candidate/` and `workspace/` domains.
- Pending: split the remaining `blackbox.py` pack/CID/evidence
  responsibilities behind characterized compatibility boundaries.
- Pending: split the remaining effectful RepoVerifier responsibilities.
- Pending: build the `application` pipeline (`VerificationPipeline`, `VerdictComposer`,
  `AssuranceEvaluator`, `AttestationBuilder`) and shadow-mode differential.

## Later stages (9+): CLI/application split, evidence/finalizer domains, Action/release hardening, QA gates

- Split CLI parser/registry and command modules while preserving entrypoint compatibility.
- Extract evidence primitives and finalizer/admission domain packages.
- Expand action scripts, offline mode, release ledger and SBOM assets. Release
  ledgers exist; a general offline mode and SBOM asset are not complete.
- Add strict type/architecture/mutation gates and external red-team stage.
  Architecture and bounded mutation gates exist; strict domain typing and an
  external red-team result do not.
- Finalize artifact-bound admission after stable core + external evidence. The
  end-to-end protected build → attestation → admission chain is not complete.

## Completion criteria per stage

1. All new modules have unit + integration coverage.
2. Golden/differential and mutation gates for the stage are green.
3. No behavior regressions in existing verdict/reason/canonical outputs.
4. `R1`/behavior-preserving `R2` PRs carry `no-behavior-change`; `R3`/`R4`
   PRs instead document the changed invariant, threat model, compatibility,
   adversarial coverage, and rollback.
