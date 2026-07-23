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

## Stage 3: Domain modeling (in progress)

- Split core contracts (`GuardRequest`, `ExecutionPhaseResult`, `VerificationEvidence`,
  `GuardDecision`) into `domain/` models.
- Add mypy strict baseline for `domain/`.

The first bounded slice moves the existing `JUnitCounts` and repository/pack
phase evidence/result models into `domain/verification.py`. Legacy verifier
paths re-export the same class objects, and CI/release run a dedicated
`mypy --strict` gate for `domain/`. Broader request, verdict, assurance, and
evidence contracts remain pending.

The second bounded slice moves frozen verdict, execution-lifecycle, and reason
semantics into `domain/verdict.py`. The versioned
`verdict_contract_v1_11.py` retains schema version, policy keys, and required
wire-record fields while re-exporting the exact semantic objects.

The third bounded slice introduces immutable `domain.policy.EffectivePolicy`
and public canonical construction/projection/digesting in `policy.effective`.
Guard retains exact compatibility facades and the raw-Git finalizer stops
importing a Guard-private policy builder, lowering the private-import ratchet
from 56 to 55. Request, assurance, aggregate evidence, and decision models
remain pending; these slices do not claim Stage 3 is complete.

The fourth bounded slice adds the dependency-closed `GuardRequest` aggregate
with repository, candidate, source-identity, policy, verifier-pack, and
coverage inputs. The unchanged public `guard()` function performs its scalar
checks, captures one owned request, and derives execution values plus one
canonical policy payload from it for all result paths. Assurance, aggregate
evidence, and decision models remain pending, so
Stage 3 is still in progress.

The fifth bounded slice adds immutable `ExecutionPhaseResult` and
`IsolationObservation` domain values. `RepoVerifier` now records its setup,
repository-suite, and verifier-pack lifecycle through a typed local builder;
one adapter projects the snapshot to the unchanged artifact keys. Pack identity
and repository-phase facts remain separate sticky verification evidence.
Aggregate `VerificationEvidence`, assurance, and decision models remain pending,
so Stage 3 is still in progress.

The sixth bounded slice adds immutable `VerificationEvidence`,
`VerifierPackEvidence`, `RepositorySuiteEvidence`, and
`RuntimeIdentityEvidence` domain values. A repository-evidence adapter owns the
verifier artifact facts once, preserves the pre-1.11 partial-artifact lifecycle
fallbacks, and projects plain JSON onto the unchanged schema-1.11 attestation.
The repo-native decision, lifecycle, assurance, and `GuardResult` no longer read
the raw artifact mapping. Black-box composition remains outside this slice.
Exact isolation payloads and count-presence flags are an explicit compatibility
bridge for legacy partial artifacts, not the final transport-independent domain
shape; they remain until a future schema boundary can remove that compatibility.
Assurance and `GuardDecision` models remain pending, so Stage 3 is still in
progress.

The seventh bounded slice adds immutable `GuardDecision` and a pure
`application.repo_decision` composer for the repo-native core decision. It
freezes the existing twelve-branch priority, including partial-artifact
presence semantics, score boundaries, and exact reason text. Guard delegates
that initial decision without moving later diff-coverage, demonstrated-fix,
or assurance demotions. Black-box composition remains on its characterized
compatibility path. Assurance remains pending, so Stage 3 is still in progress.

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
- Host-command resolution now belongs to `execution/command.py`; Guard consumes
  public setup-fidelity and harness-policy contracts from their owning modules.
  Exact `repo_verifier` aliases preserve the compatibility surface while the
  private-import ratchet first dropped from 60 to 56; the public effective-policy
  owner subsequently lowered it to 55.
- Candidate parsing and pure patch transforms now live in `candidate/` behind
  exact legacy aliases. Candidate materialization and snapshots remain pending.
- The flat `workspace.py` surface is now the classified
  `workspace/__init__.py` package with identical implementation bytes,
  preserving descriptor/TOCTOU monkeypatch seams. Internal containment
  submodules remain pending.
- Pending: split the remaining `blackbox.py` pack/CID/evidence
  responsibilities behind characterized compatibility boundaries.
- Pending: split the remaining effectful RepoVerifier responsibilities.
- Pending: extend the first application decision composer into a complete
  pipeline (`VerificationPipeline`, `AssuranceEvaluator`, `AttestationBuilder`)
  with shadow-mode differential coverage.

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
