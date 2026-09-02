# Refactor program (execution file)

> **Audience and reading order:** this is the chronological maintainer record
> for the refactor. Statements such as "pending" or "in progress" describe the
> point in time at which each bounded slice was recorded; they are not the
> current project status. Read
> [`CURRENT_STATE.md`](CURRENT_STATE.md) for the concise present-tense
> architecture, then use the machine-maintained status near the end of this
> file as the authoritative refactor summary.

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
  Local runs default to one worker. CI requests four workers explicitly; every
  concurrent mutant receives its own package overlay, process-temp root, pytest
  base temp, and watchdog process group, while reports remain in inventory order.

For `R2` slices, compatibility covers published behavior and module/effect
seams explicitly characterized before extraction. Arbitrary runtime rebinding
of Python builtins or typing-only helpers is outside that contract and does not
justify exposing those implementation details as injected services.

The merged characterization and gate slices include PRs #109, #114, #115,
#122, and #132. The capture tools require explicit `--write` for reviewed
baseline replacement.

## Stage 3: Domain modeling (completed)

- Split core contracts (`GuardRequest`, `ExecutionPhaseResult`, `VerificationEvidence`,
  `GuardDecision`) into `domain/` models.
- Add mypy strict baseline for `domain/`.

The first bounded slice moved the existing `JUnitCounts` and repository/pack
phase evidence/result models into `domain/verification.py`. Legacy verifier
paths re-export the same class objects, and CI/release run a dedicated
`mypy --strict` gate for `domain/`.

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
compatibility path.

The eighth bounded slice adds immutable `AssuranceProfile` and
`VerifierPackAssurance` values plus the pure `application.assurance` owner for
delivered-assurance construction and floor evaluation. The historical Guard
private names remain exact aliases. A frozen vector captured from the
pre-extraction implementation compares every established payload key, note,
pack lifecycle state, and shortfall diagnostic:
`python tools/ci/capture_assurance_characterization.py`.

Stage 3 is complete at the domain-contract boundary: request, policy,
verification/evidence, execution, decision, and assurance values are now
dependency-closed and strict-typed. This does **not** mean the orchestration
refactor is complete. Repo-native post-decision sequencing has moved behind a
characterized Stage 8 application boundary, while black-box composition,
public result orchestration, and other effectful verifier/CLI responsibilities
remain in their established facades.

## Stage 4+: Execution and verifier extraction (partially completed)

- Bounded process execution and cleanup were extracted in PR #112 and hardened
  by later lifecycle changes.
- Typed Docker control/image-identity and container-cleanup contracts were
  extracted in PR #117,
  retaining policy/evidence composition and compatibility facades in callers.
- Isolation-mode and image-identity admission is now explicit and fail closed.
  Only `subprocess`, `docker`, and `gvisor` are accepted before any workspace or
  process effect. Docker inspection must yield a canonical immutable
  `sha256:` plus 64-lowercase-hex image ID; configured tags and malformed
  inspection output never reach a run argv. `RepoVerifier` resolves that pin
  afresh for every verification and keeps it context-local across setup,
  suite, and pack, so a reused or concurrent verifier cannot inherit another
  judgment's image identity. This validates the judge's selection and binding;
  it does not attest the runtime, daemon, host kernel, or executed image.
- Candidate-boundary preparation was extracted in PR #118 into
  `isolation/candidate.py` behind
  the characterized `candidate_runner.py` compatibility surface.
- The black-box invocation-receipt transport was extracted in PR #120 into
  `isolation/invocation.py`, retaining evidence composition in `blackbox.py`.
- The typed black-box judge-process lifecycle was extracted in PR #123 into
  `execution/judge.py`, retaining command construction, compatibility seams,
  report interpretation, evidence composition, and verdict policy in
  `blackbox.py`.
- Black-box verifier-pack execution and completed-process interpretation now
  live in `verifiers/blackbox_pack.py` behind immutable requests/services,
  explicit terminal-or-completed outcomes, and a mutable cleanup lifecycle.
  Pre/post snapshot identity, runner-before-command lookup timing, process
  failure mapping, raw-JUnit hashing, exit/report coherence, and zero-test
  rejection are frozen by a pre-extraction vector and focused mutations.
  `blackbox.py` retains command construction, `BlackboxResult`, outer cleanup
  precedence, and workspace lifetime.
- The R2-2 candidate-runtime slice now owns launcher/CID evidence retries and
  candidate-container cleanup coordination in the strict-typed, stdlib-only
  `verifiers/blackbox_candidate_runtime.py` module. The facade retains its exact
  private signatures, live concrete Docker adapters,
  `CandidateContainerCleanupError` identity, result projection, and outer
  primary-versus-cleanup exception policy. The frozen 12-case/23-test vector
  and focused mutations bind provider lookup timing, immediate monotonic CID
  mutation, one-time known-ID freezing, failure ordering, and exact
  `BaseException` propagation.
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
  exact legacy aliases. The contained FILE-then-PATCH transaction and
  judge-manifest restoration now live in `verifiers/repo_materialization.py`
  behind RepoVerifier's dynamic compatibility facade. At that slice,
  repository copying, deletion, and execution remained pending. Optional
  verifier-pack intake and its judge-owned snapshot identity now live in the
  immutable `verifiers/repo_pack_intake.py` contract. Verifier-pack host/docker/gVisor
  execution and later JUnit interpretation now live behind separate immutable
  contracts in `verifiers/repo_pack.py`; pre/post snapshot verification,
  candidate runtime continuity, sticky evidence, phase composition, final
  projection, and cleanup coordination remained in RepoVerifier at that slice.
- Repository-suite host/docker/gVisor execution and judge-owned JUnit
  interpretation now live in `verifiers/repo_suite.py` behind separate
  immutable contracts and frozen branch/order/provider-timing vectors.
  Runtime-tree continuity is delegated to the owner described below;
  `RepoVerifier` retains workspace cleanup, while sticky projection is
  delegated to the result owner described below.
- Repository-candidate parsing/admission, copy/materialization coordination,
  and post-pack safe deletion now live in
  `verifiers/repo_candidate.py`. Immutable XOR contracts and live effect
  providers preserve the order
  admission → RepoVerifier allocation → copy/materialization → RepoVerifier
  pack intake → deletion → execution. Allocation, pack handling, runtime
  identity, and final cleanup remain in `RepoVerifier`; result projection is
  delegated below.
- The mandatory-pack runtime-tree baseline, suite/pack drift checks, elapsed
  identity-scan accounting, continuity state, and immutable runtime evidence
  projection now live in `verifiers/repo_runtime_continuity.py`. Its providers
  are resolved at each historical operation, the no-pack path performs no
  identity lookup, its phase state cannot skip the suite checkpoint or recover
  from failure, and trusted host setup cannot be mislabeled as a read-only
  container boundary. Pack-snapshot continuity is delegated to the owner
  described below; phase composition and workspace cleanup remain in
  `RepoVerifier`, while sticky/final artifact projection is delegated below.
- The accepted verifier-pack identity plus pre-execution and post-completion
  snapshot checks now live in `verifiers/repo_pack_continuity.py`. Its defensively frozen
  identity and monotonic state prevent checkpoint skip/repeat/recovery, while
  both provider lookups retain their historical live timing. Controlled drift
  keeps the unchanged `pack_snapshot_changed` wire result. Unexpected provider
  failures are re-raised unchanged so the outer workspace-cleanup and primary
  exception contracts remain authoritative. Pack launch, JUnit reading,
  sticky/wire projection, verdict composition, and cleanup remain outside this
  owner.
- Repository sticky evidence and final artifact construction now live in
  `verifiers/repo_result.py`. Its typed judgment-local builder defensively
  owns an observed pack identity and completed repository phase; immutable
  inputs project completed pack evidence and the exact final artifact. A new
  pre-extraction vector freezes full results, key order, present-null sets, and
  invalid-present versus missing-pack presence. Focused mutations cover lost
  sticky identity, lost repository phase, manifest aliasing, explicit-presence
  overwrite, accidental no-pack JUnit-key emission, and facade binding of both
  sticky evidence classes. The owner has no effects; `RepoVerifier` retains
  observation timing, phase composition, workspace lifetime, and cleanup.
- Candidate path admission now lives in the immutable
  `verifiers/candidate_preflight.py` contract. Guard invokes it after parsing
  but before candidate materialization or process launch; a pre-extraction
  public vector freezes classification and execution/no-execution outcomes.
  Focused mutations cover unsafe paths, the reserved pack namespace,
  non-exemptible built-in harness paths, existing-test feature-mode bypass,
  local-Action helper discovery, and protected deletion filtering.
  Parsing, materialization, risk scoring, process execution, and verdict
  composition remain in their existing owners.
- The flat `workspace.py` surface is now the classified
  `workspace/__init__.py` package with identical implementation bytes,
  preserving descriptor/TOCTOU monkeypatch seams. The bounded
  `workspace/candidate_tree.py` owner now contains the complete hardened
  base/head intake transaction: root/reparse validation, captured object and
  metadata identity, copy-equivalent case-normalized Windows ignore matching,
  mandatory POSIX `O_NOFOLLOW`/`O_NONBLOCK`, Windows write/delete-share denial,
  bounded descriptor reads/comparisons, changed-path classification, and
  canonical serialization. Guard retains its original private value/exception
  ABI plus live injected helper facades. The guarantee is limited to each
  bounded read/compare interval; it does not close the classification/open gap
  or create an atomic whole-tree snapshot.
- The dependency-free `workspace/repository.py` owner now contains the
  historical copy-ignore tuple, filtered symlink-preserving repository copy,
  Windows symlink/reparse-root rejection, observed child
  junction/non-symlink-reparse rejection, and all-workspace cleanup
  sequencing. RepoVerifier temporary roots now carry allocation-time root and
  parent identity in a string-compatible ownership lease; a failed identity
  capture transaction uses non-recursive `rmdir` to roll back only a still-empty
  unclaimed allocator result without replacing the capture exception. A
  currently observed populated or identity-shifted path fails closed; the
  check-to-`rmdir` interval is not atomic. That capability
  gates confined Windows `READONLY` repair, rejects observed multiply linked
  files and symlink/junction/reparse components, and requires a fresh absence
  proof after successful removal. Plain compatibility strings do not receive
  that repair capability. Recursive `FileNotFoundError` is ignored only after
  the same fresh root-absence observation. Repository copying and Windows
  repair require a quiescent tree and make no atomic path-replacement claim;
  cleanup does not claim stable absence against later recreation.
  `repo_verifier` keeps live compatibility facades and retains higher-level
  repository orchestration.
- The dependency-free `workspace/repository_lifetime.py` owner now records one
  judgment's candidate root/copy and optional verifier-pack root. It registers
  the pack root before snapshotting can start, preserves the historical
  `intake-result or callback-created` reconciliation, and returns the exact
  candidate-then-pack cleanup target order. `RepoVerifier` still supplies live
  allocation/path providers and invokes its existing cleanup facade in
  `finally`, so no primary-exception or monkeypatch timing changes.
- Complete: split the bounded `blackbox.py` candidate/CID evidence and
  container-cleanup coordination behind the characterized R2-2 compatibility
  boundary. Pack execution and interpretation remain in their separate
  completed owner. `blackbox.py` deliberately retains top-level workspace,
  process, and public-result orchestration; no further behavior-preserving
  extraction is pending there.
- The dependency-free `verifiers/repo_cleanup.py` owner now coordinates the
  remaining repository cleanup effect/provider boundary. A parent-frozen
  vector binds provider lookup order, exact exception identity, note order,
  fresh absence proof, all-target attempts, and the outer facade-before-argument
  lookup rule. `RepoVerifier` retains both compatibility facades and its
  `finally`; `workspace.repository` retains the cleanup algorithm.
- Delivered-assurance evaluation is owned by `application.assurance`.
  Exact 57-key attestation assembly is now owned by the pure
  `application.attestation` builder behind Guard's unchanged private facade.
  A pre-extraction vector freezes payload order, null presence, clock count,
  and copy/reference semantics.
- Exact changed-line coverage demotion is owned by
  `application.decision_gates.apply_diff_coverage_gate`; Guard retains the
  effectful collector and invokes the pure gate in its historical order.
  A pre-extraction vector freezes the ratio, evidence access and exception
  behavior, and priority over later decision gates.
- Demonstrated-fix demotion is owned by
  `application.decision_gates.apply_demonstrated_fix_gate`; Guard retains
  baseline execution, repo-suite scope, repair-effect classification, and
  evidence annotation. The current post-coverage decision is passed through so
  an earlier failure remains authoritative.
- Delivered-assurance demotion is owned by
  `application.decision_gates.apply_assurance_gate`; Guard retains profile and
  attestation placement and supplies the shortfall evaluator. Its explicit
  eager/lazy mode freezes the different black-box and repo-native access and
  exception order instead of silently normalizing them.
- The immutable `application.pipeline.VerificationPipeline` cursor is Guard's
  single facade for repo-native decision composition and the three pure
  demotions. It remains effect-free.
- `application.repo_judgment.build_repo_judgment` now owns the bounded
  repo-native initial-judgment sequence after candidate preflight and shared
  problem construction: optional verifier execution, artifact/evidence
  projection, deletion-aware risk completion, risk scoring, and initial
  pipeline construction. The stdlib-only owner receives every runtime
  dependency through a live provider and preserves the characterized provider
  rebinding schedule, exception propagation, late verifier-field reads, and
  verifier/artifact/problem/touched-container identities. A 12-case
  pre-extraction public-Guard vector protects both executing and static paths.
  Unsupported-policy handling, preflight, black-box runtime, shared problem
  construction, repo finalization, and `GuardResult` remain in Guard.
- `application.repo_finalization.finalize_repo_verification` owns the
  repo-native post-decision effect sequence behind frozen public
  characterization. Guard injects live coverage, baseline, attestation,
  profile, shortfall, evidence-projection, and pack-presence services at their
  historical call positions. Baseline-after-coverage behavior, evidence object
  identity, trusted binding precedence, and fail-loud exception order are
  preserved.
- `verifiers.repo_baseline.run_repo_baseline` owns the pristine-copy
  setup/suite runtime, bounded host execution, judge-owned JUnit grading, and
  workspace cleanup behind Guard's unchanged private compatibility facade.
  Repair-effect policy remains in repo finalization. The facade retains the
  historical exception-binding schedule: the function-local
  `SetupFidelityError` import is bound once at entry, while `OSError`,
  containment, output-limit, and timeout matchers remain live until the
  corresponding `except` clause runs. Cross-commit characterization and one
  focused mutation per matcher protect that schedule.
- Deferred R3 follow-up, deliberately excluded from this extraction: snapshot
  caller-owned setup/test command lists and preserve an active primary
  `BaseException` across cleanup-provider lookup and cleanup execution. Both
  changes alter observable compatibility behavior and therefore require their
  own threat model, adversarial vectors, migration note, and rollback plan
  after the R2 owner boundary is merged.
- Markdown, JSON, and SARIF output projection/publication is owned by the
  stdlib-only `integrations.guard_output` adapter. Guard retains four exact
  compatibility facades. A pre-extraction vector freezes benign
  report/JSON/SARIF content and writer bytes. The owner now context-escapes
  candidate-derived Markdown (including entity introducers), validates dynamic
  numeric evidence, rejects ambiguous/control/surrogate SARIF locations, and
  routes Markdown, JSON, and SARIF through one fsynced same-directory atomic
  writer. The writer rejects observed non-regular/read-only leaves twice and
  preserves portable regular-file mode bits. Its trusted/quiescent-parent race
  bound, non-portable metadata exclusions, lack of parent-directory fsync, and
  lack of crash/NFS/multi-file durability are explicit. Focused mutations
  protect these boundaries plus URI encoding and non-PASS SARIF emission rather
  than incidental module-global lookup timing.
- `application.blackbox_finalization.finalize_blackbox_verification` owns the
  distinct post-cleanup black-box decision/evidence sequence behind public
  characterization. Guard still runs the judge and injects risk plus the
  conditional repo verifier; `blackbox.py` still owns workspace/process
  orchestration, outer cleanup precedence, compatibility identities, and the
  public runtime result while candidate evidence/container-cleanup sequencing
  delegates to its focused owner. Eager assurance-before-attestation order,
  composite counts, no-invocation refusal, and fail-loud cleanup boundaries
  remain unchanged.
- `application.diff_verification.verify_diff` owns the unified-diff
  application sequence behind the unchanged `guard_from_diff()` facade:
  fail-closed preflight, throwaway base reconstruction, changed-path
  projection, candidate serialization, and delegation to the existing Guard
  judgment. Guard supplies live filesystem, process, error/result,
  reason-code, revision-parser, verifier, and cleanup providers. Frozen
  characterization protects operation order, SHA short-circuiting,
  primary/cleanup exception behavior, caller-owned command identity, and the
  absence of an eager runtime `GuardResult` lookup. Baseline, coverage,
  verifier execution, black-box finalization, and CLI policy loading remain
  outside this owner.
- Boundary: extract a bounded verifier/runtime effect only where a
  characterized boundary reduces ownership without relocating whole
  orchestrators. Public `GuardResult` remains in Guard and
  `_run_baseline_suite` remains only as a live-wiring compatibility facade.
  After the candidate-runtime slice no additional behavior-preserving `R2`
  split is currently justified inside Guard/RepoVerifier/black-box runtime.
  Their remaining orchestrators and facades are intentional. Any shared
  `IsolationSession` or comparable trust-model redesign is `R3` work and
  requires a separate invariant, threat model, migration, and rollback plan.

## Later stages (9+): CLI/application split, evidence/finalizer domains, Action/release hardening, QA gates

- The flat CLI has been migrated byte-for-byte to the classified `cli/`
  package while preserving `evoom_guard.cli:main`, imports, and command
  behavior.
- Declarative parser construction is now owned by dependency-free
  `cli/parser.py` behind the unchanged public facade. A frozen snapshot binds
  all 45 subcommands, help pages, representative defaults, immutable-ref
  validation, and live injected helper lookups.
- The first command-family extraction moves only the public `guard` command's
  policy resolution, input routing, and output publication into the typed,
  runtime-internal-import-free `cli/guard_command.py` owner. The established
  `cli.cmd_guard` facade still supplies entry-snapshotted Guard functions and
  live config/read/path/report/signing providers. A pre-extraction vector
  freezes config/CLI precedence, patch/diff/base-head routing, fail-closed
  errors, publication order, and exit codes. Every other handler remains
  pending; no package-wide debt ceiling is lowered by this slice.
- Environment diagnostics, verifier-pack inspection/reporting, and version
  output now live in the stdlib-only `cli/diagnostic_commands.py` owner.
  `doctor_report`, `validate_pack`, and the three public command handlers remain
  live-wired compatibility facades. A pre-extraction vector freezes supported
  and unsupported doctor modes, text/JSON projection, valid/missing/invalid
  pack reports, manifest-error containment, digest metadata, and version output.
- Initialization now lives in the stdlib-only `cli/init_command.py` owner.
  Credential-name validation, exact public/private workflow generation,
  policy-path inference, and write sequencing are typed behind the unchanged
  helper and `cmd_init` facades. Every established operation is injected as a
  provider returning the live callable, and the owner captures that callable
  before evaluating its arguments. A pre-extraction vector freezes twenty-one
  public, private, short-circuit, open/write/dump/exit-failure, nested path
  lookup, property-side-effect, and mid-call rebinding cases. Parser ref
  validation and dispatch do not move in this slice.
- Signing-key generation now lives in the stdlib-only
  `cli/signing_commands.py` owner. `cmd_keygen` retains the lazy signing import
  and supplies an entry-snapshotted keypair generator. A frozen
  pre-extraction vector binds provider-before-argument timing, path re-reads,
  no-clobber reporting, and propagated exception identity.
- The Artifact Admission V1 seal/verify pair now lives in the strictly typed,
  stdlib-only `cli/artifact_admission_commands.py` owner. Its public facades
  retain entry-snapshotted domain imports and live-per-use external readers and
  reporting. A pre-extraction vector binds metadata/domain error boundaries,
  catch precedence, eager argument reads, projections, exit codes, exception
  identity, partial output, and detached offline verification.
- The Artifact Digest Admission V2 seal/verify pair now lives in its own
  strictly typed, stdlib-only `cli/artifact_digest_admission_commands.py`
  owner. Its reviewed 44-case vector freezes the additional immutable-digest
  and opaque-provenance arguments, eager stdin reads, subclass classification,
  full success projections, retained output, and a closed-world offline
  verification surface.
- GitHub attestation receipt creation, retained verification, and fresh
  provider re-verification now live in the strictly typed, stdlib-only
  `cli/github_attestation_receipt_commands.py` owner. Its reviewed 51-case
  vector freezes entry snapshots, live policy/isolation/reporting seams,
  argument and projection order, exception precedence, partial receipt/output
  residue, provider-isolation identity, fail-closed environment independence,
  and the retained verifier's closed-world offline surface. The shared policy
  and isolation helpers remain in the facade; the retained verifier service
  has no connected provider seam.
- GitHub attestation admission sealing and retained verification now live in
  the strictly typed, stdlib-only
  `cli/github_attestation_admission_commands.py` owner. Separate seal/verify
  service contracts preserve function-local entry snapshots and live
  reader/policy/reporting providers; only sealing receives the live provider
  isolation seam. The reviewed 70-case vector and at least sixteen focused
  mutations freeze seven-path eager guards, metadata/domain boundaries,
  exception precedence and identity, partial output, repeated projections,
  isolation timing, and the verifier's closed-world offline surface.
- Release-source handoff creation, protected finalizer sealing, detached
  verification, and raw-Git control derivation now live in the strictly typed,
  stdlib-only `cli/release_source_finalizer_commands.py` owner. Its reviewed
  82-case vector freezes entry snapshots, live reader/path/reporting seams,
  trusted-metadata/domain/signing classification, exact projections and
  `ALLOW`/`DENY` exits, exception identity, and the source-before-context
  partial-publication contract. The extraction adds no cleanup, transaction,
  checkout, network, or admission behavior.
- Producer-receipt creation, local/raw-Git verification, and fresh provider
  re-verification now live in the strictly typed, stdlib-only
  `cli/release_source_producer_receipt_commands.py` owner. Its reviewed 66-case
  vector freezes eager tuple reads, entry snapshots, live helper/reader/path/
  reporting seams, catch and projection order, provider-output residue, and
  archive-only opt-in exits. Both verification commands remain explicitly
  non-admitting; their services gain no signing, admission, isolation-builder,
  or executable-pin authority.
- Release Source Admission V2 sealing and detached verification now live in
  the strictly typed, stdlib-only
  `cli/release_source_admission_commands.py` owner. Independent seal/verify
  services preserve entry snapshots and live trusted-reader/helper/
  environment/reporting seams. Only sealing can access raw Git, protected
  workflow/runtime validation, fresh GitHub provider verification, provider
  evidence outputs, preflight, or a private signing key. The reviewed 56-case
  vector freezes eager inputs, key separation, no-clobber/alias preflight,
  provider ordering, exception identity, partial evidence, exact projections,
  and the verifier's closed-world offline surface.
- Release Artifact Admission online sealing and detached verification now live
  in the strictly typed, stdlib-only
  `cli/release_artifact_admission_commands.py` owner. Separate service
  contracts preserve function-entry domain/pin/isolation snapshots and
  live-per-use environment, preflight, nested-expectation, reader,
  key-separation, and reporting seams. The reviewed 45-case vector freezes
  eager reads, exception order and identity, exact projections/exits,
  partial-output residue, and the online-seal versus offline-verify boundary.
  Twelve focused mutations protect the highest-risk authority and timing seams.
   The detached verifier contract has no environment, Git/gh executable,
   repository, provider-isolation, private-key, signing-operation, or
   output-mutation capability.
- All 45 CLI handlers now delegate through typed owners; this behavior-preserving
  command-family extraction phase is complete.
- The first Stage-10 ownership-classification slice assigns four cohesive,
  stdlib-only flat modules without moving their established import paths:
  `contracts.py` and `strict_json.py` to foundation, `runtime_identity.py` to
  workspace, and `pack_manifest.py` to verifiers. An executable dependency-
  closure test keeps all four free of internal imports. The unclassified-module
  ratchet drops from 21 to 17 while private imports remain 10 and every other
  violation class remains zero. Mixed flat facades are still debt.
- The consolidated Stage-10 owner-contract slices replace the remaining ten
  cross-package private imports with four narrow public boundaries: Trusted
  Finalizer source validation, selected raw-Git regular-blob projection, one
  immutable five-operation release-source snapshot, and one immutable
  candidate-tree compatibility snapshot. Producer and CLI consumers retain
  their distinct module-import and command-entry lookup timing. Private imports
  fall from 10 to zero without moving a public module or changing a schema,
  verdict, canonical byte sequence, or authority boundary.
- Six additional cohesive stable modules are classified by their existing
  evidence, finalizer, or admission owner. Their complete dependency closures
  are executable contracts; mixed facades remain explicit debt. The
  unclassified-module ceiling falls from 17 to 11 while cycles, wildcard
  imports, unresolved dynamic imports, and layer violations remain zero.
- Three complete compatibility facades plus one pure flat owner are then
  classified by their already extracted or documented owners: `adapters.py` to
  runners, `patch_applier.py` to candidate, `candidate_runner.py` to isolation,
  and pure `patchmin.py` to candidate. Exact dependency-closure, purity, and
  selected facade/public-shape tests ratchet structural drift; semantic
  ownership remains a review obligation. The unclassified ceiling falls from
  11 to 7 with all other violation classes still zero; package runtime bytes do
  not change.
- The final Stage-10 classification slice assigns the seven remaining mixed
  facades to their reviewed existing layers and removes the last layer
  inversion. Import-boundary ratchet revision 19 records zero cycles,
  cross-package private imports, wildcard imports, unresolved dynamic imports,
  layer violations, and unclassified modules. The Stage-10 dependency and
  ownership-ratchet goal is complete; this does not complete the wider release,
  production-isolation, or independent-validation programs.
- The first Stage-11 pure-phase extraction moves trusted path and harness
  policy validation behind one characterized helper. `load_config` C901
  complexity falls from 49 to 42 while exact accepted payloads, error identity,
  message, cause, and validation order remain frozen. This is a measured
  maintainability change, not a new product or assurance claim.
- The second Stage-11 pure-phase extraction moves nested assurance and
  attestation missing/type/shape validation into an immutable verifier-owned
  projection. The public adapter keeps exact check IDs, messages, order, null
  handling, and schema-1.11/1.12 reports. Characterization and eleven focused
  mutants bind required fields, preflight null isolation, lowercase SHA-256,
  JUnit digest pairs, nested pack shape, non-negative invocations, and skip
  semantics. Measured `_nested_type_checks` complexity falls from 52 to 3;
  the largest extracted helper is 9 and total C901 findings fall from 97 to 96.
- The third Stage-11 pure-phase extraction moves ordered effective-policy
  type/shape projection into a verifier owner while leaving schema-contract
  selection, harness predicates, and independent operating-profile semantics
  in the public facade. Exact error order, input immutability, schema-1.11/1.12
  public-report digests, and 20,000 deterministic generated traces are frozen.
  Eight focused mutants bind required/extra keys, canonical harness paths and
  setup conflicts, timeout positivity, lowercase pack identity, required-pack
  coupling, and profile semantic re-verification. Measured
  `_policy_type_errors` complexity falls from 33 to 2; the largest extracted
  helper is 7 and total C901 findings fall from 95 to 94. The owner has no I/O,
  cleanup, process, hashing, report-mutation, or verdict authority.
- The fourth Stage-11 pure-phase extraction moves diff-coverage producer-shape
  validation into a stdlib-only verifier owner. The public facade preserves
  its historical list projection, check ordering and messages, threshold and
  policy semantics, and verdict authority. A pre-extraction case vector, four
  public-report digests, 20,000 deterministic generated traces, input
  immutability checks, and six focused mutants bind safe paths, positive
  sorted-unique line arrays, executed/missed disjointness, per-file arithmetic,
  exact percentage calculation, and the non-Python unmeasured-file boundary.
  Measured `_diff_coverage_type_errors` complexity falls from 26 to 1; no
  extracted helper exceeds 7 and the current C901 inventory falls from 94 to
  93. This changes neither schema nor canonical bytes and adds no efficacy or
  independent-validation claim.
- The fifth Stage-11 pure-phase extraction moves baseline producer-shape
  validation to a stdlib-only verifier owner. The public facade retains the
  historical mutable-list projection, `baseline.shape` check identity and
  order, requested-baseline and repair-effect policy semantics, and verdict
  authority. A committed pre-extraction vector freezes exact ordered errors,
  mapping lookup and exception precedence, four public-report digests, input
  immutability, and 20,000 deterministic traces; eight focused mutants bind
  keys, unsupported-mode null evidence, count/verdict truth, repair-effect,
  setup-fidelity, and changed-path rules. Measured `_baseline_type_errors`
  complexity falls from 24 to 1, the extracted-helper maximum is 7, and the
  repository C901 inventory falls from 93 to 92. This classified verifier
  owner adds no cycle, private import, layer violation, or unclassified debt;
  the mixed facade remains explicit debt and no independent-efficacy claim is
  added.
- The sixth Stage-11 pure-phase extraction moves top-level record-envelope type
  validation to a stdlib-only verifier owner. The public facade retains its
  historical mutable-list projection, `envelope.types` check identity and
  order, schema selection, subsequent shape/semantic phases, and verdict
  authority. A committed pre-extraction vector freezes 38 exact cases,
  mapping-access and exception precedence, four schema-1.11/1.12 public-report
  digests, input immutability, and 20,000 deterministic traces. Measured
  `_top_level_type_errors` complexity falls from 17 to 1, the extracted-helper
  maximum is 3, and the repository C901 inventory falls from 92 to 91. This
  classified verifier owner adds no cycle, private import, layer violation, or
  unclassified debt; the seven mixed facades remain explicit debt and neither
  schema nor verdict behavior changes.
- The bounded finalizer ownership slice moves only the raw-Git subprocess
  lifecycle from `finalizer_derivation.py::_run_git_command` into the
  effect-injected `finalizer/git_command.py` owner. The branch-free historical
  facade resolves its existing process, thread, clock, environment, limit,
  exception, and cleanup seams on every call. Existing characterization binds
  bare/worktree commands, closed pinned-executable environments, concurrent
  bounded pipe draining, deadlines, exact-`True` cleanup proof, POSIX
  post-completion cleanup, partial reader starts, primary exception identity,
  ordered bounded cleanup notes, error bytes/messages, and executable-pin
  stability. The owner imports no facade and no extracted helper exceeds the
  C901 threshold; removing the former complexity-37 hotspot lowers the current
  repository inventory from 90 to 89. This changes no raw object, verdict,
  schema, canonical byte, signature, admission, or publication behavior.

<!-- BEGIN EVOGUARD_PROJECT_STATUS:REFACTOR_PROGRAM_STATUS -->
Machine-readable status: behavior-preserving R2 is **complete**; CLI handler extraction
is **complete**; the overall refactor program is **in-progress**. Source version `4.8.1`
is a release candidate and is not yet a consumer release.
<!-- END EVOGUARD_PROJECT_STATUS:REFACTOR_PROGRAM_STATUS -->
- Extract evidence primitives and finalizer/admission domain packages.
- Expand action scripts, offline mode, release ledger and SBOM assets. The
  `v4.6.0` release ledger and SPDX SBOM asset exist; a general offline mode
  remains incomplete.
- Add strict type/architecture/mutation gates and external red-team stage.
  Architecture, bounded mutation, and strict `domain/` plus `application/`
  typing gates exist; strict typing of the entire package and an independent
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
