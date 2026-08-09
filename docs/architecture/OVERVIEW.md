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

- `foundation` owns dependency-free cross-cutting protocols and strict decoding.
- `domain` owns request, lifecycle, verdict and assurance models.
- `execution` owns scheduling/observability primitives.
- `isolation` owns containment and transport of runtime evidence.
- `runners` owns runner recognition and judge-owned report instrumentation.
- `verifiers` owns executor orchestration and report interpretation.
- `application` owns pipeline and policy/assurance composition.
- `api` / `cli` / `integrations` own compatibility boundaries.

Four stable flat modules have cohesive semantic owners without changing their
published import paths: `contracts.py` and `strict_json.py` belong to the
foundation layer, `runtime_identity.py` belongs to workspace, and
`pack_manifest.py` belongs to verification. Each currently has zero internal
EvoOM Guard dependencies. This is an ownership classification, not a runtime
move or a claim that the remaining mixed flat facades are decomposed.

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
generic verdict/lifecycle/reason semantics; frozen schema-1.11 and additive
schema-1.12 policy/wire fields remain in their versioned contracts.
`domain/policy.py` now owns the immutable
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
changed-line coverage evaluation. The same application module owns
demonstrated-fix demotion from already prepared baseline evidence and final
delivered-assurance demotion.
`application/pipeline.py` now provides the immutable decision cursor used by
the repo composer and all three gates. It remains intentionally effect-free.
`application/repo_finalization.py` owns the characterized repo-native sequence
around that cursor: coverage and baseline effects, repair-effect annotation,
attestation placement, profile construction, and lazy assurance evaluation.
The facade injects live providers at each historical call point, so effect
implementations, identity, mutation, and exception order remain compatible.
The pristine baseline runner is now owned by `verifiers.repo_baseline`; Guard's
private facade supplies the same live host effects while finalization retains
repair-effect classification and decision demotion.
`application/blackbox_finalization.py` separately owns the characterized
post-cleanup black-box sequence: interpreting judge facts, conditionally
invoking the required repo-native phase, composing decision/count/lifecycle
evidence, eagerly applying the assurance floor, and only then building the
attestation. Guard retains `run_blackbox`, risk and repo-verifier effect
implementations, the public `GuardResult`, and the live baseline facade. Runtime
cleanup completes before this boundary is entered, and primary or cleanup
`BaseException` values from the judge cannot be masked by finalization.
The two finalizers intentionally preserve their different eager/lazy assurance
and attestation order instead of pretending the paths are equivalent.
`application/diff_verification.py` now owns the characterized unified-diff
sequence: fail-closed preflight, throwaway base reconstruction, changed-path
projection, candidate serialization, and delegation to the existing Guard
judgment. The facade retains the public signature and result type and supplies
all effects, reason codes, and revision parsers through live providers. This
preserves SHA short-circuiting, cleanup/exception order, and the historical
absence of an eager runtime result-class lookup; it does not move baseline,
coverage, verifier, black-box, or CLI policy ownership.
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
aliases. Candidate materialization now has a focused
`verifiers.repo_materialization` owner behind the dynamic RepoVerifier facade;
`verifiers.repo_candidate` now coordinates parsing/admission, repository copy
plus edit materialization, and post-pack safe deletion through immutable
contracts and live providers. Workspace lifetime bookkeeping belongs to
`workspace.repository_lifetime`; pack intake, execution, and final cleanup
remain outside the candidate owner.
Optional repository verifier-pack admission now has the focused
`verifiers.repo_pack_intake` owner. It checks the required digest pin and
reserved mount, creates and identifies the judge-owned snapshot through
injected live operations, and returns immutable intake evidence. Pack
execution is separate; post-snapshot verification remains in `RepoVerifier`,
whose final cleanup facade delegates effect/provider coordination to
`verifiers.repo_cleanup`.
Repository-suite execution and JUnit interpretation now have the focused
`verifiers.repo_suite` owner. Its two immutable boundaries leave the
runtime-tree continuity check between process completion and report reading in
`RepoVerifier`; its candidate-workspace cleanup facade delegates to
`verifiers.repo_cleanup`.
Pristine-base execution now has the separate `verifiers.repo_baseline` owner.
It preserves setup fidelity, bounded subprocess and strict process-group
requirements, the judge-owned report path, JUnit/exit grading, and final
workspace cleanup. It does not classify the candidate transition or apply the
demonstrated-fix gate.
Verifier-pack execution and JUnit interpretation now have the focused
`verifiers.repo_pack` owner. Its immutable execution boundary freezes
host/docker/gVisor process evidence; its separate interpretation boundary
cannot read the judge-owned report until `RepoVerifier` has re-verified both
the accepted pack snapshot and candidate runtime tree. Pack admission,
pre/post snapshot checks, runtime continuity, phase composition, and cleanup
remain outside this execution owner.
Repository sticky evidence and completed artifact projection now have the
focused, effect-free `verifiers.repo_result` owner. It freezes the observed
pack identity and completed repository phase, projects completed pack fields,
and owns exact key order, overwrite, and presence-versus-null behavior.
`RepoVerifier` still records those facts at the same execution points and
retains provider timing, phase-composer invocation, and the live cleanup
facade/`finally`; `verifiers.repo_cleanup` coordinates the injected cleanup
effects.
`workspace.repository_lifetime` records the candidate/pack roots and cleanup
target order without importing or executing cleanup.
`verifiers/candidate_preflight.py` now owns the immutable, pre-execution
classification of changed/deleted paths. It binds local Actions from the base
tree, preserves the reserved verifier-pack and non-exemptible harness rules,
and returns the exact safe-deletion set. Guard calls it at the characterized
post-parse/pre-materialization seam and retains risk, execution, decision, and
serialization responsibilities.
`RepoVerifier` still supplies the live workspace factories and owns
verifier-pack intake and snapshot continuity, runtime identity, phase
composition, and the final cleanup call site. Candidate/pack workspace path
registration delegates to `workspace.repository_lifetime`; cleanup
effect/provider coordination delegates to `verifiers.repo_cleanup`.
Sticky/final result projection is delegated to `repo_result`; candidate
filesystem coordination is delegated to
`repo_candidate`; repository-suite and verifier-pack subprocess/container
operations are coordinated by `repo_suite` and `repo_pack` through live
injected effects. Lifecycle changes still flow through the typed builder.
`verifiers/blackbox_pack.py` now owns the characterized verifier-pack process
sequence and completed-process report interpretation through immutable
boundaries plus an explicit mutable cleanup lifecycle. `blackbox.py` retains
pack intake, command construction, candidate preparation, `BlackboxResult`
projection, outer cleanup precedence, and workspace lifetime. The stdlib-only
`verifiers/blackbox_candidate_runtime.py` owner now coordinates live
launcher/CID evidence retries and candidate-container cleanup while the facade
retains concrete Docker adapters and compatibility identities.
The flat workspace module has been migrated atomically into the classified
`workspace/` package. Its first bounded submodule,
`workspace/candidate_tree.py`, now owns root validation, reparse-safe walking,
copy-equivalent ignore matching, per-file object/metadata identity, POSIX
non-blocking/no-follow opens, Windows write/delete-share denial, bounded intake
and comparison, changed-path classification, and canonical serialization.
Windows ignore matching is case-insensitive just like the copied execution
tree. Guard's thin compatibility facade retains the historical private type
ABI and resolves helper providers at call time. This protects each bounded
read/compare interval; it does not close the classification/open gap or claim
an atomic whole-tree snapshot.
The dependency-free `workspace/repository.py` owner now contains filtered,
symlink-preserving repository-copy semantics and cleanup exception precedence.
It rejects Windows junctions and other observed non-symlink reparse objects at
each directory visit, while explicitly requiring a quiescent source rather
than claiming an atomic snapshot. Recursive cleanup preserves the primary
exception and suppresses `FileNotFoundError` only after a fresh root-absence
observation, not as a stable-absence guarantee. `repo_verifier` retains
call-time facades, so Guard, black-box, evidence, and monkeypatch-based adopters
keep the same callable identities and dynamic effect seams.
The dependency-free `workspace/repository_lifetime.py` owner records one
repository judgment's candidate root/copy and optional verifier-pack root. It
registers the pack root before snapshotting can begin, retains the historical
`intake-result or callback-created` reconciliation, and returns the exact
candidate-then-pack cleanup target order. `RepoVerifier` still supplies the
live temporary-directory factories and invokes its existing cleanup facade in
`finally`, preserving provider timing and primary-exception precedence. The
facade delegates the bounded effect/provider sequence to the dependency-free
`verifiers.repo_cleanup` owner.
The flat CLI module has likewise been migrated byte-for-byte into the
classified `cli/` package. Declarative parser construction now lives in the
dependency-free `cli/parser.py` owner behind the public `cli.build_parser`
facade. The facade injects live validators and argument-group helpers on every
call; command handlers and dispatch remain in `cli/__init__.py`.
Markdown rendering and JSON/SARIF publication now belong to the stdlib-only
`integrations/guard_output.py` owner. `guard.py` retains all four historical
function signatures. A frozen wire vector binds benign report strings,
object/key order, indentation, trailing-newline behavior, platform text
translation, and non-PASS SARIF alert emission. Candidate-derived Markdown is
escaped for its rendering context; top-level test counts, risk score, and
dynamic numeric evidence are type/range checked; and SARIF artifact paths are
canonical repository-relative URIs that reject controls, surrogates, ASCII
drive prefixes, and backslashes. SARIF message controls render as visible
escapes without changing the producer-owned JSON record. Markdown/JSON/SARIF
destinations share one fsynced same-directory temporary-write plus
atomic-replace boundary. Existing symlinks, directories, special files, and
mode-bit read-only files are rejected before staging and immediately before
replacement; an existing regular file's portable `rwx` mode is preserved.
The text wrapper uses `closefd=False`, so the writer retains exclusive raw
descriptor ownership. After wrapper close is attempted, the writer releases
the wrapper reference, disarms the cleanup slot, and attempts raw close exactly
once before unlink cleanup. This avoids both closing a reused descriptor and
leaking a Windows temporary-file handle when wrapper close fails early.
The parent directory remains a trusted, quiescent boundary between those two
checks. Ownership, ACLs, xattrs, Windows security descriptors/alternate
streams, and other non-portable metadata are not preserved. No parent-directory
fsync is performed, so this does not promise power-loss/crash, NFS/distributed
filesystem, or multi-file transactional durability.
The bounded black-box candidate evidence/container-cleanup slice is complete.
Remaining workspace/process coordination intentionally stays in the existing
orchestrators under the current `R2` program. Black-box pack sequencing,
candidate path admission, candidate-tree intake, repository workspace
ownership, and both application decision/finalization paths are also complete.

This closes the last currently justified behavior-preserving `R2` ownership
gap in Guard/RepoVerifier/black-box runtime code. Their remaining
orchestrators and compatibility facades stay in place. A cross-cutting
`IsolationSession` abstraction or equivalent trust-model consolidation would
be a semantic `R3` change, not a continuation of this extraction program.

The immediate priority is to integrate and independently validate the completed
boundaries, not to manufacture another ownership split. Any future semantic
slice must retain the existing contract, mutation, differential, and
architectural-boundary gates and satisfy the separate `R3` requirements above.
