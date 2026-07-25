# Module boundaries

## Package boundaries (current target)

- `domain/`: policy, lifecycle, verdict, assurance, request/result types.
- `policy/`: policy parsing, normalization, validation, profile identity.
- `candidate/`: candidate parsing, patch/diff, directory/file snapshot helpers.
- `workspace/`: safe file operations and runtime identity.
- `execution/`: process launch, limits, capture, cleanup, environment handling.
- `isolation/`: subprocess/docker/gVisor/container execution contracts.
- `verifiers/`: concrete verification engines (repo and blackbox) and adapters.
- `application/`: orchestration pipeline and evidence decision composition.
- `evidence/`: canonical types, record producers, bundles, signatures.
- `finalizer/`: PR/release source finalization workflows and handoff.
- `admission/`: admission adapters and output contracts.
- `api/` and `cli/`: thin public/CLI compatibility surfaces.
- `integrations/`: high-level output and external-platform adapters. Guard
  output projection is owned by `integrations/guard_output.py`; public
  `guard.py` functions remain compatibility facades. The same owner provides
  the same-directory atomic writer used by the CLI Markdown report and the
  JSON/SARIF facades. It rejects observed non-regular and read-only leaves
  before staging and again immediately before replacement, while preserving
  portable mode bits on an existing regular file. The caller owns a trusted,
  quiescent parent directory; ACL/xattr/ownership metadata, parent-directory
  fsync, crash/NFS durability, and multi-file atomicity are outside this
  boundary. The `closefd=False` stream is only a text wrapper; the writer owns,
  disarms, and closes the raw descriptor exactly once before unlink cleanup.

## Rule

- Modules above must not import from downstream layers except via explicit interfaces.
- The public API contract lives only in `evoom_guard/cli/__init__.py`,
  `evoom_guard/guard.py`,
  `evoom_guard/record_verifier.py`, and `evoom_guard/trusted_finalizer.py`.

## Current extraction boundaries

The first domain slice lives in `evoom_guard/domain/verification.py`. It owns
only dependency-free JUnit counts plus completed-run and repository/pack phase
result contracts. `verifiers.junit_oracle` and
`verifiers.repo_phase_contracts` re-export the exact same class objects for
compatibility. Parsing, grading, composition, filesystem, process, container,
trace, and serialization behavior remain outside the domain package.

The second domain slice lives in `evoom_guard/domain/verdict.py`. It owns
frozen verdict names, execution lifecycle states, reason codes, and the
read-only reason compatibility table. Version-specific schema identity, policy
keys, and required record sections remain in
`verdict_contract_v1_11.py`; that module re-exports the same semantic objects.
Guard consumes generic semantics from the domain and only the schema version
from the versioned wire contract.

The third domain slice adds the immutable `EffectivePolicy` value in
`domain/policy.py`. Trusted normalization, canonical schema-1.11 payload
projection, and the frozen JSON digest live in `policy/effective.py`; domain
does not import policy. Guard's existing `_effective_policy` and
`effective_policy_sha256` names remain compatibility facades, while the raw-Git
finalizer uses the public policy API. Validation and schema evolution remain in
their existing owners so exception timing and published hashes do not change.

The fourth domain slice adds `RepositoryInput`, `CandidateInput`,
`SourceIdentity`, and `GuardRequest` in `domain/request.py`. Guard validates its
historical public scalar arguments first, then creates exactly one owned typed
request and derives its operational values plus one canonical policy payload
from that snapshot. The request
contract performs no I/O, validation, serialization, or verdict composition;
the existing 33-parameter `guard()` callable remains unchanged for adopters.

The first candidate slice lives in `evoom_guard/candidate/`. `edits.py` owns
the dependency-free FILE/PATCH block grammar and `PatchBlock`; `patch.py` owns
the pure unique-anchor search/replace transform and its exception hierarchy.
The package performs no path validation, filesystem writes, process launch,
or verdict interpretation. Historical imports through
`verifiers.candidate_edits`, `patch_applier`, and `repo_verifier` remain exact
aliases. Candidate tree copying and edit materialization remain effectful
repository-verifier responsibilities until their own characterized slice.

The first workspace slice is an atomic module-to-package migration:
`evoom_guard/workspace/__init__.py` contains the exact implementation bytes
formerly stored in `workspace.py`. This intentionally precedes internal
splitting because TOCTOU tests and adopters patch module globals such as
`os`, `tempfile`, and `_open_parent_dir_fd`. The package owns contained
workspace reads, writes, and deletions; later submodule extraction must retain
those dynamic seams or replace them with explicit injected contracts.

The second workspace slice lives in
`evoom_guard/workspace/candidate_tree.py`. It owns the complete base/head
filesystem intake transaction: root validation, non-following traversal,
copy-equivalent ignore matching (case-insensitive on Windows), Windows reparse
classification, object/metadata identity, Windows handles that deny
write/delete sharing, non-blocking no-follow POSIX opens, bounded
reads/comparisons, changed-path classification, and canonical FILE-block
serialization. Guard retains its historical names as thin compatibility
types/facades and injects every established helper at call time, so private
type metadata and monkeypatch seams remain stable. The transaction proves only
the bounded per-file read/compare interval; it does not close the
classification/open gap or claim an atomic whole-tree snapshot. Revision
identity still requires a quiescent checkout or raw-Git finalization.
Candidate admission, repository mutation, execution, evidence, and verdict
composition remain outside this owner.

The third workspace slice lives in
`evoom_guard/workspace/repository.py`. It owns the historical `COPY_IGNORE`
tuple, filtered `copytree(..., symlinks=True)` operation, Windows
junction/non-symlink-reparse rejection at each observed directory visit, and
multi-workspace cleanup sequencing with explicit primary-exception precedence.
Repository copying still requires a quiescent source and does not claim an
atomic scan-to-open snapshot. Cleanup accepts a recursive
`FileNotFoundError` only after a fresh root-absence observation; that
observation is not a stable-absence claim against later recreation. The
`repo_verifier` compatibility facades inject their current `COPY_IGNORE`,
`shutil.copytree`, `shutil.ignore_patterns`, `shutil.rmtree`, and cleanup-note
provider on every invocation. This preserves the established module-level
monkeypatch timing used by repository verification and by the exact facade
objects already imported into Guard, black-box, and coverage evidence.
Workspace allocation, pack intake, execution, runtime identity, evidence, and
verdict composition remain in their existing owners. Candidate
admission/materialization/deletion coordination belongs to
`verifiers/repo_candidate.py`.

The fourth workspace slice lives in
`evoom_guard/workspace/repository_lifetime.py`. Its mutable judgment-local
value records the candidate root/copy and optional verifier-pack root, registers
the pack root before snapshotting starts, preserves the historical
`intake-result or callback-created` reconciliation, and returns the exact
candidate-then-pack cleanup target order. Temporary-directory and path-join
effects remain injected. `RepoVerifier` still resolves those live providers and
invokes its existing cleanup facade from `finally`, so primary-exception
precedence and compatibility monkeypatch timing do not move into this owner.
Pack admission, execution, evidence, verdict composition, and cleanup effects
remain outside the lifetime value.

Repository-judgment cleanup effect coordination lives in
`evoom_guard/verifiers/repo_cleanup.py`. Its immutable request carries the
candidate-then-pack target schedule and exact active primary exception. Its
services resolve the generic workspace cleanup algorithm, recursive remover,
and diagnostic-note callable in the historical order before invoking cleanup.
`repo_verifier` retains the two legacy facades and the outer `finally`;
`workspace.repository` retains all-path removal sequencing, fresh root-absence
proof, note wording, and first-failure/primary-exception precedence. The owner
does not import either module and does not allocate paths, execute a phase,
compose evidence, or project a verdict.

The first CLI slice is the same kind of atomic compatibility migration:
`evoom_guard/cli/__init__.py` contains the exact implementation bytes formerly
stored in `cli.py`. The import path, `evoom_guard.cli:main` console entry point,
parser behavior, command callables, and monkeypatch surface are unchanged.
This classifies the public integration boundary and creates a real package for
later parser/registry and command-family extraction; it does not by itself
claim that the 6,082-line implementation has been decomposed.

The second CLI slice gives declarative parser construction a dependency-free
owner in `evoom_guard/cli/parser.py`. The public `cli.build_parser` facade
injects the current immutable-release validator and four argument-group helpers
for each invocation, so no callable is snapshotted across monkeypatches. A
re-runnable frozen characterization binds parser structure, 41 subcommands,
all help output, representative defaults, and immutable-ref rejection.
Handlers, dispatch, file/process effects, and command-family ownership remain
in `cli/__init__.py`.

Environment/pack diagnostics and version output are owned by the stdlib-only,
dependency-injected `evoom_guard/cli/diagnostic_commands.py`. The public
`doctor_report`, `validate_pack`, `cmd_doctor`, `cmd_pack_doctor`, and
`cmd_version` facades retain live provider lookup and the existing import path.

Initialization and workflow generation are owned by the stdlib-only,
dependency-injected `evoom_guard/cli/init_command.py`. It owns the exact public
and private workflow templates, credential-name validation, policy-path
inference, and the established non-transactional write sequence. The public
`_github_actions_credential_key`, `_workflow_yaml`,
`_workflow_yaml_private`, `_default_policy_path`, and `cmd_init` facades remain
at their historical import path. They inject providers that return the live
callable for every path, filesystem, template, and JSON operation. The owner
captures each callable before evaluating its arguments, preserving both
providers rebound by an earlier operation and the historical
callable-before-argument evaluation order. A frozen pre-extraction vector binds
workflow and policy bytes, short-circuits, output order, propagated open,
write, dump, and context-exit failures, nested path lookup order, property-read
side effects, and all those lookup points. Parser ref validation and command
dispatch remain outside this owner.

Signing-key generation is owned by the stdlib-only, dependency-injected
`evoom_guard/cli/signing_commands.py`. The public `cmd_keygen` facade keeps the
lazy signing import at its historical path and snapshots `generate_keypair`
before reading `args.key` or `args.pub`. The owner retains the exact
`FileExistsError` exit-2 mapping, re-reads both paths for the success message,
and propagates argument, non-`FileExistsError` provider, and output failures
without wrapping them.

The first execution-kernel slice lives in `evoom_guard/execution/process.py`.
It owns the typed bounded-process request/result contracts, shared output cap,
timeout handling, and native process-tree cleanup. Verifiers may retain
compatibility aliases, but execution consumers must import these primitives
from `evoom_guard.execution`, not from `repo_verifier.py`.

The second execution-kernel slice lives in `evoom_guard/isolation/docker.py`.
It owns typed, bounded Docker control requests/results, image inspection and
pull facts, named-container start/absence/cleanup proofs, and validated CID
discovery/cleanup for black-box candidate containers. Existing modules retain
private compatibility facades so embedded callers and tests continue to patch
the same seams.

The two cleanup contracts are intentionally separate. Repo verification knows
the exact collision-resistant container name before launch; black-box candidate
cleanup learns one or more daemon-written 64-hex IDs from judge-owned cidfiles.
Conflating them would weaken what each absence proof means.

Repo-verifier Docker argv/mount construction, isolation selection, evidence
composition, and verdict/schema/CLI behavior remain in their existing callers.
The candidate-specific launch plan moves with candidate-boundary preparation.

The third isolation slice lives in `evoom_guard/isolation/candidate.py`. It owns
candidate-boundary preparation, launcher materialization, Docker/gVisor launch
plans, and preparation evidence. `evoom_guard/candidate_runner.py` remains the
compatibility surface: its public evidence/error identities are exact aliases,
and its `CandidateRunner` subclass delegates to the typed implementation while
preserving the historical bounded-Docker monkeypatch seam. Actual launcher/CID
observation sequencing is injected into
`verifiers/blackbox_candidate_runtime.py`; the compatibility facade and verdict
interpretation remain in `blackbox.py`.

The fourth isolation slice lives in `evoom_guard/isolation/invocation.py`. It
owns the judge-side one-way AF_UNIX datagram receiver, exact-token filtering,
cumulative receipt count, bounded receive-lock batches, and socket lifecycle.
`blackbox._InvocationRecorder` is an exact compatibility alias. The black-box
verifier still owns the policy that a host boundary needs a receipt and a
container boundary needs both a receipt and a validated runtime-written CID;
the transport cannot promote a prepared launcher into observed execution on
its own.

The fifth execution-kernel slice lives in `evoom_guard/execution/judge.py`. It
owns the typed judge-process request, limits, and result contracts together
with bounded stdout/stderr capture, timeout handling, reader lifecycle, and
process-group cleanup. It does not assemble the judge command, interpret its
report, or compose evidence or verdicts.

Black-box verifier-pack execution and interpretation live in
`evoom_guard/verifiers/blackbox_pack.py`. Its immutable request, service, and
outcome contracts plus one explicit mutable lifecycle object preserve the
established pre-snapshot check, runner-before-command provider lookup, process
error mapping, post-snapshot check, raw-JUnit digest, exit/report coherence,
and zero-test rejection. The module imports only the public execution and pack
contracts. It does not own candidate preparation, invocation/CID observation,
container cleanup, workspace lifetime, `BlackboxResult`, or evidence
attachment. Candidate runtime evidence and cleanup coordination instead live in
the separate stdlib-only `verifiers/blackbox_candidate_runtime.py` owner.
`blackbox.py` supplies live compatibility providers, retains concrete Docker
adapters and public/private identities, and performs the final projection
without changing the public ABI.

The candidate-runtime owner preserves two intentionally different lookup
schedules. Evidence resolves the scanner and sleeper live on every retry after
the current receipt drain, mutates the caller-owned observed-CID set
immediately, and only then sorts it. Cleanup captures its kernel before
freezing known IDs once, then resolves control, sleep, and path providers after
request construction. Only the historical
`blackbox.CandidateContainerCleanupError` is converted into scan-failure facts;
all other exceptions and every `BaseException` retain exact identity. The
facade retains that error class, both private function signatures, outer
cleanup-result precedence, and workspace lifetime.

Host-command ownership lives in `evoom_guard/execution/command.py`. It resolves
Windows `PATHEXT` shims without a shell and refuses candidate-controlled
relative `PATH` entries for bare judge commands. Setup-fidelity snapshot/change
contracts are public in `evoom_guard/verifiers/fidelity.py`, and harness glob
matching is public in `evoom_guard/verifiers/harness_policy.py`.
`repo_verifier.py` retains exact legacy aliases, but higher-level orchestration
must import these public owners directly.

Candidate path admission lives in
`evoom_guard/verifiers/candidate_preflight.py`. Its immutable request/result
contract classifies changed and deleted paths, binds base-tree local-Action
directories, enforces the reserved verifier-pack namespace and judge-owned
harness policy, and derives the exact safe-deletion set before execution.
Guard remains the compatibility adapter: it parses the candidate first, calls
preflight at the historical no-materialization/no-process seam, then projects
the tuples back to the established mutable-list result/problem surfaces.
Candidate parsing, repository materialization, risk scoring, verifier
execution, decision composition, and attestation remain outside this module.
A frozen public Guard vector plus focused security mutations protect the
pre-execution boundary and the new-test, allowlist, local-Action, unsafe-path,
and protected-deletion invariants.

The first repository-verifier phase slice lives in
`evoom_guard/verifiers/repo_phase_contracts.py`. It owns only pure interpretation
of completed repository-suite and mandatory verifier-pack evidence, including
their composite JUnit identity. It must not perform filesystem, subprocess,
container, or lifecycle mutation. `RepoVerifier` still owns those effects and passes
their completed evidence into the typed phase contracts.

The second repository-verifier phase slice adds immutable
`domain.execution.ExecutionPhaseResult` and `IsolationObservation` values.
`verifiers/repo_execution.py` owns the mutable verifier-local trace builder and
the compatibility projection to the existing artifact keys. `RepoVerifier`
mutates typed fields and freezes one snapshot on every return path. Verifier-pack
identity, repository-phase results, runtime-tree facts, outcomes, and JUnit
composition are deliberately not execution lifecycle and remain in their
existing owners. The optional top-level `isolation_evidence` key is emitted only
after its boundary is observed, preserving the published absence-versus-null
semantics.

The repository materialization slice lives in
`evoom_guard/verifiers/repo_materialization.py`. It owns the ordered,
fail-closed FILE/PATCH write transaction and restoration of judge-owned
`package.json` fields. The owner receives contained reads/writes, the patch
transform, and manifest restoration as explicit callables. The historical
`repo_verifier.apply_blocks_to_copy` facade resolves and injects its current
module globals on every call, preserving adopter monkeypatch seams. Repository
copying, deletion, process/container execution, pack identity, and verdict
composition do not cross this boundary.

Repository candidate coordination lives in
`evoom_guard/verifiers/repo_candidate.py`. Its immutable XOR outcomes separate
terminal policy/materialization/deletion verdicts from admitted candidates.
Admission completes before `RepoVerifier` asks the workspace-lifetime owner to
allocate and record the candidate workspace, then calls the candidate owner to
copy and materialize it. The verifier performs pack intake next and only then
calls the candidate owner to apply admitted deletions. All filesystem and
policy operations are live providers, preserving the historical facade lookup
and exception order. Workspace lifetime, verifier-pack intake, runtime
identity, process/container execution, sticky evidence, final projection, and
`finally` cleanup do not cross this boundary. A structured `file_blocks`
mapping is authoritative by presence, including an empty mapping; textual
marker parsing is used only when the structured transport is absent.

Repository verifier-pack admission lives in
`evoom_guard/verifiers/repo_pack_intake.py`. Its immutable request/result and
service contracts own no-pack/required-pin consistency, the reserved mount
collision, snapshot validation, digest matching, and the exact rejection
evidence. `RepoVerifier` supplies call-through `lexists`, workspace-allocation,
and `snapshot_pack` operations so an earlier operation can still replace a
later historical seam. The workspace-lifetime owner records the returned root
before snapshotting and reconciles the immutable intake result afterward, so
the existing `finally` cleanup covers unexpected exceptions. Pack execution
and the accepted-snapshot continuity state stay outside this boundary.

Verifier-pack execution and interpretation live in
`evoom_guard/verifiers/repo_pack.py`. Immutable execution and interpretation
requests are deliberately separate so the pack/runtime continuity owners can
verify their respective snapshots after the process completes but before
judge-owned JUnit is read. Host, Docker, and gVisor operations, phase evidence,
report readers, and the pure pack evaluator are injected as live providers at
their historical call sites. Pack admission/identity, continuity state,
sticky repository-suite evidence, phase composition, final artifact
projection, and workspace cleanup stay outside this execution owner.

Accepted verifier-pack continuity lives in
`evoom_guard/verifiers/repo_pack_continuity.py`. One immutable identity value
defensively snapshots the admitted digest and manifest. The judgment-local
state machine requires `accepted -> pre_execution_verified -> delivered`,
keeps snapshot drift sticky, and forbids skip, repeat, or recovery. The second
checkpoint applies after a completed pack execution and before JUnit reading.
The snapshot verifier remains a live provider at both historical call sites.
Unexpected provider failures enter terminal state and are re-raised unchanged,
so `RepoVerifier`'s outer `finally` retains workspace-cleanup and
primary-exception precedence. The owner neither launches a process nor reads
JUnit, projects artifacts, composes verdicts, or cleans a workspace.

Repository-suite execution and interpretation live in
`evoom_guard/verifiers/repo_suite.py`. Immutable execution and interpretation
requests are deliberately separate so `RepoVerifier` can verify runtime-tree
continuity after the suite process completes but before judge-owned JUnit is
read. Host, Docker, and gVisor operations, phase evidence, report readers, and
the pure phase evaluator are injected as live providers at their historical
call sites. Terminal execution failures return before any verifier pack can
start. Runtime-identity policy, phase-composer invocation, and workspace
cleanup stay in `RepoVerifier`; result projection stays outside this execution
owner.

Repository result and sticky-evidence projection live in
`evoom_guard/verifiers/repo_result.py`. Frozen values own the observed pack
identity, completed repository-suite phase facts, completed verifier-pack
fields, and the immutable input to final artifact construction. The
judgment-local builder attaches those sticky facts to every later terminal
return, then appends the already-observed execution snapshot while preserving
the historical overwrite and insertion order. Final construction preserves
the published distinction between always-present nullable pack fields and
pack-JUnit keys that exist only when a pack was configured. A new
pre-extraction vector freezes full result values, key order, and present-null
sets across no-pack, completed-pack, pack-launch-failure, invalid-present-pack,
and missing-pack paths. This owner performs no provider lookup, trace
mutation, process/container execution, filesystem access, clock read, or
cleanup. `RepoVerifier` retains phase/effect ordering, live provider supply,
phase-composer invocation, and the primary-exception cleanup call site;
workspace path lifetime bookkeeping belongs to
`workspace.repository_lifetime`, and cleanup effect coordination belongs to
`verifiers.repo_cleanup`.

The third repository-verifier phase slice adds immutable
`domain.evidence.VerificationEvidence`, `VerifierPackEvidence`,
`RepositorySuiteEvidence`, and `RuntimeIdentityEvidence` values.
`verifiers/repo_evidence.py` owns the only conversion from a repo-native
verifier artifact into that aggregate and the projection back to the unchanged
schema-1.11 attestation fields. Guard's repo-native decision, lifecycle,
assurance, and result construction consume typed evidence instead of repeatedly
reading the raw mapping. Exact isolation payloads and count-presence bits are a
temporary compatibility bridge for valid legacy partial artifacts; they are
not the final transport-independent domain shape. Black-box composition,
assurance evaluation, and decision composition remain outside this slice.

The first application slice adds immutable `domain.decision.GuardDecision` and
the pure `application.repo_decision` composer. It owns the existing repo-native
core decision priority and shared outcome tables without importing Guard,
verifiers, execution, isolation, filesystem, or process facilities. Guard
delegates only the initial verdict/reason composition. Diff-coverage,
demonstrated-fix, assurance demotions, black-box decisions, evidence
serialization, and effects remain in their existing owners until separately
characterized slices.

The second application slice adds immutable
`domain.assurance.AssuranceProfile` and `VerifierPackAssurance` values.
`application.assurance` is the pure owner of delivered profile construction,
verifier-pack assurance interpretation, and minimum-assurance comparison. It
imports only the domain package and the standard library. Guard retains exact
aliases for `_assurance_profile`, `_preflight_assurance_profile`,
`_static_assurance_profile`, `_pack_assurance`, and `_assurance_shortfall`.
The established dictionary wire shape is projected only at this compatibility
boundary; black-box versus repo-native key presence is frozen by a
pre-extraction characterization vector. Attestation assembly, later decision
demotions, and all runtime effects remain outside this slice.

The third application slice adds `application.attestation.build_attestation`.
It owns pure assembly of the complete established 57-key attestation and no
runtime effects. Guard's `_build_attestation` keeps its exact signature and
supplies live providers for UTC time, tool version, candidate digest, policy
digest, and verifier-pack digest format. The application layer neither imports
Guard nor chooses those values itself. Deleted paths and explicit commands
remain copied; effective policy and nested artifact evidence remain
reference-compatible. A pre-extraction vector freezes key order, present-null
fields, clock call count, and copy/reference behavior. Focused contract tests
freeze provider and artifact-lookup ordering, including both verifier-pack SHA
reads. Schema changes, evidence interpretation, validation, signing, and
finalizer logic remain outside this builder.

The fourth application slice adds
`application.decision_gates.apply_diff_coverage_gate`. It owns only the pure
demotion of an already completed `PASS` when required changed-line coverage is
unmeasured or below its exact floor. Coverage collection, candidate execution,
and policy validation remain in their existing owners. The gate preserves the
exact integer-ratio comparison, does not use the rounded display percentage for
judgment, leaves a non-positive `total` unchanged, and does not read coverage
evidence for an optional floor or an earlier non-`PASS`. A pre-extraction
characterization vector freezes decision text, access and exception order, and
priority over the later demonstrated-fix and assurance gates.

The fifth application slice adds
`application.decision_gates.apply_demonstrated_fix_gate`. It owns only the
demotion of the current decision when policy requires a demonstrated
counterfactual repair and prepared baseline evidence does not report
`repair_effect == "demonstrated"`. Baseline execution is now owned by
`verifiers.repo_baseline`; repo-suite scope, repair-effect classification, and
evidence annotation are coordinated by `application.repo_finalization`. The
gate receives the current post-coverage decision so an earlier failure cannot
be overwritten. Characterization freezes mapping access and exception order,
the two established reason variants, and precedence before assurance.

The sixth application slice adds
`application.decision_gates.apply_assurance_gate`. It owns only the final
demotion of a completed `PASS` when the delivered assurance profile is below
the caller's floor. Profile construction and the shortfall evaluator remain
separate application services; Guard still decides when effects and
attestation assembly occur. The explicit `eager_shortfall` compatibility mode
preserves an established orchestration difference: black-box runs evaluate the
shortfall before their attestation even for a prior non-`PASS`, while
repo-native runs evaluate it only after attestation and only for a requested,
completed, currently passing execution. This difference is observable through
mapping access and exception order, so a future unification requires a
versioned contract rather than an incidental refactor.

The seventh application slice adds the immutable
`application.pipeline.VerificationPipeline` cursor. It is the single Guard
facade for the repo-native composer and the three extracted decision gates, but
it deliberately does not offer a monolithic `run()` method. The underlying
composer and gates remain public, independently testable application services.

The eighth application slice adds
`application.repo_finalization.finalize_repo_verification`. It owns the
repo-native post-decision sequence: optional coverage collection and gate,
optional pristine-baseline execution and repair-effect classification,
execution/pack evidence projection, attestation placement, assurance-profile
construction, and the final lazy assurance gate. Every effect and compatibility
helper is supplied through a late provider, preserving the characterized
lookup, identity, mutation, and fail-loud exception order. The Guard facade
still owns the coverage effect, public `GuardResult`, black-box runtime branch,
and wire casts; pristine-baseline execution has the focused owner described
below. This boundary deliberately does not unify the black-box eager-assurance
path or move candidate verifier execution.

The next bounded verifier slice adds
`verifiers.repo_baseline.run_repo_baseline`. It owns only pristine-copy setup
and repository-suite execution, setup-fidelity rejection, bounded
subprocess/JUnit interpretation, and its temporary workspace lifetime. The
private Guard facade retains its historical signature and resolves host
effects live at their original operation sites. Repair-effect annotation,
scope, and decision demotion remain in `application.repo_finalization`; this
slice does not move diff coverage, candidate execution, or CLI behavior.

The ninth application slice adds
`application.blackbox_finalization.finalize_blackbox_verification`. It starts
only after the external judge and candidate/container cleanup return
successfully. It owns the established post-cleanup sequence: conservative
launcher/isolation interpretation, risk-provider placement, conditional
repo-native composition, decision and aggregate-count projection, pack and
phase evidence, the eager assurance gate, unsupported baseline/coverage
markers, and attestation placement. Guard injects live risk, repo-verifier,
profile, shortfall, and attestation services and still constructs the public
`GuardResult`. `blackbox.py` remains the runtime facade for workspaces, process
cleanup, outer container-cleanup precedence, invocation receipts, and
`BlackboxResult`; bounded candidate evidence/cleanup sequencing delegates to
its injected owner. Primary or cleanup `BaseException` values therefore exit
before finalization begins.

The tenth application slice adds
`application.diff_verification.verify_diff`. It owns the established
unified-diff preflight, throwaway base reconstruction, changed-path
projection, candidate serialization, and delegation to the existing Guard
judgment. Guard injects every filesystem, process, error/result, reason-code,
revision-parser, and cleanup operation through a provider resolved at its
historical use site. The public `guard_from_diff()` signature and `GuardResult`
remain in the facade; baseline, coverage, verifier execution, black-box
finalization, and CLI policy loading remain in their existing owners. The
boundary deliberately preserves SHA short-circuiting, primary-versus-cleanup
exception behavior, and the absence of any eager runtime result-class lookup.

The eleventh application slice adds
`application.repo_judgment.build_repo_judgment`. Its boundary starts only
after candidate preflight and the shared repository problem mapping exist, and
ends before `application.repo_finalization`. It coordinates the optional
`RepoVerifier` call, raw-artifact fallback and evidence projection,
deletion-aware risk-map completion, risk scoring, and initial
`VerificationPipeline` construction. Runtime owners are supplied through live
providers at their characterized lookup positions; in particular, pipeline
method resolution remains before the verifier's late `passed` and `score`
reads. The verifier result, non-empty artifact, problem, and touched-path
containers retain their established identities. Unsupported-policy handling,
candidate preflight, black-box runtime, shared problem construction, repo
finalization, and public `GuardResult` construction remain in `guard.py`. A
12-case public-Guard vector freezes fallbacks, provider rebinding, deletion
reads, exception propagation, mutation timing, and identity behavior.

The first command-family slice adds the typed `cli.guard_command` owner for
the public `guard` command. It owns only effective-policy resolution, routing
between patch/diff/base-head inputs, and report/JSON/SARIF/signature
publication. The `cli` package facade keeps `cmd_guard` public, snapshots the
same Guard imports at command entry, and injects call-through providers for the
historical config, path, read, report-write, and late signing seams. The owner
has no runtime import of another EvoOM module. A pre-extraction vector freezes
CLI-over-policy precedence, input modes, fail-closed errors, output order, and
exit codes. All other command handlers and parser dispatch remain in the
facade; this slice does not claim the broader CLI split is complete.

The second command-family slice adds the stdlib-only
`cli.trusted_finalizer_commands` owner for raw-Git binding derivation and
verification, semantic-record loading, handoff construction, finalizer
sealing, and finalized-bundle verification. The `cli` package facade keeps the
five historical commands plus the semantic-record helper and their exact
import/lookup contract: domain operations imported at command entry are
snapshotted, while the semantic reader, external-input reader, material
parser, path projection, and machine reporter remain call-through seams.
Frozen vectors cover report bytes, operation order, stdin rejection, error
classification, and exit status. This slice does not move parser dispatch or
any Release Source command.

The third command-family slice adds the stdlib-only
`cli.record_commands` owner for `verify-verdict`, `verify-record`,
`bundle-evidence`, `finalize-record`, and `verify-bundle`. The owner fixes the
ordered application pipeline—bounded read, parse/semantic validation,
authentication or sealing, then machine-report projection—without importing a
record, evidence, signing, or filesystem implementation. The `cli` facade keeps
all five public `cmd_*` names and signatures. Function-local imports that were
historically resolved at command entry remain entry snapshots; the bounded
reader, machine reporter, path/hash/JSON projection, and the intentionally late
`verify-verdict` JSON parser remain call-through providers. Characterization
tests freeze operation order, stdout, exit status, public signatures, and those
lookup points. This is an R2-compatible ownership move; it changes no verdict,
bundle, signature, or frozen-release format.

The fourth command-family slice adds the strictly typed, stdlib-only
`cli.artifact_admission_commands` owner for only the Artifact Admission V1
seal/verify pair. The public facades keep their function-local domain and
signing imports as entry snapshots, while external source/context readers and
the machine reporter are resolved live at every historical call site. The
owner preserves the separate metadata and domain `try` regions, the
`ArtifactAdmissionError`-before-`ValueError` catch order, eager stdin argument
reads, success projection order, exact status/exit mapping, propagated
exception identity, partial-output behavior, and the verifier's detached
offline boundary. A cross-commit vector and focused reviewed mutations protect
those contracts. No digest, GitHub, release-source, or release-artifact command
moves in this slice.

The fifth command-family slice adds the separate strictly typed, stdlib-only
`cli.artifact_digest_admission_commands` owner for only the Artifact Digest
Admission V2 seal/verify pair. The facade retains its function-local format,
domain callable, domain exception, and signing-exception snapshots. External
source/context readers and machine reporting remain live at each historical
call site, with callable resolution before argument evaluation. The owner
preserves eager stdin tuple reads, separate metadata/domain `try` regions,
domain-subclass versus plain-`ValueError` classification, exact domain argument
and success projection order, repeated payload/inspection reads, status/exit
mapping, exception identity, retained partial/sealed output, and a closed-world
offline verifier argument surface. A full 44-case cross-parent vector plus
focused reviewed mutations protect those contracts. No V1, release, source,
or GitHub-attestation command moves in this slice.

The sixth command-family slice adds the strictly typed, stdlib-only
`cli.github_attestation_receipt_commands` owner for only receipt creation,
retained-byte verification, and fresh provider re-verification. The facade
keeps the receipt format, domain exception, and three domain callables as
function-local entry snapshots. It also keeps the shared policy and provider
isolation helpers because their resolution and the isolation helper's own
function-local imports are public compatibility boundaries; the owner receives
call-through providers so each helper and the machine reporter remain live at
their historical use site. Create and reverify services expose the online
isolation seam, while the retained verifier service structurally cannot access
it. The owner preserves the domain-error-before-`ValueError` catch order,
including the historical late-error-class `ERROR/2` nuance, exact argument and
success projection order, partial outputs, exception identity, and the
retained verifier's environment-independent closed-world offline boundary. A
51-case cross-parent vector and twelve focused reviewed mutations protect the
slice. GitHub attestation admission, release-source, and release-artifact
commands remain in the facade.

The seventh command-family slice adds the separate strictly typed,
stdlib-only `cli.github_attestation_admission_commands` owner for only the
GitHub attestation admission seal/retained-verify pair. The facade keeps the
binding format, domain callable, domain exception, and signing exception as
function-local entry snapshots. External source/context readers, policy
construction, sealing-only provider isolation, and reporting remain live at
their exact historical use sites. Seal and verify use independent service
contracts rather than a generic executor; the verify contract structurally
contains no GitHub executable, timeout, provider-isolation, network,
signing-key, or output-mutation seam. The owner preserves the eager seven-path
guards, separate metadata/domain catches, GitHub-error precedence, repeated
result projections, partial-output residue, and success projection outside the
domain `try`. A 70-case cross-parent vector and at least sixteen focused
reviewed mutations protect the slice. Release-source and release-artifact
command families remain in the facade.

The eighth command-family slice adds the strictly typed, stdlib-only
`cli.release_source_finalizer_commands` owner for release-source handoff
creation, protected finalizer sealing, detached verification, and raw-Git
control derivation. The facade keeps each function-local format, domain
callable, domain exception, and signing exception as an entry snapshot.
External trust readers, absolute-path projection, and machine reporting remain
call-through providers resolved at their historical use sites. Four
independent service bundles keep each command's authority surface explicit.
The owner preserves stdin rejection, trusted-metadata versus domain/signing
classification, catch order, exact projections and exit codes, `ALLOW`/`DENY`
opt-in behavior, exception identity, and source-before-context publication
with its historical partial-source residue if the second publication fails.
An 82-case cross-parent vector plus focused reviewed mutations protect these
contracts. The extraction adds no checkout, network, provider, admission,
transaction, or cleanup semantics; release-source producer/admission and
release-artifact command families remain in the facade.

The eighth command-family slice adds the strictly typed, stdlib-only
`cli.release_source_producer_receipt_commands` owner for unsigned canonical
claim creation, local/raw-Git verification, and fresh GitHub provider
re-verification. The facade keeps each function-local format, domain exception,
and domain callable as an entry snapshot. The shared external-input helper,
external trust reader, absolute-path projection, and machine reporter remain
call-through seams resolved at their historical use sites. Three independent
service bundles make the authority difference explicit: local verification
has no provider reader, while fresh re-verification has only the historically
existing policy reader, `gh` path, and timeout surface. The owner preserves
eager tuple reads, catch/report/exit behavior, exception identity, repeated
projection order, provider-output residue, and archive-only opt-in exits.
Successful verification remains `verified=true`, `ok=false`, `decision=NONE`,
and `admission=false`; the slice adds no signing key, admission capability,
provider-isolation builder, or executable pin. A 66-case cross-parent vector
plus focused reviewed mutations protect these contracts. Release-source and
release-artifact admission command families remain in the facade.

The first admission-layer slice lives in
`evoom_guard/admission/release_source.py`. It owns the separately keyed V2
release-source `ALLOW` envelope: closed-world manifest validation, replay
binding, canonical archive inspection, signature verification, and the final
composition of already verified source, producer, provider, and verdict
relations. It may import only public contracts from the legacy evidence,
finalizer-derivation pin, GitHub-attestation, release-source-finalizer,
producer-receipt, record-verifier, and signing components. It must not execute
candidate code, derive policy, or
reinterpret the DENY-only V1 release-source decision. The package-wide schema
remains under `evoom_guard/schemas/` until the evidence/finalizer Stage 10
migration is performed atomically.
