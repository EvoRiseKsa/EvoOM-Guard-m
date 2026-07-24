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
- `integrations/`: external platform adapters.

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
Workspace allocation, candidate edit/deletion policy, pack intake, execution,
runtime identity, evidence, and verdict composition remain in their existing
owners.

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
observation and verdict interpretation remain in `blackbox.py`.

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
attachment. Those remain in `blackbox.py`, which supplies live compatibility
providers and performs the final projection without changing the public ABI.

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

Repository verifier-pack admission lives in
`evoom_guard/verifiers/repo_pack_intake.py`. Its immutable request/result and
service contracts own no-pack/required-pin consistency, the reserved mount
collision, snapshot validation, digest matching, and the exact rejection
evidence. `RepoVerifier` supplies call-through `lexists`, workspace-allocation,
and `snapshot_pack` operations so an earlier operation can still replace a
later historical seam. `RepoVerifier` also records the workspace before
snapshotting so its existing `finally` cleanup covers unexpected exceptions.
Pack execution and post-execution snapshot verification stay outside this
boundary.

Verifier-pack execution and interpretation live in
`evoom_guard/verifiers/repo_pack.py`. Immutable execution and interpretation
requests are deliberately separate so `RepoVerifier` can verify both the pack
snapshot and candidate runtime tree after the process completes but before
judge-owned JUnit is read. Host, Docker, and gVisor operations, phase evidence,
report readers, and the pure pack evaluator are injected as live providers at
their historical call sites. Pack admission/identity, both snapshot checks,
runtime continuity, sticky repository-suite evidence, phase composition,
final artifact projection, and workspace cleanup stay in `RepoVerifier`.

Repository-suite execution and interpretation live in
`evoom_guard/verifiers/repo_suite.py`. Immutable execution and interpretation
requests are deliberately separate so `RepoVerifier` can verify runtime-tree
continuity after the suite process completes but before judge-owned JUnit is
read. Host, Docker, and gVisor operations, phase evidence, report readers, and
the pure phase evaluator are injected as live providers at their historical
call sites. Terminal execution failures return before any verifier pack can
start. Runtime-identity policy, sticky artifact projection, phase composition,
and workspace cleanup stay in `RepoVerifier`.

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
`repair_effect == "demonstrated"`. Baseline execution, repo-suite scope,
repair-effect classification, and evidence annotation remain in Guard. The
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
still owns the effect implementations, public `GuardResult`, black-box branch,
baseline runner, and wire casts. This boundary deliberately does not unify the
black-box eager-assurance path or move verifier execution.

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
