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
- The public API contract lives only in `evoom_guard/cli.py`, `evoom_guard/guard.py`,
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
report, or compose evidence or verdicts. Those responsibilities remain in
`blackbox.py`, which also retains its historical private patch seams through a
compatibility facade.

Host-command ownership lives in `evoom_guard/execution/command.py`. It resolves
Windows `PATHEXT` shims without a shell and refuses candidate-controlled
relative `PATH` entries for bare judge commands. Setup-fidelity snapshot/change
contracts are public in `evoom_guard/verifiers/fidelity.py`, and harness glob
matching is public in `evoom_guard/verifiers/harness_policy.py`.
`repo_verifier.py` retains exact legacy aliases, but higher-level orchestration
must import these public owners directly.

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
