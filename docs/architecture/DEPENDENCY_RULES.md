# Dependency rules

## Hard constraints

- Core runtime dependencies between execution and domain/evidence modules must remain stdlib-only.
- No private imports from `repo_verifier.py` or other monolith modules into extracted modules.
- No circular imports.
- No `dict[str, Any]` in core domain contracts (`domain`, `application`, `policy`,
  `execution`); prefer typed dataclasses and protocol interfaces.
- `candidate` may export typed value objects plus dependency-free parsing and
  patch transforms; it must not perform filesystem, process, or container effects.
- `workspace`, `execution`, and `isolation` may only export typed contracts and
  the bounded effects those contracts explicitly describe.

## CI gate expectations

- AST import boundary gate (`tests/architecture/test_import_boundaries.py`)
- Contract vectors and differential equivalence gates
- Mutation score and branch-coverage floor
- MyPy strict for new packages
- Canonical bundle and signature vector checks

## Import-boundary ratchet

The executable AST gate analyzes the complete package tree, including local imports,
`TYPE_CHECKING` branches, relative imports, literal and opaque dynamic imports, and
wildcard imports. The initial baseline records 17 cyclic edges and 76 unique
cross-package private-symbol imports. It also records 27 unclassified legacy
modules. It permits no unresolved dynamic imports, wildcard imports, extracted-layer
direction violations, or additional unclassified modules.

The enforced layer order is explicit and matches `MODULE_BOUNDARIES.md`:
`domain -> policy/candidate/workspace -> execution/isolation ->
verifiers/runners -> application -> evidence -> finalizer/admission ->
api/cli/integrations`. A module is assigned to a layer only when its first-level
name is a real Python package; same-named compatibility files such as
`evidence.py` remain declared legacy debt until their atomic file-to-package
migrations.

The former miscellaneous `record_verification` package has been removed.
Its report-envelope and isolation-parity responsibilities now have explicit
owners in `verifiers.record_report` and `verifiers.record_isolation`. The
schema-1.12 profile slice adds `verifiers.record_policy`, which independently
re-derives profile constraints without importing the producer's policy
predicate. All three are classified in the verifier layer and the public
`record_verifier` API is unchanged.

The baseline is architectural debt, not permission to add equivalent debt:

1. A newly observed violation fails CI.
2. A removed violation also fails until its exact baseline entry is deleted.
3. When entries are removed, append the next `ratchet_history` revision and lower
   the corresponding ceiling. A later revision may never raise a ceiling.
4. A context change (for example runtime to `TYPE_CHECKING`, or module to local)
   changes the fingerprint and therefore requires explicit review.
5. A new flat module or unknown first-level package is an unclassified violation;
   new implementation must enter a documented layer instead.

Revision 2 extracts the trusted config loader into `policy.config`. Removing the
real `finalizer_derivation -> cli` dependency reduces the graph from one
eight-module strongly connected component and 17 cyclic edges to zero cycles;
it also lowers cross-package private imports from 76 to 75. The CLI keeps exact
aliases for its previous config names, so this improvement is not achieved by
suppressing an import or breaking compatibility.

Revision 3 extracts native bounded-process execution into `execution.process`.
Replacing cross-package imports of verifier-private process helpers with public
typed contracts lowers cross-package private imports from 75 to 60 while the
verifier retains exact local compatibility facades.

Revision 4 gives host-command resolution, setup-fidelity inspection, and
harness glob matching public owning contracts. `guard.py` now imports those
contracts from `execution.command`, `verifiers.fidelity`, and
`verifiers.harness_policy` rather than reaching through the `RepoVerifier`
compatibility facade. Exact legacy aliases remain available, while the measured
cross-package private-import ceiling falls from 60 to 56.

The first Stage-3 domain slice adds `domain.verification` without changing a
ratchet count: the package is classified, imports no EvoOM implementation
module, and existing verifiers depend on it through public symbols. Exact
legacy class aliases preserve identity. CI and release additionally run
`python -m mypy --strict evoom_guard/domain/`; no artificial ratchet revision is
recorded because no baseline violation is added or removed.

The verdict-semantics slice follows the same rule. `domain.verdict` is
dependency-free and owns only version-neutral lifecycle/verdict/reason data.
The schema-1.11 compatibility module retains its policy and wire-shape
constants and re-exports exact domain objects. Guard imports semantics directly
from the domain while retaining only its versioned `SCHEMA_VERSION` dependency.
No baseline count changes, so no ratchet revision is fabricated.

The first Stage-5 candidate slice moves edit parsing and the unique-anchor
patch transform into `candidate.edits` and `candidate.patch`. Guard, black-box,
evidence, and repository verification consume the public candidate contracts.
The historical `verifiers.candidate_edits` and `patch_applier` paths remain
exact compatibility facades, including the parser regex identities used by
the characterized repository verifier. At that revision candidate
materialization and all filesystem effects remained pending. The measured
baseline remains at zero
cycles, 56 cross-package private imports, and 27 unclassified legacy modules,
so this move does not fabricate a ratchet revision.

The bounded materialization slice now gives
`verifiers.repo_materialization` ownership of the contained FILE-then-PATCH
transaction and judge-manifest restoration. `repo_verifier` passes its current
workspace, patch, and restoration globals into that owner on every call, so
legacy monkeypatch seams remain dynamic. Repository copying, deletion,
subprocess/container execution, pack selection, and verdict composition remain
outside this module. This classified-to-classified extraction changes no
baseline count and therefore adds no ratchet revision.

The repository-workspace slice gives the dependency-free
`workspace.repository` module ownership of copy-ignore semantics,
symlink-preserving repository copying, and cleanup exception precedence.
`repo_verifier` remains the compatibility facade and injects its live
filesystem and note providers at every call. No policy, execution, evidence,
or verdict dependency enters the workspace layer, and no measured baseline
ceiling changes. Windows copy visits reject observed junctions and other
non-symlink reparse objects, but the source must remain quiescent: this is not
an atomic source-tree snapshot. Cleanup treats a recursive
`FileNotFoundError` as idempotent success only after its live path provider
observes the workspace root absent. Production repository-verifier roots are
claimed immediately after trusted allocation, carry captured root/parent
identity, and must prove absence after successful removal. Only that nominal
capability permits confined Windows `READONLY` repair; a plain compatibility
string never does.

The repository-workspace lifetime slice adds the dependency-free
`workspace.repository_lifetime` owner. It records candidate/pack workspace
paths, preserves pack-root reconciliation, and exposes the historical cleanup
target order while importing no verifier, execution, evidence, or verdict
module. `repo_verifier` supplies live allocation providers and retains the
outer cleanup `finally` plus primary-exception call site. The dependency-free
`verifiers.repo_cleanup` owner resolves the workspace cleanup algorithm,
recursive remover, and note provider in their historical order. It imports no
workspace or orchestrator module because all effects remain injected. This
classified-to-classified extraction changes no baseline count and therefore
adds no ratchet revision.

The bounded verifier-pack intake slice gives
`verifiers.repo_pack_intake` ownership of optional pack admission and its
judge-owned snapshot identity. `repo_verifier` injects live `lexists`,
workspace-allocation, and `snapshot_pack` operations at their historical
positions, then retains workspace cleanup and later phase coordination. The
owner has one internal dependency, the public `pack_manifest` contract. This
classified-to-classified extraction changes no baseline count and therefore
adds no ratchet revision.

The bounded verifier-pack execution slice gives
`verifiers.repo_pack` ownership of host/docker/gVisor launch and later
judge-owned JUnit interpretation through separate immutable contracts.
`repo_verifier` injects all effects through live providers and retains pack
admission, phase composition, and cleanup; `repo_result` owns sticky/final
projection.
The owner may depend only on public contracts, domain execution/verification
values, and the public execution/isolation exception vocabulary. This
classified-to-classified extraction changes no baseline count and therefore
adds no ratchet revision.

The accepted-pack continuity slice gives
`verifiers.repo_pack_continuity` ownership of the defensively frozen accepted
identity, live pre-execution/post-completion snapshot verification, and
monotonic checkpoint/failure state. It may depend only on the public
`pack_manifest` contract and must not
import execution, JUnit, verdict, evidence-projection, or workspace-cleanup
owners. `repo_verifier` maps its typed drift failure to the existing wire
artifact and retains unexpected-provider cleanup precedence. This
classified-to-classified extraction changes no baseline count and therefore
adds no ratchet revision.

The repository-result slice gives `verifiers.repo_result` ownership of typed
sticky pack/repository-phase facts and completed artifact construction. It may
depend only on public contracts, dependency-free domain execution/verification
values, and the public `verifiers.repo_execution` projection. It must not
import workspace, pack intake/continuity, runtime-identity providers,
subprocess/container launchers, clocks, or cleanup owners. `repo_verifier`
records facts at the historical operation points and retains phase composition,
workspace lifetime, live provider timing, and primary-exception cleanup.
Presence-versus-null behavior is a frozen wire-compatibility contract, not a
new schema. This classified-to-classified extraction changes no baseline count
and therefore adds no ratchet revision.

Revision 5 performs the atomic `workspace.py` to `workspace/__init__.py`
migration without changing the import name, implementation bytes, or
monkeypatch globals. The now-real `workspace` package is classified and has no
internal EvoOM dependency, so the unclassified-module ceiling drops from 27
to 26. Cycles remain zero and the private-import ceiling remains 56.

Revision 6 extracts the immutable effective-policy value into
`domain.policy` and its canonical builder/payload/digest into
`policy.effective`. Guard retains its historical private facade, while
`finalizer_derivation` now imports the public policy owner instead of
`guard.build_effective_policy_payload` (with `_effective_policy` retained only
as a same-module compatibility alias). The frozen default digest and full payload remain
byte-for-byte equivalent, and the private-import ceiling falls from 56 to 55.

The next Stage-3 slice adds `domain.request` as a dependency-closed aggregate
over repository, candidate, source identity, effective policy, verifier-pack
path, and coverage intent. Guard constructs an owned snapshot after the
existing public scalar checks, then derives all operational inputs and one
policy payload from that request. The public
33-parameter `guard()` signature remains frozen. This adds no baseline
violation and therefore does not fabricate a ratchet revision.

The domain-execution slice adds the dependency-free `domain.execution`
lifecycle snapshot and
the one-way `verifiers.repo_execution -> domain.execution` adapter. Repository
execution no longer mutates an untyped trace mapping. The adapter alone projects
typed observations to the frozen artifact keys; pack identity and repository
phase facts remain separate sticky verification evidence. No dependency
violation is added or hidden, so the ratchet ceilings remain unchanged.

The Docker isolation slice adds only public imports within the documented
`execution/isolation` layer and does not remove any remaining baseline
fingerprint. It therefore does not manufacture a ratchet revision or lower a
ceiling without a measured architectural change.

The isolation-validation slice adds the dependency-free
`domain.isolation` vocabulary. Application request preparation, the
repository verifier, the black-box entry point, and candidate-boundary
construction depend one-way on that domain contract. The domain module never
imports execution, isolation, verifier, or compatibility code. Docker's
canonical image-identity validator remains in `isolation.docker`, because it
validates an observed runtime fact rather than policy vocabulary.

The candidate-isolation slice moves launcher and boundary preparation into
`isolation.candidate`. The legacy `candidate_runner` module imports only public
typed isolation contracts and remains the compatibility surface; the extracted
module imports `isolation.docker` directly and never imports the facade or
`blackbox`, preventing a package-initialization cycle.

The invocation-transport slice moves the stdlib-only AF_UNIX receipt recorder
into `isolation.invocation`. It records bounded exact-token observations but
imports no verdict, evidence, verifier, or compatibility module. `blackbox`
retains its private recorder name as an exact alias and remains solely
responsible for combining receipts with validated container IDs.

The judge-process slice moves the black-box process lifecycle into
`execution.judge` behind public typed request, limits, result, and execution
contracts. The extracted module imports no compatibility, verifier, verdict,
or evidence module. `blackbox` remains the compatibility and orchestration
surface for command construction, patch seams, report interpretation, and
evidence composition. This move adds no import-boundary fingerprint and does
not justify a new ratchet revision or a baseline-ceiling change.

The black-box pack-phase slice moves only execution sequencing and completed
process interpretation into `verifiers.blackbox_pack`. That owner may import
the public `execution` and `pack_manifest` contracts only; it must never import
`blackbox`, candidate/isolation owners, evidence, or cleanup facilities.
`blackbox` depends one-way on this owner and retains command construction,
workspace lifetime, outer cleanup precedence, and compatibility projection.

The candidate-runtime slice moves only launcher/CID evidence retries and
candidate-container cleanup coordination into the stdlib-only
`verifiers.blackbox_candidate_runtime` owner. That module imports no internal
runtime owner: concrete Docker request/result/kernel types, the live scanner,
control/sleep/path effects, and the historical cleanup-error class are injected
by `blackbox`. The facade retains the exact private signatures, `BlackboxResult`
projection, `CandidateContainerCleanupError` identity, and the outer
primary-versus-cleanup exception policy.

Release Source Admission V2 enters the real `admission.release_source`
package. The extracted module imports only explicit public contracts from the
legacy evidence, finalizer-derivation pin, provider, release-source, receipt,
and signing components.
Those flat providers remain unclassified architectural debt until their atomic
Stage 10 migrations; their shared public facades prevent that debt from
spreading into the new admission layer.

Import-boundary ratchet revision 7 performs the atomic `cli.py` to
`cli/__init__.py` migration without changing the import path, implementation
bytes, console entry point, or public/private compatibility surface. The now
real `cli` package is classified at the integration layer, so the
unclassified-module ceiling drops from 26 to 25. Cycles remain zero and the
private-import ceiling remains 55. Parser and command extraction are separate
later slices; this move does not claim that the CLI monolith has already been
decomposed.

Import-boundary ratchet revision 8 removes the transitional
`record_verification` package after moving its two responsibilities to explicit
verifier-layer owners. The unclassified-module ceiling drops from 25 to 22 and
the cross-package private-import ceiling drops from 55 to 54 because
`record_verifier` now consumes the public `RecordChecks` contract. Cycles,
wildcard imports, unresolved dynamic imports, and layer violations remain zero.

Import-boundary ratchet revision 9 classifies the stable flat
`verdict_contract_v1_11` and `verdict_contract_v1_12` compatibility modules as
domain-owned wire vocabularies. The unclassified-module ceiling drops from 22
to 21 while both published import paths remain unchanged.

The verifier-owned `record_policy` module is a new classified verifier-layer
owner and adds no baseline violation, cycle, or unclassified debt. Its frozen
accept/reject mutation vectors are intentionally separate from producer policy
tests, so no ratchet count is changed merely to record the new module.

Declarative `argparse` construction now lives in the dependency-free
`cli.parser` owner. `cli.__init__` retains the public `build_parser` facade and
injects its immutable-ref validator and argument-group helpers on every call,
preserving the established monkeypatch surface. A frozen parser snapshot
covers all 41 subcommands, every help page, representative defaults,
immutable-ref rejection, and live helper lookup. All 41 command handlers now
delegate through typed command-family owners; their public `cmd_*` facades
retain dependency lookup timing and inject effects. Parser dispatch and the
public compatibility surface remain in `cli.__init__`. These same-package
moves create no new ratchet revision or baseline-ceiling claim.

## Acceptance rules

- Any architecture-extraction PR must:
  - select exactly one change class from the pull-request template,
  - carry `no-behavior-change` only for `R1-mechanical` or a genuinely
    behavior-preserving `R2-compatible` change,
  - for `R3-semantic` or `R4-trust-root`, state the changed invariant, threat
    model, positive/adversarial coverage, compatibility effect, and rollback,
  - include equivalent fixture results for verdict/lifecycle,
  - include at least one positive and one negative vector update for each touched contract,
  - preserve backward compatibility at the CLI/API compatibility facades.
