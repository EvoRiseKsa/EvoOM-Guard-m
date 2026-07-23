# Dependency rules

## Hard constraints

- Core runtime dependencies between execution and domain/evidence modules must remain stdlib-only.
- No private imports from `repo_verifier.py` or other monolith modules into extracted modules.
- No circular imports.
- No `dict[str, Any]` in core domain contracts (`domain`, `application`, `policy`,
  `execution`); prefer typed dataclasses and protocol interfaces.
- `candidate`, `workspace`, `execution`, and `isolation` may only export typed request/response contracts.

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
`domain -> policy/candidate/workspace -> execution/isolation -> verifiers ->
application -> evidence -> finalizer/admission -> api/cli/integrations`. A module
is assigned to a layer only when its first-level name is a real Python package;
same-named compatibility files such as `evidence.py`, `workspace.py`, and `cli.py`
remain declared legacy debt until their atomic file-to-package migrations.

`record_verification` also remains unclassified debt. Its current `report` and
`isolation` helpers do not form one justified target layer, so classifying the
package merely to silence the gate would misstate the architecture. It must be
split or moved deliberately before its three baseline entries can be removed.

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

The Docker isolation slice adds only public imports within the documented
`execution/isolation` layer and does not remove any remaining baseline
fingerprint. It therefore does not manufacture a ratchet revision or lower a
ceiling without a measured architectural change.

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

Release Source Admission V2 enters the real `admission.release_source`
package. The extracted module imports only explicit public contracts from the
legacy evidence, finalizer-derivation pin, provider, release-source, receipt,
and signing components.
Those flat providers remain unclassified architectural debt until their atomic
Stage 10 migrations; their shared public facades prevent that debt from
spreading into the new admission layer.

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
