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

The edge `finalizer_derivation -> cli` closes the current strongly connected
component. Moving configuration loading behind a lower-level public interface is
the first high-leverage cycle reduction; deleting or suppressing the import in the
gate is not an acceptable substitute.

## Acceptance rules

- Any refactor PR must:
  - be labeled `no-behavior-change`,
  - include equivalent fixture results for verdict/lifecycle,
  - include at least one positive and one negative vector update for each touched contract,
  - preserve backward compatibility at the CLI/API compatibility facades.
