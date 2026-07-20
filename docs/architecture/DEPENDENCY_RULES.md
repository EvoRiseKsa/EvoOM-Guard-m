# Dependency rules

## Hard constraints

- Core runtime dependencies between execution and domain/evidence modules must remain stdlib-only.
- No private imports from `repo_verifier.py` or other monolith modules into extracted modules.
- No circular imports.
- No `dict[str, Any]` in core domain contracts (`domain`, `application`, `policy`,
  `execution`); prefer typed dataclasses and protocol interfaces.
- `candidate`, `workspace`, `execution`, and `isolation` may only export typed request/response contracts.

## CI gate expectations

- AST import boundary gate
- Contract vectors and differential equivalence gates
- Mutation score and branch-coverage floor
- MyPy strict for new packages
- Canonical bundle and signature vector checks

## Acceptance rules

- Any refactor PR must:
  - be labeled `no-behavior-change`,
  - include equivalent fixture results for verdict/lifecycle,
  - include at least one positive and one negative vector update for each touched contract,
  - preserve backward compatibility at the CLI/API compatibility facades.

