# Compatibility matrix (behavior-preserving refactor posture)

| Scope | Compatibility strategy |
| --- | --- |
| Public CLI | Keep `evoom-guard` entry commands and flags stable; extract internals only under PRs labeled `no-behavior-change`. |
| API facades | Preserve `evoom_guard/cli.py`, `guard.py`, `record_verifier.py`, `trusted_finalizer.py` as compatibility facades. |
| Schema files | Preserve existing schema identifiers/versions unless migration is explicitly versioned. |
| Evidence formats | Preserve byte contracts for existing schema versions unless a migration doc is added. |
| Exit codes | Preserve existing numeric semantics for verification outcomes. |
| GitHub Action | Preserve behavior of existing `action.yml` inputs/outputs during stage 1 extraction work. |

Any incompatible change must land in a separate migration PR with rollback documentation and release note.

