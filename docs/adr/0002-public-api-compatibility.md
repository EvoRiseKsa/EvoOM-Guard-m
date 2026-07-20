# ADR-0002 Public API compatibility first

## Decision
Keep compatibility facades (`evoom_guard/cli.py`, `guard.py`, `record_verifier.py`,
`trusted_finalizer.py`) as stable export points during refactor.

## Rationale
Refactor should be incremental and not break existing downstream integrations.

## Status
Accepted.
