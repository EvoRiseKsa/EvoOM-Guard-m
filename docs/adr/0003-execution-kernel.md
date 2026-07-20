# ADR-0003 Execution kernel extraction

## Status

Accepted; phase 1 (bounded native process) implemented. Docker extraction is
deferred to a separately characterized change.

## Decision
Create explicit execution backends (`process`, `environment`, `docker`) behind
typed contracts, including cleanup and output limits.

## Rationale
Current monolithic execution paths mix process launch, isolation policy, and verdict logic.

## Consequences
- Enables independent failure-domain testing.
- Enables deterministic cleanup assertions.
- `repo_verifier.py` retains private compatibility names while delegating to
  the typed `evoom_guard.execution` contract.
- Candidate and black-box execution code no longer obtain process primitives
  from the concrete repository verifier.
