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
- Named-container cleanup is a fail-closed, positive absence proof: a bounded
  filtered `docker container ls --all` query must succeed and omit the exact
  validated name. The cleanup path reconciles repeatedly and requires a final
  stable sequence of absent observations so a late daemon-side create is found
  and removed within one 10-second monotonic control-plane budget. An exhausted
  budget or unverifiable observation fails immediately. This proves bounded
  snapshot stability, not permanent future absence. A failed Docker query is not
  absence evidence because daemon, authorization, and client failures are
  indistinguishable from not-found.
- `repo_verifier.py` retains private compatibility names while delegating to
  the typed `evoom_guard.execution` contract.
- Candidate and black-box execution code no longer obtain process primitives
  from the concrete repository verifier.
