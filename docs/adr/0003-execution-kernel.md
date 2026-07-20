# ADR-0003 Execution kernel extraction

## Status

Accepted; phase 1 (bounded native process) and phase 2 (Docker control,
identity, and cleanup) implemented behind typed contracts.

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
  the typed `evoom_guard.execution` and `evoom_guard.isolation` contracts.
- Candidate and black-box execution code no longer obtain process primitives
  from the concrete repository verifier.
- `isolation/docker.py` owns bounded Docker control commands, image-identity
  observations, named-container lifecycle cleanup, and candidate-CID cleanup.
- Named repo-verifier containers and black-box candidate CID containers remain
  distinct contracts: one proves cleanup of a known name, while the other
  discovers only validated runtime-written IDs before proving absence.
- Docker argv/mount construction, isolation policy, evidence composition, and
  verdict wording remain with their existing callers. `CandidateRunner` itself
  is not moved by this phase.
