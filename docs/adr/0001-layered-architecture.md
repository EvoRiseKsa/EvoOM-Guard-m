# ADR-0001 Layered architecture and boundaries

Date: 2026-07-20

## Context
The codebase is functionally correct in key paths but operational risk is high when orchestration
and domain logic are coupled.

## Decision
Adopt a layered architecture with explicit seams:
`domain -> policy/candidate/workspace -> execution/isolation -> verifiers ->
application -> api/cli/integrations`.

## Consequences
- Lower coupling, clearer ownership, safer future security hardening.
- Initial refactor cost in many files with no behavior changes.

