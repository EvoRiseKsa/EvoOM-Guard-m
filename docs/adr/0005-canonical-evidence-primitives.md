# ADR-0005 Canonical evidence primitives

## Decision
Centralize canonical encoding, bounded file handling, and archive behavior in shared
`evidence/primitives` modules.

## Rationale
Evidence bytes are a hard boundary and must be deterministic.

## Consequences
- Deterministic signature inputs
- Lower duplicate logic in finalizer/admission paths
