# ADR-0004 Producer/Verifier separation

## Decision
Keep producer (record materialization and handoff) and verifier (analysis logic) as
separate logical domains with explicit contracts.

## Rationale
Security boundary clarity and evidence integrity are critical for trusted finalizer paths.

## Consequences
- Easier audit mapping and incident triage.
- Smaller blast radius for refactor mistakes.
