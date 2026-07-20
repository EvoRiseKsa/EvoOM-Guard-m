# ADR-0006 Error taxonomy and reason-code integrity

## Decision
Keep reason-code, lifecycle, and exit-code mapping explicit and audited:
`PASS`, `REJECTED`, `FAIL`, `TAMPERED`, `ERROR` with stable semantics.

## Rationale
Ambiguous failure modes create high-risk blind spots in merge gate and post-incident analysis.

## Consequences
- Stronger operational diagnosis.
- Safer policy/risk automation.
