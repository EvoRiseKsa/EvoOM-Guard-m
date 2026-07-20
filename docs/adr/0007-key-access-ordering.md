# ADR-0007 Key-access ordering

## Decision
Split signing operations behind a small protocol (`SigningKeyOpener`) with deterministic
ordering: source/context validation -> raw-Git derivation -> handoff match -> key-domain checks.

## Rationale
Prevents key exposure in branches that have not passed evidence verification.

## Consequences
- Easier spy/failure-path testing.
- Reduces accidental key misuse in non-critical branches.
