# ADR-0008 Release truth and ledger discipline

## Decision
Persist a release ledger entry for each published immutable release with source/version,
artifact hash, schema versions, and attestation references.

## Rationale
Version drift and `LATEST_PUBLISHED_RELEASE` ambiguity created prior consistency risks.

## Consequences
- Reliable mapping from GitHub release to runtime artifacts.
- Better reproducibility during incident and compliance checks.
