# ADR-0008 Release truth and ledger discipline

## Decision
Persist a release ledger entry for each published immutable release with source/version,
artifact hash, schema versions, and attestation references.

## Rationale
Version drift and `LATEST_PUBLISHED_RELEASE` ambiguity created prior consistency risks.

## Consequences
- Reliable mapping from GitHub release to runtime artifacts.
- Better reproducibility during incident and compliance checks.
- The frozen v4.0.1 ledger remains inside its full baseline directory.
- Later releases may use a minimal release-ledger directory when no new
  behavioral capture was performed; such a ledger must not copy or imply
  behavioral evidence that was not collected for that release.
- The historical `release-ledger-v1` schema remains frozen for v4.0.2 through
  v4.3.0. A release traversing the protected A-H pipeline uses the separate
  post-publication `release-ledger-v2` contract, offline cross-binding and byte
  validation, and a detached signature over canonical ledger bytes.
- A schema, template, source candidate, or pre-publication run is not itself a
  ledger. External release facts and expiring workflow evidence are frozen only
  after the immutable release exists.
