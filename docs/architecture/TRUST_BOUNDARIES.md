# Trust boundaries

## Current trust model

- `guard` default judge is not a sandbox boundary; it is a policy execution boundary.
- `--blackbox` path is an explicit judge-owned evidence channel and is preferred for
  high-confidence isolation.
- `docker`/`gvisor` isolation is capability-defined and must be explicitly requested.

## Evidence trust roots

- Raw Git derivation and candidate/tree hashes.
- Policy + profile digest.
- Verifier pack identity and snapshot.
- Verifier run evidence (JUnit/report + process state + cleanup evidence).
- Signature and key-domain checks.

## Boundary limitations (explicit)

- Artifact admission binds bytes to a trusted finalizer decision; it does not prove
  upstream build or deployment provenance alone.
- No claim is made that a successful verdict implies complete software correctness.
- Same-account cross-repository evidence is operationally useful but not independent.

