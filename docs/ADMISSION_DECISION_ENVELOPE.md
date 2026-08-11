<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# Admission Decision Envelope V1

> **Availability:** unreleased, library-only source contract. It has no CLI,
> required-check workflow, hosted service, or production deployment claim.

Admission Decision Envelope V1 turns one complete Agent Change admission proof
into a small deterministic decision document. The document uses the
[in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
outer shape so generic attestation tooling can identify its subject and
predicate type.

The envelope is a **proof-bound projection**, not a new signature and not a new
trust root. A consumer must retain the original `.evb`, re-run the Agent Change
verifier with externally selected public keys, source/context, and raw-Git
bindings, regenerate the envelope, and compare its canonical bytes literally.
Schema validation or structural inspection alone grants no authority.

## Why this boundary exists

The existing Agent Change proof already contains the signed Guard record,
Trusted Finalizer handoff, raw-Git derivations, agent proposal, and separately
signed control-plane authorization. Copying selected claims into another JSON
object without re-verification would weaken that chain. Signing the new object
with a new key domain in V1 would instead expand every existing key-separation
registry before a production custody design exists.

V1 therefore does neither. It provides one stable decision surface while its
authority remains the exact original proof and its established verifiers.

## Closed contract

The top-level object contains exactly the in-toto `_type`, one `subject`, one
`predicateType`, and one `predicate`. The predicate contains:

- `format = EVOGUARD_ADMISSION_DECISION_ENVELOPE_V1`;
- `profile = agent-change` and `decision = ALLOW`;
- the repository, immutable base/head commits and trees, PR and repository IDs,
  candidate digest and size; the in-toto subject is the head Git commit and uses
  `gitCommit`, while the EvoOM-specific candidate identity remains in the
  predicate rather than masquerading as the commit digest;
- the raw-Git-derived policy and optional verifier-pack digests;
- the SHA-256 and size of the complete `.evb` proof plus the projected finalizer
  and authorization key IDs and purposes;
- an explicit `PROOF_BOUND_PROJECTION` authority block.

The authority block fixes `merge`, `publication`, `deployment`, and
`external_action` to `false`. An external system may act only after applying its
own authenticated policy and replay controls to the verified result.

## Verified flow

```text
exact Agent Change .evb
        │
        ├─ stable bounded snapshot
        ├─ Trusted Finalizer signature + raw-Git derivation verification
        ├─ control-plane authorization signature + scope verification
        └─ exact source/context/external-root comparison
                         │
                         ▼
             deterministic in-toto projection
                         │
             literal canonical-byte comparison
                         ▼
          proof-reprojected inspected view
```

The implementation is split deliberately:

- [`admission/decision_envelope.py`](../evoom_guard/admission/decision_envelope.py)
  owns only the closed shape, canonical bytes, and structural inspection.
- [`admission/decision_sources.py`](../evoom_guard/admission/decision_sources.py)
  snapshots and re-verifies the original Agent Change proof before projecting
  or accepting an envelope.
- [`admission-decision-envelope-1.schema.json`](../evoom_guard/schemas/admission-decision-envelope-1.schema.json)
  defines the machine-readable structural contract.

## Supported and deliberately unsupported

V1 supports only the complete `agent-change` `ALLOW` proof family. It does not
accept generic evidence bundles, observation records, provider receipts, or the
data-only Release Source V3 / Release Artifact V2 manifests under another
label. Additional proof families require a reviewed adapter and a new compatible
contract version; an unknown profile fails closed.

V1 does not claim:

- that GitHub branch protection consumed the decision;
- that a merge, build, release, publication, or deployment occurred;
- artifact provenance, reproducibility, vulnerability absence, or SLSA level;
- freshness beyond the independently supplied run/source/context expectations;
- correctness or completeness of the verifier pack;
- production-grade key custody, KMS/HSM protection, quorum, or transparency-log
  inclusion.

Those are separate control-plane and operational responsibilities. A later
private acceptance chain may authorize, sign, and ledger-bind the exact envelope
digest, but those receipts must remain outside the envelope payload to avoid a
circular hash relation.
