<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see ../LICENSE for permitted use.
-->

# Semantic core extraction plan

> **Status:** descriptive and non-normative. This document is an inventory and
> extraction plan for the exact protected source at
> `7fc7eeb4f9ecc5425cec22ba8532a2c777466c82`. It is not a standard, public
> protocol profile, conformance specification, certification program, or claim
> of an independent implementation.

## Purpose

EvoOM Guard currently contains several related but differently scoped
identities and admission contracts. This plan identifies the smallest semantic
pieces that could later become a portable software-change admission profile
without treating GitHub, Docker, pytest, EvoOM-specific evidence, or release
operations as part of a universal core.

Extraction is deliberately deferred until the independent field round and
external adversarial review have tested the assumptions that the proposed
boundary would preserve. The temporary descriptive name is **Experimental
Software Change Admission Profile**. No acronym or permanent product name is
assigned here.

## Source inventory

The SHA-256 values below identify source files at the commit named above. They
are review aids, not a new signed manifest or release identity.

| Layer | Source | SHA-256 |
| --- | --- | --- |
| Candidate text-map semantics | [`CANDIDATE_TEXT_MAP_IDENTITY_V2.md`](CANDIDATE_TEXT_MAP_IDENTITY_V2.md) | `545b0323ddf46f39a2d82d289cd44590a75669d456705af0362b7ee5c3d244ac` |
| Text-map vectors | [`vectors/candidate-text-map-v2.json`](vectors/candidate-text-map-v2.json) | `16475cc3d9dacc9f82eaf9ceb7763c648af3c19ad8afa545eff1e446beb185ff` |
| Candidate-selection vectors | [`vectors/agent-change-candidate-selection-v1.json`](vectors/agent-change-candidate-selection-v1.json) | `5bd435f49c9a48c330ec4f180e62e5403f9df28510a63b84975ad9ac0d7ee6d4` |
| Identity implementation | [`../evoom_guard/candidate/identity.py`](../evoom_guard/candidate/identity.py) | `2e52e348d3e3b00763b828101f59fbc2ebc2653fa8644a1ecff8a47f698a50a9` |
| Proposal V2 schema | [`../evoom_guard/schemas/agent-change-proposal-2.schema.json`](../evoom_guard/schemas/agent-change-proposal-2.schema.json) | `58f8cc53b179f345bc9038ec69f88216c19bad3fe7bce10ea0760a4a113bac24` |
| Git bindings V2 schema | [`../evoom_guard/schemas/agent-change-git-bindings-2.schema.json`](../evoom_guard/schemas/agent-change-git-bindings-2.schema.json) | `31e064cb2d2a477938f9c9c14c28815a26ca0900ff01f2b62d73a796fd470470` |
| Decision envelope V2 schema | [`../evoom_guard/schemas/admission-decision-envelope-2.schema.json`](../evoom_guard/schemas/admission-decision-envelope-2.schema.json) | `ea34bd79c306cdd8fe95607570d4e8232c10cdd20443e6a86eb01df9dd273969` |
| Agent-change implementation | [`../evoom_guard/admission/agent_change.py`](../evoom_guard/admission/agent_change.py) | `2372d53da0b52439717b28c47c3431086d95f83e88d80ebbb95b3bfb531fc359` |
| Envelope implementation | [`../evoom_guard/admission/decision_envelope.py`](../evoom_guard/admission/decision_envelope.py) | `2dce4c94f9f4ff6b22c1dfa3d4a7ff18059ab8493801c7dcc10c99a8ac04c2b4` |
| Proof-source projection | [`../evoom_guard/admission/decision_sources.py`](../evoom_guard/admission/decision_sources.py) | `74842d178f1c9c214a73d94ecbad16b2f20ad3a1f1dff6b2d57784eb3b6d8729` |

Related contracts are inventory inputs but remain outside the candidate core:

| Boundary | Source | SHA-256 |
| --- | --- | --- |
| Agent-change admission | [`AGENT_CHANGE_ADMISSION.md`](AGENT_CHANGE_ADMISSION.md) | `b5534382ca66b590ea131d5dc854eae796e877850a1292c3ae3c2a3219b3fa3d` |
| Decision-envelope admission | [`ADMISSION_DECISION_ENVELOPE.md`](ADMISSION_DECISION_ENVELOPE.md) | `25010494f7c595bac3365c269a6a8f69cd6101801af9c64ec04d8e176c8aa3a8` |
| Verifier-pack identity | [`VERIFIER_PACKS.md`](VERIFIER_PACKS.md) | `c8ec3b6f866c203e7b0fea6924164135b9930c4f4624528cc94ed5fe5f7661d6` |
| Artifact admission | [`ARTIFACT_ADMISSION.md`](ARTIFACT_ADMISSION.md) | `313cd24fe2199272cb69031bf8db3d45e63a2dfd6b78bf168377097ff59dada5` |
| Artifact digest V2 | [`ARTIFACT_DIGEST_ADMISSION_V2.md`](ARTIFACT_DIGEST_ADMISSION_V2.md) | `980a651ed1a22283852093209cef34aa433ce98c98d36422911b17abe4d62fe2` |
| Artifact provider V3 | [`ARTIFACT_PROVIDER_V3.md`](ARTIFACT_PROVIDER_V3.md) | `cae232dd1fb74c7cb7ff2af6405c0497b92398116b725c504ccae03c5478de97` |
| Release-source admission | [`RELEASE_SOURCE_ADMISSION_V2.md`](RELEASE_SOURCE_ADMISSION_V2.md) | `6366fd3a1820213d84c973f6f62c6a81f086f474d8c6b09a86f71f3d44d00eef` |
| Release-artifact admission | [`RELEASE_ARTIFACT_ADMISSION_V1.md`](RELEASE_ARTIFACT_ADMISSION_V1.md) | `75c751be84e838b79befd1b908862aec0640295a681dea07753512de91230d77` |
| Operating profiles | [`OPERATING_PROFILES.md`](OPERATING_PROFILES.md) | `313862480bd0f9f581eee44c085188f34e577e732bd248d1ff5ec2e1dfe13b68` |
| Runner conformance | [`RUNNER_CONFORMANCE.md`](RUNNER_CONFORMANCE.md) | `313069c2d99a33cc4717a43be7cb4dcfe5c947c0b7cb6f2058b7dd2816e5eca3` |
| Isolation conformance | [`ISOLATION_CONFORMANCE.md`](ISOLATION_CONFORMANCE.md) | `c788f2c7cd48fad81b65d459c7a38274cd873ba35ac03337e05f25040afbe33d` |

## Candidate semantic boundary

The possible core is a dependency graph, not one current schema:

1. **Candidate text-map identity primitive.** Strict UTF-8 bytes, byte-order
   path sorting, an explicit domain, element count, type tag, and unsigned
   64-bit big-endian lengths produce an unambiguous framed serialization. Its
   SHA-256 identifier relies on collision resistance; SHA-256 itself is not
   injective.
2. **Change selection.** A separate rule determines the files and deletions
   included in a candidate. Selection is not hidden inside the text-map hash.
3. **Proposal and source binding.** Repository identity, object format, base
   commit/tree, head commit/tree, changed paths, and the named identity
   algorithm bind one proposal to one source-control view.
4. **Policy and evidence projection.** A decision must name the policy,
   evidence, judge, freshness, and authority inputs it actually verified. A
   digest alone does not prove their truth or independence.
5. **Authorization separation.** Merge, release, deployment, and external
   action remain distinct authorities. An `ALLOW` for one purpose does not
   grant another.

## Portable and implementation-specific surfaces

| Surface | Current classification | Reason |
| --- | --- | --- |
| V2 text-map framing | Candidate portable primitive | Dependency-free semantics and cross-language vectors exist. |
| Git candidate selection and bindings | Candidate Git profile | Git object identity is useful but not source-control-neutral. |
| Proposal and decision-envelope fields | EvoOM experimental profile | Current schemas retain EvoOM names, purposes, and proof bindings. |
| Verifier-pack identity | EvoOM extension | The pack and its evidence semantics remain Guard-specific. |
| Artifact and release admission | Separate domain profiles | Their subjects, providers, attestations, and authorities differ from source-change admission. |
| Runner, Docker, gVisor, pytest, and GitHub workflows | Implementation evidence only | They test one implementation and are not semantic-core requirements. |

The library name `Independent Verifier Packs` means candidate-independent and
judge-owned; it is not evidence of independent human review. Likewise, the
current portable evidence tools demonstrate packaging and re-verification, not
cross-implementation interoperability.

In `v4.6.0`, V2 generation remains explicit opt-in and V1 remains the default.
This inventory does not change a runtime default, schema alias, or compatibility
contract.

## Evidence still required before a proposed profile

- complete the preregistered current-release field round with independently
  reviewed labels and independently reproduced results;
- complete an external adversarial review of identity, canonicalization,
  replay, finalizer, evidence, and authority boundaries;
- resolve whether an agent-origin stratum is merely sampling metadata or a
  reportable per-agent comparison;
- replace placeholder or unverified schema identifiers with controlled,
  durable identifiers;
- extend vectors to include negative and error cases across
  proposal-to-bindings-to-envelope processing;
- decide, with legal review, a separate license for any normative text,
  schemas, vectors, and minimal verifier intended for independent
  implementation;
- choose a non-conflicting permanent name and trademark policy; and
- obtain at least one genuinely independent implementation and consumer before
  making interoperability or adoption claims.

The repository's current source-available license remains authoritative. This
plan does not grant redistribution, sublicensing, trademark, competing-product,
or implementation rights beyond [`../LICENSE`](../LICENSE).

## Deferred claims register

Until the evidence above exists, do not call this inventory a standard,
normative specification, independent protocol, conformance suite, second
implementation, interoperable ecosystem, or external adoption. Do not treat
same-owner accounts, system-acceptance exercises, portable packaging, or a
second code path written by EvoRise as independent validation.

After the field and adversarial gates, the next review may extract three
separate documents: a small semantic core, a Git change profile, and an EvoOM
proof-binding extension. Artifact and deployment profiles remain separate
later work.
