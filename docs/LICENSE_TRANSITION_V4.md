<!--
  Copyright (c) 2026 EvoRise Company. All rights reserved.
  Original creator: Mana Alharbi.
  Source-available — see LICENSE for permitted use.
-->

# v4 license-transition gate

This document records the conditions for publishing EvoOM Guard `v4.0.0` under
the EvoRise Research and Evaluation License 1.0. It is not evidence that a v4
release has been published, that a commercial license exists, or that the
required IP-assignment to EvoRise Company has been executed.

## What this transition changes

- A future v4 release will be source-available for the limited research and
  evaluation uses in [LICENSE](../LICENSE).
- Commercial, production, required-CI, merge-gate, hosted, managed-service,
  redistribution, and competitive uses will require a separate signed license.
- `v3.8.0` and earlier releases retain the license distributed with each exact
  immutable release; see [LICENSE_HISTORY.md](../LICENSE_HISTORY.md).

## Conditions before merge and release

1. Record the legal identity of the intended v4 licensor: EvoRise Company, an
   active Saudi one-person limited-liability company. Keep registration evidence
   private; do not publish a national number or registration certificate here.
2. Retain a signed IP-assignment or other chain-of-title record moving the
   applicable economic rights from Mana Alharbi to EvoRise Company. Preserve
   Mana Alharbi's original-creator attribution and exclude Third-Party
   Materials. Retain an authorized EvoRise Company acceptance/manager decision
   with an effective date and scope. Until both records are signed, do not
   merge or publish this v4 license transition.
3. Review every contributor, copied fixture, upstream patch, dependency,
   generated asset, data set, and workflow dependency against
   [THIRD_PARTY.md](../THIRD_PARTY.md).
4. Have qualified Saudi legal counsel review the license, commercial terms,
   trademark wording, privacy/data handling, and any Marketplace listing.
5. Bump the source version to `4.0.0`, run the full test and release checks,
   create a new immutable tag and release, and publish fresh checksums and
   provenance for that exact artifact.
6. Keep private verifier packs, signing keys, customer repositories, customer
   policy, held-out corpora and labels, operational logs, and control-plane
   code outside public repositories.
7. Ensure public documentation never describes the v4 research/evaluation
   runtime as a production merge gate, managed service, independent audit, or
   certification.
8. Before the actual v4 release, perform a deliberate copyright-banner
   inventory. Update only non-historical company-owned material and preserve
   immutable audit/release records and third-party notices unchanged.

## Repository boundaries

- This authoritative repository may remain public for inspectable source,
  schemas, public keys, checksums, threat-model documentation, and safe
  examples.
- Historical `demo`, `eval`, finalizer-pilot, and receipt-pilot repositories
  must retain their existing historical licenses and evidence. Do not try to
  make their past public content confidential retroactively.
- `PRIVATE_REPOSITORY_NOTICE.txt` belongs only in future private repositories;
  it must not be published here because public material is not confidential.

## Required release record

The v4 release notes must state the target tag, source commit, artifact
SHA-256, release-attestation status, governing license, EvoRise Company as
commercial licensor, Mana Alharbi as original creator, and the fact that
earlier releases remain governed by their original license.
