<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# v4 license-transition gate

This document records the conditions for publishing EvoOM Guard `v4.0.0` under
the EvoRise Research and Evaluation License 1.0. It is not evidence that a v4
release has been published, that a commercial license exists, or that EvoRise
Tech has acquired copyright.

## What this transition changes

- A future v4 release will be source-available for the limited research and
  evaluation uses in [LICENSE](../LICENSE).
- Commercial, production, required-CI, merge-gate, hosted, managed-service,
  redistribution, and competitive uses will require a separate signed license.
- `v3.8.0` and earlier releases retain the license distributed with each exact
  immutable release; see [LICENSE_HISTORY.md](../LICENSE_HISTORY.md).

## Conditions before merge and release

1. Record the exact legal name and jurisdiction of the EvoRise Tech entity.
2. Retain a signed IP-assignment or other chain-of-title record if copyright is
   to move from Mana Alharbi to that entity. Until then, do not replace the
   copyright holder or Licensor in the published license.
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
SHA-256, release-attestation status, governing license, commercial contact,
and the fact that earlier releases remain governed by their original license.
