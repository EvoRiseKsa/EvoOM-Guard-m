<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Commercial licensing is administered by EvoRise Company.
  Source-available — see LICENSE for permitted use.
-->

# Project status, evidence map, and operational boundary

This page is a status map, not a product claim. It separates the public
implementation, frozen evidence, and private operational material so that a
reader does not infer a stronger assurance level than the evidence supports.

## What EvoOM Guard is today

EvoOM Guard is a source-available CLI and GitHub Action for one narrow
admission question:

> Did an untrusted software change satisfy the selected judge without changing
> the harness or evidence that supplies the decision?

It is not a general vulnerability scanner, an AI code reviewer, a hosted
control plane, or a claim of complete software correctness. It is an early
engineering product and reference implementation, not an independently
validated security service.

## Public repository map

| Component | Public role | Evidence/version boundary | What it does **not** establish |
| --- | --- | --- | --- |
| [`EvoOM-Guard-m`](https://github.com/EvoRiseKsa/EvoOM-Guard-m) | Authoritative source-available CLI, Action, releases, threat model, and security policy. | The repository publishes [`v4.1.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.1.0), the latest published immutable consumer release. See [release status](RELEASE_STATUS.md). Consumers must inspect [Releases](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases) before adopting a different version pin. | External adoption, independent security review, or universal correctness. |
| [`evoom-guard-demo`](https://github.com/EvoRiseKsa/evoom-guard-demo) *(public archive)* | Frozen reproducible demonstration of honest fixes, protected-harness tampering, stdout forgery, and black-box evidence. | Its public scenario is pinned to **v3.5.2** and frozen at [`proof-v3.5.2`](https://github.com/EvoRiseKsa/evoom-guard-demo/releases/tag/proof-v3.5.2). | Any capability added in v3.6 or v3.7, including the raw-Git Trusted Finalizer. |
| [`evoom-guard-eval`](https://github.com/EvoRiseKsa/evoom-guard-eval) *(public archive)* | Historical evaluation protocol and reproducibility record. | Its public record is pinned to **v3.5.2**, frozen at [`historical-v3.5.2-evaluation`](https://github.com/EvoRiseKsa/evoom-guard-eval/releases/tag/historical-v3.5.2-evaluation), and explicitly records both conformance and infrastructure failures. | A general accuracy rate, an independent evaluation, or a v3.7 result. |
| [`evoom-guard-finalizer-pilot`](https://github.com/EvoRiseKsa/evoom-guard-finalizer-pilot) *(historical v3.7 pilot)* | Frozen operational evidence for the v3.7 Trusted Finalizer reference. | It records a same-owner, cross-account v3.7.0 raw-Git `ALLOW` exercise and public verification inputs in [`ROUND2_RESULTS.md`](https://github.com/EvoRiseKsa/evoom-guard-finalizer-pilot/blob/main/ROUND2_RESULTS.md). | A v4 result, deployed production merge gate, independent audit, hostile-runner boundary, or software-release provenance claim. |
| [`evoom-guard-v4-finalizer-pilot`](https://github.com/EvoRiseKsa/evoom-guard-v4-finalizer-pilot) *(public archive)* | Frozen current-runtime, non-production Trusted Finalizer and regular-file Artifact Admission evidence. | `v4.0.2` Round 1 and Artifact Admission Round 1 are complete. The latter binds file SHA-256 `555695a5b1b6aa082495dc8b4faeb5562fcbc7e23124daf046ef4592d253eae6` to a freshly verified GitHub attestation and same-head finalizer `ALLOW`; exact runs and downloaded evidence are in [`ARTIFACT_ADMISSION_ROUND1.md`](https://github.com/EvoRiseKsa/evoom-guard-v4-finalizer-pilot/blob/main/ARTIFACT_ADMISSION_ROUND1.md). | Build reproducibility, protected-main release provenance, OCI/registry/deployment admission, production readiness, or independent review. |
| [`evoom-guard-receipt-pilot`](https://github.com/EvoRiseKsa/evoom-guard-receipt-pilot) *(public archive)* | Frozen non-production A-to-B-to-C research evidence for an authenticated producer receipt. | Clean, failed-A, and moved-`main` records are retained. The final live matrix used A run `29880368085`, B run `29880394791`, and C run `29880410278`; C attempts 2/3/4 rejected wrong-workflow, wrong-run-attempt, and altered-receipt inputs respectively. Attempt 4 first verified the original receipt bytes on the same runner. The exact 19-file record is in [`evidence/negative-receipt-matrix`](https://github.com/EvoRiseKsa/evoom-guard-receipt-pilot/tree/main/evidence/negative-receipt-matrix), merged at `392bff6ca3e84adb5b1810c3d58dd61d157d35cb`; final CI passed and activation variables were removed before archival. | Artifact admission, release/deployment authorization, an `ALLOW` decision, independent review, or independent proof that A executed Guard. |

The second GitHub account, [`MANA-awam`](https://github.com/MANA-awam), is used
for technical separation of review/deployment roles in the pilot. Both accounts
are controlled by the same owner. The resulting review trail is useful
operational evidence, but it is **not** independent review or third-party
validation. See [governance](GOVERNANCE.md).

## Assurance status by mechanism

| Mechanism | Publicly supported statement | Boundary that remains |
| --- | --- | --- |
| Basic Guard | Rejects edits/deletions to configured protected harness paths before the suite runs; uses a structured judge-owned JUnit/exit-code verdict. | The default in-process report channel is deliberately forgeable by malicious candidate code. |
| Changed-line coverage | Measures direct execution of changed Python lines, applies conservative denominator rules, and fails closed when a configured floor cannot be measured. | Candidate code shares and can mutate the live `coverage.py` state. It is a non-hostile-code quality signal, not adversarial admission evidence. |
| `--blackbox-only` | Adds a judge-owned external process/protocol report and can fail closed on delivered isolation. | It is a narrowly supported target model, not a universal sandbox or proof of artifact provenance. |
| Trusted Finalizer reference | Separates untrusted re-verification from a signing job that re-derives specified raw-Git bindings before key access. | It is a reference template and pilot, not enabled as this repository's merge requirement or proof of an unbreakable runner boundary. |
| Artifact admission V1 | Can bind one observed regular-file digest and size to a verified finalizer `ALLOW`. The v4 pilot exercised this with a fresh, identity-constrained GitHub provider check and retained evidence. | It does not prove how that file was built, published, deployed, or secured, and the completed round is PR-head-bound rather than protected-main release authorization. |
| GitHub artifact attestations | [`v4.1.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.1.0) publishes `evo-guard.pyz`, its exact `SHA256SUMS`, and a GitHub Actions build-artifact attestation. | [`v3.7.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v3.7.0) predates that workflow and has no such GitHub Actions artifact attestation. An attestation is provenance evidence, not a correctness or security verdict. |
| GitHub-attestation admission adapter | The experimental `v3.8.0` baseline constrains `gh attestation verify` to explicit repository/workflow/digest/source bindings. Published `v4.1.0` additionally parses the returned statement/certificate semantics and offers opt-in pinned, lowered-identity provider execution. | Shipping the hardening is not a live V2 pilot or proof for an arbitrary artifact. The adapter remains same-repository only and is not a general supply-chain guarantee, production gate, or independent verification of arbitrary provenance data. |
| Authenticated producer receipt pilot | In the clean round, B created one bounded receipt and C freshly verified one GitHub Artifact Attestation for its exact bytes. The moved-`main` control failed before receipt creation/download. The final matrix then rejected wrong-workflow, wrong-run-attempt, and altered-receipt substitutions; the altered-byte control included a positive provider baseline for the original bytes on the same runner. | These are non-admitting observations only. They do not independently prove A executed Guard and do not authorize a release, deployment, merge, artifact admission, or `ALLOW`. |
| Release Source Admission V2 *(published bootstrap; not yet exercised)* | Implements a signed protected-main source `ALLOW` binding A/B/C workflow blobs and run attempts, strong receipt evidence, semantic provider output, externally checked signed Git/`gh` digest and UID/GID pins, a provider-inaccessible signing-key path, and five distinct key domains. | Publishing the implementation is not a live V2 pilot. It does not bind a release artifact or publication, is not a production gate, and has no independent review. The historical receipt pilot is not V2 `ALLOW` evidence. |

For exact threat models and non-guarantees, read [ASSURANCE.md](ASSURANCE.md),
[TRUSTED_FINALIZER.md](TRUSTED_FINALIZER.md), and
[GITHUB_ARTIFACT_ATTESTATIONS.md](GITHUB_ARTIFACT_ATTESTATIONS.md). The
published V2 source contract is specified separately in
[RELEASE_SOURCE_ADMISSION_V2.md](RELEASE_SOURCE_ADMISSION_V2.md).

## Public code versus private operational assets

Public reviewability is useful here: adopters need to inspect the judge,
schemas, workflow examples, release checksums, and published evidence before
depending on them. The following boundary is intentional.

| Keep public when safe to disclose | Keep private |
| --- | --- |
| Released CLI/Action source, schemas, threat model, reproducible examples, frozen non-sensitive evidence, public keys, release checksums, and non-sensitive verifier-pack examples. | Signing/private keys, GitHub or cloud credentials, customer repositories, customer policy, internal verifier packs, unannounced vulnerability reports, held-out evaluation corpus and labels, label rationale, operational logs, and customer-specific results. |

The public source is not a trade secret. Historical releases through v3.8.0
remain governed by the licenses shipped with those exact releases. The current
published immutable [`v4.1.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.1.0)
release ships the EvoRise Source-Available License 1.0. It does not prevent
someone from studying the design or independently implementing the ideas.
Long-term differentiation therefore has to come from independently validated
operational practice, high-quality private policy/packs and data, trustworthy
service operation, and customer integrations—not from obscuring already
published Python or workflow files.

The source tree and latest published immutable consumer release are both
version `4.1.0`. The project cannot
retract rights already granted with v3.8.0; see
[LICENSE_HISTORY.md](../LICENSE_HISTORY.md). The v4 license applies only to
material distributed with it. Commercial licensing is administered by EvoRise
Company; see [LICENSE](../LICENSE),
[COMMERCIAL-LICENSING.md](../COMMERCIAL-LICENSING.md), and
[RELEASE_STATUS.md](RELEASE_STATUS.md).
## Evidence still required before stronger claims

The repository has strong automated tests and controlled demonstrations, but it
does **not** yet have evidence for any of the following:

- independent human security review or independent efficacy evaluation;
- adoption or measured outcomes by external consumer repositories;
- a frozen, independently labelled held-out corpus;
- a multi-tenant service, service-level support commitment, or central policy
  plane; or
- an end-to-end live chain from protected-main release-source authorization
  through the actual release artifact, publication, and deployment. The v4
  pilot proves a narrower PR-head/regular-file/provider/finalizer relation and
  must not be generalized to that missing chain.

Until that evidence exists, descriptions should remain limited to implemented
behaviour, tested boundaries, and the exact version/evidence record linked
above. The next work is ordered in [ROADMAP.md](../ROADMAP.md).
