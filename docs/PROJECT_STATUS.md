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
| [`EvoOM-Guard-m`](https://github.com/EvoRiseKsa/EvoOM-Guard-m) | Authoritative source-available CLI, Action, releases, threat model, and security policy. | Source now publishes [`v4.0.1`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.0.1), the latest published immutable consumer release at commit `5ed7e84017619496521b813f859a6a8bf0a2b1df`; see [release status](RELEASE_STATUS.md). Consumers must inspect [Releases](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases) before adopting a different version pin. | External adoption, independent security review, or universal correctness. |
| [`evoom-guard-demo`](https://github.com/EvoRiseKsa/evoom-guard-demo) *(public archive)* | Frozen reproducible demonstration of honest fixes, protected-harness tampering, stdout forgery, and black-box evidence. | Its public scenario is pinned to **v3.5.2** and frozen at [`proof-v3.5.2`](https://github.com/EvoRiseKsa/evoom-guard-demo/releases/tag/proof-v3.5.2). | Any capability added in v3.6 or v3.7, including the raw-Git Trusted Finalizer. |
| [`evoom-guard-eval`](https://github.com/EvoRiseKsa/evoom-guard-eval) *(public archive)* | Historical evaluation protocol and reproducibility record. | Its public record is pinned to **v3.5.2**, frozen at [`historical-v3.5.2-evaluation`](https://github.com/EvoRiseKsa/evoom-guard-eval/releases/tag/historical-v3.5.2-evaluation), and explicitly records both conformance and infrastructure failures. | A general accuracy rate, an independent evaluation, or a v3.7 result. |
| [`evoom-guard-finalizer-pilot`](https://github.com/EvoRiseKsa/evoom-guard-finalizer-pilot) | Controlled operational evidence for the v3.7 Trusted Finalizer reference. | It records a same-owner, cross-account v3.7.0 exercise and public verification inputs. | A deployed production merge gate, an independent audit, a hostile-runner boundary, or a software-release provenance claim. |
| [`evoom-guard-receipt-pilot`](https://github.com/EvoRiseKsa/evoom-guard-receipt-pilot) | Sanitized, disposable, non-production A-to-B-to-C research topology for an authenticated producer receipt. | One controlled public-safe A-to-B-to-C evidence-chain round completed on 2026-07-19 at protected-`main` commit `eaec5be2d1f98ea1aa665438ec90f9531d33da2b`; its exact byte manifest and public-safe inputs are retained in [`evidence/round1`](https://github.com/EvoRiseKsa/evoom-guard-receipt-pilot/tree/main/evidence/round1). The workflows are disabled by default and activation is permitted only transiently for a separately reviewed controlled round. | Artifact admission, release/deployment authorization, an `ALLOW` decision, independent review, or independent proof that A executed Guard. |

The second GitHub account, [`MANA-awam`](https://github.com/MANA-awam), is used
for technical separation of review/deployment roles in the pilot. Both accounts
are controlled by the same owner. The resulting review trail is useful
operational evidence, but it is **not** independent review or third-party
validation. See [governance](GOVERNANCE.md).

## Assurance status by mechanism

| Mechanism | Publicly supported statement | Boundary that remains |
| --- | --- | --- |
| Basic Guard | Rejects edits/deletions to configured protected harness paths before the suite runs; uses a structured judge-owned JUnit/exit-code verdict. | The default in-process report channel is deliberately forgeable by malicious candidate code. |
| `--blackbox-only` | Adds a judge-owned external process/protocol report and can fail closed on delivered isolation. | It is a narrowly supported target model, not a universal sandbox or proof of artifact provenance. |
| Trusted Finalizer reference | Separates untrusted re-verification from a signing job that re-derives specified raw-Git bindings before key access. | It is a reference template and pilot, not enabled as this repository's merge requirement or proof of an unbreakable runner boundary. |
| Artifact admission V1 | Can bind one observed regular-file digest and size to a verified finalizer `ALLOW`. | It does not prove how that file was built, published, deployed, or secured. |
| GitHub artifact attestations | [`v4.0.1`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.0.1) publishes `evo-guard.pyz` with SHA-256 `81a5139e1e0f3c5ce1f9180db85c699eec305474f9588f7d2831099defdce2f7` and a GitHub Actions build-artifact attestation. | [`v3.7.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v3.7.0) predates that workflow and has no such GitHub Actions artifact attestation. An attestation is provenance evidence, not a correctness or security verdict. |
| GitHub-attestation admission adapter | Released experimentally in `v3.8.0`; it constrains `gh attestation verify` to explicit repository/workflow/digest/source bindings. | It is limited to its documented same-repository model and is not a general supply-chain guarantee, an enabled production admission gate, or independent verification of arbitrary provenance data. |
| Authenticated producer receipt pilot | In the documented Round 1, B created one bounded receipt and C freshly verified one GitHub Artifact Attestation for its exact bytes under explicit repository, workflow, commit, ref, and GitHub-hosted-runner constraints. | This is non-admitting evidence only. It does not independently prove A executed Guard and does not authorize a release, deployment, merge, artifact admission, or `ALLOW`. |

For exact threat models and non-guarantees, read [ASSURANCE.md](ASSURANCE.md),
[TRUSTED_FINALIZER.md](TRUSTED_FINALIZER.md), and
[GITHUB_ARTIFACT_ATTESTATIONS.md](GITHUB_ARTIFACT_ATTESTATIONS.md) before
depending on a result.

## Public code versus private operational assets

Public reviewability is useful here: adopters need to inspect the judge,
schemas, workflow examples, release checksums, and published evidence before
depending on them. The following boundary is intentional.

| Keep public when safe to disclose | Keep private |
| --- | --- |
| Released CLI/Action source, schemas, threat model, reproducible examples, frozen non-sensitive evidence, public keys, release checksums, and non-sensitive verifier-pack examples. | Signing/private keys, GitHub or cloud credentials, customer repositories, customer policy, internal verifier packs, unannounced vulnerability reports, held-out evaluation corpus and labels, label rationale, operational logs, and customer-specific results. |

The public source is not a trade secret. Historical releases through v3.8.0
remain governed by the licenses shipped with those exact releases. The current
published immutable [`v4.0.1`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.0.1)
release ships the EvoRise Source-Available License 1.0. It does not prevent
someone from studying the design or independently implementing the ideas.
Long-term differentiation therefore has to come from independently validated
operational practice, high-quality private policy/packs and data, trustworthy
service operation, and customer integrations—not from obscuring already
published Python or workflow files.

The source tree now declares and ships `4.0.1`. It cannot
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
- an end-to-end live chain from protected build through artifact attestation to
  final admission and deployment.

Until that evidence exists, descriptions should remain limited to implemented
behaviour, tested boundaries, and the exact version/evidence record linked
above. The next work is ordered in [ROADMAP.md](../ROADMAP.md).
