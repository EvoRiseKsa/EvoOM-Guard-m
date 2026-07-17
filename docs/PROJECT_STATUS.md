<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
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
| [`EvoOM-Guard-m`](https://github.com/EvoRiseKsa/EvoOM-Guard-m) | Authoritative source-available CLI, Action, releases, threat model, and security policy. | The latest published product release is [`v3.7.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v3.7.0). Changes on `main` after that tag are unreleased development work. | External adoption, independent security review, or universal correctness. |
| [`evoom-guard-demo`](https://github.com/EvoRiseKsa/evoom-guard-demo) | Frozen reproducible demonstration of honest fixes, protected-harness tampering, stdout forgery, and black-box evidence. | Its public scenario is pinned to **v3.5.2**. | Any capability added in v3.6 or v3.7, including the raw-Git Trusted Finalizer. |
| [`evoom-guard-eval`](https://github.com/EvoRiseKsa/evoom-guard-eval) | Historical evaluation protocol and reproducibility record. | Its public record is pinned to **v3.5.2** and explicitly records both conformance and infrastructure failures. | A general accuracy rate, an independent evaluation, or a v3.7 result. |
| [`evoom-guard-finalizer-pilot`](https://github.com/EvoRiseKsa/evoom-guard-finalizer-pilot) | Controlled operational evidence for the v3.7 Trusted Finalizer reference. | It records a same-owner, cross-account v3.7.0 exercise and public verification inputs. | A deployed production merge gate, an independent audit, a hostile-runner boundary, or a software-release provenance claim. |

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
| GitHub artifact attestations | `main` contains a release workflow that will attest a future release asset before upload. | [`v3.7.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v3.7.0) predates that workflow and has no such GitHub Actions artifact attestation. An attestation is provenance evidence, not a correctness or security verdict. |
| GitHub-attestation admission adapter | The implementation on `main` constrains `gh attestation verify` to explicit repository/workflow/digest/source bindings. | It is unreleased experimental work, limited to its documented same-repository model, and is not a general supply-chain guarantee. |

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

The public source is not a trade secret. The custom source-available license
places legal conditions on redistribution and competing hosted use, but it does
not prevent someone from studying the design or independently implementing the
ideas. Long-term differentiation therefore has to come from independently
validated operational practice, high-quality private policy/packs and data,
trustworthy service operation, and customer integrations—not from obscuring
already published Python or workflow files.

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
