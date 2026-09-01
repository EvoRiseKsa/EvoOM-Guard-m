<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# Governance and trust boundaries

EvoOM Guard is a change-admission evidence system. Its security claims depend on
who can change the policy, the judge, the workflow, and the signing boundary.
This file records the present governance truth rather than implying a review
process that does not exist.

## Current status

The [LICENSE](LICENSE) identifies **EvoRise Tech** as the copyright holder and
Licensor, and **Mana Alharbi** as the author and original creator. Mana Alharbi
is currently the sole maintainer and human controller of both `@EvoRiseKsa`
and `@MANA-awam`. This repository records that operating identity; it does not
purport to verify corporate-registration, assignment, or jurisdictional
documents.

The repository's [`CODEOWNERS`](.github/CODEOWNERS) mapping uses the two
accounts for a technically separate review workflow on trust-root paths. That
is **not** independent review, third-party validation, multi-person governance,
or a separate security authority.

`CODEOWNERS` is a routing file, not a security control by itself. It becomes an
enforced control only when GitHub branch protection or a ruleset requires code
owner review, protects `CODEOWNERS` itself, and the listed account retains the
necessary repository access. It must never be cited as evidence of an
independent audit. The operating rules are in
[`docs/GOVERNANCE.md`](docs/GOVERNANCE.md). Current implementation and release
facts are maintained separately in
[`docs/PROJECT_STATUS.md`](docs/PROJECT_STATUS.md) and
[`docs/RELEASE_STATUS.md`](docs/RELEASE_STATUS.md); governance does not copy a
moving version status.

## Release governance

The latest published product release is the stable consumer line. The default
branch is development source and must not be represented as a released or
production-supported version merely because its CI is green.

- A patch release contains only a bounded security or functional-correctness
  fix and the tests, changelog, and release records needed to verify it. It is
  prepared from the affected stable tag or maintenance branch; unrelated
  default-branch development is not swept into the patch.
- Documentation, benchmark-data, or evidence-index corrections alone do not
  create a product release. They are published through the protected default
  branch and, when necessary, an explicit erratum.
- A minor release may add compatible behavior only after its intended scope is
  recorded, all required CI and release-trust gates pass, migration/compatibility
  effects are documented, and the exact candidate and target are bound by the
  release evidence. It must never be gated on dates, elapsed time, or a
  stabilization window; relevant drift invalidates the evidence and requires an
  immediate re-run instead of a calendar wait.
- A major release is required for an intentional break in public CLI, schema,
  canonical-byte, signature-domain, policy, or verifier contract. It requires
  a migration guide and retained verification for the preceding stable line.
- Published tags, assets, checksums, attestations, and release ledgers are
  immutable. A defect creates a new version or erratum; it never retargets or
  replaces a published object.
- Starting with the next product release, the source release commit must be the
  exact GitHub-verified protected-branch object with its required checks, and an
  annotated release tag signed by the pinned maintainer key must bind that
  object. The signed tag is the maintainer's release authorization; requiring
  the local maintainer key on a GitHub-generated PR merge commit would make the
  protected PR path inoperable without adding assurance. If tag-signing
  authority is unavailable, the product release is blocked rather than silently
  downgraded.

This repository makes no general support-duration or service-level promise.
Any commercial maintenance window or SLA is established by a separate written
agreement with EvoRise Tech.

## Security-policy changes

The following are security-policy changes, not ordinary feature edits:

| Surface | Why it is security-sensitive |
|---|---|
| `.evoguard.json` and protected-path rules | Defines what may be changed and what a `PASS` means. |
| Verifier Pack files and digest pins | Defines the behavioural oracle and evidence identity. |
| `.github/workflows/`, `action.yml`, and workflow action pins | Defines token, artifact, checkout, and execution authority. |
| `examples/trusted-finalizer/` and finalizer modules | Defines the separation between untrusted execution and privileged sealing. |
| Guard release asset SHA, finalizer Environment/key/reviewer | Defines the executable and authority used to sign an admission decision. |
| This file, `SECURITY.md`, and assurance documentation | Defines the published threat model and non-guarantees. |

Any change in this table requires an explicit threat-model review. Open pull
requests must be re-verified after it lands; an earlier finalizer result did not
run under the new policy.

The review routing is intentionally narrow. It covers GitHub configuration,
the core verifier/finalizer implementation, finalizer templates, release
definition, and documents that state an assurance or trusted-boundary claim.
See [`.github/CODEOWNERS`](.github/CODEOWNERS) and
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the exact path mapping and contribution
requirements.

## Required state before production finalizer enforcement

Before a repository makes the finalizer a required merge condition, it must have:

1. The controls in
   [`docs/RELEASE_GATE_CHECKLIST.md`](docs/RELEASE_GATE_CHECKLIST.md) have
   been evaluated for that deployment.
2. A protected default branch that also protects policy, pack, and workflow paths.
3. A protected `evoguard-finalizer` Environment holding the private key, with a
   real reviewer distinct from the candidate author.
4. A protected Guard release SHA and fully pinned GitHub Actions.
5. A recorded operational audit of repeated Check Run behaviour and raw-Git
   finalizer evidence for the deployed version.
6. A policy for re-running every open PR after any security-policy change.

Until those conditions are true, finalizer output is a pilot record, not a
production merge authorization.

## Independent evaluation

An independent efficacy claim needs a person or organization that does not
control the product, case selection, labels, and interpretation. Labels and
manifests must be frozen before runs, tuning cases separated from held-out cases,
and raw outcomes retained. The evaluation repository records these requirements;
same-owner cross-account testing is operational evidence only.
