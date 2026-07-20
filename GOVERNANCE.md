<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Governance and trust boundaries

EvoOM Guard is a change-admission evidence system. Its security claims depend on
who can change the policy, the judge, the workflow, and the signing boundary.
This file records the present governance truth rather than implying a review
process that does not exist.

## Current status

The authoritative repository is currently maintained by one owner.
`@MANA-awam` is a second GitHub account controlled by that same owner. The
repository's [`CODEOWNERS`](.github/CODEOWNERS) mapping uses it for a technically
separate review workflow on trust-root paths; it is **not** independent review,
third-party validation, or a separate security authority.

`CODEOWNERS` is a routing file, not a security control by itself. It becomes an
enforced control only when GitHub branch protection or a ruleset requires code
owner review, protects `CODEOWNERS` itself, and the listed account retains the
necessary repository access. It must never be cited as evidence of an
independent audit. The operational rules for the current v3.7 boundary are in
[`docs/GOVERNANCE.md`](docs/GOVERNANCE.md).

The core repository's v3.7.0 raw-Git Trusted Finalizer remains a reference
deployment; it is not an active merge requirement here.

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

- Use `docs/RELEASE_GATE_CHECKLIST.md` as the hardening control ledger for this repository before merge gating.
Before a repository makes the finalizer a required merge condition, it must have:

1. A protected default branch that also protects policy, pack, and workflow paths.
2. A protected `evoguard-finalizer` Environment holding the private key, with a
   real reviewer distinct from the candidate author.
3. A protected Guard release SHA and fully pinned GitHub Actions.
4. A recorded operational audit of repeated Check Run behaviour and raw-Git
   finalizer evidence for the deployed version.
5. A policy for re-running every open PR after any security-policy change.

Until those conditions are true, finalizer output is a pilot record, not a
production merge authorization.

## Independent evaluation

An independent efficacy claim needs a person or organization that does not
control the product, case selection, labels, and interpretation. Labels and
manifests must be frozen before runs, tuning cases separated from held-out cases,
and raw outcomes retained. The evaluation repository records these requirements;
same-owner cross-account testing is operational evidence only.
