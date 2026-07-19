<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Contributing to EvoOM Guard

EvoOM Guard is a verification gate. A change can affect not only behaviour but
also what a `PASS`, `ALLOW`, or signed evidence bundle means. This guide keeps
ordinary maintenance separate from changes to that trust boundary.

This document describes the engineering process; it does not grant permission
beyond the [LICENSE](LICENSE). Submit only material that you have the right to
share.

## Contribution and licensing boundary

For a contribution first accepted into a future v4 release, the contributor
must have authority to grant the contribution terms in Section 9 of the v4
`LICENSE`. The project may require a separate Contributor License Agreement
before accepting it. This prospective condition does **not** retroactively
relicense historical releases, third-party material, or prior contributors'
work; those remain governed by their existing notices and agreements.

Do not submit employer-owned, customer-owned, confidential, export-controlled,
or third-party material unless you have written authority to license it on the
applicable terms. See [THIRD_PARTY.md](THIRD_PARTY.md).

## Before opening a pull request

1. Start from the current default branch; do not modify an existing release tag
   or release asset. In particular, `v3.7.0` is an immutable release record,
   not a moving development branch.
2. Keep the change narrow and explain the observed problem, intended behaviour,
   and any compatibility effect in the pull request.
3. Add or update tests for a behavioural change. Do not weaken an existing test,
   test configuration, CI workflow, or verifier pack to make a result pass.
4. Run the checks appropriate to the change. The local baseline is:

   ```bash
   python -m pytest -q
   ruff check evoom_guard/ tests/
   mypy evoom_guard/
   ```

   Docker and black-box changes also need the relevant isolated test path from
   the CI workflow. A green local test run is not a substitute for reviewing an
   assurance claim.

5. For a security issue or a possible false `PASS`, use the private reporting
   process in [SECURITY.md](SECURITY.md), not a public pull request or issue.

## Changes that alter the trust boundary

Treat the following as security-policy changes, even when the diff is small:

- `.github/`, `action.yml`, dependency/tooling pins, or release workflow logic;
- `.evoguard.json`, protected-path behaviour, verifier-pack identity, or test
  command selection;
- code under `evoom_guard/` that derives a verdict, assurance field, evidence
  record, signature, finalizer binding, or artifact-admission binding;
- `examples/trusted-finalizer/`, including token scopes, artifact names,
  Environment/key controls, or raw-Git derivation logic; and
- documentation that states a threat model, assurance level, deployment
  prerequisite, or a limitation of the v3.7.0 Trusted Finalizer or Artifact
  Admission V1.

Such a pull request must include all of the following:

1. The specific invariant or threat-model change.
2. A test or reproducible negative case showing why the new behaviour is
   needed.
3. The expected effect on existing records, policies, open pull requests, and
   consumer deployments.
4. A note about whether finalizer/evidence results must be re-run because a
   policy, pack, Guard executable digest, Environment, reviewer, or workflow
   binding changed.

The required controls are explained in
[GOVERNANCE.md](GOVERNANCE.md),
[docs/GOVERNANCE.md](docs/GOVERNANCE.md), and
[docs/REPOSITORY_PROTECTION.md](docs/REPOSITORY_PROTECTION.md).

## Review and ownership

`.github/CODEOWNERS` designates `@MANA-awam` for the core trust-root paths.
That account is controlled by the same project owner as `@EvoRiseKsa`; it gives
the project a technically separate GitHub review identity but is **not** an
independent reviewer or external validation. Code-owner approval only becomes
an enforced control after GitHub branch protection/ruleset configuration
requires it. Do not describe the presence of `CODEOWNERS` alone as a security
guarantee.

For a production consumer deployment, use a reviewer and Environment authority
that are genuinely distinct from the candidate author. The reference Trusted
Finalizer is not enabled as this repository's own merge gate; see
[docs/TRUSTED_FINALIZER.md](docs/TRUSTED_FINALIZER.md).

## Evidence and release changes

- Preserve historical evidence exactly. Do not rewrite a benchmark, a signed
  bundle, or a frozen record to make a newer version look better.
- A new release needs a new tag, a recorded asset digest, and validation against
  the source it actually contains. Documentation-only corrections do not make a
  past release retroactively different.
- Artifact Admission V1 binds one regular-file digest to a pre-merge finalizer
  `ALLOW`; it is not release provenance, OCI verification, deployment proof, or
  an SBOM/vulnerability claim. See
  [docs/ARTIFACT_ADMISSION.md](docs/ARTIFACT_ADMISSION.md).
- Do not claim independent efficacy, accuracy, or security audit results unless
  the case selection, labels, reviewer, and methodology are actually
  independent and retained as evidence.

## Documentation

When behaviour or an assurance boundary changes, update the closest canonical
document and state both the strengthened guarantee and the remaining limit.
Avoid changing historical documents to imply that an older release had later
behaviour. Link a current document instead.
