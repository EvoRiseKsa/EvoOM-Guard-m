<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# EvoOM Guard

[![CI](https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/workflows/ci.yml/badge.svg)](https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/workflows/ci.yml)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-EvoOM%20Guard-B93A2B?logo=github)](https://github.com/marketplace/actions/evoom-guard)
[![Release](https://img.shields.io/github/v/release/EvoRiseKsa/EvoOM-Guard-m?color=1E7B4F)](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/latest)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: Source-available](https://img.shields.io/badge/license-source--available-lightgrey)](LICENSE)

**Policy- and evidence-bound verification for untrusted software changes, with
AI-generated patches as the primary use case.**

EvoOM Guard asks one narrow question: did this change satisfy the selected
judge without editing or deleting an evidence path protected by the active
policy? It runs the candidate in a throwaway copy, reports a stable verdict,
and can emit machine-readable evidence for CI and offline verification.

It does not infer who wrote a change. A `PASS` is not proof of complete
correctness or security; it means only that the selected judge passed within
the recorded policy and assurance boundary.

> **Naming:** EvoOM Guard is the product, `evo-guard` is the CLI, and
> `evoom_guard` is the Python package.

## Release channel

Use an immutable release tag or full commit SHA in consumer repositories. Do
not use `@main` as a production release channel.

<!-- BEGIN EVOGUARD_PROJECT_STATUS:README_RELEASE_CHANNEL -->
Source version `4.6.0.dev0` is **unreleased development** and is not a consumer release.
The latest immutable consumer release recorded by the protected source tree is
[`v4.5.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.5.0) at commit
`6bb4c328e56661b661e50532886802c6ba36a997`. Its `evoguard-release-ledger-v2` ledger
records the release assets `evo-guard.pyz`, `evo-guard.spdx.json`, `SHA256SUMS`. Its
release attestation binds `evo-guard.pyz`, `evo-guard.spdx.json`, `SHA256SUMS`, while
its build-provenance attestation binds `evo-guard.pyz`. The ledger records the SPDX SBOM
release asset and its provenance. Canonical ledger:
`evidence/release-ledgers/v4.5.0/RELEASE_LEDGER.json`.

The protected A-H release pipeline is implemented in source and **disabled by default**.
The legacy release workflow is hard-disabled. The externally anchored signed v2 ledger
records a completed protected A-H operation. That validated ledger also records the
resulting publication. An admitted release is contracted to exactly `evo-guard.pyz`,
`evo-guard.spdx.json`, `SHA256SUMS`; this source contract is not evidence that those
assets were published.
<!-- END EVOGUARD_PROJECT_STATUS:README_RELEASE_CHANNEL -->

The two post-publication correction records are
[`docs/errata/V4.4.0-LEDGER.md`](docs/errata/V4.4.0-LEDGER.md) and
[`docs/errata/V4.4.1-LEDGER.md`](docs/errata/V4.4.1-LEDGER.md). Their linked
`UNSEALED_STATUS.json` files are separate unsigned observations, not the
missing release ledgers. `v4.4.1` is the later exception.

The repository documentation follows the repository source and may describe
features not present in the latest ledger-recorded consumer release. Confirm
each page's version and evidence boundary before copying a command.

## Install and run

EvoOM Guard is not distributed through PyPI. Install the recorded release
directly from GitHub:

<!-- BEGIN EVOGUARD_PROJECT_STATUS:README_QUICKSTART_PIN -->
```bash
pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m@v4.5.0"   # ledger-recorded release; pin a SHA for strictest CI

# From the branch you want checked (the diff is reverse-applied to a
# throwaway copy; your working tree is never modified):
git diff main...HEAD | evo-guard guard --diff - --no-config --test-command "python -m pytest -q"
```
<!-- END EVOGUARD_PROJECT_STATUS:README_QUICKSTART_PIN -->

For a no-install path, download
[`evo-guard.pyz`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/download/v4.5.0/evo-guard.pyz),
[`evo-guard.spdx.json`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/download/v4.5.0/evo-guard.spdx.json),
and [`SHA256SUMS`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/download/v4.5.0/SHA256SUMS)
from the [`v4.5.0` release](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.5.0).
Run `sha256sum -c SHA256SUMS`, then `python -I evo-guard.pyz ...`.

The command never edits the checked working tree: it applies the diff to a
throwaway copy and runs the selected judge there.

## Read the verdict

| Verdict | Meaning | Exit |
|---|---|---:|
| `PASS` | The selected judge passed and no effective-policy protected path was edited or deleted. | 0 |
| `REJECTED` | The change tripped the protected-path policy before the suite ran. This is a policy result, not proof of intent. | 1 |
| `FAIL` | The change was applied and the selected judge failed. | 1 |
| `TAMPERED` | Recorded execution facts disagree, or a trusted identity changed during judgment. | 1 |
| `ERROR` | Verification could not complete safely, including invalid input, setup failure, timeout, unavailable isolation, or an unmet assurance floor. | 1 |

Every run can write JSON with a stable `schema_version`, fixed `reason_code`,
execution state, policy identity, and assurance profile:

```bash
git diff main...HEAD |
  evo-guard guard --diff - --no-config \
    --test-command "python -m pytest -q" \
    --json verdict.json --report verdict.md --sarif verdict.sarif
```

Integrations should use `verdict`, `reason_code`, and the documented schema,
not parse terminal text. See [JSON contract](docs/JSON_SCHEMA.md).

## Use it in GitHub Actions

Generate a workflow and a base-owned `.evoguard.json` policy:

<!-- BEGIN EVOGUARD_PROJECT_STATUS:README_INIT_PIN -->
```bash
evo-guard init --ref v4.5.0 --test-command "python -m pytest -q"
```
<!-- END EVOGUARD_PROJECT_STATUS:README_INIT_PIN -->

Review and commit both generated files. On pull requests, the Action derives
the policy from the verified base revision rather than candidate-controlled
workflow inputs.

Alternatively, add the Action directly:

<!-- BEGIN EVOGUARD_PROJECT_STATUS:README_ACTION_PIN -->
```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
    with:
      fetch-depth: 0
      persist-credentials: false
  - uses: EvoRiseKsa/EvoOM-Guard-m@v4.5.0   # ledger-recorded release; pin a SHA for strictest CI
    with:
      comment: "false"   # explicit for older releases; candidate jobs never comment
      fail-on: "any-non-pass"
```
<!-- END EVOGUARD_PROJECT_STATUS:README_ACTION_PIN -->

Protect the workflow with repository rules, required checks, and appropriate
review controls. A candidate job should not receive secrets or PR-write
permissions. If comments are required, use a separate metadata-only job that
never checks out or executes candidate code.

## Choose an assurance path

| Need | Path | Start with |
|---|---|---|
| Block edits to modeled test, configuration, CI, and judge paths | Basic integrity gate | [`GUARD.md`](docs/GUARD.md) |
| Add organization-owned checks outside the candidate tree | Verifier pack | [`VERIFIER_PACKS.md`](docs/VERIFIER_PACKS.md) |
| Judge a CLI through an external report channel | Black-box, preferably `--blackbox-only` | [`BLACKBOX.md`](docs/BLACKBOX.md) |
| Add a delivered container or gVisor boundary | Isolated execution | [`BLACKBOX.md`](docs/BLACKBOX.md#boundary-evidence-is-observed-never-inferred-from-policy) |
| Evaluate named assurance profiles in ledger-recorded `v4.5.0` | `v4.5.0` profiles (verify runtime evidence) | [`OPERATING_PROFILES.md`](docs/OPERATING_PROFILES.md) |
| Produce portable, authenticated evidence | Signed verdict or evidence bundle | [`SIGNED_VERDICTS.md`](docs/SIGNED_VERDICTS.md) |
| Separate re-verification, signing, and final admission | Trusted Finalizer | [`TRUSTED_FINALIZER.md`](docs/TRUSTED_FINALIZER.md) |
| Project signed `ALLOW` and `DENY` attempts for advisory analysis | Change Attempt Observation V1 *(included in v4.5.0)* | [`CHANGE_ATTEMPT_OBSERVATION.md`](docs/CHANGE_ATTEMPT_OBSERVATION.md) |

The bounded, same-owner development-snapshot corpus for Change Attempt
Observation V1 is recorded with exact hashes and explicit non-claims in
[`change-attempt-corpus-v1.md`](docs/evidence/change-attempt-corpus-v1.md).

Current unreleased source also contains a library-only
[Artifact Provider V3](docs/ARTIFACT_PROVIDER_V3.md) path for one canonical,
digest-qualified public GHCR subject (not an anonymous-registry-access claim).
It relates one exact GitHub Artifact
Attestation direct same-revision branch build and builder run/attempt to
external Trusted Finalizer context, then uses unchanged V2 to bind the exact
subject and receipt. It has no CLI, protected workflow, or live OCI pilot and
must not be described as SLSA compliance, reproducibility, image safety,
vulnerability status, registry retention, publication, deployment, or runtime
identity.

The isolated path does not inherit Docker registry configuration, and no live
pilot has yet proved a compatible protected registry-auth mechanism.

For an adoption decision, start with the
[production blueprint](docs/PRODUCTION_BLUEPRINT.md). Advanced release-source,
artifact-admission, and publication contracts are separate boundaries; none
should be treated as proof of another.

## Minimal trusted policy

Store judge-shaping settings in the protected base version of
`.evoguard.json`:

```json
{
  "test_command": ["python", "-m", "pytest", "-q"],
  "timeout": 180,
  "strict_harness": true,
  "harness_inputs": ["ci/run-tests.sh"]
}
```

EvoOM Guard recognizes conventional test, build, CI, configuration, and
auto-execution paths. It does not discover a complete transitive harness graph.
Declare repository-owned wrappers and helpers explicitly as `harness_inputs`.
Built-in protected paths and declared harness inputs cannot be waived by
`allow`; legitimate changes require a separately trusted policy-maintenance
path.

## Honest limits

- `PASS` is evidence about the selected judge, policy, candidate, and delivered
  assurance profile. It is not merge authority or proof of correctness,
  security, deployment, authorship, or complete harness discovery.
- The repository-native test channel shares a process with candidate code. A
  deliberate process-level report forgery can fake that channel. Use a
  meaningful judge-owned verifier pack with `--blackbox-only` to remove it.
- Host-subprocess execution shares an OS identity and filesystem. Container or
  gVisor modes add a boundary only when the verdict records that the requested
  isolation was actually delivered.
- The base policy, workflow, verifier pack, keys, and final admission step must
  remain outside candidate control. A tool cannot compensate for an
  unprotected deployment.
- Published same-owner demonstrations and pilots are reproducible operational
  evidence, not independent validation. See the
  [independent evaluation protocol](docs/INDEPENDENT_EVALUATION.md).
- Source admission, artifact admission, publication, and deployment are
  distinct decisions. Evidence for one does not silently authorize another.

The full threat and evidence model is in
[Assurance](docs/ASSURANCE.md), [Reward-hacking catalog](docs/REWARD_HACKING_CATALOG.md),
and [Repository protection](docs/REPOSITORY_PROTECTION.md).

## Documentation

Use the [documentation index](docs/README.md) to choose a path by audience.

| Entry point | Purpose |
|---|---|
| [Start here](docs/START_HERE.md) | Choose the basic, black-box, isolated, or finalizer path. |
| [Adoption guide](docs/ADOPTION.md) | Introduce the gate into a repository and interpret results. |
| [Guard reference](docs/GUARD.md) | CLI, policy, input forms, and execution behavior. |
| [Assurance](docs/ASSURANCE.md) | Trust boundaries, failure modes, and non-claims. |
| [JSON contract](docs/JSON_SCHEMA.md) | Stable machine-readable verdict fields. |
| [Production blueprint](docs/PRODUCTION_BLUEPRINT.md) | Deployment profiles and readiness requirements. |
| [Project and release status](docs/PROJECT_STATUS.md) | Current implementation, evidence, and release boundary. |

Historical demonstrations, release procedures, architecture decisions, and
advanced admission contracts remain public and discoverable through the index
without crowding this landing page.

## Release provenance

<!-- BEGIN EVOGUARD_PROJECT_STATUS:README_ATTESTATION_SCOPE -->
Historical `v3.7.0` has a GitHub release attestation but no GitHub Actions
build-artifact attestation. The validated `v4.5.0` ledger records build provenance whose
subject is `evo-guard.pyz` under
`.github/workflows/evoguard-build-release-artifact.yml`. Its release attestation
separately binds `evo-guard.pyz`, `evo-guard.spdx.json`, `SHA256SUMS` and records SPDX
SBOM provenance. Provider attestations are provenance evidence, not an EvoOM Guard
verdict, artifact-admission decision, or proof of deployment. See
[`docs/GITHUB_ARTIFACT_ATTESTATIONS.md`](docs/GITHUB_ARTIFACT_ATTESTATIONS.md) for the
bounded procedure.
<!-- END EVOGUARD_PROJECT_STATUS:README_ATTESTATION_SCOPE -->

Release assets, checksums, tags, ledgers, and attestations are retained as
historical evidence. See [release status](docs/RELEASE_STATUS.md),
[governance](docs/GOVERNANCE.md), and [SBOM scope](docs/SBOM.md).

## Security, contribution, and feedback

Use [SUPPORT.md](SUPPORT.md) to choose the correct support or reporting route.
Report vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue.
The public/private operating boundary is documented in
[governance](docs/GOVERNANCE.md). Never publish signing keys, credentials,
customer policy, held-out evaluation data, or private operational logs.

Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Copyright © 2026 EvoRise Tech. All rights reserved. Mana Alharbi is the author
and original creator; EvoRise Tech is the Licensor.

Current v4 material is source-available under the
[EvoRise Source-Available License 1.0](LICENSE), not open source. Commercial,
production, required-CI or merge-gate, redistribution, hosted, and managed
service use require a separate agreement; see
[commercial licensing](COMMERCIAL-LICENSING.md). Historical releases retain the
license shipped with their exact version; see [license history](LICENSE_HISTORY.md).
