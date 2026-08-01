<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# Trusted Finalizer deployment kit

The deployment kit turns the reviewed Trusted Finalizer reference into a
deterministic, no-clobber consumer installation. It installs the current
workflow pair, a public verification key, and a machine-readable manifest; it
then checks those committed inputs and the finalizer policy without contacting
GitHub.

This command set is repository-source behavior added after the immutable
`v4.5.0` tag. The generated workflows deliberately download the reviewed
`v4.5.0` runtime and bind its published zipapp SHA-256. Do not claim that the
kit itself shipped in `v4.5.0`; use the exact source commit or a later release
that contains this page and these commands.

## Install into a new consumer repository

Generate the finalizer Ed25519 keypair in a protected operator environment.
Keep the private PEM outside the repository. Pass only the public
SubjectPublicKeyInfo PEM to the installer:

```bash
umask 077
openssl genpkey -algorithm Ed25519 -out finalizer.key.pem
openssl pkey -in finalizer.key.pem -pubout -out finalizer.pub.pem
```

On Windows, generate the same files in an access-controlled directory and
restrict `finalizer.key.pem` to the operator account before continuing. Never
place the private PEM under the consumer repository root.

```bash
evo-guard finalizer-init \
  --root /path/to/consumer \
  --public-key /protected/operator/finalizer.pub.pem
```

The command writes exactly these paths:

```text
.github/workflows/evoguard-reverify.yml
.github/workflows/evoguard-seal.yml
.evoguard/finalizer-deployment.json
security/evoguard-finalizer.pub.pem
```

It refuses to continue if any target already exists. There is intentionally no
`--force`: an existing deployment must be upgraded by a reviewed diff, not by
silently replacing protected workflow or trust-root files. The installer never
writes a private key, policy, verifier pack, CODEOWNERS file, repository
variable, secret, Environment, or ruleset.

The committed deployment manifest uses
`EVOGUARD_FINALIZER_DEPLOYMENT_V1`; its schema is
[`finalizer-deployment-1.schema.json`](../evoom_guard/schemas/finalizer-deployment-1.schema.json).
The installed public PEM is canonicalized and bound by both its file SHA-256
and a DER-based `sha256:` key ID. Runtime provenance metadata also records the
exact v4.5.0 source commit and raw release-ledger SHA-256. Those fields aid an
offline audit; the workflow's executable trust root remains the separately
protected zipapp digest.

## Add the trusted-base judge policy

The consumer must separately commit `.evoguard.json` and the referenced
verifier pack. The static finalizer floor requires:

- `blackbox: true` and `blackbox_only: true`;
- `require_report_integrity: external_process_isolated`;
- `isolation: docker` or `gvisor`, with an identical
  `require_candidate_isolation`;
- `docker_network: none` (absence has the same workflow default);
- no trusted host setup;
- an image ending in an immutable lowercase `@sha256:<64 hex>` digest; and
- a repository-relative verifier-pack path whose actual framed pack digest
  equals `expect_verifier_pack_sha256`.

The static doctor uses the same strict policy parser and framed pack digest as
Guard. It rejects policy, pack, workflow, manifest, and public-key drift:

```bash
evo-guard finalizer-doctor --root /path/to/consumer
evo-guard finalizer-doctor --root /path/to/consumer --json
```

JSON output uses `EVOGUARD_FINALIZER_DEPLOYMENT_REPORT_V1`; its schema is
[`finalizer-deployment-report-1.schema.json`](../evoom_guard/schemas/finalizer-deployment-report-1.schema.json).
A zero exit code means `static_ready: true`. It always reports
`github_controls_checked: false` and `enforcement_ready: false`, because this
first kit does not call the GitHub API.

## Complete the live GitHub controls

Static success is a prerequisite, not admission readiness. Complete and
independently review every live step in
[`TRUSTED_FINALIZER.md`](TRUSTED_FINALIZER.md#required-repository-controls):

1. Set protected repository variable `EVOGUARD_GUARD_ARTIFACT_SHA256` to the
   reviewed `v4.5.0` `evo-guard.pyz` digest recorded by the kit manifest.
2. Create Environment `evoguard-finalizer`, add distinct required reviewers,
   and store the private PEM only as Environment secret
   `EVOGUARD_FINALIZER_KEY`.
3. Dispatch `EvoOM Guard Reverify` once. Record its numeric workflow ID in
   protected variable `EVOGUARD_REVERIFY_WORKFLOW_ID`, then start a new full
   attempt.
4. Protect the workflows, policy, verifier pack, public key, and default branch
   through CODEOWNERS/ruleset controls.
5. Complete the Round 1 retry/check-lifecycle audit before making `EvoOM Guard
   Trusted Finalizer` a required merge check.

No local report can prove those provider-side facts. Retain screenshots or API
exports and the Round 1 run URLs as separate operational evidence.

## Scope and non-claims

The kit removes copy/paste and version-drift errors from a specific deployment
contract. It does not make Docker a hostile-code security boundary, prove the
judge's tests are sufficient, configure GitHub, rotate or escrow keys, support
fork PRs, or turn a static `PASS` into a production-ready claim. The supplied
workflows remain limited to open same-repository PRs targeting the protected
default branch.
