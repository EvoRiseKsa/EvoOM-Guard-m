<!--
  Copyright (c) 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available - see LICENSE for permitted use.
-->

# EvoOM Guard v4.5.0 external-review companion

This directory is a review aid for the immutable [`v4.5.0` release][release].
It is not part of that release, does not amend its claims, and is not an
independent-review result. The exact product target is commit
`6bb4c328e56661b661e50532886802c6ba36a997`, tree
`bd81a595ca8608ad7da04390f31d5e489f5083ef`, and the three assets pinned in
[`manifest.json`](manifest.json).

The release commit is **not signed**. GitHub reports
`commit.verification.verified=false` and `reason=unsigned`. The GitHub Release
has a separate release attestation; that attestation must not be described as
a commit signature. Both facts are checked by the reproduction scripts.

This companion is source-controlled at `audit/v4.5.0` and separately frozen at
[`review-v4.5.0-r1`][companion]. That tag freezes these reviewer instructions;
it is not a product release and does not alter `v4.5.0`. The frozen product
target remains the immutable product Release, not a moving `main` checkout.

[release]: https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.5.0
[companion]: https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/review-v4.5.0-r1

## Identity-only verification

On Linux or WSL:

```bash
bash audit/v4.5.0/reproduce.sh /tmp/evoguard-v4.5.0-review
```

On Windows PowerShell:

```powershell
& .\audit\v4.5.0\reproduce.ps1 `
  -OutputDirectory "$env:TEMP\evoguard-v4.5.0-review"
```

By default the scripts do **not** execute the released zipapp, candidate code,
workflow artifacts, or signing material. They require a valid GitHub Release
attestation, verify exact Release metadata and asset bytes, resolve the tag and
tree, confirm the expected unsigned commit observation, and pin the successful
tag CI run. `--smoke` / `-Smoke` optionally executes only `version` and
`doctor` in an authorized disposable environment. Python `-I` is import
isolation, not a sandbox.

If `gh release verify` cannot initialize a Sigstore verifier, the script fails.
That is an unverified environment, not proof that the attestation is valid or
invalid. Record the CLI version, trust-root state, network path, and error.

## Evidence that is deliberately outside the target

The signed Release Ledger v2 now retained on `main` has SHA-256
`9ee6c49e7a3c93d611c34e208f5e3936f147bf0ed0b8ff2c41b3e53b891da239`.
It was committed after publication and is absent from the `v4.5.0` tree. It is
same-owner evidence, and validation requires an externally supplied root plus
a disjoint trusted-parent checkout. Follow the exact separation procedure in
[`REVIEWER_RUNBOOK.md`](REVIEWER_RUNBOOK.md).

The gVisor record under
`evidence/runtime-observations/v4.5.0-gvisor-31298956172` is also a later,
same-owner, non-production observation on current `main`. It is not inside the
immutable release ledger and is not independent or field-efficacy evidence.
Firecracker remains design-only.

## Review scope and reporting

[`TEST_MATRIX.md`](TEST_MATRIX.md) maps issue [#141][issue] to exact test entry
points present in the frozen source tree and to adversarial boundaries. Use
[`REVIEWER_RUNBOOK.md`](REVIEWER_RUNBOOK.md) and
[`REVIEW_REPORT_TEMPLATE.md`](REVIEW_REPORT_TEMPLATE.md). A passing identity
script proves target identity only; it does not prove security, efficacy,
production readiness, compliance, or independence.

`EvoRiseKsa` and `MANA-awam` are controlled by the same owner. Their separate
accounts, PRs, approvals, environments, and pilots are operational separation,
not independent review. Potential vulnerabilities belong in the private route
documented by the frozen `SECURITY.md`, not in issue #141 or a public PR.

[issue]: https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues/141
