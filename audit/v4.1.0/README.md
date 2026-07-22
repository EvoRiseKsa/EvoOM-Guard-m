<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# EvoOM Guard v4.1.0 external-review companion

This directory is a review aid, not an independent-review result and not part
of the frozen executable target. The target is the immutable
[`v4.1.0` release][release], resolved to commit
`16029f3e34237ed07b97649c5c9be35d0a356bf7`. Its two product assets are
`evo-guard.pyz` and `SHA256SUMS`; exact identities are in
[`manifest.json`](manifest.json).

The companion is frozen separately as [`review-v4.1.0-r1`][companion]. It is
not a Guard version, Marketplace publication, or amendment to `v4.1.0`. The
public coordination target is [issue #141][issue]. Potential vulnerabilities
belong in the private route documented by `SECURITY.md`, not that issue.

The separately preserved [Release Source Admission V2 Round 1][round1] is an
additional evidence target. It is bound to one exact protected-main source and
specific workflow attempts. It does not expand the product release's claims,
authorize an artifact or publication, or constitute independent review.

[release]: https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.1.0
[companion]: https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/review-v4.1.0-r1
[issue]: https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues/141
[round1]: https://github.com/EvoRiseKsa/evoom-guard-release-source-v2-pilot/blob/main/docs/ROUND1_EVIDENCE.md

## Identity-only verification

On Linux or WSL:

```bash
bash audit/v4.1.0/reproduce.sh /tmp/evoguard-v4.1.0-review
```

On Windows PowerShell:

```powershell
& .\audit\v4.1.0\reproduce.ps1 -OutputDirectory "$env:TEMP\evoguard-v4.1.0-review"
```

By default the scripts do **not** execute the released zipapp, candidate code,
workflow artifacts, or signing material. They verify GitHub's release
attestation, the exact assets and checksum bytes, the resolved source tag,
source tree, and commit signature. An optional `--smoke` / `-Smoke` executes
only `version` and `doctor` in a disposable authorized environment; Python
`-I` is import isolation, not a sandbox.

## What to review

[`TEST_MATRIX.md`](TEST_MATRIX.md) maps the requested properties to regression
entry points and adversarial questions. The main new surfaces since the older
v3.7 companion are:

- Release Source Admission V2 and its A/B/C/D reference topology;
- semantic validation and bounded lifecycle handling around GitHub Artifact
  Attestation provider output;
- executable-digest and root-to-nonroot provider isolation;
- five-domain key separation and provider-inaccessible signing-key paths; and
- the distinction between source admission, artifact binding, and release or
  deployment authorization.

Use [`REVIEWER_RUNBOOK.md`](REVIEWER_RUNBOOK.md) and
[`REVIEW_REPORT_TEMPLATE.md`](REVIEW_REPORT_TEMPLATE.md). Mark untested or
partially tested properties explicitly; a report with no finding covers only
the exercised paths.

## Independence and safe reporting

`EvoRiseKsa` and `MANA-awam` are controlled by the same owner. Their PR,
Environment, and pilot roles are useful operational separation but are not
independent review. An independent reviewer must disclose the relationship to
the project owner and who controlled case selection, labels, and interpretation.

Do not request or publish private keys, tokens, cookies, Environment exports,
credential-bearing URLs, or unredacted secret-bearing logs. Use only
repositories and runners you are authorized to test. Passing the identity
script proves target identity, not security, efficacy, production readiness,
or compliance.
