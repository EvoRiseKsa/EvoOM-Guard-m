<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# v3.7.0 external-review runbook

This runbook freezes the instructions for reviewing the already immutable
EvoOM Guard `v3.7.0` release. It is not a product release, a result of an
independent review, or an amendment to the v3.7.0 executable.

## Verify two separate immutable identities

First verify the target that may be tested:

| Item | Exact identity |
| --- | --- |
| Product repository | `EvoRiseKsa/EvoOM-Guard-m` |
| Product release tag | `v3.7.0` |
| Resolved product commit | `1f0ceae5009198b1bf161a3a07fced54c1f01337` |
| Product asset | `evo-guard.pyz` |
| Product asset SHA-256 | `1d36f7ec45f47f9f6c3178a25a58accf8f8beb0ffd9d29e7bf93b7fe17ad3ec9` |

Then obtain this review companion only from its own frozen tag:

```bash
git clone https://github.com/EvoRiseKsa/EvoOM-Guard-m.git evoguard-review-companion
git -C evoguard-review-companion fetch --tags --force
git -C evoguard-review-companion checkout --detach review-v3.7.0-r1
git -C evoguard-review-companion rev-parse HEAD
```

The resolved companion commit is an input to the review report. Do not replace
it with `main`, a current web page, or a copied instruction file. Next run the
default **identity-only** verification from that detached companion checkout:

```bash
cd evoguard-review-companion
bash audit/v3.7.0/reproduce.sh /tmp/evoguard-v3.7.0-review
```

On Windows PowerShell:

```powershell
& .\audit\v3.7.0\reproduce.ps1 -OutputDirectory "$env:TEMP\evoguard-v3.7.0-review"
```

The default scripts verify the GitHub release attestation, downloaded asset
hashes and sizes, the `SHA256SUMS` bytes, and the source tag. They intentionally
do not execute the zipapp. Add `--smoke` or `-Smoke` only in a disposable,
authorized environment; `python -I` is not a sandbox or a no-side-effects
claim.

## Authorized testing boundary

The public target may be downloaded and inspected. Test exploit attempts only
in a disposable repository and runner you control. Do not test third-party
repositories, GitHub shared infrastructure, personal accounts you do not own,
or any production deployment. Do not exfiltrate data, attempt service
disruption, retain credentials, or publish a working bypass before coordinated
disclosure.

No review requires a finalizer private key, `EVOGUARD_FINALIZER_KEY`, personal
access token, Actions token, cookie, Environment export, or time-limited URL.
If a key-bearing deployment is relevant, provide a non-secret reproducer and
ask the maintainer to run it in a controlled environment.

## Scope and result taxonomy

The requested surface is exactly the seven properties in
[TEST_MATRIX.md](TEST_MATRIX.md). The core repository's Trusted Finalizer is a
reference template, not its enabled merge gate; evaluate a consumer deployment
only as a separately named configuration. Artifact Admission V1 is a
file-to-pre-merge-finalizer relation, not build provenance, OCI registry proof,
release publication, deployment authorization, SBOM coverage, or vulnerability
status.

For every property, report one of:

- `finding` — a reproducible failure within a stated claim;
- `tested-no-finding` — the exact paths exercised and environment;
- `partial` — what was tested and why coverage is incomplete;
- `not-tested` or `not-applicable` — with a reason.

Use [REVIEW_REPORT_TEMPLATE.md](REVIEW_REPORT_TEMPLATE.md). A negative result
is not a general endorsement, an effectiveness rate, an independent audit, or
proof of immunity.

## Reporting

Potential vulnerabilities belong in the private reporting route in
[`SECURITY.md`](../../SECURITY.md), not in issue #80 or a public pull request.
Issue #80 is a public coordination and scope record only. Report the reviewer's
relationship to EvoRiseKsa and MANA-awam. Work performed solely by those two
owner-controlled accounts is useful technical-role evidence but is not an
independent review.
