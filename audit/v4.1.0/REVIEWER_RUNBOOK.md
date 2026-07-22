<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# v4.1.0 external-review runbook

This runbook freezes instructions for reviewing EvoOM Guard `v4.1.0` and the
separately retained V2 Round 1 evidence. It is not an independent-review result
or an amendment to either target.

## Verify the two immutable review identities

| Item | Exact identity |
| --- | --- |
| Product release | `v4.1.0` |
| Product commit | `16029f3e34237ed07b97649c5c9be35d0a356bf7` |
| Product tree | `7c749ed298050840fdd52577e6364a6e63cd36a6` |
| Product asset SHA-256 | `d5ce7dbefa870307d6fe49ddec1e9847cad89d15f6afe2b74f4e7b8953fc62b2` |
| Review companion | `review-v4.1.0-r1` |

Obtain the companion from its frozen tag, not `main`:

```bash
git clone https://github.com/EvoRiseKsa/EvoOM-Guard-m.git evoguard-review-v410
git -C evoguard-review-v410 fetch --tags --force
git -C evoguard-review-v410 checkout --detach review-v4.1.0-r1
git -C evoguard-review-v410 rev-parse HEAD
cd evoguard-review-v410
bash audit/v4.1.0/reproduce.sh /tmp/evoguard-v4.1.0-review
```

On Windows, invoke `reproduce.ps1` instead. The default is identity-only and
does not execute the zipapp. Use the explicit smoke option only in a disposable
authorized environment.

## Verify the operational evidence separately

Round 1 is not bundled into the product release. Resolve the pilot ledger from
its exact repository and record the ledger commit you reviewed:

```bash
git clone https://github.com/EvoRiseKsa/evoom-guard-release-source-v2-pilot.git v2-pilot
git -C v2-pilot rev-parse HEAD
git -C v2-pilot show HEAD:docs/ROUND1_EVIDENCE.md
```

The positive claim is bound only to source
`af8e4592ef5572acfe2ea295c435eed6a8e122fc` and A/B/C attempts
`29896945747/1`, `29896982146/1`, and `29897001564/1`. The later evidence-
ledger commit is not itself admitted. Re-fetch run and repository metadata;
do not infer a current setting from a historical ledger.

## Authorized testing boundary

Inspect and download the public target. Execute exploit attempts only in a
disposable repository and runner you control. Do not test third-party systems,
shared data, production deployments, or GitHub infrastructure beyond ordinary
documented use. Do not exfiltrate data, disrupt service, retain credentials, or
publish a working bypass before coordinated disclosure.

No review requires an EvoRise private signing key, GitHub token from the
maintainer, cookie, or Environment export. If protected-key behavior matters,
provide a non-secret reproducer for controlled maintainer execution.

## Result taxonomy

For every property in [`TEST_MATRIX.md`](TEST_MATRIX.md), report one of:

- `finding`;
- `tested-no-finding`;
- `partial`;
- `not-tested`; or
- `not-applicable`.

Explain the exact paths and environment. A negative result is not a general
endorsement, measured error rate, proof of production readiness, or proof of
immunity from a different threat class.

## Reporting

Potential vulnerabilities belong in the private reporting route in
[`SECURITY.md`](../../SECURITY.md), not issue #141 or a public pull request.
Use [`REVIEW_REPORT_TEMPLATE.md`](REVIEW_REPORT_TEMPLATE.md), disclose the
reviewer's relationship and case-selection control, and hash safe retained
evidence. Work performed solely through `EvoRiseKsa` and `MANA-awam` is not an
independent external review.
