<!--
  Copyright (c) 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available - see LICENSE for permitted use.
-->

# EvoOM Guard v4.5.0 external-review report template

Do not include credentials, private keys, cookies, Environment exports,
credential-bearing URLs, or unredacted secret-bearing logs.

## 1. Target and companion confirmation

| Field | Required value or observation |
| --- | --- |
| Repository | `EvoRiseKsa/EvoOM-Guard-m` |
| Companion commit reviewed |  |
| Release | `v4.5.0`, ID `363544789`, immutable |
| Published | `2026-08-01T14:32:33Z` |
| Commit | `6bb4c328e56661b661e50532886802c6ba36a997` |
| Tree | `bd81a595ca8608ad7da04390f31d5e489f5083ef` |
| Commit verification | Expected `verified=false`, `reason=unsigned` |
| Release attestation | Result, CLI version, verifier/trust-root details |
| Runtime SHA-256 / bytes | `44bf036666bc7bb2903b647f33b63254771771887de4f170c91e8cdd8307c89d` / `2356398` |
| SPDX SHA-256 / bytes | `d073198e6a3a7d565895b3cf885c95386768670a243e05e5b1471636a0f8da4b` / `99797` |
| SHA256SUMS SHA-256 / bytes | `0172d35b903661328f16366517fe5a8f666aaf282cf26c5ec4e263da4abedd0f` / `166` |
| Tag CI | Run `30703985270`, expected successful head at product commit |
| Identity script | Command, exit status, retained output hash |

Stop and report any mismatch. A valid Release attestation is not a signed Git
commit, and the expected unsigned commit state is not itself a vulnerability.

## 2. Reviewer relationship and independence

- Reviewer / organization:
- Funding and engagement owner:
- Relationship to EvoRise Tech, EvoRiseKsa, MANA-awam, Mana Alharbi, or the project:
- Who controlled case selection, labels, execution, and interpretation:
- Is the reviewer independent of product and evidence control? Explain:
- Conflicts of interest:

`EvoRiseKsa` and `MANA-awam` are controlled by the same owner; separation
between them does not establish independence.

## 3. Environment and exact commands

| Item | Value |
| --- | --- |
| OS / architecture / clock source |  |
| Python / executable |  |
| Git / GitHub CLI |  |
| Dependency lock / installed hashes |  |
| Docker / gVisor / other boundary |  |
| Image references / resolved IDs |  |
| Network / credentials / resource limits |  |
| Cleanup and retention assumptions |  |
| Exact commands |  |

## 4. Requested-property results

Use `finding`, `tested-no-finding`, `partial`, `not-tested`, or
`not-applicable` for every row in `TEST_MATRIX.md`.

| Property | Status | Expected | Observed | Evidence |
| --- | --- | --- | --- | --- |
| Release identity / attestation / unsigned commit |  |  |  |  |
| Base authority / protected harness |  |  |  |  |
| Verdict / record / evidence / signature integrity |  |  |  |  |
| Assurance / lifecycle / cleanup / isolation |  |  |  |  |
| Pack identity / candidate execution |  |  |  |  |
| Trusted Finalizer |  |  |  |  |
| Release Source Admission V2 |  |  |  |  |
| GitHub attestation adapter |  |  |  |  |
| Release Artifact Admission V1 |  |  |  |  |
| Agent Change Admission / operating profiles |  |  |  |  |
| Action / ledger / publication controls |  |  |  |  |
| Later ledger / gVisor / Firecracker reconciliation |  |  |  |  |

## 5. Finding

### Title and severity rationale

### Exact published property or trust boundary

### Non-secret preconditions and minimal reproduction

### Expected versus observed result

Include exit status, decision/reason, lifecycle and assurance fields, skips,
retries, and safe raw-evidence hashes. State whether the unmodified frozen
target reproduces the result.

### Impact, scope, and limitations

### Suggested remediation and regression test

## 6. Evidence inventory

| Artifact | SHA-256 / identifier | Origin | Inside v4.5.0? | Retention / redaction |
| --- | --- | --- | --- | --- |
| Released zipapp |  | Immutable Release | yes |  |
| Released SPDX SBOM |  | Immutable Release | yes |  |
| SHA256SUMS |  | Immutable Release | yes |  |
| Source checkout |  | Fixed tag | yes |  |
| Release attestation |  | GitHub | external |  |
| Signed Release Ledger v2 | `9ee6c49e7a3c93d611c34e208f5e3936f147bf0ed0b8ff2c41b3e53b891da239` | Later `main` | no |  |
| gVisor public record |  | Later `main` / private source run | no |  |
| Test records / bundles / receipts |  | Reviewer environment | n/a |  |
| Logs |  | Reviewer environment | n/a | Redacted |

## 7. Claim-separation checklist

- [ ] Release attestation was not called a commit signature.
- [ ] Commit state was recorded as unsigned.
- [ ] Later ledger was not represented as a file in the frozen release tree.
- [ ] Same-owner evidence was not represented as independent review.
- [ ] gVisor was not upgraded to production, field, hostile-host, or VM proof.
- [ ] Firecracker remained classified as design-only.
- [ ] Environment-gated skips were not counted as tested passes.

## 8. Disclosure checklist

- [ ] Authorized repository and runner only.
- [ ] No secret, key, token, cookie, or credential-bearing URL retained.
- [ ] Potential vulnerabilities sent through private reporting.
- [ ] Safe evidence hashes and exact commands preserved.
- [ ] Untested paths, dependencies, and independence limits stated.

## 9. Interpretation

A useful finding identifies the frozen target, repeatable non-secret inputs,
expected and observed behavior, and impact within a published claim. A clean
report is not a general endorsement, measured field error rate, production
certification, compliance result, or proof of immunity.
