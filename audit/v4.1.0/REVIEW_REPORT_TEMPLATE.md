<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# EvoOM Guard v4.1.0 external-review report template

Do not include credentials, private keys, cookies, Environment exports, or
credential-bearing URLs.

## 1. Target confirmation

| Field | Required value or observation |
| --- | --- |
| Repository | `EvoRiseKsa/EvoOM-Guard-m` |
| Release | `v4.1.0` |
| Commit | `16029f3e34237ed07b97649c5c9be35d0a356bf7` |
| Tree | `7c749ed298050840fdd52577e6364a6e63cd36a6` |
| Asset SHA-256 | `d5ce7dbefa870307d6fe49ddec1e9847cad89d15f6afe2b74f4e7b8953fc62b2` |
| Asset size | `1388088` bytes |
| SHA256SUMS SHA-256 | `2e9839e838d9384a2f7200f9caddb336ffe043cd971f8151c9d3efb090fa4c3b` |
| Companion tag and commit |  |
| Identity script result |  |

Stop and report any mismatch before treating the target as verified.

## 2. Reviewer relationship and independence

- Reviewer / organization:
- Relationship to EvoRiseKsa, MANA-awam, Mana Alharbi, or the project:
- Who controlled case selection, labels, execution, and interpretation:
- Is the reviewer independent of product control? Explain:
- Conflicts of interest:

The two GitHub accounts are controlled by the same owner and do not establish
independence.

## 3. Environment and exact commands

| Item | Value |
| --- | --- |
| OS / architecture |  |
| Python / executable |  |
| Git / GitHub CLI |  |
| Docker or isolation runtime |  |
| Image references and resolved digests |  |
| Dependency resolution / hashes |  |
| Network, credential, and sandbox assumptions |  |
| Exact commands |  |

## 4. Requested-property results

Use `finding`, `tested-no-finding`, `partial`, `not-tested`, or
`not-applicable` for every row in `TEST_MATRIX.md`.

| Property | Status | Expected | Observed | Evidence |
| --- | --- | --- | --- | --- |
| Base authority / protected harness |  |  |  |  |
| Verdict / record / bundle integrity |  |  |  |  |
| Assurance / runtime truthfulness |  |  |  |  |
| Pack identity / candidate execution |  |  |  |  |
| Trusted Finalizer |  |  |  |  |
| Release Source Admission V2 |  |  |  |  |
| GitHub attestation adapter |  |  |  |  |
| Artifact Admission V1/V2 |  |  |  |  |
| Action / release supply chain |  |  |  |  |
| V2 Round 1 reconciliation |  |  |  |  |

## 5. Finding

### Title and severity rationale

### Exact claimed property

### Non-secret preconditions and minimal reproduction

### Expected versus observed result

Include exit status, decision/reason, lifecycle and assurance fields, and safe
raw-evidence hashes. State whether the unmodified frozen target reproduces it.

### Impact and limitations

### Suggested remediation and regression test

## 6. Evidence inventory

| Artifact | SHA-256 / identifier | Origin | Retention / redaction |
| --- | --- | --- | --- |
| Released zipapp |  | Immutable release |  |
| SHA256SUMS |  | Immutable release |  |
| Source checkout |  | Fixed tag |  |
| Policy / pack |  | Base Git objects |  |
| Verdict / bundle / receipt |  | Safe copy |  |
| Workflow run / attempt |  | GitHub URL / API |  |
| Logs |  | Redacted |  |

## 7. Disclosure checklist

- [ ] Authorized repository and runner only.
- [ ] No secret, private key, token, cookie, or credential-bearing URL.
- [ ] Potential vulnerabilities sent through private reporting.
- [ ] Safe evidence hashes and exact commands preserved.
- [ ] Untested paths and independence limitations stated.

## 8. Interpretation

A useful finding identifies the frozen target, repeatable non-secret inputs,
expected and observed behavior, and impact inside a published claim. A clean
report is not a general endorsement, measured field error rate, production
certification, or proof of immunity.
