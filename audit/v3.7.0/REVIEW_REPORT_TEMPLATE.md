<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# External-review report template

Copy this template into a private advisory or a report you are authorized to
share. Do not paste credentials, private keys, tokens, cookies, secrets, or
time-limited credential-bearing URLs.

## 1. Target confirmation

| Field | Required value or observation |
| --- | --- |
| Repository | EvoRiseKsa/EvoOM-Guard-m |
| Release tag | v3.7.0 |
| Release commit | 1f0ceae5009198b1bf161a3a07fced54c1f01337 |
| Release asset | evo-guard.pyz |
| Asset SHA-256 | 1d36f7ec45f47f9f6c3178a25a58accf8f8beb0ffd9d29e7bf93b7fe17ad3ec9 |
| Asset size | 852118 bytes |
| SHA256SUMS SHA-256 | bc7c85aa06f29298e6ee1af2ad793c6164ede9b9162474f66344dfe9227980c7 |
| Release attestation command and result |  |
| Target-verification script and result |  |

State any mismatch immediately. Do not continue as though a newer branch,
rebuilt artifact, or mutable tag were the requested target.

## 2. Reviewer relationship and independence

- Reviewer / organization:
- Relationship to EvoRiseKsa, MANA-awam, or the project owner:
- Who selected the cases, labels, and interpretation:
- Is the reviewer independent of product control? Explain yes, no, or unknown:
- Conflicts of interest:

MANA-awam and EvoRiseKsa are controlled by the same owner. Work performed only
by those identities is not independent review. A report that cannot establish
independence may still provide useful technical evidence, but must not use an
independent-audit conclusion.

## 3. Environment and commands

| Item | Value |
| --- | --- |
| OS and version |  |
| CPU architecture |  |
| Python version and executable |  |
| Git / GitHub CLI version |  |
| Docker or other isolation runtime and version |  |
| Image references and resolved digests |  |
| Dependency resolver output / lock hash |  |
| Exact commands |  |
| Network, credential, or sandbox assumptions |  |

If a finalizer workflow is in scope, also record the public key fingerprint,
policy digest, verifier-pack digest, base/head commits and trees, workflow
run/attempt, and Check Run identity. Do not collect the private finalizer key.

## 4. Requested-property results

For every property in [TEST_MATRIX.md](TEST_MATRIX.md), choose one:
tested with no finding, finding, partially tested, not tested, or not
applicable. Explain why a property was not fully tested.

| Property | Status | Expected result | Observed result | Evidence references |
| --- | --- | --- | --- | --- |
| Base-owned authority / protected harness |  |  |  |  |
| Verdict and evidence integrity |  |  |  |  |
| Assurance-boundary truthfulness |  |  |  |  |
| Verifier-pack identity and execution |  |  |  |  |
| Raw-Git Trusted Finalizer |  |  |  |  |
| Artifact Admission V1 |  |  |  |  |
| Action and release supply chain |  |  |  |  |

## 5. Finding template

### Title and severity rationale

### Claimed property that appears to fail

Quote or link the exact release-era claim and explain why the observation is
inside that claim rather than a documented limitation.

### Preconditions

List only non-secret prerequisites. State whether the target was modified, what
was modified, and why the change is necessary for the reproduction.

### Minimal reproduction

Provide exact, copyable commands and inputs. Redact credentials rather than
replacing them with live values. If the proof requires a protected deployment,
give the maintainer a non-secret procedure for controlled reproduction.

### Expected versus observed result

Include exit status, verdict or decision, reason code, and the relevant
assurance fields. Attach or hash safe raw evidence. Explain whether the result
reproduces against the unmodified frozen target.

### Impact and limitations

Describe the realistic authority needed, affected decision, and what the proof
does not show. Do not claim release provenance, deployment impact, or a
hostile-runner escape unless the evidence directly establishes it.

### Suggested remediation and regression test

## 6. Evidence inventory

| Artifact | SHA-256 / identifier | Origin | Retention / redaction note |
| --- | --- | --- | --- |
| Released evo-guard.pyz |  | Immutable release |  |
| SHA256SUMS |  | Immutable release |  |
| Source checkout / commit |  | Fixed tag |  |
| Policy and verifier-pack identity |  | Base Git objects |  |
| Verdict / evidence bundle |  | Safe copy only |  |
| Workflow run, attempt, Check Run |  | GitHub URL / API |  |
| Logs |  | Redacted before sharing |  |

## 7. Disclosure checklist

- [ ] I did not include a private key, token, cookie, environment export, or
      credential-bearing URL.
- [ ] I used a repository and runner I am authorized to test.
- [ ] I did not publish a potentially exploitable bypass in a public issue.
- [ ] I submitted a potential vulnerability through the private route in
      SECURITY.md.
- [ ] I preserved enough hashes and commands for controlled reproduction.

## 8. Interpretation and acceptance criteria

A technically actionable finding identifies the frozen target, a repeatable
non-secret reproduction, expected versus observed behaviour, impact within a
published claim, and safe evidence sufficient for a maintainer to reproduce.

A negative report must identify its tested surface and environment. It is not a
general endorsement, a measured field error rate, proof of independent review,
or proof of immunity from new attack classes.
