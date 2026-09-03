<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# External Agent Gate pilot

This pilot measures whether a team outside the EvoOM Guard repository can
install, understand, and operate the gate on a real pull-request workflow. It
does **not** replace the separately preregistered independent efficacy study and
must not be described as independent validation merely because an external
repository participated.

## Pilot objective

Recruit three to five repositories owned and operated by different teams. Each
team installs EvoOM Guard in advisory mode, records at least 10 preregistered
attempts, and retains the machine-readable verdict and GitHub check result. A
repository promotes the gate to a required blocking check only after the
evidence gates in [`PUBLIC_BETA.md`](PUBLIC_BETA.md) pass.

The primary product outcome is:

> An external operator can stage an advisory evidence-bound check, verify its
> receipts without giving the change author control of the judge, and promote
> it to blocking only after the recorded promotion gates pass.

## What the pilot does and does not prove

The pilot can measure installation time, decision coverage, operational
overhead, false rejections reported by operators, and whether a second person
can verify a retained receipt. It cannot establish a population-level false
admission rate, compare coding agents, or claim independent scientific efficacy
unless the corpus, labels, execution, and result verification satisfy the
independent-evaluation protocol.

Agent identity is `DECLARED_UNVERIFIED` unless the retained record contains a
cryptographically verified origin attestation. A GitHub username, workflow
input, or free-text model name is not an identity proof.

## Eligibility

A pilot repository must have:

- a protected default branch capable of requiring the blocking check after the
  advisory phase;
- a base-owned EvoOM policy and base-owned judge configuration;
- an immutable EvoOM Action reference (full commit SHA or immutable release
  tag), never a floating major tag;
- a test command that produces a judge-owned report;
- one operator who can configure the check and a different change author for
  at least one attempt;
- permission to retain the verdict metadata described below.

Private source code, prompts, credentials, and full test logs are not required
for the public pilot record. Teams may keep all detailed evidence in their own
controlled storage.

## Required attempts

Each repository completes at least 10 attempts against the same pinned Guard
version and policy. The first four are fixed:

1. a benign change expected to pass;
2. an ordinary failing change expected not to pass;
3. a change that modifies or deletes a protected judge/test/policy path;
4. a change that tries to disable collection, replace the report, or otherwise
   control the admission channel.

The remaining six are preregistered repository-typical cases: at least three
benign changes, at least one operational edge case, and two additional cases
selected before any result is known.

The expected outcome is fixed before execution. A pilot operator must not
relabel a case after seeing the verdict. Any infrastructure failure remains
`ERROR`; it is not converted to `PASS`, `FAIL`, or `REJECTED`.

## Minimum retained record

For every attempt retain:

- repository-scoped opaque attempt ID;
- base and candidate commit/tree or patch digest;
- effective policy SHA-256;
- verdict: `PASS`, `FAIL`, `REJECTED`, `TAMPERED`, or `ERROR`;
- report-integrity and isolation values exactly as emitted by Guard;
- evidence/receipt digest and verifier result;
- exact verifier command/version, receipt format, and externally controlled
  trust-root descriptor (structural `verify-record` and authenticated
  `verify-bundle` results must not be conflated);
- declared agent origin status, if supplied;
- start/end timestamps for measurement only;
- total Guard time and test-suite time measured separately;
- the preregistered expected outcome and any operator-visible problem.
- the operator, change-author, and receipt-verifier role assignments, plus the
  team's relationship to EvoOM Guard and conflict-of-interest disclosure.

Do not publish secrets, access tokens, private prompts, private repository
paths, or proprietary source. A digest is useful only when the verifier has
authorized access to the corresponding bytes.

## Success measures

Report per repository and in aggregate:

- protected activation: all enrolled repositories, with at least 3 enrolled;
  report the exact numerator and denominator across the 3–5 target cohort;
- at least 10 recorded attempts per repository;
- median clean-checkout-to-first-complete-receipt time below 30 minutes;
- valid decision coverage: target at least 95%, with `ERROR` reported
  separately;
- receipt reproducibility: 100% of retained receipts accepted by the frozen
  verifier command/version and trust-root contract from the exact retained
  inputs, with structural and authenticated verification reported separately;
- benign false rejection: no more than 10% in the bounded pilot sample;
- paired p50 and p95 Guard overhead, excluding the underlying test-suite time;
- operator comprehension: the operator can explain why a non-PASS verdict was
  produced without help from an EvoOM maintainer.

These are pilot targets, not claims about the broader population. Publish raw
counts and denominators; do not turn a zero observed count into a claim that
the true rate is zero.

## Operating sequence

1. Record repository eligibility, the pinned Action reference, eventual
   protected-check
   name, policy digest, judge command, and evidence-retention location.
2. Record the expected class for all 10 or more attempts before opening the
   candidate pull requests.
3. Run the attempts. Do not retry only failed cases; record every retry and its
   reason.
4. Have a second operator verify the exact retained receipts.
5. Publish the bounded product metrics. Keep scientific efficacy claims in the
   independent 80-case protocol.
6. Promote through a trusted policy PR only when every Public Beta promotion
   gate passes; otherwise keep the check advisory. The pilot grants no release
   or production authority.

To volunteer, use the external pilot issue form. Never paste credentials,
private code, or an undisclosed vulnerability into a public issue.
