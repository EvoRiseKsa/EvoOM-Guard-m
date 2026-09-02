<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see ../LICENSE for permitted use.
-->

# Public Beta launch and promotion

## Current launch boundary

The EvoOM Guard Public Beta is open for self-hosted GitHub Action and CLI
adoption on the immutable `v4.7.1` consumer release. The launch claim is narrow:
teams can install the gate, observe its five verdicts, retain exact receipts,
and promote a supported repository to a protected blocking check after the
evidence gates below pass.

This page is an operating contract, not evidence that an external cohort has
already completed it. Until published results exist, adoption and compatibility
targets remain targets with explicit numerators and denominators—not product
claims.

## Stage 0: pin and preflight

1. Pin `EvoRiseKsa/EvoOM-Guard-m` to `v4.7.1` or its recorded full commit SHA.
2. Run `evo-guard version` and retain the output.
3. Run `evo-guard preflight . --strict --json` using the proposed base-owned
   policy. Preflight does not execute candidate code and is not a `PASS`.
4. Resolve every error. Review every warning; do not suppress a warning merely
   to reach a green result.
5. Record the operating system, runtime, exact test command, adapter, policy
   digest, and setup time without repository secrets or private source.

## Stage 1: advisory observation

Generate the advisory preset and keep its check non-required. It preserves the
real Guard verdict while permitting a completed non-`PASS` observation; missing
or empty JSON/Markdown evidence still makes the workflow red.

Each repository records at least **10 attempts** on one pinned Guard version and
policy before promotion. The first four are fixed:

1. one benign change expected to `PASS`;
2. one ordinary test failure expected to `FAIL`;
3. one protected test/policy/workflow edit expected to `REJECTED`; and
4. one report or admission-channel manipulation expected not to `PASS`.

The remaining six attempts are preregistered repository-typical changes,
including at least three benign changes and at least one operational edge case.
Every retry is recorded; an `ERROR`, timeout, unsupported command, or missing
receipt remains in the denominator and is never relabelled after the result.

## Stage 2: promotion to blocking

A repository may regenerate the blocking preset and make its check required
only when all of these evidence gates pass:

- all 10 or more attempts have non-empty JSON and Markdown evidence;
- every result is explained and agrees with its preregistered expected class,
  or the mismatch has a reviewed disposition and regression test;
- every `ERROR`, timeout, unsupported case, retry, and infrastructure failure is
  classified; none is converted into a decision;
- retained receipts verify from the frozen verifier inputs, with structural
  and authenticated verification reported separately;
- the workflow, base policy, judge inputs, and required-check controls are
  protected from the candidate;
- the candidate job has read-only permissions and no secret or write-capable
  credential;
- no known P0 or P1 defect remains in the exact path being enabled; and
- the repository has a tested rollback that removes the required check or pins
  the last accepted immutable Guard version without weakening unrelated branch
  protection.

Promotion is a trusted policy change. Review the generated diff and merge it
through the repository's policy-maintenance path; do not let a candidate PR
promote itself.

## Cohort launch measures

The initial product cohort target is **3–5 repositories** operated outside the
EvoOM Guard repository. It should include Python and Node plus at least one Go
or JVM repository. Report raw counts per repository and in aggregate:

- enrolled and activated repositories, with the exact numerator/denominator;
- median time from a clean checkout to the first complete advisory receipt,
  target under 30 minutes;
- at least 10 attempts per repository and the exact verdict/reason-code counts;
- valid-decision coverage, target at least 95%, with `ERROR` and unsupported
  cases reported separately;
- 100% retained-receipt verification from the declared frozen inputs;
- benign false rejections with the exact count and denominator;
- paired p50/p95 Guard overhead excluding the underlying suite time; and
- every P0/P1 issue, rollback, and unresolved compatibility limitation.

These measures establish bounded product usability and operability. They do not
establish population efficacy, compare agents, or replace the preregistered
independent 80-case protocol.

## Support, incident, and rollback rules

- Suspected bypasses, credential exposure, or evidence forgery use private
  vulnerability reporting and are never posted publicly.
- Wrong verdicts and compatibility failures use the Guard report form with the
  exact immutable ref, operating system, runtime, command, reason code, and a
  redacted receipt.
- A confirmed P0 security bypass or P1 wrong-admission defect in the enabled
  path stops promotion and triggers rollback to advisory or check removal while
  preserving other repository protections.
- An unavailable or unsupported judge returns non-`PASS`; operational pressure
  must not convert it into `PASS`.
- Public Beta support is best effort and has no response-time, resolution-time,
  or availability SLA. Commercial support terms are separate.

See [`../SUPPORT.md`](../SUPPORT.md) for the reporting routes and
[`EXTERNAL_AGENT_GATE_PILOT.md`](EXTERNAL_AGENT_GATE_PILOT.md) for the external
pilot record.

## Data minimization

Public cohort records use opaque repository/attempt identifiers and bounded
metadata. Do not publish source code, prompts, full logs, private paths,
credentials, customer identifiers, or undisclosed vulnerabilities. A digest is
useful evidence only when the authorized verifier can access the corresponding
bytes.

## Exit from Public Beta

Public Beta is not Core GA until the maintained release has:

- fixed the structured-verdict/preflight consistency boundary;
- a supported distribution design with no package-ownership collision and a
  pinned, deterministic, byte-verifying build path;
- a real multi-operating-system/version conformance matrix for every advertised
  runner;
- completed cohort measures with no open P0/P1 in the declared GA path; and
- a new signed immutable release through the protected publication workflow.

Hostile-code production remains a separate exit. It additionally requires the
authority separation, dedicated isolation, retained evidence, operational
exercises, external security review, and independent evaluation defined by
[`PRODUCTION_BLUEPRINT.md`](PRODUCTION_BLUEPRINT.md).

