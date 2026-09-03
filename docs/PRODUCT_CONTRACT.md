<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see ../LICENSE for permitted use.
-->

# Product contract

## Status and delivery model

EvoOM Guard is available as a **Public Beta** for self-hosted use through its
GitHub Action and command-line interface. The maintained consumer artifact is
the immutable [`v4.8.1` release](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.8.1).
Consumers pin that tag or, for the strictest identity, its recorded full commit
SHA, `e63e9d806fef38c9dfd3bfb1a0bc1b2d12c58ac8`.
The product is not a hosted SaaS, a managed merge service, or a PyPI
distribution.

Public Beta means the documented interface can be evaluated and used today,
while compatibility and operational evidence are still being collected across
external repositories. It does not mean Core GA, an availability SLA, or a
hostile-code production certification. The rollout and promotion gates are in
[`PUBLIC_BETA.md`](PUBLIC_BETA.md).

## The one product question

EvoOM Guard answers exactly one question:

> Did this change satisfy the selected judge without editing or deleting an
> evidence path protected by the active policy?

The inputs are a candidate change, a trusted base-owned policy, and a selected
judge. Guard applies the change to a throwaway copy, checks the protected
evidence paths before judgment, runs the selected judge, and derives a verdict
from the judge-owned report plus the process exit code. Standard outputs are a
stable JSON receipt, a Markdown report, an exit code, and optionally SARIF.

The verdicts are `PASS`, `FAIL`, `REJECTED`, `TAMPERED`, and `ERROR`. `PASS`
means only that the selected judge passed inside the recorded policy,
report-integrity, and isolation boundary. It is eligibility for the next
separately authorized step; it is never merge, release, or deployment authority
by itself.

## Who needs it

The Beta is designed for:

- repositories that accept changes from coding agents, bots, forks, or other
  authors who can edit files in the candidate tree;
- platform teams that need a consistent, machine-readable admission receipt;
- maintainers who want to prevent a candidate from making a naive test gate
  green by editing tests, test configuration, auto-execution hooks, or the gate
  workflow; and
- organizations that already own a useful test or verifier suite and need to
  protect the relationship between the proposed change and that judge.

It is usually unnecessary for a small, fully trusted team with a low-impact
repository, or for a system whose judge already runs outside candidate control
and produces an immutable admission decision. It cannot compensate for a weak,
nondeterministic, or incomplete judge.

## Supported Beta profiles

| Profile | Intended use | Admission authority |
|---|---|---|
| Advisory | First installation, compatibility discovery, and outcome review | No. Keep the check non-required. |
| Protected blocking | A repository that has completed its local Beta promotion gates and protects the workflow, policy, and required check | Yes, but only for the bounded Guard question. |
| Hostile-code production | Dedicated isolation, separately operated judge/finalizer, protected evidence storage, and external assurance | Not a Public Beta claim. Follow the production blueprint. |

The Public Beta supports the documented runner adapters only when preflight and
the actual repository attempts confirm the selected command. Offline adapter
conformance is not evidence that every external runner version and operating
system combination was executed.

## Required deployment boundary

Before treating Guard as blocking, the adopting repository must establish all
of the following:

1. Pin the Action to an immutable release tag or reviewed full commit SHA.
2. Keep `.evoguard.json`, the judge configuration, declared harness inputs, and
   the workflow under protected base-branch ownership.
3. Prevent candidate jobs from receiving secrets, write tokens, or later
   privileged steps that trust candidate-produced state.
4. Configure a required check and review/ruleset controls so a candidate cannot
   remove or replace the gate.
5. Use a judge-owned structured report supported by the selected adapter; a
   missing, empty, contradictory, or unsupported verdict fails closed.
6. Retain the JSON receipt and its exact verification inputs according to the
   adopter's evidence policy.
7. Complete the advisory observations and promotion criteria in
   [`PUBLIC_BETA.md`](PUBLIC_BETA.md).

For untrusted hostile code, subprocess execution is insufficient. Use
`--blackbox-only` with a delivered container, gVisor, or VM-class boundary and
the authority separation in [`PRODUCTION_BLUEPRINT.md`](PRODUCTION_BLUEPRINT.md).
The current Public Beta does not certify that deployment.

## Explicit non-products and non-claims

EvoOM Guard is not:

- a code reviewer, code generator, SAST/DAST scanner, linter, or vulnerability
  management product;
- proof that a change is correct, secure, compliant, or free of defects;
- proof of who or which model authored a change;
- a replacement for branch protection, CODEOWNERS, secret isolation, or a
  trustworthy test/verifier suite;
- artifact provenance, publication authority, deployment approval, or runtime
  identity merely because a Guard verdict is `PASS`; or
- independently validated merely because the maintainer CI, a same-owner
  account, or an external repository reproduced a result.

Independent efficacy, hostile-code production, artifact admission, and
deployment are separate evidence boundaries. Their open work is tracked in
[`ROADMAP.md`](../ROADMAP.md) and the production documents; none is silently
inherited by the Public Beta label.

## Distribution and licensing boundary

The shipped repository is one open-core distribution. Apache-2.0 core paths
and source-available platform paths are defined by
[`LICENSING.md`](../LICENSING.md), not by the package name alone. A separately
published "core-only" wheel is not currently a supported product and must not
be inferred from the path-level Apache grant. Production support or rights
beyond the public license require a separate written agreement.
