<!-- Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved. -->
<!-- Source-available — see LICENSE for permitted use. -->

# Security policy

EvoOM Guard is a verification gate: its value depends on its verdicts being
trustworthy. Reports that show a way to make the gate lie — or that break a claim
it makes about itself — are especially welcome.

## Reporting a vulnerability

**Please report privately, not in a public issue.**

- Preferred: GitHub **private vulnerability reporting** — the **Security** tab →
  **Report a vulnerability**. (Repo owner: enable it under Settings → Advanced
  Security if it is not already on.)
- Include: the version (`evo-guard version`), a minimal repro, and the impact.

This is a solo, best-effort project: there is no bug-bounty and no guaranteed
response time, but genuine reports will be looked at and credited (with your
permission) when fixed.

## In scope

- A patch that obtains a **false `PASS`** within a guarantee Guard claims — e.g.
  forging the verdict under `--blackbox`, or editing/deleting a protected harness
  path without a `REJECTED`.
- **Isolation not delivered but reported as delivered** (a run labelled
  `candidate_isolation: docker` that did not actually run in a container).
- Path-escape, report-injection, or entity-bomb style attacks on the judge.

## Known and documented — NOT vulnerabilities

These are stated limits, not defects (see [`docs/ASSURANCE.md`](docs/ASSURANCE.md)):

- The **default (same-process) judge** can be forged by deliberate in-process
  source (`report_integrity: same_process_candidate_writable`). The fix is
  `--blackbox`; the same-process boundary is documented, not hidden.
- The **subprocess boundary is not a sandbox**. Use `--isolation docker`/`gvisor`
  for OS-level confinement.
- The verdict binds to the runtime image digest, **not** a separately built
  artifact (artifact-bound verification is on the roadmap).

If you are unsure whether something is in scope, report it privately anyway.
