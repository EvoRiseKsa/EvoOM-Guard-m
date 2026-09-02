<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# Support

## Bugs, questions, and product feedback

Search the existing issues first. For a wrong verdict, installation problem,
or ordinary product question, open the
[Guard report form](https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues/new?template=guard-report.md)
and include the exact command, output, operating system, Python version, and
expected behavior. Keep the report free of secrets and private repository data.

Community support and issue triage are provided on a best-effort basis. The
public repository does not include a response-time, resolution-time, or
availability service-level agreement.

## Public Beta triage

The self-hosted Action and CLI are in Public Beta. Reports are classified by
impact so launch and promotion decisions do not depend on informal labels:

- **P0 — security bypass:** a candidate obtains an unexplained `PASS`, escapes
  the declared isolation boundary, forges trusted evidence, or exposes a
  credential. Report privately and stop blocking use of the affected path.
- **P1 — wrong admission:** a reproducible false allow/deny, fail-open behavior,
  or supported-path compatibility defect can change a required-check decision.
  Roll the affected repository back to advisory or remove that required check
  while preserving its other protections.
- **P2 — degraded operation:** an `ERROR`, unsupported runner, excessive
  overhead, or evidence usability defect does not produce a false `PASS` but
  blocks or materially impairs adoption.
- **P3 — question or documentation:** no admission or security impact.

Include the immutable Action/CLI ref, operating system, runtime, exact command,
reason code, and a redacted receipt. Never convert an unavailable or
unsupported judge into `PASS`. The operating and promotion rules are in
[`docs/PUBLIC_BETA.md`](docs/PUBLIC_BETA.md).

## Security vulnerabilities

Do **not** disclose a suspected vulnerability, working bypass, credential, or
secret in a public issue or pull request. Use GitHub Private Vulnerability
Reporting as described in [SECURITY.md](SECURITY.md).

## Commercial support and licensing

Production support, enterprise service levels, and rights beyond the public
license require a separate written agreement. Use the canonical contact listed
in [COMMERCIAL-LICENSING.md](COMMERCIAL-LICENSING.md).
