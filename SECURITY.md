<!-- Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved. -->
<!-- Source-available — see LICENSE for permitted use. -->

# Security policy

EvoOM Guard is a verification gate: its value depends on its verdicts being
trustworthy. Reports that show a way to make the gate lie — or that break a claim
it makes about itself — are especially welcome.

## Reporting a vulnerability

**Please report privately, not in a public issue.**

- Preferred: GitHub **private vulnerability reporting** — the **Security** tab →
  **Report a vulnerability**. This repository has that private channel enabled.
- Direct form: <https://github.com/EvoRiseKsa/EvoOM-Guard-m/security/advisories/new>.
- Include: the version (`evo-guard version`), a minimal repro, and the impact.

This is a solo, best-effort project: there is no bug-bounty and no guaranteed
response time, but genuine reports will be looked at and credited (with your
permission) when fixed.

For a non-sensitive independent-review starting point, see the frozen
[v3.7.0 review companion](audit/v3.7.0/). It names the exact release target
and a safe evidence/report template. Do not put a working bypass, secret, or
credential-bearing artifact in its public tracking issue; use the private route
above for a potential vulnerability.

## In scope

- A patch that obtains a **false `PASS`** within a guarantee Guard claims — e.g.
  forging the verdict under `--blackbox`, or editing/deleting a protected harness
  path without a `REJECTED`.
- **Isolation or runtime assurance not delivered but reported as delivered**
  (for example, a run labelled `candidate_isolation: docker` that did not run in
  a container, or a static pre-gate result claiming report/pack assurance even
  though no suite or pack started).
- A configured verifier pack whose accepted `EVOGUARD_PACK_V2` identity, expected
  digest pin, mandatory execution, or pre/post snapshot checks can be bypassed
  while Guard still returns `PASS`.
- A container verdict that claims setup/suite isolation inconsistent with the
  recorded `setup_isolation`, resolved image ID, or read-only suite/pack mounts.
- A `PASS` after the judge process group or an observed candidate container
  could not be proven absent; that condition must fail closed as
  `runtime_cleanup_failed`.
- A POSIX workspace operation that escapes the descriptor-relative/no-follow
  root while Guard still reports a clean result, or runtime-continuity evidence
  inconsistent with the tree/boundary that actually ran.
- Path-escape, report-injection, entity-bomb, or partial-JUnit-set attacks on the
  judge. A Maven/Surefire-style report directory containing any symlinked,
  special, unreadable, malformed, oversized, DTD, or entity-bearing `*.xml`
  entry must fail closed; a valid sibling cannot mask it.
- A Trusted Finalizer false `ALLOW` caused by cross-PR, cross-run, or cross-attempt
  replay; confusion between an immutable control record and an untrusted handoff;
  stale base/head/tree metadata; or reuse of an old Check Run.
- Any path by which candidate-controlled code, an untrusted workflow artifact, or
  a candidate-adjacent token can read the finalizer key, cause privileged sealing,
  or cause a seal job to execute candidate code.

## Known and documented — NOT vulnerabilities

These are stated limits, not defects (see [`docs/ASSURANCE.md`](docs/ASSURANCE.md)):

- The **default (same-process) judge** can be forged by deliberate in-process
  source (`report_integrity: same_process_candidate_writable`). `--blackbox`
  adds an external judge but is composite by default, so its overall assurance
  still includes the weaker required repo-native channel. For process-boundary
  targets, `--blackbox-only` is the fully external report profile; the
  same-process boundary is documented, not hidden.
- The **subprocess boundary is not a sandbox**. Use `--isolation docker`/`gvisor`
  for OS-level confinement.
- POSIX CPU/memory rlimits do not exist on native Windows (the wall timeout still
  applies). The shell-free black-box subprocess launcher also requires a POSIX
  host and fails closed on native Windows; use Linux/GitHub Actions or WSL.
- Workspace containment has a platform-specific strength. On POSIX, supported
  operations traverse from held directory descriptors and use no-follow,
  descriptor-relative reads/writes/deletes; missing primitives fail closed. On
  Windows, Python's standard library has no `openat`/`unlinkat` equivalent:
  Guard rejects reparse parents and checks parent/file identity before and after
  each protected operation, but this remains a **best-effort, non-atomic** check.
- Under docker/gVisor, `setup_command` runs in a writable container by default,
  while suite and pack candidate mounts are read-only. Explicit
  `trust_setup_on_host` is a documented compatibility downgrade and is reflected
  as effective `subprocess` isolation.
- `setup_output_globs` are trusted policy exclusions. If a repository owner
  deliberately exempts a broad path, setup fidelity makes no claim about that
  matching content while setup runs; protect and review `.evoguard.json`
  accordingly. They do **not** exclude the post-setup runtime tree from
  repo-suite/verifier-pack continuity checks.
- For a repo-native verifier pack, `EVOGUARD_RUNTIME_TREE_V1` binds the accepted
  post-setup runtime tree, including outputs setup created. In subprocess mode,
  `snapshot_boundary_checked` detects differences at phase boundaries; it does
  not prevent a lingering process from mutating and restoring bytes between
  observations. `read_only_enforced` is reserved for Docker/gVisor suite/pack
  mounts when setup was not moved to the host with `trust_setup_on_host`.
- The verdict binds to the runtime image digest, **not** a separately built
  artifact. The V1 artifact-admission command can bind a regular file observed
  at read time to an authenticated pre-merge finalizer `ALLOW`, but it does not
  establish build provenance, reproducibility, OCI/registry identity, release
  publication, deployment, SBOM coverage, or vulnerability status.
- The v3.7.0 Trusted Finalizer reference re-derives PR/run/tree bindings and
  independently recomputes candidate text, ordered deletions, effective policy,
  and verifier-pack identity from raw base/head Git objects before sealing. It
  is an independent check of those specified identities, not a proof that the
  runner is an unbreakable hostile-code boundary or that a later build/release
  artifact came from the admitted source.
- The Trusted Finalizer workflows are reference templates under
  `examples/trusted-finalizer/`; they are not deployed as a merge gate in this
  repository. Their manual same-repository-PR scope, Environment review, and
  Round 1 requirement are documented in `docs/TRUSTED_FINALIZER.md`.

If you are unsure whether something is in scope, report it privately anyway.
