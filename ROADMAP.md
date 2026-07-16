<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Roadmap

AI-generated patches remain EvoOM Guard's primary use case, but the technical
threat model is broader: any untrusted software change that can influence the
evidence used to judge it. Guard still focuses on one narrow question:

> Did the change satisfy the selected judge without manipulating the evidence
> used to judge it?

## Shipped today

- **Protected-path gating** — edits or deletions of tests, their configuration,
  CI, or auto-executed files are rejected before the suite runs.
- **Structured, judge-owned verdicts** across eight test runners (verdict read
  from a JUnit report + exit code, never from stdout); a `TAMPERED` verdict when
  they disagree or when the judged candidate/pack snapshot drifts during a
  multi-phase run.
- **Independent record verification** — a bounded, strict schema-1.11 consumer
  checks lifecycle, policy, receipt, isolation, pack, and verdict-source
  invariants without executing candidate code.
- **Authenticated evidence envelopes** — deterministic bundles bind the exact
  record and optional materials to external repository/run/revision context and
  an Ed25519 key; verification requires the key and expected context out of band.
- **Split Trusted Finalizer** — a pre-candidate immutable control record and
  no-secret re-verification handoff are compared with current PR/tree metadata
  in a separate signing job that never checks out or runs candidate code. The
  signed bundle carries that exact handoff and preserves both `ALLOW` and `DENY`
  decisions. Each run attempt has a distinct pending Check Run and artifact
  bindings; a non-secret reconciler completes failed attempts as `DENY`.
- **Assurance reporting** — every verdict states its `report_integrity` and
  `candidate_isolation` honestly.
- **External black-box verification** (`--blackbox`) — the verdict comes from the
  judge's own process over judge-owned tests that never import the candidate.
- **Delivered candidate isolation** — a real container boundary whose evidence is
  read from what actually ran; requesting isolation that cannot be delivered
  fails closed. Exercised against a real Docker daemon in CI.
- **Canonical Independent Verifier Packs** — strict manifest parsing, framed
  `EVOGUARD_PACK_V2` identities, optional expected-digest pins, verified external
  snapshots and a separate mandatory pack phase with non-zero test evidence.
- **Phase-aware setup isolation** — docker/gVisor setup runs inside the exact
  resolved image with a writable candidate mount; suite and pack phases use
  read-only candidate mounts. Setup fidelity permits conventional new outputs;
  additional `setup_output_globs` are explicit trusted policy.

## Current limits (stated plainly)

- The default same-process judge can be forged by deliberate in-process source;
  use `--blackbox` to close that. See [`docs/ASSURANCE.md`](docs/ASSURANCE.md).
- The subprocess boundary is not a sandbox; container isolation is opt-in.
- POSIX rlimits are unavailable on native Windows, and the black-box subprocess
  launcher has a POSIX executable contract (use Linux/GitHub Actions or WSL).
- Read-only container suite/pack mounts require dependencies and build products
  to be prepared during setup or baked into the image; this is not a general
  writable development-container workflow.
- `setup_output_globs` are trusted exclusions, so overly broad repository policy
  weakens setup-fidelity coverage by design.
- A verdict binds to the runtime image, not a separately built artifact.
- The reference Trusted Finalizer starts with manual, open same-repository PRs
  targeting the protected default branch and a protected Environment secret. It
  does not turn a
  Docker runner into a complete hostile-code boundary, support forks, or
  independently recompute every candidate/policy/pack digest in the seal job.
  Its shared display name must be audited against the actual GitHub ruleset
  before it is enforced as a required check; a Required Workflow is preferred.
- Networked-service (HTTP) targets need a judge↔candidate channel the hardened
  `--network none` container does not yet provide.

## Next work is gated by evidence

Future work is driven by verified adoption, real threat cases, and observed user
needs — not feature accumulation. The order matters:

1. **Operational pilot / Round 1.** Install the v3.6.0 reference finalizer in a
   protected consumer repository, record PASS → cancelled or failed attempt →
   fresh PASS behaviour on one unchanged PR head, and verify what GitHub actually
   treats as a merge requirement. It is not a required check until that behaviour
   is recorded. A second account controlled by the same person is useful for an
   operational exercise, not independent review.
2. **Independent finalizer derivation.** Define and implement canonical,
   Git/API-derived candidate, effective-policy, and verifier-pack identities in
   the sealing job without executing candidate code. See
   [`docs/TRUSTED_FINALIZER_HARDENING.md`](docs/TRUSTED_FINALIZER_HARDENING.md).
3. **Artifact-bound admission.** Bind a signed ALLOW/DENY to the exact container
   image, package, binary, or release bundle that is built after admission, then
   make that evidence consumable alongside build provenance.
4. **Only after external evidence.** Stronger fork/VM boundaries, organization
   policy enforcement, and an adapter/pack SDK require evidence from real
   adopters and their onboarding failures. They are not assumed product needs.

Risk scoring and ML may become advisory research tools only after an independent,
frozen labelled corpus exists. They must not decide `ALLOW`, `DENY`, or merge
eligibility merely because a model assigns a probability.

**No future capability is considered committed until it has an implemented,
tested, and documented security boundary.**

## Non-goals

- EvoOM Guard is not a general security scanner, a linter, or a code reviewer —
  one explicit, policy-bound question stays the contract.
- Subprocess execution is not described as a sandbox; isolation levels stay
  explicit (`subprocess` < `docker` < `gvisor`).
- Isolation claims must reflect the boundary actually delivered.
- A passing verdict does not prove complete software correctness.
