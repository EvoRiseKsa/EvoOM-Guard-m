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
  v3.7.0 template independently reconstructs candidate text, ordered deletions,
  effective policy, and verifier-pack identity from exact raw Git objects
  before it opens the signing key. The signed bundle carries that exact handoff
  and preserves both `ALLOW` and `DENY` decisions. Each run attempt has a
  distinct pending Check Run and artifact bindings; a non-secret reconciler
  completes failed attempts as `DENY`.
- **Narrow artifact admission** — a separately keyed
  `EVOGUARD_ARTIFACT_BINDING_V1` can bind one regular-file digest and size to a
  verified pre-merge finalizer `ALLOW`. Its format and verification order are
  deliberately small; it is not a build, OCI, release, registry, or deployment
  provenance system.
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
- A Guard verdict binds to the runtime image, not a separately built artifact.
  The optional V1 artifact binding only relates bytes read at sealing time to a
  pre-merge finalizer decision; it still does not establish how those bytes were
  built, published, or deployed.
- The reference Trusted Finalizer starts with manual, open same-repository PRs
  targeting the protected default branch and a protected Environment secret. It
  does not turn a
  Docker runner into a complete hostile-code boundary or support forks. The
  v3.7.0 reference does independently derive candidate/policy/pack/deletion
  bindings from raw Git, but that does not prove that GitHub's runner or a later
  build/release artifact is trustworthy.
  Its shared display name must be audited against the actual GitHub ruleset
  before it is enforced as a required check; a Required Workflow is preferred.
- Networked-service (HTTP) targets need a judge↔candidate channel the hardened
  `--network none` container does not yet provide.

## Next work is gated by evidence

Future work is driven by verified adoption, real threat cases, and observed user
needs — not feature accumulation. The order matters:

1. **Operational pilot / Round 2.** Upgrade a protected consumer repository to
   the v3.7.0 reference templates, record a raw-binding `ALLOW` → deliberately
   failed or cancelled attempt → fresh `ALLOW` sequence on one unchanged PR
   head, and independently verify the resulting `.evb` using saved external
   source/context inputs. Confirm what GitHub actually treats as a merge
   requirement. Same-owner cross-account operation is useful evidence of the
   workflow, not independent review.
2. **Trusted build and merge-candidate boundary.** Before using artifact
   admission for a release, verify a provider-specific immutable build
   provenance statement and bind it to a protected build and merge-candidate
   identity. The current V1 file relation alone cannot support an OCI,
   package-release, registry, or deployment claim.
3. **Only after external evidence.** Stronger fork/VM boundaries, organization
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
