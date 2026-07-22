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

- **Immutable `v4.1.0` consumer release** — the published zipapp is pinned by
  its release `SHA256SUMS` and has a GitHub build-artifact attestation. This is
  publication/provenance evidence, not a newly captured behavioral baseline or
  an independent security review.

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

## Shipped source contract awaiting operational evidence

- **Release Source Admission V2** — published in `v4.1.0`, this separately keyed
  protected-main source `ALLOW` binds A/B/C workflow blobs and run attempts, a canonical producer
  receipt, strong execution evidence, one semantically constrained GitHub
  attestation result, and an exact five-domain key-separation contract. The
  admission path requires a SHA-256-pinned Git snapshot plus POSIX root-to-
  nonroot isolation for a SHA-256-pinned `gh` process, and proves that the
  provider identity cannot read the bound signing-key path before launch. The
  signed manifest exposes both tool digests and the provider UID/GID for
  detached comparison against external expectations.
  V1 remains DENY-only. Publishing the implementation does not complete a live
  V2 pilot and does not make it a production gate.

## Operational evidence completed

- The frozen
  [`v4.0.2` finalizer pilot](https://github.com/EvoRiseKsa/evoom-guard-v4-finalizer-pilot)
  completed a fresh same-owner, cross-account Trusted Finalizer `ALLOW` and a
  separately keyed Artifact Admission round for one exact regular file. The
  protected admission job freshly verified the file's GitHub Artifact
  Attestation, the exact finalizer source/head, and the retained evidence; it
  also exercised 13 negative controls. Exact run IDs, artifact IDs, digests,
  and downloaded bytes are preserved in
  [`ARTIFACT_ADMISSION_ROUND1.md`](https://github.com/EvoRiseKsa/evoom-guard-v4-finalizer-pilot/blob/main/ARTIFACT_ADMISSION_ROUND1.md).
  This establishes only the recorded regular-file/provider relation. It is not
  build reproducibility, release, OCI, registry, deployment, production, or
  independent-review evidence.
- The v3.7.0 finalizer pilot completed one same-owner, cross-account raw-Git
  `ALLOW` exercise and preserved its exact verification inputs in
  [`ROUND2_RESULTS.md`](https://github.com/EvoRiseKsa/evoom-guard-finalizer-pilot/blob/main/ROUND2_RESULTS.md).
  The bundle was recomputed with separately fetched source/context inputs. This
  is operational evidence, not third-party review, and it does not establish
  that an `ALLOW` → failed/cancelled attempt → fresh `ALLOW` sequence was
  completed on one unchanged PR head.
- The now-archived receipt pilot preserved one clean A-to-B-to-C evidence-chain
  round, two failed-A controls, a moved-`main` rejection, and a final live
  negative matrix. On the same B receipt/head, C rejected the wrong workflow
  (attempt 2), wrong run attempt (attempt 3), and altered receipt bytes
  (attempt 4); the last control first verified the original bytes successfully
  on the same runner. The exact 19-file evidence manifest is retained under
  [`evidence/negative-receipt-matrix`](https://github.com/EvoRiseKsa/evoom-guard-receipt-pilot/tree/main/evidence/negative-receipt-matrix).
  These are non-admitting observations, not a release authorization.

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

1. **Exercise V2 before relying on it.** Run a disposable protected-main A/B/C
   pilot using the published bootstrap runtime, pinned Git/`gh`, mandatory
   provider isolation, five distinct key domains, and retained positive and
   negative evidence.
2. **Release-artifact and publication boundary.** Extend the completed
   regular-file/provider pilot with a distinct protected-main release-source
   `ALLOW`, the actual release artifact digest, its provider attestation, and a
   separately privileged draft-release consumer. OCI, registry, deployment,
   and reproducibility remain separate later contracts.
3. **Independent evidence.** Request external security review and a genuinely
   blind evaluation; same-owner cross-account review remains operational
   separation, not independence.
4. **Only after adoption evidence.** Stronger fork/VM boundaries, organization
   policy enforcement, and an adapter/pack SDK require evidence from real
   adopters and onboarding failures. They are not assumed product needs.

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
