<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# Roadmap

AI-generated patches remain EvoOM Guard's primary use case, but the technical
threat model is broader: any untrusted software change that can influence the
evidence used to judge it. Guard still focuses on one narrow question:

> Did the change satisfy the selected judge without manipulating the evidence
> used to judge it?

[`docs/PRODUCTION_BLUEPRINT.md`](docs/PRODUCTION_BLUEPRINT.md) is the normative
product boundary and production-gate plan. This roadmap records capability
history; it must not be used to promote an implemented mechanism past the
evidence level allowed by that blueprint.

## Current source capabilities and consumer-release boundary

<!-- BEGIN EVOGUARD_PROJECT_STATUS:ROADMAP_LATEST_RELEASE -->
Source version `4.8.0` is a **release candidate**; it is unsupported and is not yet a
consumer release. The latest immutable consumer release selected by the protected source
tree remains [`v4.7.1`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.7.1)
at commit `b222c7df0a3eaef6e89287cd1354625b88ac8b8b`. Detached-maintainer-signed record
`evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json` binds the published asset
observations `evo-guard.pyz`, `evo-guard.spdx.json`, `SHA256SUMS`. It records successful
release-attestation verification for `evo-guard.pyz`, `evo-guard.spdx.json`,
`SHA256SUMS` and a provider-attestation job whose build-provenance subject is
`evo-guard.pyz` under `.github/workflows/release.yml`. The record is a same-owner
post-publication observation created after the tag; it is not part of the release, a
protected A-through-H ledger, independent review, or proof of correctness, security,
deployment, or efficacy. The latest historical validated A-through-H ledger remains
`evidence/release-ledgers/v4.6.0/RELEASE_LEDGER.json` for `v4.6.0` and does not apply to
`v4.7.1`.
<!-- END EVOGUARD_PROJECT_STATUS:ROADMAP_LATEST_RELEASE -->

- Verdict schema `1.11` remains the frozen contract used by `v4.3.0`.
  Schema `1.12` adds the explicit `operating_profile` field and is supported by
  the ledger-recorded `v4.6.0` consumer release. The immutable `v4.4.0` and
  `v4.4.1` publications remain historical published-unledgered exceptions; see
  their [release-ledger errata](docs/errata/V4.4.0-LEDGER.md) and
  [v4.4.1 erratum](docs/errata/V4.4.1-LEDGER.md).
- **Protected-path gating** — edits or deletions of tests, their configuration,
  CI, or auto-executed files are rejected before the suite runs.
- **Structured, judge-owned verdicts** across eight test runners (verdict read
  from a JUnit report + exit code, never from stdout); a `TAMPERED` verdict when
  they disagree or when the judged candidate/pack snapshot drifts during a
  multi-phase run.
- **Independent record verification** — the bounded, strict `v4.6.0` verifier
  checks schema-1.11/1.12 lifecycle, policy, receipt, isolation, pack, and
  verdict-source invariants without executing candidate code.
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
- **`v4.6.0` provider-specific OCI relation** — the released source
  includes a library-only `EVOGUARD_ARTIFACT_PROVIDER_RECEIPT_V3` path for one
  canonical digest-qualified public GHCR subject. It requires an exact GitHub
  Artifact Attestation direct same-revision branch build and builder
  run/attempt, relates it to externally supplied finalizer repository/head
  context, enforces provider isolation/key separation, and signs the exact
  receipt/subject/finalizer relation through unchanged V2. It has no CLI,
  protected reference workflow, or live OCI pilot and makes no SLSA,
  reproducibility, safety, vulnerability, registry-retention, publication,
  deployment, or runtime claim. See
  [`docs/ARTIFACT_PROVIDER_V3.md`](docs/ARTIFACT_PROVIDER_V3.md).
- **Assurance reporting** — every verdict states its `report_integrity` and
  `candidate_isolation` honestly.
- **External black-box verification** (`--blackbox`) — adds a judge-owned
  external channel over tests that never import the candidate. The default
  overall verdict remains composite; only `--blackbox-only` removes the weaker
  repo-native channel.
- **Delivered candidate isolation** — a real container boundary whose evidence is
  read from what actually ran; requesting isolation that cannot be delivered
  fails closed. Daemon-backed tests and conformance tooling exist; a release
  claim still requires a retained result bound to the final commit and runtime.
- **Canonical Independent Verifier Packs** — strict manifest parsing, framed
  `EVOGUARD_PACK_V2` identities, optional expected-digest pins, verified external
  snapshots and a separate mandatory pack phase with non-zero test evidence.
- **Phase-aware setup isolation** — docker/gVisor setup runs inside the exact
  resolved image with a writable candidate mount; suite and pack phases use
  read-only candidate mounts. Setup fidelity permits conventional new outputs;
  additional `setup_output_globs` are explicit trusted policy.

## Shipped source contract with bounded operational evidence

- **Release Source Admission V2** — published in `v4.1.0`, this separately keyed
  protected-main source `ALLOW` binds A/B/C workflow blobs and run attempts, a canonical producer
  receipt, strong execution evidence, one semantically constrained GitHub
  attestation result, and an exact five-domain key-separation contract. The
  admission path requires a SHA-256-pinned Git snapshot plus POSIX root-to-
  nonroot isolation for a SHA-256-pinned `gh` process, and proves that the
  provider identity cannot read the bound signing-key path before launch. The
  signed manifest exposes both tool digests and the provider UID/GID for
  detached comparison against external expectations.
  V1 remains DENY-only. A separate public pilot subsequently completed one
  exact source-only V2 round; this does not make the mechanism a production
  gate or authorize any artifact or publication.

- **Agent Change Admission V1** — published in `v4.3.0`, this profile separates an
  untrusted automated-agent proposal from a distinct signed authorization,
  independently re-derived raw-Git facts, and a Trusted Finalizer `ALLOW`.
  The archived public same-owner pilot admitted one exact bounded change,
  rejected an additional ignored tracked path before signing, and replayed the
  unchanged base/head pair with identical Git binding bytes and fresh run-bound
  signatures. Publication does not make it a production merge gate,
  hostile-code isolation proof, single-use grant, code healer, or independent
  validation.

## Implemented contract with bounded operational evidence

- **Release Artifact Admission V1** — published in the `v4.2.0` bootstrap, this
  contract implements a
  sixth-key protected-main artifact `ALLOW`. It re-verifies one exact `.rsae`
  source admission against external roots and nested tool pins; binds one
  detached regular artifact, protected E/F workflow identities and raw-Git
  blobs, exact builder run/attempt, and a fresh constrained GitHub Artifact
  Attestation; then emits a canonical signed `.raae` that can be verified
  over retained evidence without a fresh provider call. A later public,
  same-owner protected-main pilot used the immutable v4.2.0 runtime for one
  exact E/F/G round. Protected F returned `SEALED/ALLOW`; detached G returned
  `VERIFIED/ALLOW`; and all five retained-evidence mutations exercised by G
  returned `REJECTED`. The admitted object was a 290-byte JSON descriptor, not
  a package, binary, image, release asset, or deployed runtime. The round
  grants no publication, deployment, OCI, registry, production,
  reproducibility, or independent-review claim. See
  [`docs/RELEASE_ARTIFACT_ADMISSION_V1.md`](docs/RELEASE_ARTIFACT_ADMISSION_V1.md).

## Operational evidence completed

- The
  archived
  [`Agent Change Admission pilot`](https://github.com/EvoRiseKsa/evoom-guard-agent-change-pilot)
  retained permitted run `29983466826`, ignored tracked-path rejection
  `29983731021`, and exact-change replay `29983835620`. The positive and replay
  bundles verified offline; the negative exposed `dist/hidden.txt` through raw
  Git, failed before authorization signing, skipped finalization, and produced
  no `.aca` or `.evb`. Both accounts have the same owner, so this is bounded
  operational evidence rather than independent review or production
  enforcement.
- The
  [`Release Source Admission V2 pilot`](https://github.com/EvoRiseKsa/evoom-guard-release-source-v2-pilot)
  completed one protected-main source-only round with the immutable `v4.1.0`
  runtime. A/B/C attempts `29896945747/1`, `29896982146/1`, and
  `29897001564/1` produced a Docker/network-none external-judge `PASS`, an
  attested producer receipt, protected `SEALED/ALLOW`, and detached
  `VERIFIED/ALLOW`. Its ledger separates live settings mutations and eleven D
  mutations from cases not executed live. The result is bound only to source
  `af8e4592ef5572acfe2ea295c435eed6a8e122fc`; it is not artifact, release,
  publication, deployment, production, or independent-review evidence.
- The same public pilot later used the immutable `v4.2.0` runtime to complete a
  separate A-through-G source-to-artifact round for protected-main target
  `382a24774e2da7d1117f8969455816bd7b941af2`. E/F/G attempts
  `29963621119/1`, `29963656590/1`, and `29963877837/1` built and admitted the
  exact 290-byte descriptor with SHA-256
  `c2e573ad7556ec15db102e6e92c4197d2b413970e37f8d12f823ac4b7aefe64e`,
  then verified the retained RAAE without a fresh provider call. Five G
  mutations returned `REJECTED`; unexecuted matrix rows remain explicit. The
  exact non-secret outputs, public attestation bundles, six public roots, and
  `SHA256SUMS` are retained in its
  [`evidence/round2`](https://github.com/EvoRiseKsa/evoom-guard-release-source-v2-pilot/tree/a1937ea599204751deebcbcadbd416092d8f46f9/evidence/round2)
  snapshot. This still is not evidence for a distributable artifact,
  publication/deployment authority, reproducibility, production, or independent
  review.
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

- The stable `v4.6.0` release contains the operating-profile and isolation
  conformance tooling; the repository source is on that ledger-recorded release line. Consumer
  availability is determined by an immutable GitHub Release, not by presence in
  the repository. One exact, same-owner private run exercised the released
  zipapp with `gvisor`/`runsc` on a GitHub-hosted runner; its bounded public
  record is retained under
  [`evidence/runtime-observations/v4.5.0-gvisor-31298956172`](evidence/runtime-observations/v4.5.0-gvisor-31298956172).
  This does not certify a production, field, dedicated-host, hostile-host, or
  independently operated deployment. Missing evidence still includes a
  dedicated/hostile-host or VM boundary, a real multi-OS runner matrix, a
  third-party held-out evaluation with an independently controlled launcher
  when execution identity matters, and provider-backed telemetry/retention
  exercises.
- The default same-process judge can be forged by deliberate in-process source.
  `--blackbox` adds a stronger external channel, but the default composite still
  includes the weaker repo-native channel; use `--blackbox-only` to remove it
  from the end-to-end verdict. See [`docs/ASSURANCE.md`](docs/ASSURANCE.md).
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

## Direction and priorities

<!-- BEGIN EVOGUARD_PROJECT_STATUS:ROADMAP_CURRENT_PIPELINE -->
Releases ship through the manually dispatched protected-release workflow
(`.github/workflows/release.yml`): tag-equals-version validation, the full test suite,
Linux and Windows end-to-end checks, a reproducible artifact build with checksums, and
asset attestation. It prepares a byte-verified draft, then a distinct protected
Environment approval authorizes a no-checkout job to revalidate live source,
tag-ruleset, signed-tag, and asset authority, publish, and prove exact immutable
readback. No release step is gated on dates, elapsed time, or stabilization windows. The
detached-maintainer-signed direct record for `v4.7.1` records successful workflow run
`33532737067` and post-publication byte readback. Its signature authenticates the exact
maintained record bytes, but the evidence remains a same-owner observation, not
independent validation or a protected A-through-H ledger. The archived A-H signed lane
is implemented in source but inert with every activation flag false; it is a design
reference, not the current release path.
<!-- END EVOGUARD_PROJECT_STATUS:ROADMAP_CURRENT_PIPELINE -->

Future work is driven by verified adoption, real threat cases, and observed user
needs — not feature accumulation. The ordering below is a statement of priority,
not a freeze: the gate continues to grow, scoped honestly.

The near-term priority is adoption and distribution of the core gate. The
self-contained, mechanically-provable assurance already established — invariant
fuzzing, mechanical-corpus efficacy, the security mutation gate, and metamorphic
agreement (see [`SELF_PROOF.md`](docs/SELF_PROOF.md)) — needs no external reviewer
and is sufficient to ship and to be useful today, provided every claim stays
within the recorded scope and the standing non-claims below. Independent
third-party evaluation is a **valued but optional, additive** credibility
milestone — not a precondition for release, adoption, or any affirmative claim
this project already makes within scope. Near-term external assurance is pursued
through reproducible run-it-yourself evidence and an open "make the gate lie"
red-team, neither of which waits on appointed reviewers. The independent round
described below is run when a concrete need calls for it, not as a gate on
everything else.

1. **Current artifact boundary.** The current immutable `v4.7.1` consumer is
   selected by a detached-maintainer-signed same-owner direct record of the
   exact protected publication and byte readback. It is not an A-through-H
   ledger or independent review. Historical `v4.6.0` remains the latest signed
   ledger and records a bounded, completed protected A-H operation over its
   zipapp, SPDX SBOM, checksum manifest, and publication. Neither record
   establishes reproducibility, correctness, production readiness, deployment
   authorization, or independent review. Release `v4.6.0` also contains one
   separate versioned, library-only public-GHCR OCI provider
   relation, but it has no CLI, protected workflow, or live manifest/index
   pilot. Therefore neither that implementation, the current `.raae`, nor the
   release ledger grants production OCI or deployment authority.
   [Issue #78](https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues/78) remains
   open pending the real OCI evidence and its other acceptance paths.
2. **Independent evidence.** The immutable
   [`review-v4.5.0-r1` companion](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/review-v4.5.0-r1)
   remains a frozen historical aid for the unsupported `v4.5.0` release. The
   [security-review request #141](https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues/141)
   targets the immutable `v4.6.0` release. Neither the historical companion nor
   the open request is evidence that an independent review occurred. The separate
   [current field-pilot #266](https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues/266)
   must pre-register exactly **80 total cases**: **32 tuning** cases from four
   repositories (eight per repository) and **48 held-out** cases from four
   different repositories (twelve per repository). Each subset spans Python,
   Node, Go, and JVM, and no repository may cross the tuning/held-out boundary.
   Freeze the sampling
   unit, duplicate rule, label balance, exclusions, per-track policy/profile,
   verifier pack, runtime and baseline, declared label/execution/finalizer
   authorities, distinct key identities, and ownership/control relationships
   before execution. Bind the exact `v4.6.0` release commit, asset, and signed
   ledger bytes. Report Guard errors, unsupported/incomplete cases, timeouts,
   and infrastructure failures outside the confusion matrix rather than
   converting abstentions into decision errors. That round measures protocol,
   compatibility, and onboarding behavior; it is not by itself a production
   or population-accuracy proof. Same-owner cross-account review remains
   operational separation, not independence; genuine independence would require
   externally independent organizational control. When pursued, this round is an
   optional, additive validation milestone that strengthens the
   independent-evidence claim — it gates neither release nor use.
3. **Only after adoption evidence.** Stronger fork/VM boundaries, organization
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
