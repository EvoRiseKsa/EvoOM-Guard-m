# Protected release trust pipeline

> **ARCHIVED (2026-08-31).** The A–H signed lane described here is an inert
> design reference, not the release path. Time-based release gates — the
> freeze declaration, the fourteen-day boundary, and their validators — are
> abolished by policy (see [`GOVERNANCE.md`](GOVERNANCE.md)), and the
> promotion workflow P has been deleted. Releases ship through the manually
> dispatched draft-release workflow documented in
> [`RELEASING.md`](RELEASING.md). Procedural sections below that reference
> P, the freeze declaration, or waiting windows are historical.

> **Audience:** release maintainers and independent auditors. This is an
> implementation and authority-separation contract, not an end-user setup
> guide. Consumers should start with [`README.md`](../README.md) or
> [`START_HERE.md`](START_HERE.md).

This document describes an inert-by-default signed-source promotion P followed
by the A–H release pipeline. Except for
the exact retained `v4.4.2`, `v4.5.0`, and `v4.6.0` evidence named under **Current state**, its
procedural sections do not claim that another release has traversed the
pipeline, that mutable repository settings remain configured, or that any
corresponding private signing key currently exists or remains controlled.

## Current state

<!-- BEGIN EVOGUARD_PROJECT_STATUS:RELEASE_TRUST_PIPELINE_STATUS -->
Releases ship through the manually dispatched protected-release workflow
(`.github/workflows/release.yml`): tag-equals-version validation, the full test suite,
Linux and Windows end-to-end checks, a reproducible artifact build with checksums, and
asset attestation. It prepares a byte-verified draft, then a distinct protected
Environment approval authorizes a no-checkout job to revalidate live source,
tag-ruleset, signed-tag, and asset authority, publish, and prove exact immutable
readback. No release step is gated on dates, elapsed time, or stabilization windows. The
detached-maintainer-signed direct record for `v4.8.0` records successful workflow run
`33642398535` and post-publication byte readback. Its signature authenticates the exact
maintained record bytes, but the evidence remains a same-owner observation, not
independent validation or a protected A-through-H ledger. The archived A-H signed lane
is implemented in source but inert with every activation flag false; it is a design
reference, not the current release path.
<!-- END EVOGUARD_PROJECT_STATUS:RELEASE_TRUST_PIPELINE_STATUS -->

`v4.6.0` is the latest historical A-through-H ledger referenced by
`PROJECT_STATUS.json`; the current consumer release is direct-recorded
`v4.8.0`. The historical ledger's canonical signed
[`release-ledger-v2`](../evidence/release-ledgers/v4.6.0/RELEASE_LEDGER.json)
records the exact protected A-through-H operation and resulting publication.
The previous signed
[`release-ledger-v2`](../evidence/release-ledgers/v4.5.0/RELEASE_LEDGER.json)
remains historical evidence.
The earlier signed [`v4.4.2` recovery ledger](../evidence/release-ledgers/v4.4.2/RELEASE_LEDGER.json)
remains historical evidence. Both `v4.4.0` and `v4.4.1` remain
published-unledgered under their separate errata, including the
[`v4.4.1` release-ledger erratum](errata/V4.4.1-LEDGER.md).

The reviewed `v4.6.0` ledger-signing public root is pinned at
[`v4.6.0.pub.pem`](../security/release-ledger-roots/v4.6.0.pub.pem) with key ID
`sha256:ef56c9e65a355d2956201fe8e02abb7c39857d42ee3623d09d71236341ac1da1`.
That previously authenticated root and the admitted parent are trust inputs;
the root alone did not prove private-key custody, a signature, pipeline
execution, or publication. The canonical signed directory plus offline
validation now establish only the retained byte and binding claims implemented
by the validator. They do not turn mutable GitHub state into an independent
attestation. Publication-authority retirement remains a separate post-ledger
operation and is not claimed complete by the `v4.6.0` ledger.

After those committed ledger bytes were independently revalidated, the exact
temporary `v4.6.0` publication authority was removed. The later signed,
same-owner point-in-time absence observation is retained separately as
[`KEY_RETIREMENT.json`](../evidence/release-operations/v4.6.0/KEY_RETIREMENT.json).
It does not alter the ledger's correct `pending-post-ledger` state or prove
secure erasure, absence of external copies, or prevention of later re-addition.

For `v4.5.0`, the later signed, same-owner point-in-time retirement observation
is retained separately as
[`KEY_RETIREMENT.json`](../evidence/release-operations/v4.5.0/KEY_RETIREMENT.json).

The proposed `v4.5.1` stable patch remains a separate, inert maintenance case.
Its Phase-0 analysis recorded the then-current main-line limitations: source
promotion could not preserve a maintainer-signed commit and H created a
lightweight tag. The v4.7.0 main-line contract now addresses those two issues
for a new minor release with exact signed-commit promotion and a pre-signed
annotated tag object; it does not retroactively activate or prove the v4.5.1
maintenance lane.
The Phase-0 model, negative tests, explicit blockers, and required redesign are
recorded in [`V4.5.1_MAINTENANCE_LANE.md`](V4.5.1_MAINTENANCE_LANE.md). The model
does not treat a self-reported snapshot as live or closed-world proof, and it is
not evidence that a maintenance branch, candidate, tag, or release exists. Its
observation helper validates non-authoritative shapes only; it performs no
GitHub authentication, cryptographic verification, F/G byte comparison, or
canonical tag parsing. The generic DeployKey ruleset bypass additionally
requires a future complete owner-collected listing proving one exact
write-enabled deploy key, exact publication-secret metadata, private/public key
binding inside trusted H, per-run temporal binding, and post-publication key,
secret, variable, and one-shot retirement.
The Phase-0 contract now freezes the maintainer public key at the normalized
repository path `security/v4.5.1-maintainer-signing.pub`, mode `100644`, and
requires its externally pinned blob to appear under that path in the pinned
trusted-workflow tree observation. Raw annotated-tag input is limited to 32 KiB
decoded so its Base64 form remains conservatively below GitHub's 48 KiB
variable limit. Control-plane timestamps are real, canonical whole-second UTC
RFC3339 values, and the activation blocker inventory is an exact closed set of
stable IDs.

The v4.7.0 design, custody non-claims, server-time freeze anchor, ruleset-only
promotion window, local signing procedure, and retirement order are specified
in [`V4.7.0_SIGNED_RELEASE_LANE.md`](V4.7.0_SIGNED_RELEASE_LANE.md). GitHub
registration of the pinned maintainer public signing key and all live
post-merge configuration remain pending external prerequisites.

## Phase contracts

| Phase | Workflow | Authority and prohibited operations |
| --- | --- | --- |
| P | `evoguard-promote-signed-release-source.yml` | From the exact frozen declaration commit, accepts only one reviewed, GitHub-verified and locally verified maintainer-signed one-parent v4.7.0 candidate. Preflight reads the source-transport and ruleset identities once, exports them as immutable job outputs, and all later jobs consume only those outputs. Before the transport secret is exposed, P requires aggregate PR approval/clean state, exact checks, resolved threads, a fresh GitHub server-time freeze anchor, no classic branch protection, one exact active/effective `main` ruleset, and one exact write deploy key; it then uploads a closed active-authority snapshot/receipt. A short key-bearing step pushes only the exact raw candidate SHA to `main` with a lease and accepts only Git's true-fast-forward porcelain record. Once the closed active artifact exists, the protected retirement job runs on ordinary failure even if promotion does not complete and accepts only `main` at the frozen base or exact candidate. Its five-file terminal artifact binds `promotion_completed` and the observed terminal SHA to the active evidence and fresh retired snapshot under the same ruleset/key identity. P fails overall for the base state and cannot succeed until it also has complete post-push capture, validation, and upload; A and H reject any state except the exact candidate. It has no maintainer signing key. |
| A | `evoguard-release-source-reverify.yml` | Reads the exact one-parent protected-main v4.7.0 candidate. Before candidate execution, parent-owned code downloads and validates the exact five-file terminal P artifact named by run ID/attempt, derives the frozen source key/ruleset identity from that binding rather than mutable variables, recaptures and proves the source authority remains retired, then verifies the raw commit signature, release-record-only freeze declaration, GitHub exact-push server-time anchor and fourteen-day boundary, and exact `4.7.0.dev0` to `4.7.0` compatible-minor promotion scope. Its observer token is Administration-read only; A has no signing, OIDC, attestation, or write authority. |
| B | `evoguard-produce-release-source-receipt.yml` | Produces an unsigned canonical receipt and GitHub attestation for A. It never checks out or executes candidate source. |
| C/D | `evoguard-admit-release-source.yml` | Preflight freezes external controls before Environment access; protected C freshly verifies B under a provider UID that cannot read the RSAE key; detached D verifies the envelope and negative mutations without a key or provider call. |
| E-build | `evoguard-build-release-artifact.yml` | Verifies RSAE and checks out the admitted source. The executable builder and SPDX generator are literal `100644` Git blobs from its sole parent, whose commit and tree must equal A's admitted base. E extracts and hashes those blobs without filters, runs them in one exact digest-pinned container with `network: none` against the read-only candidate, records the container reference/digest/network plus parent commit/tree in `builder-controls.json`, and independently compares every packaged byte to source. F reconstructs and requires that exact controls object from trusted Git/API context and the downloaded bytes. E has no OIDC, attestation, secret, or write permission. |
| E-attest | same workflow, separate job | Downloads an exact closed file set, performs no checkout and executes neither source nor artifact, then creates build-provenance attestations for the pyz and SPDX subjects plus an SBOM attestation binding the SPDX predicate to the pyz. |
| F | `evoguard-admit-release-artifact.yml` | Freezes E/F identities and six distinct admission public roots before Environment access. A no-secret `verify-attestations` job freshly verifies all three E attestations, retains their exact receipts and provider outputs in the complete F control artifact, and only then may the protected seal job create separate RAAEs for the pyz and SPDX bytes. |
| G | `evoguard-verify-release-artifact.yml` | Re-verifies both detached RAAE envelopes, exact checksums, cross-artifact substitution, byte mutations, root substitution, and tool-pin mutations without a provider call or private key. It also requires each RAAE's embedded provider evidence to equal the complete F controls and the retained ledger evidence byte-for-byte. |
| H | `evoguard-publish-admitted-release.yml` | Preflight independently re-verifies both RAAE envelopes and the exact pre-signed annotated v4.7.0 tag object against the parent-pinned maintainer root, preserves the F-to-G bindings, and stages exactly three assets. It derives the retired source-transport ID and fingerprint from the exact P retirement artifact named by the admitted source, not from mutable repository variables. The two protected Environments retain read-only intent then publication separation. Immediately before exposing the tag transport secret, and again after publication, parent-owned code uses a read-only observer to prove the source key remains retired, main has no bypass, one exact `v*` tag ruleset has the sole generic `DeployKey` bypass, and the pinned, cryptographically distinct H key is the sole enabled writer. H imports the bounded raw tag bytes into a bare repository and pushes the tag-object SHA—not the target commit—through that key. It requires an annotated `tag` ref peeling to the admitted commit plus GitHub `verified=true`, `reason=valid`. H never receives a maintainer signing key. A failure-only step removes only the exact still-draft release after a pre-PATCH failure, only when the tag is provably absent and the ID, body, author, target, and complete asset set all match; ambiguity or a PATCH-boundary marker requires manual recovery. After PATCH begins no automatic destructive recovery is safe. |

The pyz and SPDX document use separate RAAE envelopes because the core contract
binds one regular file per envelope. `SHA256SUMS` is derived by E from those two
exact files, checked by F, G, and H, and is not treated as a third independent
admission.

## v4.7.0 signed-minor bootstrap sequence

1. Merge this parent contract while every activation flag remains false. Add
   the pinned maintainer public key to the `EvoRiseKsa` account as a GitHub
   signing key; the private key remains outside the repository and Actions.
2. Create the exact active `main` repository ruleset in
   [`V4.7.0_SIGNED_RELEASE_LANE.md`](V4.7.0_SIGNED_RELEASE_LANE.md), prove
   ordinary PR behavior, then remove classic `main` protection. Record the
   ruleset ID and the four exact freeze-push workflow IDs. No global
   required-signatures rule is added; P/A enforce the release object instead.
3. Merge a separate one-parent release-record-only freeze declaration. Pin its
   resulting commit/tree. Git `%ct` is only a sanity check: the four exact
   successful attempt-1 push runs and GitHub `created_at` values are the time
   anchor. Wait at least fourteen full days with no candidate-tree change.
4. Locally create the exact stable-scope one-parent commit with the offline
   maintainer key. Push that immutable SHA to a same-repository review branch;
   do not amend, squash, merge, or rebase it afterward. Require aggregate
   `APPROVED`/`CLEAN`, exact-head MANA approval, resolved threads, and all eleven
   check/App-ID pairs.
5. Install exactly one temporary write deploy key and the Administration-read
   observer token in `evoguard-release-source-promotion`. Confirm no other
   enabled write deploy key exists, enable only the exact candidate SHA, and
   approve P. P freezes the public key/ruleset identities once, uploads the
   active-authority evidence before exposing the private key, performs its
   pre/post snapshots and exact fast-forward, but remains non-terminal pending
   authority retirement.
6. Delete the source deploy key first, remove the generic DeployKey bypass from
   the `main` ruleset, then approve only
   `evoguard-release-source-retirement`. Require P's five-file terminal closure
   artifact to bind the same active key/ruleset evidence to the retired state;
   remove its private-key secret and one-shot variable, but retain the
   read-only observer and frozen authority IDs through A and H. Do this before
   any tag deploy key is installed.
7. Enable and run A/B/C/D, then E/F/G, preserving the existing separation and
   exact evidence-set contracts. A must independently bind the terminal P run,
   re-prove live source retirement, and reproduce both the raw Git signature
   result and GitHub server-time freeze result before candidate execution.
8. Locally create and verify the signed annotated `v4.7.0` tag without pushing
   it. Export its exact raw bytes, pin their Base64 and tag-object SHA, and
   configure H's fresh sole write tag key plus `v*` ruleset.
9. Approve H's read-only intent and publication Environments. Require its
   immediate pre-secret and post-publication authority receipts, then require
   the tag ref to remain an annotated object with the exact object SHA, peel to
   the admitted commit, and be GitHub-verified before and after immutable
   release publication.
10. Freeze a new signed ledger version rather than mutating historical v2
    schemas or records. It must retain the signed source/tag receipts, freeze
    server-time anchor, P control-plane snapshots, A–H evidence, public roots,
    workflow/tool pins, assets, and pending retirement state.
11. Independently revalidate the committed ledger bytes, then remove H's tag
    key/secret/raw-object variables and freeze a separate signed retirement
    observation. Actions artifacts alone are not durable evidence.

## Historical v4.6.0 bootstrap sequence

The following retained sequence explains the already recorded v4.6.0 ledger.
It must not be used to bypass the v4.7.0 signed-commit, server-time, ruleset, or
annotated-tag requirements above.

1. Merge this inert infrastructure through protected `main` with a merge
   commit. Squash and GitHub rebase-and-merge rewrite or discard the benchmark
   source/results commit IDs named by the final manifest and are invalid.
   Verification requires those commits to be distinct, ordered
   source-to-results, and retained below the protected parent.
2. Keep all activation flags false and confirm a manual A/E dispatch skips.
3. Before changing a flag, verify protected `main` has strict required status
   checks and `enforce_admins`, with admin bypass disabled. Configure all four
   Environments (`evoguard-release-source-v2`,
   `evoguard-release-artifact-v1`, `evoguard-release-draft`, and
   `evoguard-release-publication`) with required reviewer `MANA-awam`,
   prevent-self-review,
   deployment branches limited to `main`, and no administrator bypass. Merely
   naming an Environment does not establish these controls.
4. Read the seven numeric workflow IDs from GitHub and the seven raw-Git blobs
   from the exact protected merge tree. Record them out of band before setting
   repository variables.
5. Pin one previously published Guard runtime that already implements RSAE and
   RAAE. The URL and SHA-256 are separate trust roots; a checksum fetched from
   the same URL is not a pin.
6. Review the canonical Git executable hash on `ubuntu-24.04`. For GitHub CLI,
   review the official pinned archive, archive size, one exact member, and the
   resulting executable hash/size embedded in each C/F/H workflow. Every job
   that executes `gh` independently materializes those bytes at the fixed
   root-owned path and invokes that path explicitly; it must not discover the
   runner's preinstalled `/usr/bin/gh`. The externally configured `gh` digest
   must equal the embedded executable pin. Source admission uses UID/GID 60001;
   artifact admission uses 60002. The identities must not be root or `65534`.
7. Establish six mutually distinct admission Ed25519 signing public-key IDs.
   Store only their public PEM values as repository variables. Establish a
   fresh per-release seventh ledger-signing identity before the trusted
   parent/candidate. The `v4.6.0` public PEM/ID above was pinned in
   the reviewed parent tree; keep its private half offline and outside the
   admission Environments. The retained ledger copy is never
   its own trust anchor. C and F private keys belong
   only in their separately protected Environments. Separately create exactly one
   write-enabled deploy key for release tags; store its private half only in
   `evoguard-release-publication`. H has no signing secret.
8. Merge a distinct one-parent **source candidate**. A must consume its policy,
   pack, locks, and release-scope validator from that candidate's parent; the
   infrastructure commit cannot authorize itself. For v4.6.0, the parent
   validator requires literal path case and an exact development-to-stable
   version-assignment byte replacement, in addition to Guard's protected-path
   and external verifier-pack checks. The candidate may not refresh
   `benchmarks/results.jsonl` or `benchmarks/run-manifest.json`; CI uses the
   explicit exact-promotion verification rule described in the benchmark
   documentation.
9. Temporarily freeze protected `main`; run A/B/C/D; inspect the no-secret C
   controls before approving C; require `ALLOW` and detached negatives.
10. Dispatch E with the separately reviewed stable `X.Y.Z` version. Run E/F/G;
    inspect the complete no-secret F controls before approving the protected
    seal; require three fresh provider verifications, exact receipt/output
    retention, two detached `ALLOW` results, and the complete negative matrix.
11. Before H, freeze every other `contents: write` actor and all manual or
    automated release operations. Require an active `v*` tag ruleset covering
    creation, update, deletion, and non-fast-forward, with `DeployKey` as its
    only bypass class; require the main ruleset to expose no bypass, the retired
    source-key ID to be absent, and the repository to have exactly one
    write-enabled deploy key. Record the tag ruleset/key IDs and public
    fingerprint, then require H's parent-owned validator to reproduce this
    complete live state immediately before secret exposure and again after
    publication.
    With an administrator credential outside Actions, require
    `GET /repos/EvoRiseKsa/EvoOM-Guard-m/immutable-releases` to return
    `enabled=true`, then set `EVOGUARD_RELEASE_PUBLICATION_ENABLED` to the exact
    admitted target SHA (never the generic value `true`). This target-bound
    owner authorization must still match when each protected job starts.
    Enable publication only for the reviewed G attempt. Approve the read-only
    `evoguard-release-draft` intent, then separately approve
    `evoguard-release-publication`; that one job creates and immediately
    publishes the exact draft through the API. The read-only observer and
    frozen source/tag authority IDs remain available through this gate but
    cannot write. Require H success,
    `immutable=true`, and the new tag resolving to the admitted target. Do not
    use the GitHub **Publish release** button as a trusted alternative.
    If PATCH begins and H then fails, disable publication, inspect the exact
    release ID recorded by H, and delete only a still-draft matching ID, tag,
    target, marker, author, and assets; never use the Publish UI to recover.
    Marketplace listing remains a separate, non-admission step.
12. Immediately after H, return all flags to false and remove both admission
    signing private-key Environment secrets. Record successful, fully paginated
    repository and Environment secret-name-list observations for those exact
    names. The repository is owned by the `EvoRiseKsa` user account, not an
    organization, so there is no organization-secret scope to query. These are
    same-owner observations in one bounded non-atomic API window and do not
    prove simultaneous state, absence from another repository, absence of
    external key copies, or prevent re-addition. Keep the publication deploy-key secret
    and exact write deploy key until the operator has committed and revalidated
    a signed release ledger that records their public ID/fingerprint and
    explicitly marks retirement pending. Then delete both and freeze a separate
    signed retirement receipt;
    create a fresh deploy key for the next release window. If an operational
    exception keeps it temporarily, it must remain only in the no-admin-bypass
    publication Environment and the repository must still have exactly one
    write deploy key.
    GitHub Actions artifacts are temporary evidence (even where repository
    retention is configured for 30 days), not a durable ledger.
13. The published `v4.4.0` and `v4.4.1` operations cannot issue canonical
    ledgers because each descriptor is bound to its own frozen validator
    defect recorded in the corresponding
    [`v4.4.0`](errata/V4.4.0-LEDGER.md) and
    [`v4.4.1`](errata/V4.4.1-LEDGER.md) errata. Do not apply corrected
    validators retroactively. The `v4.4.2` recovery operation produced a signed
    post-publication ledger containing both RAAE envelopes, RSAE/controls, six
    admission public roots and IDs, a seventh distinct release-ledger signing
    public root/ID, run/workflow/tool pins, and release checksums. Those trust
    envelopes were not published as release assets, and the ledger step must
    never create, move, or rewrite a tag. Never rewrite a frozen release,
    historical baseline, or prior ledger.
    The retained post-publication ledger validates against
    `tests/baseline/schema/release-ledger-v2.schema.json` and passes the offline
    byte, binding, envelope, and signature checks in
    `tools/ci/validate_release_ledger_v2.py`. The schema, validator, and
    pre-pinned root alone did not constitute that ledger.
    Validate with the independently retrieved key via
    `--trusted-ledger-pub`, commit the ledger to protected main, and validate
    the committed bytes again before removing publication authority. This
    ordering is an operator procedure: the retirement receipt proves signed
    observation timestamps after the ledger's `created_utc`, not that a Git
    commit existed first. Retain the offline ledger private key only through
    the separate retirement-receipt signature and validation, then destroy it.
    GitHub permits editing an immutable release's title and description, so
    neither field is authoritative trust metadata. The immutable tag, exact
    assets and digests, attestations, and separately frozen signed ledger are
    the durable evidence.

## Exact non-claims

Same-owner GitHub account approval is procedural separation, not independent
review. GitHub-hosted runners, GitHub Attestations, the reviewed runtime,
Docker, Git, `gh`, and protected repository settings remain explicit trust
dependencies. An RAAE proves the implemented binding and verification events;
it does not prove absence of vulnerabilities, reproducibility across unrelated
builders, safe deployment, or external certification.
GitHub's release API has no compare-and-swap transaction spanning draft
creation, deploy-key tag creation, and publication. The active tag ruleset
prevents other actors from creating or mutating `v*`, while the
`contents: write` freeze limits release-API races. The postcheck detects
interference but cannot safely undo an already immutable wrong publication.
GitHub force-cancellation, runner loss, or control-plane outage can prevent an
`always()` cleanup or retirement step from running. Such a run is non-terminal:
the operator must prove source/tag authority retirement and reconcile any exact
draft/tag state before another release attempt. No workflow claim upgrades that
operational recovery into globally exactly-once execution.
