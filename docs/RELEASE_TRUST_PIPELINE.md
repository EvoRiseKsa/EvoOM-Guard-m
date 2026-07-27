# Protected release trust pipeline

This document describes an inert-by-default A–H release pipeline. It does not
claim that a release has traversed the pipeline, that repository settings have
been configured, or that any key currently exists.

## Current state

<!-- BEGIN EVOGUARD_PROJECT_STATUS:RELEASE_TRUST_PIPELINE_STATUS -->
The protected A-H release pipeline is implemented in source and **disabled by default**.
The legacy release workflow is hard-disabled. No externally anchored signed v2 ledger
records a completed protected A-H operation. No externally anchored signed v2 ledger
records publication by this pipeline. An admitted release is contracted to exactly
`evo-guard.pyz`, `evo-guard.spdx.json`, `SHA256SUMS`; this source contract is not
evidence that those assets were published.
<!-- END EVOGUARD_PROJECT_STATUS:RELEASE_TRUST_PIPELINE_STATUS -->

## Phase contracts

| Phase | Workflow | Authority and prohibited operations |
| --- | --- | --- |
| A | `evoguard-release-source-reverify.yml` | Reads the exact one-parent protected-main candidate. The policy, verifier pack, dependency lock, executable runtime, and v4.4.0 scope validator come from the parent or protected settings. Before candidate execution, the parent validator compares both fresh trees, requires an exact-case subset of the frozen existing release paths with unchanged file modes, rejects additions, deletions, ordinary unlisted changes, and benchmark evidence rewrites, and permits `evoom_guard/__init__.py` to differ only by the exact `4.4.0.dev0` to `4.4.0` assignment bytes. The retained benchmark therefore continues to name the dev0 engine actually measured; its explicit release-promotion verifier normalizes only that proven assignment while requiring every other source byte, result digest, and Git binding. A has no secret, OIDC, attestation, or write authority. |
| B | `evoguard-produce-release-source-receipt.yml` | Produces an unsigned canonical receipt and GitHub attestation for A. It never checks out or executes candidate source. |
| C/D | `evoguard-admit-release-source.yml` | Preflight freezes external controls before Environment access; protected C freshly verifies B under a provider UID that cannot read the RSAE key; detached D verifies the envelope and negative mutations without a key or provider call. |
| E-build | `evoguard-build-release-artifact.yml` | Verifies RSAE and checks out the admitted source. The executable builder and SPDX generator are literal `100644` Git blobs from its sole parent, whose commit and tree must equal A's admitted base. E extracts and hashes those blobs without filters, runs them in one exact digest-pinned container with `network: none` against the read-only candidate, records the container reference/digest/network plus parent commit/tree in `builder-controls.json`, and independently compares every packaged byte to source. F reconstructs and requires that exact controls object from trusted Git/API context and the downloaded bytes. E has no OIDC, attestation, secret, or write permission. |
| E-attest | same workflow, separate job | Downloads an exact closed file set, performs no checkout and executes neither source nor artifact, then creates build-provenance attestations for the pyz and SPDX subjects plus an SBOM attestation binding the SPDX predicate to the pyz. |
| F | `evoguard-admit-release-artifact.yml` | Freezes E/F identities and six distinct admission public roots before Environment access. A no-secret `verify-attestations` job freshly verifies all three E attestations, retains their exact receipts and provider outputs in the complete F control artifact, and only then may the protected seal job create separate RAAEs for the pyz and SPDX bytes. |
| G | `evoguard-verify-release-artifact.yml` | Re-verifies both detached RAAE envelopes, exact checksums, cross-artifact substitution, byte mutations, root substitution, and tool-pin mutations without a provider call or private key. It also requires each RAAE's embedded provider evidence to equal the complete F controls and the retained ledger evidence byte-for-byte. |
| H | `evoguard-publish-admitted-release.yml` | Preflight independently re-verifies both RAAE envelopes, preserves the F-to-G attestation-evidence bindings, and stages exactly three assets. The first protected Environment is read-only and rejects any existing tag/release. Only the second protected Environment has `contents: write` and the tag deploy key; it rechecks main and Immutable Releases, creates an attributable draft, reads back exact GitHub SHA-256 asset digests, creates the exact tag through the deploy-key-only `v*` ruleset, and immediately submits `draft=false` in the same job. Pre-PATCH failures delete only the exact verified draft and any exact tag created by that run; after PATCH begins no automatic deletion is safe. Bounded polling then requires an immutable release and exact tag-to-target binding. Marketplace listing remains separate. |

The pyz and SPDX document use separate RAAE envelopes because the core contract
binds one regular file per envelope. `SHA256SUMS` is derived by E from those two
exact files, checked by F, G, and H, and is not treated as a third independent
admission.

## Bootstrap sequence

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
6. Review the canonical Git and `gh` executable hashes on `ubuntu-24.04`.
   Source admission uses UID/GID 60001; artifact admission uses 60002. The
   identities must not be root or `65534`.
7. Establish six mutually distinct admission Ed25519 signing public-key IDs.
   Store only their public PEM values as repository variables. Establish a
   fresh per-release seventh ledger-signing identity before the trusted
   parent/candidate: pin its public PEM/ID in the reviewed parent tree or
   another authenticated immutable channel, and keep its private half offline
   and outside the admission Environments. The retained ledger copy is never
   its own trust anchor. C and F private keys belong
   only in their separately protected Environments. Separately create exactly one
   write-enabled deploy key for release tags; store its private half only in
   `evoguard-release-publication`. H has no signing secret.
8. Merge a distinct one-parent **source candidate**. A must consume its policy,
   pack, locks, and release-scope validator from that candidate's parent; the
   infrastructure commit cannot authorize itself. For v4.4.0, the parent
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
    only bypass class; verify the repository has exactly one write-enabled
    deploy key and record its ID and public fingerprint.
    Enable publication only for the reviewed G attempt. Approve the read-only
    `evoguard-release-draft` intent, then separately approve
    `evoguard-release-publication`; that one job creates and immediately
    publishes the exact draft through the API. Require H success,
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
13. After the first publication, freeze a `v4.4.0` ledger containing both RAAE
    envelopes, RSAE/controls, six admission public roots and IDs, a seventh
    distinct release-ledger signing public root/ID, run/workflow/tool pins, and
    release checksums. Do not publish those trust envelopes as release
    assets and do not create, move, or rewrite any tag from the ledger step.
    Never rewrite a frozen release, historical baseline, or prior ledger.
    The post-publication ledger must validate against
    `tests/baseline/schema/release-ledger-v2.schema.json` and pass the offline
    byte, binding, envelope, and signature checks in
    `tools/ci/validate_release_ledger_v2.py`. The schema and validator existing
    before publication do not themselves constitute a `v4.4.0` ledger.
    Validate with the independently retrieved key via
    `--trusted-ledger-pub`, commit the ledger, and validate the committed bytes
    again. This ordering is an operator procedure: the retirement receipt proves
    signed observation timestamps after the ledger's `created_utc`, not that a
    Git commit existed first. Retain the offline ledger private key only through
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
