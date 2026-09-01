<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# Releasing EvoOM Guard

This is the complete, current release process. It is evidence-gated and
manual-dispatch: nothing waits on dates, elapsed time, or stabilization
windows (see the [release cadence policy](GOVERNANCE.md#release-cadence-policy-evidence-gated-never-time-gated)).

## Live prerequisites

These are state checks, not waiting periods. They may all be satisfied and
re-checked immediately:

- GitHub Immutable Releases is enabled for the repository. A disabled,
  inaccessible, or schema-incompatible setting fails before any draft is
  created.
- Both `evoguard-release-draft` and `evoguard-release-publication` remain
  custom-branch-policy `main`-only, use the configured MANA-awam review
  authority, prevent self-review and have no wait timer. Before it can mutate a
  release, the publish job requires the publication Environment to contain
  exactly reviewer `MANA-awam` (`User` ID `304223352`), one branch-policy rule,
  and one paginated deployment-branch-policy entry whose exact name/type is
  `main`/`branch`; administrator bypass must be disabled.
- Both Environments contain
  `EVOGUARD_IMMUTABLE_RELEASES_READ_TOKEN`, a fine-grained token limited to
  repository Metadata read, Administration read, Actions read, Checks read,
  and Contents read. The write-capable GitHub job token remains separate.
- The exact dispatch commit remains in the ancestry of current protected
  `main`, has a valid GitHub signature, and has all eleven required checks from
  their exact GitHub App IDs in `success`. Normal merges may advance `main`
  while approval is pending; advancing it does not invalidate an already
  signed release commit that remains in protected history.
- The exact active `main` ruleset is pinned by
  `EVOGUARD_RELEASE_MAIN_RULESET_ID`, targets only `refs/heads/main`, and has no
  bypass actors. In particular, the temporary tag transport must never gain a
  generic DeployKey bypass on `main`.
- One active repository-owned tag ruleset named
  `EvoOM Guard release tag authority` is pinned by
  `EVOGUARD_RELEASE_TAG_RULESET_ID`. It targets only `refs/tags/v*` and makes
  creation, update, deletion, and non-fast-forward operations bypass-only. Its
  sole bypass class is `DeployKey`; no repository role or administrator is a
  ruleset bypass.
- The temporary write deploy key used to transport the already-signed tag has
  been deleted before dispatch. Publication requires the paginated repository
  deploy-key inventory to be empty. Neither release job receives a private key.
- A pre-existing annotated `vX.Y.Z` tag points to that exact commit and is
  signed by the pinned EvoRiseKsa maintainer key. Lightweight, unsigned,
  missing, or retargeted tags fail closed. Any drift may be corrected and
  re-checked immediately without a calendar delay.

The no-bypass main ruleset, tag ruleset, retired transport key, and pre-existing
signed tag form one live state gate. As soon as that state is exact, the
workflow may be dispatched and approved immediately; there is no stabilization
duration, cooldown, or timed freeze hidden in the publication path.

## The path

One workflow, [`release.yml`](../.github/workflows/release.yml), dispatched
by a maintainer. It runs entirely on the default branch, prepares a **draft**,
then pauses at a second protected Environment. Publication remains a
deliberate human approval, while the state transition and its readback are
performed by one fail-closed job instead of an unbound web-UI click.

1. **Prepare `main`.**
   - `evoom_guard/__init__.py` carries the exact stable version
     (`X.Y.Z`, no `.dev0`).
   - `CHANGELOG.md` has a dated `[X.Y.Z]` section.
   - CI is green on the tip of `main`.
2. **Create the signed tag through the declared authority.** Sign an annotated
   `vX.Y.Z` tag at that exact `main` commit with the pinned release-maintainer
   signing key, then push the already-signed object using a temporary write
   deploy key. The active tag ruleset allows that temporary authority
   to create the tag while preventing ordinary repository credentials from
   creating, replacing, retargeting, or deleting `v*` tags. Delete the deploy
   key immediately after the push and prove the repository key inventory is
   empty before dispatch. The `main` ruleset must have zero bypass actors. The
   workflow itself receives neither private key and will not create or mutate a
   tag. The initial tag-push CI verifies source/tag consistency but treats an
   absent release or exact draft as an expected prepublication state; the
   release workflow's mandatory `post-publication-verify` job reruns the
   read-only immutable asset verifier.
3. **Dispatch.** GitHub → Actions → *Release* → *Run workflow*, with
   `tag = vX.Y.Z`. The tag input must equal `'v' + evoom_guard.__version__`
   or the run fails immediately.
4. **The workflow does the rest, fail-closed at every step:**
   - `validate-test` — tag/version match, Ruff, strict Mypy lanes, the full
     test suite;
   - `release-e2e` and `release-windows-e2e` — end-to-end runs of the built
     gate on Linux and Windows;
   - `build-artifact` — reproducible `evo-guard.pyz` plus the
     `evo-guard.spdx.json` SBOM and a filename-ordered `SHA256SUMS`;
   - `attest-release-assets` — GitHub build-provenance and SBOM
     attestations for the exact asset bytes, verified in a clean job;
   - `prepare-draft` — after the first protected Environment approval, re-reads the
     immutable-release setting, exact GitHub-verified `main`, the annotated-tag
     signature against the pinned maintainer root, and required checks; then
     re-verifies the transferred assets, enumerates drafts with pagination,
     requires a unique tag match, and binds the **draft** release and all asset
     readbacks to numeric provider IDs. The draft for the existing tag contains
     exactly `evo-guard.pyz`,
      `evo-guard.spdx.json`, and `SHA256SUMS`;
   - `publish-release` — after the distinct publish Environment approval,
     performs no checkout and executes no project bytes. It revalidates the
     exact protected `main` SHA, required check/App identities, immutable-release
     setting, publish-Environment rules, raw annotated-tag signature, release
     identity, canonical null/string body digest, asset IDs/labels/uploaders,
     server asset digests, and numeric-ID-downloaded asset bytes immediately
     before publishing. The public release-by-tag identity is joined only after
     the provider reports the release published and immutable.
     It then publishes and requires an immutable release, unchanged tag, exact
     body/metadata, and byte-identical asset readback.
   - `post-publication-verify` invokes the separate read-only reusable verifier
     after `publish-release`; it rebuilds and compares the immutable assets, so
     the pre-existing-tag ordering cannot leave a successful release workflow
     without a postpublication observation. The verifier can also be dispatched
     manually later from exact descriptors.
5. **Review and approve publication.** While `publish-release` is waiting for
   Environment approval, the maintainer inspects the draft — assets,
   checksums, and generated notes — without modifying it. The post-upload draft
   body is digest-bound; any edit after preparation fails publication. If notes
   need correction, edit the still-unpublished draft and rerun the workflow so
   the corrected body is captured and reviewed afresh. Approval, rather than a
   separate Publish click, authorizes the guarded transition.
6. **Record the exact published result.** On a follow-up commit, create
   `evidence/direct-releases/vX.Y.Z/DIRECT_RELEASE.json` from the immutable
   provider readback. The record must bind the source and annotated tag,
   numeric release/asset/run/job/deployment identities, exact asset bytes,
   workflow blobs, postpublication verification, point-in-time controls, and
   the explicit same-owner/non-independent trust boundary. Authenticate those
   exact JSON bytes with the pinned EvoRiseKsa maintainer key as the detached
   `DIRECT_RELEASE.json.sig`, using SSH identity `EvoRiseKsa` and namespace
   `git`. Pin both lowercase SHA-256 digests in `PROJECT_STATUS.json`, retain
   the newest validated A-through-H ledger only as historical evidence, then
   run `python -I ops/render_project_status.py --write`. The renderer verifies
   the byte pins, detached signature, record cross-bindings, historical
   boundary, and generated status blocks before the follow-up commit is
   reviewable. This maintained direct record is not an A-through-H release
   ledger, independent review, RSAE/RAAE evidence, or a substitute for any of
   them; do not fabricate a ledger, unsealed-status exception, erratum, or key
   disposition for a successful `simple-release-v1` publication.

The automated claim now ends at a published immutable release with exact tag,
metadata, digest, and byte readback. GitHub exposes no conditional/CAS form of
the release-publication PATCH, so this is not a claim of mathematical atomicity
against every possible concurrent repository writer. The workflow narrows that
provider boundary by re-reading all mutable authority immediately before the
single PATCH and proving the complete immutable post-state immediately after
it. Any ambiguous or changed state fails closed and requires manual recovery;
it never introduces a calendar delay.

Actions artifacts use GitHub's ordinary storage retention. That storage
lifetime is not a not-before condition: if the draft-approval job is left
pending until its build artifact expires, rerun the workflow and approve the
new exact attempt immediately. The final publication job depends only on the
already-reviewed draft assets plus their bounded descriptors, not on a
short-lived Actions artifact.

## Rules that survive from the old design

The archived signed lane ([RELEASE_TRUST_PIPELINE.md](RELEASE_TRUST_PIPELINE.md))
is gone as a process, but its non-negotiables remain policy:

- **Never mutate a published release.** Tags, assets, checksums,
  attestations, and ledger/record bytes of anything already published are
  immutable; corrections ship as a new version plus an explicit erratum.
- **Draft-then-protected-publish.** No unreviewed job may publish. A human
  authorizes the final act through the separate protected Environment, and the
  reviewed job—not the browser—performs and proves the state transition.
- **Exact assets only.** A release carries exactly the three contracted
  assets; nothing else rides along.
- **Honest claims.** Release notes state what the evidence shows and carry
  the project's non-claims where they apply (see
  [ASSURANCE.md](ASSURANCE.md)).
- **Authenticated records remain bounded records.** A detached maintainer
  signature authenticates the exact postpublication record bytes and signer;
  same-owner signing does not turn the record into independent validation or
  into an A-through-H release ledger.

## What was deliberately removed

- The fourteen-day stabilization window, its freeze declaration, and both
  freeze validators (deleted 2026-08-31; policy in
  [GOVERNANCE.md](GOVERNANCE.md)).
- The signed-source promotion workflow `P` — promotion to `main` through a
  frozen declaration no longer exists as a concept.
- Any dependency of releasing on repository Actions variables of the
  `EVOGUARD_V470_FREEZE_*` family; they are unused and safe to delete.
