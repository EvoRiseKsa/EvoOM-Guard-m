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
- `evoguard-release-draft` remains `main`-only, requires its configured
  reviewer, prevents self-review and has no wait timer.
- That Environment contains
  `EVOGUARD_IMMUTABLE_RELEASES_READ_TOKEN`, a fine-grained token limited to
  repository Metadata read, Administration read, Checks read, and Contents
  read. The write-capable GitHub job token remains separate.
- The exact dispatch commit is still protected `main`, has a valid GitHub
  signature, and has all eleven required checks from their exact GitHub App IDs
  in `success`.
- A pre-existing annotated `vX.Y.Z` tag points to that exact commit and is
  signed by the pinned EvoRiseKsa maintainer key. Lightweight, unsigned,
  missing, or retargeted tags fail closed. Any drift may be corrected and
  re-checked immediately without a calendar delay.

## The path

One workflow, [`release.yml`](../.github/workflows/release.yml), dispatched
by a maintainer. It runs entirely on the default branch and ends in a
**draft** — publication stays a deliberate human click.

1. **Prepare `main`.**
   - `evoom_guard/__init__.py` carries the exact stable version
     (`X.Y.Z`, no `.dev0`).
   - `CHANGELOG.md` has a dated `[X.Y.Z]` section.
   - CI is green on the tip of `main`.
2. **Create the signed tag.** Create and push an annotated SSH-signed
   `vX.Y.Z` tag at that exact `main` commit using the pinned release-maintainer
   key. The workflow will not create, replace, or retarget a tag.
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
   - `prepare-draft` — after protected Environment approval, re-reads the
     immutable-release setting, exact GitHub-verified `main`, the annotated-tag
     signature against the pinned maintainer root, and required checks; then
     re-verifies the transferred assets and creates a **draft** release for the
     existing tag with exactly `evo-guard.pyz`,
     `evo-guard.spdx.json`, and `SHA256SUMS`.
5. **Review and publish.** The maintainer inspects the draft — assets,
   checksums, generated notes — edits the notes as needed, and publishes.
6. **Record.** After publication, update the release record docs
   (`ops/render_project_status.py --write`) on a follow-up commit so the
   maintained status blocks reflect the published tag.

The automated claim currently ends at a re-read, byte-matched draft. The
subsequent web-UI publication is a separate human act, so it must not be
described as an atomic evidence-bound publication. A future protected publish
job should repeat the same live checks, re-download the draft assets, publish,
and verify `isImmutable=true` in one reviewed job; this is a state-transition
hardening item, not a reason to restore a calendar wait.

## Rules that survive from the old design

The archived signed lane ([RELEASE_TRUST_PIPELINE.md](RELEASE_TRUST_PIPELINE.md))
is gone as a process, but its non-negotiables remain policy:

- **Never mutate a published release.** Tags, assets, checksums,
  attestations, and ledger/record bytes of anything already published are
  immutable; corrections ship as a new version plus an explicit erratum.
- **Draft-then-publish.** No workflow publishes a release on its own;
  the final publication act is always human.
- **Exact assets only.** A release carries exactly the three contracted
  assets; nothing else rides along.
- **Honest claims.** Release notes state what the evidence shows and carry
  the project's non-claims where they apply (see
  [ASSURANCE.md](ASSURANCE.md)).

## What was deliberately removed

- The fourteen-day stabilization window, its freeze declaration, and both
  freeze validators (deleted 2026-08-31; policy in
  [GOVERNANCE.md](GOVERNANCE.md)).
- The signed-source promotion workflow `P` — promotion to `main` through a
  frozen declaration no longer exists as a concept.
- Any dependency of releasing on repository Actions variables of the
  `EVOGUARD_V470_FREEZE_*` family; they are unused and safe to delete.
