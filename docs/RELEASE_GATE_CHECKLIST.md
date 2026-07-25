# Release gate checklist (v4 baseline hardening)

Use this checklist for the published `v4.0.1` behavioral baseline, the minimal
`v4.0.2`, `v4.1.0`, `v4.2.0`, and `v4.3.0` release ledgers, and as the minimum
gate for later releases before enforcing EvoOM Guard as a required CI merge
gate.

## Required repository controls

1. **Required branch policy / required workflow** for the protected branch
   - The exact Guard check name must be required in a protected branch rule.
   - If using an organization required workflow, confirm that candidate PRs cannot
     bypass it via renamed/alternative checks.

2. **Code-owner review for trust inputs**
   - `.github/workflows/**`
   - `.evoguard.json`
   - `SECURITY.md`, `GOVERNANCE.md`
   - verifier pack paths used by your policy
   - `LICENSE`, `LICENSE_HISTORY.md`, `COMMERCIAL-LICENSING.md`
   - protect `.github/CODEOWNERS` and these paths from changes by the PR author.

3. **Action pinning**
   - Pin `actions/checkout`, `actions/setup-python`, and EvoOM Guard action to full
     SHAs.
   - Pin any Node/runner actions used in the same workflow.

4. **Workflow scope & permissions**
   - Use `pull_request` (not `pull_request_target`) for candidate checks.
   - Minimal permission set; include `pull-requests: write` only if a comment is needed.
   - Never give the candidate job `contents: write` when it only verifies code.

5. **No edit-time bypasses**
   - Confirm a PR cannot satisfy merge by disabling/replacing the workflow.
   - Confirm status name is not trivially forgeable by a different workflow.

6. **Governance evidence**
   - Keep audit record for the required checks and whether required checks actually
     block merge until up-to-date.
   - Re-run guarded PRs after any change to workflow, policy, or pack hashes.

7. **Immutable release artifact controls**
   - Tag and release created only from tested commit.
   - Historical releases retain their recorded immutable asset sets.
   - For a future SBOM-enabled release, require exactly the three manually
     uploaded assets `evo-guard.pyz`, `evo-guard.spdx.json`, and `SHA256SUMS`
     (apart from GitHub-generated source archives), with two filename-ordered
     checksum lines and byte equality in tag CI.
   - Verify build-provenance attestations for the exact zipapp and SPDX
     subjects, plus the SBOM attestation that binds the SPDX predicate to the
     zipapp subject. None is an EvoGuard verdict or independent review.

## Frozen baseline verification

- `tests/baseline/v4.0.1/BASELINE_MANIFEST.json` validates against the strict
  `tests/baseline/schema/baseline-v2.schema.json` schema.
- The manifest distinguishes the reference-capture commit from the published
  release and asset-build commit; it does not reuse one ambiguous source SHA.
- Every non-metadata file under the baseline is inventoried exactly once with a
  byte size and SHA-256, and no unsafe path or symlink is accepted.
- `tests/baseline/v4.0.1/SHA256SUMS_v4.0.1.txt` matches `pyz/evo-guard.pyz`.
- The frozen zipapp runs offline and reports `evo-guard 4.0.1`.
- The signed baseline sample verifies cryptographically against
  `artifacts/baseline-sign-pub.pem` using its exact committed CRLF bytes.
- The verifier-pack digest is recomputed from the frozen pack rather than trusted
  only from the recorded `pack-doctor` report.
- The frozen `action.yml` exposes exactly the inventoried 25 inputs and 5 outputs.
- The benchmark snapshot contains 16 expected rows; its timing is observational,
  not a claim of byte- or time-deterministic reproduction.
- `release-manifest.json` binds the release workflow and recorded provenance to
  the release commit and zipapp digest.
- External GitHub release, Marketplace, and attestation state is independently
  re-queried when current online truth is required; the local manifest alone is
  not treated as cryptographic proof of that external state.
- `ERRATA.md` is reviewed and the immutable `v4.0.1` tag/assets remain untouched.

## v4.0.2 through v4.3.0 release-ledger verification

- Each `RELEASE_LEDGER.json` under `tests/baseline/v4.0.2/`,
  `tests/baseline/v4.1.0/`, `tests/baseline/v4.2.0/`, and
  `tests/baseline/v4.3.0/` validates against
  `tests/baseline/schema/release-ledger-v1.schema.json`.
- Each ledger's commit, tree, release/run identifiers, asset sizes/digests,
  attestation
  identities, Marketplace observation, and tag-CI result are the facts observed
  after publication; they are not inferred from source-tree version strings.
- Each `SHA256SUMS` and `pyz/evo-guard.pyz` pair contains the exact downloaded
  immutable release assets. The checksum bytes, file sizes, SHA-256 values, and
  offline `version` command are regression-tested.
- Release and build attestations are verified against the exact tag, source SHA,
  signer workflow, source ref, and GitHub-hosted runner boundary before their
  externally observed identities are recorded.
- Marketplace propagation and the tag-triggered CI result, including
  `release-tag-guard` and `publish-pyz`, are observed after publication rather
  than assumed from the release form.
- This minimal ledger is not a behavioral baseline. It intentionally contains
  no copied historical command output, verdict, signature, verifier-pack,
  benchmark, or erratum evidence. The v4.1.0 ledger does not claim a live
  Release Source Admission V2 pilot merely because that implementation ships.
  Likewise, the v4.2.0 bootstrap ledger does not claim a live Release Artifact
  Admission V1 E/F/G pilot, artifact-publication authorization, reproducible
  build, production readiness, or independent security review. The v4.3.0
  ledger does not copy its separate same-owner Agent Change Admission pilot or
  claim a required production gate, hostile-runner proof, single-use
  authorization, or independent validation.

## Protected A-H release-ledger v2 readiness

- `tests/baseline/schema/release-ledger-v2.schema.json` is the contract for a
  future post-publication protected A-H ledger. It does not apply retroactively
  to v1 ledgers and must not be used to rewrite a frozen baseline.
- Before a v2 ledger is committed, run:

  ```text
  python -I tools/ci/validate_release_ledger_v2.py validate <ledger-directory> `
    --trusted-ledger-pub <independently-obtained-public-key> `
    --trusted-parent-repo <disjoint-trusted-parent-repository>
  ```

  The trusted key
  path must be outside the ledger and must come from a pinned parent tree,
  immutable tag, or other previously authenticated channel; never copy it from
  the directory being validated.
  The trusted-parent repository must contain the exact admitted parent
  commit/tree; the validator resolves and byte-compares its schema, validator,
  repository-control collector, and per-release ledger-public-key anchor Git
  blobs, so self-reported parent fields or a newly supplied self-signed key are
  insufficient.
  Schema-only validation is insufficient: the command verifies cross-phase run
  bindings, the exact three-asset set and checksum bytes, retained controls,
  RSAE/RAAE signatures and subjects, all public-key identities, closed file
  inventory, and the detached signature over canonical ledger bytes under that
  external EvoRise trust anchor.
- The v2 schema is not caller-selectable. The signed ledger binds the exact
  repository schema digest and the exact validator digest/Git blob; both
  descriptors bind the admitted trusted-parent commit/tree. Execute the
  validator extracted from that parent, not candidate-controlled bytes.
  `README.md`, all directories, and all retained
  regular files are part of the closed, bounded inventory. Validation uses a
  private immutable byte snapshot; hard links, extra empty directories, path
  swaps, same-size restored-mtime changes, and post-read mutations fail closed.
- C/D and F/G result objects and both negative matrices must be retained in the
  exact formats emitted by the protected workflows. GitHub verifier outputs
  must bind one subject, one source dependency, the exact run/attempt, and the
  exact SPDX predicate where applicable.
- A complete ledger is assembled only after the immutable release, tag CI, and
  Marketplace observation exist. A template, schema, candidate source version,
  or successful pre-publication workflow is not a release ledger.
- The ledger records the exact A-H run IDs and attempts, all seven workflow
  ID/blob pins (C and D share one run), tool/runtime/container pins, six
  admission roots, a distinct ledger-signing root, protected repository
  controls, the tag ruleset, and the sole write deploy-key fingerprint.
- Run `tools/ci/collect_repository_controls_v2.py` only after H. Its exact 19
  ordered logical observations retain all pages for repository/main
  protection, Actions, immutable releases, tag rules, deploy keys,
  Environments/policies, activation variables, the repository Actions-secret
  list, and the two Environment admission-secret lists. More than 19 HTTP calls
  are valid when pagination requires them.
- Require the repository metadata body to remain public and user-owned with
  repository ID `1293651176`, owner login/type `EvoRiseKsa`/`User`, and owner
  ID `231647061`. A rename, transfer, deletion/recreation, or namespace-ID
  change requires an explicit trusted-parent policy migration.
- The two admission signing-secret names have post-H, successful, fully
  paginated repository and Environment API observations with `present=false`.
  `EvoRiseKsa/EvoOM-Guard-m` is user-owned, so no organization-secret scope
  exists to query for this repository. The complete record is an unsigned
  owner-collected bounded, non-atomic window, not proof of simultaneous state,
  absence of external copies, or absence from another repository. Publication
  deploy-key retirement remains an explicit post-ledger action and is never
  claimed complete inside the ledger.
- E must have produced three independently verified receipts: pyz SLSA
  provenance, SPDX-file SLSA provenance, and the pyz-subject SPDX predicate.
  A pyz-subject SBOM attestation cannot authorize F to seal the SPDX file.
  F must verify all three in its no-secret `verify-attestations` job and retain
  the exact receipt/raw-output pairs in
  `evoguard-release-artifact-v1-complete-controls-<attempt>`. The protected seal,
  both RAAEs, G controls, H preflight, and the ledger must preserve those byte
  identities.
- The ledger step is data-only. It must not have release or tag write authority,
  and it must not publish RSAE/RAAE envelopes as GitHub Release assets.

See [Protected release ledger v2](RELEASE_LEDGER_V2.md) for the retained
directory, canonicalization, validation, and exact non-claims.

Update this file with every major process change (workflow templates, policy schema,
attestation format, or check ownership mapping).
