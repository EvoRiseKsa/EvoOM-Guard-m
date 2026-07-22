# Release gate checklist (v4 baseline hardening)

Use this checklist for the published `v4.0.1` behavioral baseline, the minimal
`v4.0.2`, `v4.1.0`, and `v4.2.0` release ledgers, and as the minimum gate for
later releases before enforcing EvoOM Guard as a required CI merge gate.

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
   - `evo-guard.pyz` + `SHA256SUMS` exact and immutable.
   - Optional: GitHub release attestation present for uploaded action artifact.

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

## v4.0.2 through v4.2.0 release-ledger verification

- Each `RELEASE_LEDGER.json` under `tests/baseline/v4.0.2/`,
  `tests/baseline/v4.1.0/`, and `tests/baseline/v4.2.0/` validates against
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
  build, production readiness, or independent security review.

Update this file with every major process change (workflow templates, policy schema,
attestation format, or check ownership mapping).
