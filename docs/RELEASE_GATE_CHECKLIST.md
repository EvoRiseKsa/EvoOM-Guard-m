# Release gate checklist (v4 baseline hardening)

Use this checklist before tagging `v4.0.1` as immutable and before enforcing as a
required CI merge gate.

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

## One-time release releaseability pre-flight

- `tests/baseline/v4.0.1/BASELINE_MANIFEST.json` exists and matches collected assets.
- `tests/baseline/v4.0.1/SHA256SUMS_v4.0.1.txt` matches `pyz/evo-guard.pyz`.
- Signed baseline sample verifies (`verify-verdict` against
  `artifacts/baseline-sign-pub.pem`).
- `pack-doctor` vector verifies for the in-repo verifier pack.

Update this file with every major process change (workflow templates, policy schema,
attestation format, or check ownership mapping).
