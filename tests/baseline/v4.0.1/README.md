# Baseline v4.0.1 (published release)

This directory stores the frozen release-grounding captures for the published,
immutable `v4.0.1` release. `BASELINE_MANIFEST.json` uses the strict
`baseline-v2` schema and distinguishes the commit used to collect reference
outputs from the commit that built and published the release asset.

## Contents

- `BASELINE_MANIFEST.json` — central inventory with SHA-256 and size metadata.
- `release-manifest.json` — recorded external release, workflow, asset, and
  provenance facts verified after publication.
- `SHA256SUMS_v4.0.1.txt` — checksum manifest for the local release zipapp.
- `action/` — exact `action.yml` snapshot whose inputs and outputs are inventoried.
- `benchmarks/` — the frozen 16-row benchmark snapshot; timing is observational.
- `commands/` — command help/version outputs.
- `evidence/` — PASS/FAIL/REJECTED records, Markdown reports, and SARIF.
- `packs/` — verifier-pack snapshot plus its identity/validation output.
- `artifacts/` — exact signed PASS verdict bytes, signature, and public key.
- `pyz/` — the release-identical `evo-guard.pyz`.
- `ERRATA.md` — the post-publication correction record; the release tag was not moved.

## Reproduction (offline)

1. Validate `BASELINE_MANIFEST.json` against `../schema/baseline-v2.schema.json`.
2. Recompute every size and SHA-256 in `artifact_inventory`.
3. Run `python -I pyz/evo-guard.pyz version`.
4. Recompute the verifier-pack digest from `packs/blackbox-cli/`.
5. Verify the detached Ed25519 signature over the exact signed-record bytes.
6. Re-query GitHub independently when recorded publication/provenance facts must
   be trusted anew.

The local checks prove byte integrity and internal consistency. They do not, by
themselves, cryptographically re-verify GitHub's current release state or its
online attestation service.
