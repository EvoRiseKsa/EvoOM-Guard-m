# Baseline v4.0.1 (pre-release)

This directory stores immutable sample outputs for release-grounding checks.

## Contents

- `BASELINE_MANIFEST.json` — inventory of every baseline artifact with SHA-256 and
  size metadata.
- `SHA256SUMS_v4.0.1.txt` — checksum manifest for the local baseline `evo-guard.pyz`.
- `commands/` — command help/version outputs.
- `evidence/` — canonical PASS/FAIL/REJECTED records, Markdown reports, and SARIF.
- `packs/` — verifier-pack identity and manifest validation output.
- `artifacts/` — signed PASS verdict + detached signature + public key.
- `pyz/` — locally built `evo-guard.pyz` for deterministic local reproduction.

## Reproduction (local)

1. Run the command set in `stage-0` as documented in `docs/architecture/REFACTOR_PROGRAM.md`.
2. Collect outputs into the same file names above.
3. Recompute a manifest and compare it to `BASELINE_MANIFEST.json`.
4. Regenerate `SHA256SUMS_v4.0.1.txt` from `pyz/evo-guard.pyz`.

## Grounding checks (what to verify)

- `python -m evoom_guard.cli --help` output hash.
- sample `guard` outcomes and signed-off records.
- `pack-doctor` digest and manifest fields.
- detached signature verification (`verify-verdict`).
- release artifact SHA is consistent with manifest + checksum file.
