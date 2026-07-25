# Release Ledger v2 offline assembly

`tools/ci/assemble_release_ledger_v2.py` is a deterministic convenience tool,
not an evidence collector and not a release authority. It accepts:

1. a closed directory containing the retained A–H files;
2. an operator-reviewed JSON claims file outside that directory; and
3. a disjoint local Git repository containing the exact admitted parent.

It performs no network request and no signing. It refuses existing outputs.

## What the assembler derives

The claims file supplies the v2 object shape and the retained relative paths.
The assembler reads every path as a stable, regular, non-link, single-link
file, then derives or cross-checks:

- every retained file size and SHA-256 descriptor;
- release-asset GitHub digest fields and the exact two-line `SHA256SUMS`
  bindings;
- RSAE format, decision, target commit/tree, algorithm, signer key ID, and
  canonical manifest identity;
- each RAAE decision, artifact subject size/digest, signer key ID, embedded
  RSAE identity, and canonical manifest identity;
- control-manifest formats and the C/F/G workflow run identities that those
  manifests actually contain;
- attestation subject, predicate, signer workflow, source, run/attempt, receipt
  digest, and raw-output digest;
- all retained admission and ledger public-key IDs;
- schema, validator, and per-release ledger-key Git blob IDs and SHA-256
  values from the exact admitted parent commit/tree.

If a reviewed claim already supplies one of those fields, it must equal the
derived value. The assembler rejects rather than silently replacing a
contradiction.

It then applies the official schema and semantic validator, exact
trusted-parent checks, a closed-world file/directory inventory, the repository
observation checks, control-manifest checks, raw GitHub attestation checks,
RSAE/RAAE signature and cross-binding checks, and a final input-stability
check. Byte-semantic validation runs from a private snapshot.

## What remains operator-reviewed

The assembler cannot derive mutable or external GitHub state from retained
bytes. The claims file must still record reviewed:

- immutable Release identity, numeric IDs, publication state and timestamps;
- A–H workflow IDs, workflow blobs, conclusions, job sets, and phase times
  except for identities already embedded in retained evidence;
- GitHub Actions artifact IDs, digests, URLs, retention periods, and
  observation times;
- branch protection, ruleset, Environment, deploy-key, activation-flag, and
  secret-name-list observations;
- tag CI and Marketplace observations;
- bootstrap, runner-image, executable, and trusted-build-input pins not
  recoverable from an authenticated retained manifest;
- post-publication observation times and the ledger creation time.

Those are claims because the assembler deliberately does not contact GitHub.
They become acceptable only when the official validator can cross-bind them to
the retained evidence and contract rules.

## Command

```powershell
python tools/ci/assemble_release_ledger_v2.py `
  .\collected\vX.Y.Z `
  .\reviewed\vX.Y.Z.claims.json `
  .\reviewed\RELEASE_LEDGER.unsigned.json `
  --provenance .\reviewed\RELEASE_LEDGER.assembly-provenance.json `
  --trusted-parent-repo .\trusted-parent-checkout
```

Both output files are canonical JSON. The provenance manifest inventories
every exact input and explicitly records that no signing, network collection,
external ledger-key authentication, or post-commit validation occurred.

The unsigned draft is not a release ledger. After human review it must be
signed with the separately held per-release ledger private key, installed as
`RELEASE_LEDGER.json`, and validated with
`validate_release_ledger_v2.py validate` using the independently obtained
ledger public key and trusted-parent repository.
