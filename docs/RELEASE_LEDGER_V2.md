# Protected release ledger v2

`release-ledger-v2` is the post-publication evidence contract for the protected
A–H release pipeline. It is deliberately separate from the historical
`release-ledger-v1` contract and from every frozen baseline. No `v4.4.0` ledger
exists until an immutable `v4.4.0` release has actually completed A–H and its
external facts have been observed.

The schema is
[`tests/baseline/schema/release-ledger-v2.schema.json`](../tests/baseline/schema/release-ledger-v2.schema.json).
The offline validator is
[`tools/ci/validate_release_ledger_v2.py`](../tools/ci/validate_release_ledger_v2.py).
Validation is not self-authenticating: the caller must supply the release's
ledger public key from a previously trusted channel outside the evidence
directory. The retained copy is evidence, not the trust anchor.

## Why schema validation is not enough

JSON Schema rejects missing fields, extra fields, wrong types, unsafe path
spellings, non-`ALLOW` decisions, incomplete asset sets, incomplete A–H phase
sets, missing trust roots, and weakened repository-control booleans. It cannot
express all equality and byte-level relations.

The validator therefore also requires:

- the signed ledger to bind the exact repository schema ID, path, and SHA-256;
  neither the CLI nor the Python validation entry point accepts a replacement
  schema;
- the project version, immutable tag, release commit/tree, admitted source, all
  A–H heads, tag CI, attestations, RSAE, and both RAAEs to bind one candidate;
- B→A, C→B, D→C, F→E, G→F, and H→G to name exact run IDs and attempts;
- C and D to share the same workflow run, workflow ID, workflow blob, head, and
  attempt;
- E's dispatch inputs to name the exact C attempt and release version;
- the three immutable assets to be exactly `evo-guard.pyz`,
  `evo-guard.spdx.json`, and `SHA256SUMS`;
- `SHA256SUMS` to contain exactly two filename-ordered lines for the pyz and
  SPDX bytes;
- one RSAE and two separate RAAEs, with their retained signatures verified
  against distinct recorded public roots;
- all six admission public roots to be distinct, and the ledger signing key to
  be a seventh distinct Ed25519 identity whose exact PEM and key ID equal the
  caller-supplied external trust anchor;
- source controls, artifact controls, publication controls, and
  publication-ready evidence to bind their exact workflow attempts and their
  closed material sets (9 source, 13 artifact, 3 publication, and 3
  publication-ready files);
- protected C/D and F/G success reports, the canonical eleven-case source
  negative JSON record, and the ordered seven-line artifact negative record to
  equal the formats emitted by the actual CLI/workflows, with no extra keys or
  duplicate/reordered cases;
- three E attestation receipts: SLSA provenance for the pyz, SLSA provenance
  whose subject is the SPDX file itself, and the SPDX predicate whose subject
  is the pyz. The SBOM predicate binds the SBOM to the pyz; it is not provenance
  for the SBOM file and cannot substitute for the separate SPDX-file subject;
- each retained raw verifier output to contain one exact subject, one exact
  source dependency, the expected workflow run/attempt and hosted-runner
  identity. Version-specific `gh` provider metadata may add non-security
  fields, but the certificate, workflow, source, subject, predicate, builder,
  run, and hosted-runner bindings remain mandatory; the SPDX predicate must
  equal the retained canonical `evo-guard.spdx.json` object;
- pinned runtime, networkless OCI image, Git, `gh`, provider UID/GID, sole
  parent commit/tree, and exact parent-tree build tool blobs;
- canonical whole-second UTC timestamps, non-overlapping Aâ€“H phase order, and
  post-publication observations bounded by the signed ledger timestamp;
- protected-main, Environment, immutable-release, tag-ruleset, sole write
  deploy-key, and post-publication flag observations;
- every retained file (including `README.md`) to be signed by a descriptor,
  regular, single-link, uniquely backed, and byte-exact; every directory is
  also closed-world. The authenticated inventory is bounded, copied from one
  verified read into a private snapshot for all semantic checks, then every
  original byte and component/file identity is rechecked to detect path swaps,
  restored-mtime mutations, or changes during validation;
- `RELEASE_LEDGER.json` to use one canonical UTF-8 serialization and its
  detached signature to authenticate those exact bytes.

Duplicate JSON keys and non-finite numbers are rejected before schema
validation.

## Required directory

The post-publication directory has this logical shape. Paths below are
illustrative; the ledger inventories their exact paths, sizes, and digests.

```text
vX.Y.Z/
├── README.md
├── RELEASE_LEDGER.json
├── RELEASE_LEDGER.json.sig
├── release-assets/
│   ├── evo-guard.pyz
│   ├── evo-guard.spdx.json
│   └── SHA256SUMS
├── controls/
│   ├── source/...
│   ├── artifact/...
│   ├── publication/...
│   └── publication-ready/...
├── admission/
│   ├── source/...rsae
│   └── artifact/...raae
├── attestations/...
└── trust/
    ├── release-source-admission-v2.pub.pem
    ├── trusted-finalizer.pub.pem
    ├── artifact-admission-v1.pub.pem
    ├── artifact-digest-admission-v2.pub.pem
    ├── release-source-finalizer-v1.pub.pem
    ├── release-artifact-admission-v1.pub.pem
    └── release-ledger-v2.pub.pem
```

The RSAE and RAAE files are durable ledger evidence, not GitHub Release assets.
The immutable GitHub Release still contains exactly the three public assets.

## Structural example

This fragment illustrates the identity links; it is intentionally incomplete
and must fail validation. Placeholders are never accepted as release evidence.

```json
{
  "schema_version": "evoguard-release-ledger-v2",
  "project": {"name": "EvoOM Guard", "version": "<X.Y.Z>"},
  "release": {
    "tag": "<vX.Y.Z>",
    "commit_sha": "<40 lowercase hex>",
    "immutable": true
  },
  "workflow_chain": [
    {"phase": "A", "event": "workflow_dispatch"},
    {"phase": "B", "upstream": {"phase": "A", "run_id": "<exact A run>"}},
    {"phase": "C", "upstream": {"phase": "B", "run_id": "<exact B run>"}},
    {"phase": "D", "upstream": {"phase": "C", "run_id": "<same C/D run>"}},
    {"phase": "E", "dispatch_inputs": {"source_admission_run_id": "<C run>"}},
    {"phase": "F", "upstream": {"phase": "E", "run_id": "<exact E run>"}},
    {"phase": "G", "upstream": {"phase": "F", "run_id": "<exact F run>"}},
    {"phase": "H", "upstream": {"phase": "G", "run_id": "<reviewed G attempt>"}}
  ]
}
```

## Post-publication procedure

1. Before the trusted parent/candidate is merged, generate a fresh per-release
   Ed25519 ledger key. Pin its public PEM and key ID in the reviewed parent tree
   or another independently authenticated, immutable channel; keep its private
   half offline. A key first discovered beside the ledger is not a trust anchor.
2. Do not create the directory from source-tree expectations. Download the
   exact immutable release assets and all recorded A–H artifacts by their
   reviewed run IDs and attempts.
3. Query the release, tag target, workflow runs, tag CI, Marketplace state,
   branch protection, Environments, immutable-release setting, tag ruleset,
   and exact sole write deploy key. Record observations rather than inferred
   values.
4. Copy the signed README, RSAE, both RAAEs, controls, detached results, negative matrices,
   all three E attestation receipts and outputs, and seven public keys into a
   new directory. Never modify a prior ledger or baseline. Do not proceed if E
   did not create separate SLSA provenance whose exact subject is
   `evo-guard.spdx.json`; F cannot freshly admit that file from a pyz-subject
   SBOM attestation.
5. Assemble a complete draft whose schema descriptor hashes the exact
   repository schema bytes. Canonicalization validates only that schema and
   cross-field bindings but does not collect or invent evidence:

   ```powershell
   python tools/ci/validate_release_ledger_v2.py canonicalize `
     .\RELEASE_LEDGER.draft.json `
     .\vX.Y.Z\RELEASE_LEDGER.json
   ```

6. Review the canonical bytes, then sign that exact file with the dedicated
   release-ledger Ed25519 key. The signature sidecar is base64 and the public
   key ID must match `ledger_signature.key_id`. The ledger signing key must not
   be any of the six admission keys.
7. Export or retrieve the previously pinned public PEM through that independent
   channel to a path outside the ledger directory, then validate offline:

   ```powershell
   python tools/ci/validate_release_ledger_v2.py validate .\vX.Y.Z `
     --trusted-ledger-pub .\trusted-roots\vX.Y.Z-release-ledger.pub.pem
   ```

   Never point `--trusted-ledger-pub` at the retained
   `vX.Y.Z\trust\release-ledger-v2.pub.pem` copy. The validator rejects an
   in-root, linked, hard-linked, changed, or byte-different anchor.
8. Commit the new directory only after the command reports
   `release-ledger-v2: VALID`. The ledger step must not create, move, delete, or
   rewrite a tag or GitHub Release. Re-run external-key validation from the
   committed tree, then destroy the per-release ledger private key.
9. The two admission private-key Environment secrets must already have been
   removed immediately after H. After the public deploy-key ID/fingerprint is
   frozen in the valid ledger, remove the publication deploy-key secret and the
   exact write deploy key according to the release runbook.

There is intentionally no evidence collector or “generate from GitHub”
command. Collection combines mutable external state, expiring artifacts, and
human approval boundaries; automating it as an authoritative generator would
turn unchecked API responses into claimed truth. The canonicalizer only
serializes a reviewed, already-complete draft; it does not authenticate the
draft or establish an EvoRise signing identity.

## Evidence boundary

The ledger proves the integrity and recorded bindings implemented by A–H. It
does not prove that GitHub-hosted runners were honest, that the software is
vulnerability-free, that same-owner approvals are independent review, that the
build is reproducible on unrelated builders, or that an operator observation
was made by an independent party. Release titles and descriptions remain
mutable display metadata and are not trust roots.
