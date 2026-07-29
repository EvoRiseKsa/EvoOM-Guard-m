# Protected release ledger v2

`release-ledger-v2` is the post-publication evidence contract for the protected
A–H release pipeline. It is deliberately separate from the historical
`release-ledger-v1` contract and from every frozen baseline. The immutable
`v4.4.0` GitHub Release exists, but no valid `v4.4.0` ledger exists in the
protected source tree. The live publication observation does not prove that
protected A–H completed; see the
[release-ledger erratum](errata/V4.4.0-LEDGER.md). Its frozen validator
mismatch cannot be repaired retroactively. Only a new release operation may
produce a new signed ledger.

The schema is
[`tests/baseline/schema/release-ledger-v2.schema.json`](../tests/baseline/schema/release-ledger-v2.schema.json).
The offline validator is
[`tools/ci/validate_release_ledger_v2.py`](../tools/ci/validate_release_ledger_v2.py).
The read-only recorder is
[`tools/ci/collect_repository_controls_v2.py`](../tools/ci/collect_repository_controls_v2.py).
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
  closed material sets (9 source, 20 artifact, 3 publication, and 3
  publication-ready files);
- protected C/D and F/G success reports, the canonical eleven-case source
  negative JSON record, and the ordered seven-line artifact negative record to
  equal the formats emitted by the actual CLI/workflows, with no extra keys or
  duplicate/reordered cases;
- three E attestation receipts: SLSA provenance for the pyz, SLSA provenance
  whose subject is the SPDX file itself, and the SPDX predicate whose subject
  is the pyz. The SBOM predicate binds the SBOM to the pyz; it is not provenance
  for the SBOM file and cannot substitute for the separate SPDX-file subject;
- F's no-secret `verify-attestations` job to retain the exact receipt and raw
  provider bytes for all three E attestations before the signing Environment is
  entered. The F control manifest, both RAAEs, G publication controls, and the
  final ledger must cross-bind those same bytes;
- each retained raw verifier output to contain one exact subject, one exact
  source dependency, the expected workflow run/attempt and hosted-runner
  identity. Version-specific `gh` provider metadata may add non-security
  fields, but the certificate, workflow, source, subject, predicate, builder,
  run, and hosted-runner bindings remain mandatory; the SPDX predicate must
  equal the retained canonical `evo-guard.spdx.json` object;
- pinned runtime, networkless OCI image, Git, `gh`, provider UID/GID, sole
  parent commit/tree, and exact parent-tree build tool blobs;
- the exact [GitHub Releases API `created_at`
  value](https://docs.github.com/en/rest/releases/releases) as
  `release.created_utc`. GitHub defines that field as the date of the commit
  used for the Release, not the time the draft or Release was created; Git
  commit dates are not trusted lifecycle clocks, so the field is canonical
  metadata rather than a phase-H chronology boundary;
- `release.published_utc` inside phase H, canonical whole-second UTC
  timestamps, non-overlapping Aâ€“H phase order, and post-publication
  observations bounded by the signed ledger timestamp;
- one canonical 19-observation repository-control record: public repository
  identity, including trusted namespace IDs `1293651176` (repository) and
  `231647061` (the `EvoRiseKsa` user owner),
  main ref/protection (including all eleven check context/app identities,
  including both fuzz sanitizers),
  Actions permissions and SHA pinning, immutable-release owner state, tag
  ruleset include/exclude/rules/bypass, every deploy-key page, all four
  Environments and stable reviewer/rule/policy identities, all three activation
  variables, the repository Actions-secret list, and both post-H Environment
  admission-secret lists. The normalized ledger claims are derived from those
  retained bodies rather than supplied as unbound assertions;
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
3. Query the release, tag target, workflow runs, tag CI, and Marketplace state.
   Copy the GitHub Releases API `created_at` field exactly into
   `release.created_utc`; do not substitute a draft-creation time or require it
   to fall inside H. Copy `published_at` into `release.published_utc`; that is
   the release-lifecycle timestamp that must fall inside H.
   After H, run the reviewed trusted-parent repository-control recorder:

   ```powershell
   python -I tools/ci/collect_repository_controls_v2.py `
     --repo EvoRiseKsa/EvoOM-Guard-m `
     --ruleset <reviewed-tag-ruleset-id> `
     --output .\controls\repository\repository-controls-observation.json
   ```

   The recorder performs exactly 19 ordered logical observations; pagination
   may require more than 19 HTTP requests. It retains complete parsed page
   bodies and validated completion metadata. An API denial, incomplete page
   sequence, duplicate identity, changed total/last-page bound, or non-200
   response fails closed. Its output is unsigned owner-collected evidence over
   a bounded **non-atomic** window, not a GitHub snapshot or independent
   attestation.
4. Copy the signed README, RSAE, both RAAEs, controls, detached results, negative matrices,
   all three E attestation receipts and outputs, and seven public keys into a
   new directory. Never modify a prior ledger or baseline. Do not proceed if E
   did not create separate SLSA provenance whose exact subject is
   `evo-guard.spdx.json`; F cannot freshly admit that file from a pyz-subject
   SBOM attestation. Retain the final F controls artifact named
   `evoguard-release-artifact-v1-complete-controls-<attempt>`; the earlier
   preflight artifact is incomplete and is not ledger evidence.

   Provision the validator's locked Python runtime and dependency roots outside
   the checkout, current working directory, system temporary directory,
   evidence directory, candidate, and trusted-parent repository. None of those
   paths may contain the runtime or be contained by it. An overlapping
   environment fails closed because its validation dependencies could be
   candidate-controlled. `python -I` does not make an in-checkout `.venv`
   trusted.

5. Assemble a complete draft whose schema descriptor hashes the exact
   repository schema bytes. The schema, validator, and repository-control
   collector descriptors record SHA-256, Git blob ID, and the same
   trusted-parent commit/tree admitted by A; run those bytes from that parent,
   never candidate replacements. The assembler derives API-provable normalized
   controls from the retained V2 bodies, rejects contradictory operator claims,
   performs no network request, and emits no signature:

   ```powershell
   python -I tools/ci/assemble_release_ledger_v2.py `
     .\vX.Y.Z `
     .\reviewed\vX.Y.Z.claims.json `
     .\reviewed\RELEASE_LEDGER.unsigned.json `
     --provenance .\reviewed\RELEASE_LEDGER.assembly-provenance.json `
     --trusted-parent-repo .\trusted-parent-checkout
   ```

6. Review the canonical bytes, then sign that exact file with the dedicated
   release-ledger Ed25519 key. The signature sidecar is base64 and the public
   key ID must match `ledger_signature.key_id`. The ledger signing key must not
   be any of the six admission keys.
7. Export or retrieve the previously pinned public PEM through that independent
   channel to a path outside the ledger directory, then validate offline:

   ```powershell
   python -I tools/ci/validate_release_ledger_v2.py validate .\vX.Y.Z `
     --trusted-ledger-pub .\trusted-roots\vX.Y.Z-release-ledger.pub.pem `
     --trusted-parent-repo .\trusted-parent-checkout
   ```

   Never point `--trusted-ledger-pub` at the retained
   `vX.Y.Z\trust\release-ledger-v2.pub.pem` copy. The validator rejects an
   in-root, linked, hard-linked, changed, or byte-different anchor.
   `--trusted-parent-repo` must be a disjoint trusted checkout/object store
   containing the admitted parent commit. The validator resolves the exact
   `100644` schema, validator, repository-control collector, and per-release
   ledger-public-key anchor blobs from that commit/tree and compares their
   bytes, Git object IDs, and SHA-256 values; descriptor fields alone are not
   accepted as proof. Git repository,
   worktree, object-directory, alternate-object, and replace-ref environment
   redirections are not inherited by this check.
8. Commit the new directory only after the command reports
   `release-ledger-v2: VALID`. The ledger step must not create, move, delete, or
   rewrite a tag or GitHub Release. Re-run external-key validation from the
   committed tree. Keep the offline per-release ledger private key only long
   enough to sign the separate publication-authority retirement receipt.
9. The two admission private-key Environment secrets must already have been
   removed immediately after H. Their recorded repository-scope and
   Environment-scope `present=false` values are same-owner observations within
   one bounded non-atomic collection window. Because the repository is owned by
   the `EvoRiseKsa` user account rather than a GitHub organization, there is no
   organization-secret scope to query. These observations do not prove that no
   external copy exists, do not prove simultaneous repository state, and do not
   prevent a later re-addition. The release
   ledger must record publication authority retirement as pending, never as
   already completed. As an operator procedure, commit and revalidate the signed
   ledger before removing the publication deploy-key secret and exact write
   deploy key. Then create and validate the separately signed
   `KEY_RETIREMENT.json` and destroy the per-release ledger private key. The
   receipt and its detached signature live outside the already closed ledger
   directory and are verified under the same independently pinned ledger public
   key:

   ```powershell
   python -I tools/ci/validate_release_ledger_v2.py validate-retirement `
     .\vX.Y.Z .\KEY_RETIREMENT.json .\KEY_RETIREMENT.json.sig `
     --trusted-ledger-pub .\trusted-roots\vX.Y.Z-release-ledger.pub.pem `
     --trusted-parent-repo .\trusted-parent-checkout
   ```

   A valid receipt proves that its signed observation timestamps are later than
   the signed ledger's `created_utc`; it does not cryptographically prove Git
   commit ordering. Commit-before-retirement remains an operator procedure. A
   `404`, denied API call, incomplete page sequence, or unsigned JSON is not
   retirement evidence. The receipt remains a same-owner point-in-time
   observation; it does not prove destruction of copies outside GitHub and does
   not prevent a new key or secret from being added later.

The former absence of a collection command has been replaced by the bounded
repository-control recorder. The recorder is a transport recorder, not an
authoritative generator: it has no
mutation or signing authority and does not convert mutable GitHub API bodies
into independent truth. Its exact trusted-parent bytes, complete page bodies,
endpoint order, time window, and normalization rules are bound by the ledger;
the observation still remains unsigned same-owner evidence. The assembler and
canonicalizer do not establish an EvoRise signing identity.

## Evidence boundary

The ledger proves the integrity and recorded bindings implemented by A–H. It
does not prove that GitHub-hosted runners were honest, that the software is
vulnerability-free, that same-owner approvals are independent review, that the
build is reproducible on unrelated builders, or that an operator observation
was made by an independent party. Release titles and descriptions remain
mutable display metadata and are not trust roots.
