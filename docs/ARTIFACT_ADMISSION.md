<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# File artifact admission — narrow V1

`EVOGUARD_ARTIFACT_BINDING_V1` binds one **regular-file** SHA-256 observed at
read time to one externally verified Trusted Finalizer `ALLOW`. It is a small follow-on
evidence relation, not a general supply-chain platform.

```text
external finalizer public key + source/context + final.evb
                                      │ verify-finalized (ALLOW only)
                                      ▼
regular file ── SHA-256 + size ──> signed .eab binding
                                      │
external artifact-binding public key ┘
```

## Exact claim

An authenticated V1 binding means only:

> The holder of the artifact-admission key bound this exact regular-file
> SHA-256 and byte length to a separately authenticated finalizer `ALLOW` with
> the stated repository, run/attempt, base/head/tree, policy, pack and Guard
> executable context.

The finalizer input is verified again at both sealing and consumption. The
artifact binding therefore cannot choose its own finalizer key, source,
context, or finalizer bundle. A successful command authenticates the bytes it
has just read, not arbitrary bytes that may later appear at the same pathname.
Before acting on a pathname, a consumer must verify it immediately before use
or consume an immutable/content-addressed copy. A command-line interface
cannot retain an open file descriptor for a later process.

It does **not** mean that the file was built reproducibly, came from a specific
build system, was released, was published under a tag, was scanned for
vulnerabilities, is deployed, or is safe. URLs, filenames, tags, registry
names, release IDs, and labels are intentionally absent from the authority
format.

## Pre-merge only

V1 must only be used when a protected workflow separately establishes that the
file comes from the exact admitted PR `head_sha` before merge. The binding
itself does not establish that fact, and it must not be described as proof about
a post-merge artifact. A normal GitHub merge/rebase can create a different
commit SHA even when its tree is identical. Binding a release from that commit
needs a future merge-candidate/merge-queue finalizer boundary; it is not
silently inferred here.

## Seal and verify

The artifact-admission signing key must be separate from the finalizer key and
available only to a protected post-build job that never executes candidate code.
V1 enforces distinct public-key identities; reusing the finalizer key is
rejected.

```bash
evo-guard seal-artifact-admission dist/product.whl final.evb \
  --out product.eab \
  --finalizer-pub finalizer.pub \
  --expected-source source.json \
  --expected-context context.json \
  --sign-key artifact-admission.pem

evo-guard verify-artifact-admission product.eab dist/product.whl final.evb \
  --trusted-pub artifact-admission.pub \
  --finalizer-pub finalizer.pub \
  --expected-source source.json \
  --expected-context context.json
```

All public keys and expected finalizer data are external inputs. Copying any of
them out of `product.eab` does not establish trust. A finalizer `DENY`, stale
source/context, substituted bundle, changed file, missing key, malformed input,
or signature mismatch fails closed.

## Wire format

The output is a deterministic stored ZIP archive:

```text
binding.json  canonical JSON payload
binding.sig   exactly 88 ASCII base64 bytes for one detached Ed25519 signature
```

The signed bytes are exactly:

```text
"EVOGUARD_ARTIFACT_BINDING_V1" || NUL || binding.json bytes
```

`binding.json` has exactly these top-level fields:

```json
{
  "format": "EVOGUARD_ARTIFACT_BINDING_V1",
  "decision": "ALLOW",
  "subject": {"kind": "file", "sha256": "…", "size": 123},
  "finalizer": {
    "bundle_sha256": "…",
    "record_sha256": "…",
    "key_id": "sha256:…",
    "source": {"…": "existing trusted-finalizer source V1 fields"},
    "context": {"…": "existing evidence-context V1 fields"}
  },
  "authentication": {
    "algorithm": "Ed25519",
    "key_id": "sha256:…",
    "purpose": "evoguard-artifact-admission",
    "signature_path": "binding.sig"
  }
}
```

Only one subject is legal. Its `kind` is exactly `file`; the hard maximum is
4 GiB and hashing rejects symlinks, reparse points, special files, and files
that change while read. The payload, ZIP metadata/order, detached signature,
and all digest encodings are canonical. The published structural contract is
[`artifact-binding-1.schema.json`](../evoom_guard/schemas/artifact-binding-1.schema.json).

## Deliberate prerequisites not implemented in V1

No GitHub attestation, SLSA, OCI, SBOM, release publication, registry fetch, or
deployment verifier is implemented by this command. Do not attach an arbitrary
`artifact_sha256` field to a finalizer record and call that artifact admission.
The next provider-specific design must independently verify immutable build
provenance and a protected build control before it can bind a release or OCI
manifest. Until then, this command is only a narrow file-to-finalizer relation.

## Experimental V2 follow-on

`v3.8.0` releases a separate opt-in V2 digest contract for one generic
SHA-256 or OCI manifest-or-index digest plus opaque provenance bytes. It does
not change this V1 contract or the immutable v3.7.0 release, and it remains
experimental. See [Artifact digest admission V2](ARTIFACT_DIGEST_ADMISSION_V2.md)
for its strictly limited claim and remaining provenance-verifier work.
