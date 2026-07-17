<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Artifact digest admission V2 — unreleased next-minor contract

EVOGUARD_ARTIFACT_BINDING_V2 is an opt-in follow-on to the released V1
regular-file relation. It has not changed the immutable v3.7.0 tag or release
asset. A future release must publish this contract and its exact implementation
before users rely on it.

V2 binds one immutable SHA-256 subject and one opaque provenance-reference file
to an externally verified Trusted Finalizer ALLOW. Its two legal subject kinds
are:

- artifact-sha256 — a generic content digest supplied by a protected caller.
- oci-manifest-or-index — one OCI manifest or index digest supplied by a
  protected caller.

Both use the exact lower-case representation sha256: followed by 64 hex
characters. A tag, URL, registry hostname, repository name, filename, release
name, media type, and display label are not accepted as a V2 subject.

## Exact claim

A valid V2 record means only:

> The holder of the separate artifact-digest admission key bound the exact
> externally supplied subject kind and SHA-256 digest, and the exact opaque
> provenance bytes plus identity label, to one separately authenticated
> Trusted Finalizer ALLOW with the stated source and context.

The verifier requires all of these as external inputs:

1. The artifact-digest admission public key.
2. The Trusted Finalizer public key.
3. The exact finalizer source and context JSON.
4. The expected subject kind and immutable digest.
5. The exact provenance file bytes and its expected identity label.

The binding cannot choose its own key, finalizer bundle, source/context,
subject, provenance bytes, or provenance identity at verification time.
Changing any of those inputs fails verification.

## Provenance is opaque by design

V2 reads a bounded regular provenance file, rejects symlinks and changing files,
and stores only its SHA-256, byte length, and a bounded identity label. It does
not parse, verify, or interpret that file.

Therefore, a V2 success does not establish any of the following:

- that the provenance document has a valid signature;
- that it is a SLSA, GitHub, Sigstore, in-toto, or any other supported format;
- that its builder, materials, invocation, or predicate are trustworthy;
- that its claimed source revision matches the finalizer head;
- that the OCI digest exists in a registry or has the claimed media type;
- that the artifact was built, released, scanned, deployed, or reproduced.

Do not use the term verified provenance for V2. The correct term is
provenance identity-and-digest binding. A future provider-specific verifier
must independently authenticate and parse the provenance before it can make
those broader claims.

## Protected workflow requirement

The V2 sealing command is a cryptographic primitive, not a secure build
workflow. Its caller must run in a protected post-build/release boundary that:

1. derives the digest from an immutable, independently obtained artifact or
   registry response;
2. obtains the provenance file from a trusted control plane rather than a
   candidate-controlled workspace;
3. verifies the finalizer bundle with external source/context before opening
   the separate artifact-digest signing key; and
4. does not execute candidate code after that key becomes available.

The command performs step 3 itself. It cannot enforce the other workflow
properties from a local path or digest string.

## Seal and verify

The subject and provenance inputs below must come from the protected caller,
not from an untrusted pull-request job.

    evo-guard seal-artifact-digest-admission final.evb \
      --subject-kind oci-manifest-or-index \
      --subject-digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
      --provenance provenance.json \
      --provenance-identity provider:build-run-123 \
      --out product.eab \
      --finalizer-pub finalizer.pub \
      --expected-source source.json \
      --expected-context context.json \
      --sign-key artifact-digest-admission.pem

    evo-guard verify-artifact-digest-admission product.eab final.evb \
      --subject-kind oci-manifest-or-index \
      --subject-digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
      --provenance provenance.json \
      --provenance-identity provider:build-run-123 \
      --trusted-pub artifact-digest-admission.pub \
      --finalizer-pub finalizer.pub \
      --expected-source source.json \
      --expected-context context.json

The output is a deterministic stored ZIP with exactly binding.json and
binding.sig. The signature covers:

    EVOGUARD_ARTIFACT_BINDING_V2 || NUL || canonical binding.json bytes

V2 has a distinct signature domain and purpose from V1. A V2 signature cannot
be replayed as a V1 signature.

The schema has the intentionally non-release-addressed identifier
urn:evoguard:artifact-digest-binding:2 until the next minor release gives it an
immutable release address. The V1 schema and released V1 behavior remain
unchanged.

## Fail-closed behavior

V2 rejects malformed or unknown digest algorithms, mutable values such as tags,
unknown subject kinds, zero/multiple subjects, missing or changed provenance,
non-regular provenance inputs, a finalizer DENY, finalizer replay, a different
admission key, a reused finalizer/admission key, payload mutation, and
non-canonical archive bytes.

It does not close Issue 78 by itself. The remaining work is a narrowly defined
provenance verifier and protected build or merge-candidate integration.

## GitHub Artifact Attestation adapter

The unreleased [`GITHUB_ATTESTATION_ADMISSION.md`](GITHUB_ATTESTATION_ADMISSION.md)
adapter is a provider-specific protected-boundary path for the GitHub CLI. It
does not redefine V2 or make every V2 provenance reference verified: only its
own function invokes `gh attestation verify` with a constrained policy before
it creates a V2 binding. The record must retain both its canonical receipt and
the exact raw GitHub CLI output. Its recheck is byte continuity, not a new
online signature verification.
