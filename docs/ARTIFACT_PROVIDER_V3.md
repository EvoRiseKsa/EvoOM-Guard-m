# Artifact Provider V3 — public GHCR OCI admission

`EVOGUARD_ARTIFACT_PROVIDER_RECEIPT_V3` is a **library-only contract released
in `v4.6.0`**. It is present in the latest immutable consumer release but has no
CLI command or reference protected
workflow, and has not completed a live OCI pilot.

The implementation is
[`evoom_guard/admission/artifact_provider_v3.py`](../evoom_guard/admission/artifact_provider_v3.py).
The canonical receipt schema is
[`artifact-provider-receipt-3.schema.json`](../evoom_guard/schemas/artifact-provider-receipt-3.schema.json).
V1 and V2 formats, signatures, schemas, and verification paths are unchanged.

## Exact claim

A successfully verified V3 admission means only:

> The configured GitHub CLI/GitHub/Sigstore provider accepted exactly one
> GitHub Artifact Attestation for one digest-qualified public GHCR subject,
> with the exact repository, direct same-revision branch workflow, source
> digest, builder run ID, and builder run attempt supplied by the protected
> caller; EvoOM Guard retained that result and bound its exact receipt bytes,
> immutable subject digest, and an externally verified Trusted Finalizer
> `ALLOW` through the existing V2 signature.

EvoOM Guard validates the authority-bearing fields returned by the provider;
it does not reimplement GitHub/Sigstore cryptography. The protected caller and
verifier must still supply the admission public key, finalizer public key,
expected finalizer source/context, provider policy, builder run/attempt, GHCR
repository, and digest from external trust inputs.

## Supported subject and provider

V3 accepts exactly this canonical subject shape:

```text
oci://ghcr.io/<owner>/<image>[/<path>...]@sha256:<64 lowercase hex>
```

The API receives the repository and digest separately and constructs the URI.
It accepts canonical lowercase `ghcr.io/<owner>/<image>[/...]` plus exact
`sha256:<64-hex>`. It rejects tags, missing digests, other registries or
algorithms, uppercase spellings, URL schemes in the repository field, query
strings, and fragments. The attestation bundle source is fixed to the OCI
registry through `--bundle-from-oci`.

The subject is recorded as `oci-manifest-or-index`, but this adapter does not
independently query or authenticate the object's OCI media type. It is a
single-provider, public-GHCR subset, not a generic registry or package
adapter. URI syntax alone also cannot prove repository visibility; “public” is
an integration constraint, not an attested access-control fact.

### Registry authentication is not yet proven

“Public GHCR” does **not** mean anonymous registry access. GitHub CLI 2.90.0
states that an OCI client must already be authenticated with the container
registry, and GitHub's container-attestation guide performs `docker login
ghcr.io` before `gh attestation verify`. The isolated provider environment in
this implementation deliberately creates an empty `HOME`/`GH_CONFIG_DIR`, does
not inherit an operator's Docker configuration, and preserves only
`GH_TOKEN`/`GITHUB_TOKEN` as credential inputs.

The V3 API does not yet stage an authenticated registry configuration, and no
live run has established that either preserved token is sufficient for this
`--bundle-from-oci` path. A protected integration may therefore require an
additional, explicitly reviewed registry-auth mechanism that remains available
after the UID/GID drop without exposing credentials to candidate code. Until
that mechanism and a live positive/negative pilot exist, OCI provider
reachability is an unresolved integration gate, not an implemented guarantee.

## Required provider and source relation

The adapter fails closed unless all of the following are true:

1. exactly one provider result contains the exact subject repository and
   SHA-256 digest;
2. the attestation repository equals
   `expected_finalizer_context["repository"]`;
3. the attested source digest equals
   `expected_finalizer_context["head_sha"]`;
4. the GHCR namespace equals the attested repository owner;
5. the signer workflow belongs to that exact repository and its Git digest
   equals the attested source digest;
6. the source ref is an exact `refs/heads/...` branch, not a tag;
7. the certificate, statement source, builder, GitHub-hosted runner, GitHub
   Actions OIDC issuer, and SLSA v1 predicate fields satisfy the existing
   GitHub-attestation semantic validator;
8. the signed invocation URI carries the exact externally supplied builder run
   ID and attempt; and
9. that builder invocation is not the exact finalizer invocation.

The SLSA predicate identifier is a provider-policy selector only. Passing this
check is **not** a claim of SLSA level or SLSA compliance.

## Receipt and V2 binding

Fresh creation writes two distinct, no-clobber regular files:

- the canonical `EVOGUARD_ARTIFACT_PROVIDER_RECEIPT_V3` JSON receipt; and
- the exact successful GitHub CLI JSON output.

The receipt binds the provider name and registry bundle source, GHCR repository
and digest, exact builder run/attempt, complete normalized provider policy, and
the raw-output SHA-256, size, and one-result count. The provider result is not a
new EvoOM Guard signature.

`seal_artifact_provider_v3_admission()` then uses the unchanged
`EVOGUARD_ARTIFACT_BINDING_V2` contract. V2 signs:

- subject kind `oci-manifest-or-index` and the exact digest;
- the exact V3 receipt bytes as its provenance reference;
- an `artifact-provider-v3:sha256:...` identity committing to every
  authority-bearing provider pin; and
- the separately authenticated Trusted Finalizer `ALLOW` under the caller's
  exact external source/context.

The V3 receipt, raw output, V2 binding, finalizer bundle, and both public keys
must be retained as separate evidence objects.

## Retained verification versus fresh reverification

The operations have deliberately different meanings:

| Operation | Provider/registry contact | What it establishes |
| --- | --- | --- |
| `verify_artifact_provider_v3_receipt()` | No | Canonical retained receipt, exact policy/subject/build expectations, semantic consistency of retained provider JSON, and byte continuity. |
| `verify_artifact_provider_v3_admission()` | No | The retained checks plus the unchanged V2 signature and externally verified finalizer relation. |
| `reverify_artifact_provider_v3_receipt()` | Yes | A new provider verification for the exact immutable subject and the exact policy/build pins recorded in the receipt. |

A retained verification does not re-check a provider signature, revocation,
registry availability, or current registry state. Fresh output may differ in
non-authority-bearing metadata; it must still satisfy the exact semantic pins.

## Provider isolation and key boundary

Every V3 live operation requires an explicit
`GitHubAttestationProviderIsolation` configuration. This binds the expected
GitHub CLI executable digest and a dedicated POSIX UID/GID execution identity,
uses isolated GitHub configuration and temporary paths, and retains the
existing bounded provider-process lifecycle.

That isolation also removes ambient Docker-registry credentials. The caller
must not infer registry authentication from `GH_TOKEN`/`GITHUB_TOKEN`; whether
either token is accepted for the exact CLI/registry path must be demonstrated
under the protected integration described above.

The sealing API additionally validates that the provider identity cannot read
the artifact-admission private-key path before it launches the provider. The
key remains separate from the Trusted Finalizer key. This check is a local
filesystem/identity boundary; it is not a VM, hostile-host, or independent
runner attestation.

## Python integration boundary

There is intentionally no V3 CLI yet. A protected integration must call the
library with policy, registry, builder, and finalizer values derived outside
candidate control:

```python
from evoom_guard.admission.artifact_provider_v3 import (
    seal_artifact_provider_v3_admission,
)

sealed = seal_artifact_provider_v3_admission(
    "ghcr.io/owner/product",
    "sha256:" + immutable_manifest_digest,
    "evidence/provider-v3.receipt.json",
    "evidence/provider-v3.raw.json",
    "evidence/finalized.evb",
    "evidence/product.eab",
    repository="owner/project",
    signer_workflow="owner/project/.github/workflows/build-image.yml",
    signer_digest=trusted_context["head_sha"],
    source_ref="refs/heads/main",
    source_digest=trusted_context["head_sha"],
    cert_oidc_issuer="https://token.actions.githubusercontent.com",
    workflow_run_id=trusted_builder_run_id,
    workflow_run_attempt=trusted_builder_run_attempt,
    trusted_finalizer_public_key_path="keys/finalizer.pub",
    expected_finalizer_source=trusted_source,
    expected_finalizer_context=trusted_context,
    private_key_path="keys/artifact-provider.pem",
    gh_executable="/trusted/bin/gh",
    provider_isolation=provider_isolation,
)
```

This sketch is not a deployable workflow. A real protected workflow must also
derive the immutable registry subject independently, pin the executable,
protect all external inputs and keys, retain every evidence object, and avoid
candidate execution after signing authority becomes reachable.

## Explicit non-claims and open issue

V3 does **not** establish:

- SLSA compliance or a SLSA level;
- reproducible or deterministic builds;
- image safety, correctness, vulnerability/CVE status, or SBOM quality;
- registry retention, continued registry existence, publication, or promotion;
- deployment authorization, deployed-runtime identity, or runtime behavior;
- semantic equivalence between source tests and image bytes;
- an independent provider implementation, independent review, or production
  readiness.

[Issue #78](https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues/78) remains open.
This source closes only one library-level, provider-specific OCI relation. It
does not yet supply a protected reference workflow or CLI, and no live public
GHCR manifest/index pilot or OCI negative-control evidence has been retained.
The issue's separate real release-asset path and remaining production
acceptance criteria are also not satisfied.
