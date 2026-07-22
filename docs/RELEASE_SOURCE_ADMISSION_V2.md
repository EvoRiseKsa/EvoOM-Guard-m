<!--
  Copyright (c) 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Source-available — see LICENSE for permitted use.
-->

# Release Source Admission V2

Release Source Admission V2 is a protected-main **source authorization**. It is
separate from the PR Trusted Finalizer, Artifact Admission, and the DENY-only
Release Source Finalizer V1. It neither changes nor reinterprets a V1 bundle.

The signed format is `EVOGUARD_RELEASE_SOURCE_ADMISSION_V2`. A valid `ALLOW`
means only this:

> Under externally supplied source, A/B/C workflow, run-attempt, bootstrap,
> provider-policy, and public-key roots, a protected V2 signer admitted the
> exact protected-main source and exact producer-receipt evidence preserved in
> the bundle after a fresh constrained provider verification.

It is not an artifact-build, publication, deployment, reproducibility,
vulnerability, or complete-correctness claim.

The implementation is in `evoom_guard.admission.release_source`. Its exact
internal dependency allowlist is enforced by architecture tests. The schema is
`evoom_guard/schemas/release-source-admission-2.schema.json`.

## Trust topology

The admitting path has three distinct workflow roles:

1. **A — source re-verification.** A no-secret job runs an immutable prior
   Guard runtime for one exact `refs/heads/main` commit and produces the
   verdict, source, context, and handoff.
2. **B — authenticated receipt producer.** A distinct GitHub-hosted job checks
   A's numeric workflow/run/attempt identity, re-derives raw-Git bindings,
   creates canonical receipt bytes, and requests a GitHub Artifact Attestation
   for those exact bytes.
3. **C — protected V2 signer.** A separately protected job checks its own
   protected identity and B trigger, repeats the raw-Git, receipt, verdict,
   runtime, and fresh provider checks, and only then opens a V2-only Ed25519
   signing key.

C is signed, not merely described externally. Before provider execution the
admitting CLI requires C to match all of the following:

- the externally supplied C identity;
- C's exact workflow blob in the protected-main Git tree;
- the current `GITHUB_REPOSITORY`, repository ID, workflow ref/SHA, run ID,
  run attempt, event, ref, and commit context; and
- the `workflow_run` event payload identifying the exact successful B
  workflow ID, path, commit, run ID, and run attempt.

The signed manifest includes the full C identity, A/B/trigger/C replay
selectors, both verifier executable SHA-256 pins, and the provider UID/GID
isolation contract. This still is not independent proof of GitHub. GitHub's control
plane, the reviewed A/B/C workflow definitions, the GitHub-hosted runner, the
immutable prior Guard runtime, the pinned Git and GitHub CLI binaries, and the
protected signing key remain trust roots.

`RUNNER_ENVIRONMENT` is a GitHub default variable. GitHub documents
`GITHUB_*` and `RUNNER_*` defaults as non-overridable; C requires its exact
`github-hosted` value in addition to the workflow/run/source bindings.

## Fail-closed verification order

`seal-release-source-admission` performs this order in one process:

1. validate external source, context, producer B, admitter C, bootstrap,
   GitHub policy, and the exact named cross-domain key registry;
2. preflight every input/output path and reject aliases or provider-evidence
   overwrite attempts;
3. bind a canonical absolute Git executable to an external SHA-256 and use a
   private stable snapshot for all raw-Git reads;
4. verify C's raw workflow blob, current GitHub Actions context, and exact B
   `workflow_run` event;
5. re-derive the protected-main commit/tree, its single parent, candidate,
   policy, verifier-pack, and A/B/C workflow-blob bindings;
6. verify the verdict, handoff, canonical producer receipt, strong isolated
   `PASS` profile, and all run-attempt replay relations;
7. before provider launch, prove that the chosen provider UID/GID cannot read
   the exact V2 signing-key path;
8. run a SHA-256-pinned `gh attestation verify` snapshot as that dedicated
   non-root identity with cleared supplementary groups and an allowlisted
   environment;
9. require one semantically valid provider result bound to the exact receipt
   SHA-256, predicate type, repository, workflow, ref, source/signer digests,
   issuer, GitHub-hosted runner, builder/dependency/invocation URIs, and B run
   ID/attempt; and
10. only after provider termination and cleanup, read one bounded stable,
    non-symlink snapshot of the separately scoped V2 private key and sign the
    canonical envelope; and
11. write a same-directory staging file, re-open and verify its canonical bytes
    and Ed25519 signature against the externally supplied V2 public key, then
    atomically promote it. With `--force`, an existing output remains untouched
    if staging verification fails.

The admission-capable path is deliberately POSIX-only and must start with
effective UID 0 so it can lower only the provider process to a distinct,
non-root UID/GID. It fails closed on unsupported platforms. Generic
non-admitting receipt verification remains available without this boundary,
but its result cannot be converted into a V2 `ALLOW`.

The signing key must be an absolute canonical regular non-symlink file, owned
by root/the caller, with mode exactly `0600`. Every parent directory must be
non-symlink and non-writable by the provider UID/GID. The key path, provider
isolation contract, and Git executable pin are bound into the private
in-process capability minted before the provider run; a different or
unisolated result is rejected before key access. The later key read is bounded
to 64 KiB and repeats regular-file, link/reparse, descriptor identity, size,
and before/after stability checks.

## Key separation

The V2 signer is the fifth distinct key domain. The other four required public
keys form a closed-world registry:

- `trusted_finalizer`
- `artifact_admission_v1`
- `artifact_digest_admission_v2`
- `release_source_finalizer_v1`

All four registry key IDs must be mutually distinct, and the V2 signing key
must differ from every one of them. Arbitrary deny-list flags are not accepted.

## Envelope and detached verification

The canonical `.rsae` ZIP contains exactly:

```text
admission.json
admission.sig
record/verdict.json
materials/release-source-handoff.json
materials/producer-receipt.json
provider/github-attestation-receipt.json
provider/github-attestation-output.json
```

`admission.sig` is an Ed25519 signature over the canonical manifest under the
distinct `EVOGUARD_RELEASE_SOURCE_ADMISSION_V2\0` domain. Detached verification
requires the trusted V2 public key plus expected source, context, producer B,
admitter C, bootstrap, GitHub policy, Git/`gh` SHA-256 pins, provider UID/GID,
and all four key-registry public keys from outside the bundle. Embedded values
never select their own trust roots.

The detached verifier re-parses the retained provider output and checks its
narrow semantic bindings. It does not contact GitHub and does not independently
re-run DSSE/Sigstore verification. Freshness and authenticity at sealing time
come from the isolated live `gh` invocation and the trusted V2 signature.

## Commands

Signing and signature verification require the optional `sign` dependency
(`cryptography>=41`), for example `python -m pip install ".[sign]"`. The
zero-dependency core remains usable for commands that do not sign or verify
Ed25519 evidence.

The seal command must run as root on POSIX. Resolve executable symlinks before
computing the two SHA-256 pins.

```bash
evo-guard seal-release-source-admission \
  producer-receipt.json handoff.json verdict.json \
  --out source-allow.rsae \
  --source expected-source.json \
  --context expected-context.json \
  --producer expected-producer.json \
  --admitter expected-admitter.json \
  --bootstrap-guard-sha "$BOOTSTRAP_SHA256" \
  --github-policy expected-github-policy.json \
  --git-repository /trusted/objects.git --git-repository-bare \
  --git-executable /trusted/bin/git \
  --git-executable-sha256 "$GIT_SHA256" \
  --github-receipt-out fresh-provider-receipt.json \
  --github-raw-output-out fresh-provider-output.json \
  --gh-executable /trusted/bin/gh \
  --gh-executable-sha256 "$GH_SHA256" \
  --provider-isolation-uid 65534 \
  --provider-isolation-gid 65534 \
  --sign-key /protected/release-source-admission.pem \
  --sign-pub /trust/release-source-admission.pub.pem \
  --trusted-finalizer-pub /trust/trusted-finalizer.pub.pem \
  --artifact-admission-v1-pub /trust/artifact-admission-v1.pub.pem \
  --artifact-digest-admission-v2-pub /trust/artifact-digest-admission-v2.pub.pem \
  --release-source-finalizer-v1-pub /trust/release-source-finalizer-v1.pub.pem

evo-guard verify-release-source-admission source-allow.rsae \
  --trusted-pub /trust/release-source-admission.pub.pem \
  --expected-source expected-source.json \
  --expected-context expected-context.json \
  --expected-producer expected-producer.json \
  --expected-admitter expected-admitter.json \
  --expected-bootstrap-guard-sha "$BOOTSTRAP_SHA256" \
  --expected-github-policy expected-github-policy.json \
  --expected-git-executable-sha256 "$GIT_SHA256" \
  --expected-gh-executable-sha256 "$GH_SHA256" \
  --expected-provider-isolation-uid 65534 \
  --expected-provider-isolation-gid 65534 \
  --trusted-finalizer-pub /trust/trusted-finalizer.pub.pem \
  --artifact-admission-v1-pub /trust/artifact-admission-v1.pub.pem \
  --artifact-digest-admission-v2-pub /trust/artifact-digest-admission-v2.pub.pem \
  --release-source-finalizer-v1-pub /trust/release-source-finalizer-v1.pub.pem
```

`--force` may replace only the final `.rsae`; fresh provider receipt and raw
output paths are always no-clobber.

## Bootstrap and remaining release boundary

The first release containing V2 cannot use itself as its prior Guard runtime or
as evidence that its own source was admitted. It must be published through the
existing reviewed release process, and its immutable asset URL/SHA must be
established separately. Only a later run may use it.

A source `ALLOW` is still insufficient to publish bytes. A separate protected
release-artifact adapter must bind the actual artifact digest to a fresh build
attestation whose source digest equals the admitted protected-main commit. A
separately privileged consumer must verify both relations before publication.

## Explicit non-claims

V2 does not establish:

- independent review when `EvoRiseKsa` and `MANA-awam` are controlled by the
  same owner;
- provenance or safety of a release asset, package, OCI image, registry object,
  or deployed runtime;
- reproducibility, SLSA conformance, SBOM/CVE coverage, or complete software
  correctness;
- that mutable repository settings were unchanged outside the recorded audit;
- that POSIX ACLs or a reused provider UID cannot widen access beyond the
  reviewed mode/owner checks (production must use a dedicated UID and a
  root-owned, non-provider-writable C workspace); or
- production readiness without a separately protected live integration and
  preserved positive and negative evidence.
