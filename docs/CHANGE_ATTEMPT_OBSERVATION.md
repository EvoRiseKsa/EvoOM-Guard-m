# Change Attempt Observation V1

`EVOGUARD_CHANGE_ATTEMPT_OBSERVATION_V1` is a deterministic,
privacy-bounded projection of one authenticated Trusted Finalizer bundle. It
lets an advisory consumer study both accepted and denied attempts without
turning a `DENY` into an Agent Change admission.

This contract is implemented on the repository source line after `v4.4.2`. It
is not present in the immutable `v4.4.2` release.

## What it accepts

The producer accepts only:

- a canonical signed Trusted Finalizer `.evb`;
- the finalizer public key supplied from an external trust root;
- the exact expected finalizer handoff source; and
- the exact expected evidence context.

It does not accept a caller-provided verdict, decision, digest, correlation
group, or parsed record as trusted input. The bundle is read into one stable,
bounded snapshot; its hash and verification are derived from those same bytes.

## Python producer

```python
from evoom_guard.change_attempt_observation import (
    produce_change_attempt_observation,
)

verified = produce_change_attempt_observation(
    "finalized.evb",
    "attempt-observation.json",
    trusted_finalizer_public_key_path="finalizer.pub",
    expected_source=expected_source,
    expected_context=expected_context,
)

print(verified.observation_sha256)
print(verified.inspection.payload["outcome"])
```

Publication is canonical, atomic, and no-clobber by default. `force=True` is
an explicit overwrite opt-in. The output path may never equal or alias the
input bundle or trusted public-key path, even with `force=True`.

## Python consumer

```python
from evoom_guard.change_attempt_observation import (
    verify_change_attempt_observation,
)

verified = verify_change_attempt_observation(
    "attempt-observation.json",
    bundle_path="finalized.evb",
    trusted_finalizer_public_key_path="finalizer.pub",
    expected_source=expected_source,
    expected_context=expected_context,
)
```

The consumer re-authenticates the `.evb`, re-projects the observation from the
verified record, and requires byte-for-byte equality with the supplied
observation. The returned public wrapper is
`VerifiedChangeAttemptObservation`. Structural inspection alone is
deliberately non-authoritative:
`inspect_change_attempt_observation()` checks canonical shape and the bounded
cross-field rules owned by this projection, but it does not re-run the verdict
record verifier or authenticate the finalizer. Only exact authenticated
verification may be relied upon.

## Outcome semantics

Only a semantic Guard `PASS` with `passed=true` projects to `ALLOW`.
`REJECTED`, `FAIL`, `ERROR`, and `TAMPERED` project to `DENY`.

`TAMPERED` in a valid observation means that the authenticated Guard record
reported detected tampering. A modified bundle, signature, context, or
observation does not project to `TAMPERED`; verification fails and produces no
verified observation.

## One correlated source

Every observation contains exactly five closed channels:

- `raw_git_binding`;
- `guard_execution`;
- `repository_suite`;
- `verifier_pack`; and
- `runtime_identity`.

All five carry the same bundle digest, finalizer key ID, and derived
correlation group, with `independently_countable=false`.

Applicability is deterministic: a null verifier-pack source digest and
`runtime_identity_continuity=not_applicable` require their corresponding
channels to be `NOT_APPLICABLE`. Black-box-only, completed composite, and
short-circuited composite profiles similarly fix repository-suite
applicability. Result facts are forbidden on incomplete channels.

The reserved wire key `raw_git_binding` has scope `RAW_GIT_BINDING` and is
`UNAVAILABLE` in V1. Its result fields are null because this projector does
not invoke Git, read literal Git objects, or verify an independent raw-Git
derivation. The exact expected source/context is still authenticated and
re-projected at the top level; that signed binding must not be mislabeled as a
raw-Git observation. The other four channels have scope
`SIGNED_RECORD_CLAIM`: the finalizer signature preserves those record claims,
but does not make them independent witnesses.

## Deliberate exclusions

The projection contains no source or diff text, paths, commands, policy or
pack content, diagnostics, stdout/stderr, raw JUnit, test names, free-form
reason text, risk score, vulnerability claim, or safety claim.

Local `verifier_id`, `verified_at`, and `observation_sha256` values belong to
the returned runtime wrapper. They are not signed by the finalizer and do not
appear in the deterministic wire bytes.

## Authority boundary

The authority block is fixed to `ADVISORY_ONLY`; admission, merge, deployment,
promotion, and external-action authority are all `false`.

The finalizer signature proves the exact bundle bytes, handoff, external
source/context binding, record semantics, and deterministic finalizer
decision. It does not prove test sufficiency, candidate correctness, complete
isolation, independent execution witnessing, production suitability, or
freedom from vulnerabilities or malicious behavior.

The normative design and cross-field invariants are frozen in
[`ADR-0009`](adr/0009-change-attempt-observation-v1.md). The packaged wire
shape is
[`change-attempt-observation-1.schema.json`](../evoom_guard/schemas/change-attempt-observation-1.schema.json).
Byte-exact observation and consumer-rejection vectors are published in
[`tests/fixtures/change_attempt_observation`](../tests/fixtures/change_attempt_observation);
their deterministic key is public test material, not a deployable secret. The
test reconstructs the producer input deterministically; the raw signed bundle
is intentionally not published because it contains the full verdict record
that this privacy-bounded projection excludes.

The implementation snapshots the input bundle and caller-owned source/context
objects before multi-step verification. Its private temporary directory
protects against pathname replacement and other principals; it is not an
isolation boundary against hostile code already running under the same OS
account. Run the API only in the trusted finalizer process.
