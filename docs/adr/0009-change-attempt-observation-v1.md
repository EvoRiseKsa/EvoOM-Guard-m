# ADR-0009 Bounded change-attempt observation V1

## Status

Accepted for contract-first implementation.

## Context

The Agent Change admission profile intentionally accepts only a verified
Trusted Finalizer `ALLOW` over a semantic Guard `PASS`. It therefore cannot
represent rejected, failed, incomplete, or tampered attempts without changing
the meaning of an admission.

The generic Trusted Finalizer already signs exact verdict bytes for all five
Guard verdicts and deterministically maps only `PASS` with `passed=true` to
`ALLOW`; every other valid verdict maps to `DENY`. A downstream advisory
consumer needs those negative observations, but it must not:

- reinterpret a denial as an Agent Change admission;
- count several fields from one run as independent witnesses;
- receive source, diff, policy, verifier-pack, test-name, diagnostic, or
  stdout/stderr content; or
- receive a producer-authored risk, vulnerability, safety, or maliciousness
  claim.

This ADR freezes the producer and consumer boundary requested by
[Issue #263](https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues/263) before
runtime projection code is added.

## Decision

Add a separate, advisory-only projection with:

- wire format `EVOGUARD_CHANGE_ATTEMPT_OBSERVATION_V1`;
- consumer schema identity
  `evorise.change-advisory.attempt-observation.v1`; and
- JSON Schema
  `evoom_guard/schemas/change-attempt-observation-1.schema.json`.

The public verified runtime wrapper is named
`VerifiedChangeAttemptObservation`. The projection is not an extension of, or
substitute for, an Agent Change admission.

### Trusted input and projection sequence

The producer accepts a bounded regular-file Trusted Finalizer bundle and
trusted expected source/context plus the trusted finalizer public key. It must:

1. parse the archive and JSON with the existing strict bounded readers;
2. authenticate `EVOGUARD_EVIDENCE_BUNDLE_V1` and its exact canonical members;
3. verify the finalizer signature, exact handoff, expected source/context,
   verdict-record semantics, and bundle-to-record binding;
4. derive `ALLOW` or `DENY` from the verified record rather than accepting a
   caller-provided decision;
5. project only the fields frozen in the V1 schema;
6. validate every V1 cross-field invariant listed below; and
7. serialize canonical JSON.

A caller-supplied parsed record, claimed digest, claimed verification result,
or already-projected observation is not a trusted producer input.

For the same authenticated bundle and the same fixed trusted verification
inputs, the canonical observation bytes must be identical. Local clock time,
process identity, verifier identity/version, host identity, invocation ID, and
randomness must not influence the wire projection.

### Closed and bounded content

The observation contains only:

- repository name and immutable repository, handoff-workflow-run,
  bundle-context-run, commit, tree, candidate, policy, pack, and Guard
  artifact identities;
- signed bundle and verdict-record identities;
- the authenticated finalizer key and deterministic correlation-group
  identity;
- closed finalizer and Guard outcomes;
- bounded assurance states; and
- five closed evidence-channel summaries.

Every object rejects unknown keys. Counts have explicit maxima. Digests,
Git object IDs, key IDs, format identifiers, states, phases,
verdict sources, and reason codes are canonical or closed. There are no
extension maps, arbitrary metadata, paths, commands, or narrative values.

### Source namespaces

The source projection preserves two run namespaces because the current Trusted
Finalizer verifies each against separately trusted expected input but does not
require them to be equal:

- `pull_request_number`, `handoff_workflow_run_id`, and
  `handoff_workflow_run_attempt` come from the exact
  `EVOGUARD_TRUSTED_FINALIZER_HANDOFF_V1.source`;
- `repository`, `repository_id`, `context_run_id`, and
  `context_run_attempt` come from the exact signed
  `EVOGUARD_EVIDENCE_BUNDLE_V1.context`;
- `base_sha` and `head_sha` occur in both namespaces and are projected only
  after the finalizer has required exact equality between them; and
- tree, candidate, effective-policy, verifier-pack, and Guard-artifact
  identities come from the signed bundle context after verdict/context
  validation.

Neither the wire format nor its semantic verifier may infer that
`handoff_workflow_run_id/attempt` equals `context_run_id/attempt`. If a later
profile establishes that relationship independently, it requires an explicit
new invariant rather than silently collapsing these fields.

### Outcome invariants

Shape validation is necessary but not sufficient. The producer and consumer
validators must also enforce:

- `ALLOW` if and only if the verified record has `verdict=PASS` and
  `passed=true`;
- `DENY` for `REJECTED`, `FAIL`, `ERROR`, and `TAMPERED`;
- `passed=true` if and only if `verdict=PASS`;
- exact equality of the projected reason code, execution state, execution
  phase, and verdict source to the semantically verified record;
- exact equality of source/context and digest identities across the trusted
  expected context, finalizer handoff, bundle manifest, record attestation,
  and projection wherever the source format exposes them; and
- consistency of execution and assurance lifecycle states under the existing
  verdict-record verifier.

Unknown verdicts, phases, reason codes, assurance values, schema versions, or
non-canonical values fail closed. V1 supports verdict-record schemas `1.11`
and `1.12`; later record schemas require an explicit observation-schema
revision or a demonstrated byte- and semantics-compatible amendment.

### Correlation and provenance

V1 deliberately models one authenticated Guard/finalizer run as one external
evidence group. The five required channels are:

1. reserved raw-Git binding channel, unavailable until a separate raw-Git
   derivation is actually verified;
2. signed Guard-execution record claim;
3. signed repository-suite record claim;
4. signed verifier-pack record claim; and
5. signed runtime-identity record claim.

Every channel carries the same signed-bundle provenance tuple. Its
`correlation_group_id` is:

```
cg:sha256:<lowerhex SHA-256(
  UTF-8("EVOGUARD_CORRELATION_GROUP_V1\0"
        + "SIGNED_FINALIZER_BUNDLE\0"
        + "EVOGUARD_EVIDENCE_BUNDLE_V1\0"
        + bundle_sha256 + "\0"
        + finalizer_key_id)
)>
```

All five channel tuples must exactly match the top-level authenticated bundle
digest, finalizer key ID, and derived correlation group. Relabeling,
duplicating, omitting, or transplanting a channel fails closed.

`independently_countable` is the literal `false` in V1. A field, JUnit digest,
runtime-tree digest, or signed source/context binding carried by the same
finalizer bundle does not become an independent source merely because it has a
different role or digest. Independent counting requires a future schema
revision that names an independently specified signed receipt, authenticates a
distinct trusted producer/key domain, binds the same subject/context, and
derives a separate correlation group. A caller-set flag or group label can
never establish independence.

### Channel availability

`AVAILABLE` means that the named bounded facts were present and semantically
verified. `UNAVAILABLE` means the producer could not establish that channel.
`NOT_APPLICABLE` means the verified execution profile did not require it.

For unavailable or inapplicable channels, count fields are zero or null and
digest/state fields are null as fixed by the schema and semantic validator.
For available channels, the channel-specific minimum fields must be present.
Test counts additionally require `0 <= passed <= total`; completed implies
started; passed implies completed. Runtime tree counts must stay within the
runtime-identity scanner limits. Availability is evidence about the presence
of a bounded signed claim, not evidence that the attempted change was safe or
independently observed.

The `raw_git_binding` wire key has scope `RAW_GIT_BINDING`. It is always
`UNAVAILABLE` in V1, with null `bound_identity_count` and `binding_sha256`,
because this projector does not invoke Git, read literal Git objects, or
verify a separate raw-Git derivation. Successful full verification still
authenticates and cross-checks the exact expected handoff source, bundle
context, and verdict bindings projected in the top-level `source` object.
Those facts are signed context bindings, not raw-Git observations. A future
producer may make this channel available only under a revised contract that
specifies and verifies the independent derivation.

The other four channels have scope `SIGNED_RECORD_CLAIM`. Their values are
bounded claims extracted from the authenticated verdict record. Their
signatures preserve and bind those claim bytes; they do not prove that the
finalizer independently witnessed the underlying execution.

`guard_execution.execution_evidence_sha256` is the SHA-256 of canonical JSON
for this closed preimage:

```json
{
  "format": "EVOGUARD_CHANGE_ATTEMPT_EXECUTION_EVIDENCE_V1",
  "verdict_record_sha256": "<the signed_evidence verdict-record digest>",
  "test_command_started": "<the exported boolean>",
  "candidate_invocation_count": "<the exported integer or null>"
}
```

It binds the small execution summary to the exact signed verdict-record
identity. It is not another receipt, signature, witness, or assertion that the
command exercised the intended candidate.

Applicability is cross-bound, not caller-selected:

- a null `source.verifier_pack_sha256` requires the verifier-pack channel to
  be `NOT_APPLICABLE`; a non-null digest forbids that value;
- `assurance.runtime_identity_continuity=not_applicable` requires the runtime
  channel to be `NOT_APPLICABLE`, and every other continuity state forbids it;
- `black_box_external_judge`, `composite_blackbox_repo_native`, and
  `blackbox_composite_short_circuit` require repository-suite availability of
  `NOT_APPLICABLE`, `AVAILABLE`, and `UNAVAILABLE`, respectively; and
- an incomplete test channel cannot carry result counts or a result digest.

`runtime_identity.exported_identity_count` counts exported runtime-tree
identities, not internal capture or comparison operations. It is exactly `1`
when the channel is `AVAILABLE`, and `0` otherwise.

### What the finalizer signature proves

Successful verification proves that:

- the trusted finalizer key authenticated the canonical bundle bytes;
- the bundle preserves the exact verdict record and verified handoff bytes;
- the record is semantically valid under its supported verdict schema;
- the expected source/context and content digests are bound exactly; and
- the deterministic finalizer decision matches the verified verdict.

It does not prove that:

- the finalizer independently reran the candidate;
- every record field came from an independent witness;
- subprocess, container, or gVisor isolation prevents every escape;
- the test suite is sufficient, complete, or honest;
- the change is safe, vulnerability-free, non-malicious, correct, or suitable
  for production; or
- the observation authorizes admission, merge, deployment, promotion, or any
  external action.

### Runtime-wrapper metadata is not wire evidence

A runtime wrapper may record local operational metadata such as `verifier_id`,
`verified_at`, or a hash of the completed canonical observation bytes. Those
values are not signed EVB facts and must not appear inside
`EVOGUARD_CHANGE_ATTEMPT_OBSERVATION_V1`, its canonical bytes, or the digest
whose input is those bytes. Consumers must not present them as facts proven by
the finalizer bundle.

If a wrapper computes a local observation hash, it does so only after the
canonical bytes are complete and stores it outside the observation. V1 has no
self-referential observation-digest member. Wrapper metadata provides local
audit convenience only; it provides no finalizer-authenticated verifier
identity, freshness, revocation, or trusted-time guarantee.

### Privacy and semantic exclusions

V1 must not export source or diff content, file paths, touched/deleted-path
lists, commands, policy content, verifier-pack content, raw JUnit, test names,
diagnostics, reasons, stdout/stderr, free-form narratives, existing producer
`risk_level`/`risk_score` fields, Cognitive scores, or vulnerability, safety,
maliciousness, and production-readiness claims.

The fixed authority block states that the observation is advisory only and
has no admission, merge, deployment, promotion, or external-action authority.

### Canonical and fail-closed verification

Both producer and consumer must reject:

- duplicate JSON keys, non-UTF-8 input, non-canonical strings, unknown keys,
  unknown enum values, booleans used as integers, and values outside bounds;
- digest, source, context, run, commit/tree, candidate, policy, pack, Guard
  artifact, record, or key mismatches;
- decision/verdict/passed or execution/assurance contradictions;
- invalid channel availability/count combinations;
- duplicate, omitted, renamed, relabeled, or cross-run channel summaries;
- any V1 channel marked independently countable;
- swapped records, bundles, contexts, or correlation groups; and
- omission, substitution, or representational collapse of the handoff
  workflow-run and bundle-context-run namespaces. Coincidentally equal values
  remain separately sourced and do not establish an equality invariant.

Producer publication also rejects an output path that lexically, canonically,
or by existing-file identity aliases the input bundle or trusted public key.
`force=true` authorizes replacement only of a distinct output; it never
authorizes destruction of a trust input.

JSON Schema validates the closed wire shape. The dedicated semantic verifier
owns equality, derivation, chronology, lifecycle, and cryptographic checks
that JSON Schema cannot express.

The producer reads the caller-selected bundle path once, hashes and verifies
the same retained bytes through a private `0700` directory and `0600`
snapshot, and snapshots caller-owned source/context mappings before the
multi-step verifier reads them. This prevents pathname and mutable-mapping
swaps across the operation. It does not isolate hostile code already running
as the same operating-system principal; the API belongs in a trusted finalizer
process, not beside candidate code.

Published golden observation and consumer-rejection vectors live under
`tests/fixtures/change_attempt_observation/`. Their deterministic signing key
is deliberately public test material and is reconstructed by the test. The
input bundle is intentionally not committed because it contains the full
verdict record excluded from this projection. The committed observation
contains no private key or raw execution, source, command, path, diagnostic,
policy, pack, stdout/stderr, or JUnit content.

## Compatibility

This is an additive contract. Existing verdict records, evidence bundles,
Trusted Finalizer behavior, Agent Change formats, and Agent Change admission
semantics remain byte- and semantically compatible. No existing V1 format is
widened or reinterpreted.

## Consequences

- Negative and tampered attempts can be studied without fabricating
  admissions.
- Downstream deterministic and Cognitive analysis receives bounded,
  privacy-preserving facts.
- One signed run remains one correlated source, so the first advisory consumer
  should normally withhold claims that require independent corroboration.
- Rich code-risk analysis remains impossible until separately authenticated
  diff/content, coverage, policy, pack, and outcome-quality evidence contracts
  exist.
- Multi-attestor evidence requires a new explicit contract; V1 cannot be
  relabeled into it.
