# Offline record verification

`evo-guard verify-record` validates the schema-1.11 JSON record itself without
running candidate code:

```bash
evo-guard verify-record verdict.json
```

The command reads at most 8 MiB once and always writes one JSON report. Once the
bounded input bytes have been read, the report includes their exact length and
SHA-256 even if JSON decoding fails. Exit status is `0` when no semantic
contradiction is found, `1` for a readable JSON value that fails verification,
and `2` when the input cannot be read as JSON. Use `-` to read from standard
input. Parsing is strict: duplicate object keys, the non-JSON numeric values
`NaN`, `Infinity`, and `-Infinity`, numeric overflow such as `1e9999`, integers
over 128 digits, unpaired Unicode surrogates, and nesting over 256 levels are
rejected as unusable input.

The report contains a stable list of checks with `pass`, `fail`, or `skip`
status. A skipped check is not presented as proof. For example, schema 1.11
permits `attestation: null`; that record can still be structurally consistent,
but policy binding and attestation parity are explicitly skipped.

The verifier checks:

- the schema/tool/version envelope, bounded diagnostics, timestamps, SHA-256
  identities, and nested enum/type contracts;
- verdict, `reason_code`, `passed`, exit status, protected-violation, and count
  invariants;
- lifecycle parity across the top level, `assurance`, and `attestation`;
- the complete typed 24-field effective policy and canonical recomputation of
  `attestation.policy_sha256`;
- black-box candidate-receipt zero/non-zero semantics;
- delivered isolation and assurance-profile/report-channel semantics;
- binding of `verdict_source` to mode, `blackbox_only`, required pack, execution
  phase, and repo/pack composition, so a required channel cannot be dropped;
- exact measured/unmeasured `diff_coverage` and baseline shapes, including
  per-file count/percentage reconciliation, and binding of coverage/fix reasons
  and `PASS` to the thresholds and repair evidence in effective policy;
- observed report-integrity/candidate-isolation floors and an expected
  verifier-pack digest pin, including the corresponding fail-closed reasons;
- verifier-pack configuration, identity, lifecycle, counts, and the stronger
  evidence required before a pack-backed `PASS`; and
- composite count decomposition and weakest-channel semantics when the record
  contains enough phase evidence.

Verification is a total operation over JSON-like input: malformed enum values,
arrays where objects were expected, invalid nested fields, and non-canonical
policy objects produce failed checks rather than an exception or a partial
success report. Excessive parser nesting is reported as invalid JSON.

The structural JSON Schema is
[`evoom_guard/schemas/verdict-record-1.11.schema.json`](../evoom_guard/schemas/verdict-record-1.11.schema.json).
JSON Schema cannot express all cross-field invariants, so consumers should run
the command as well as structural validation.

## Trust boundary

This command verifies **internal consistency only**. It does not verify a
signature, prove that the producer was trusted, re-hash external artifacts, or
re-run the judged change. `verify-verdict` checks its signature and requested
context fields from one byte snapshot, but two separate commands over a writable
path are not one atomic admission decision. If used together for diagnostics,
compare the `input_sha256` printed by both commands:

For the same reason, arithmetic consistency of `diff_coverage` does not prove
its runtime truth. Repo-native candidate code shares the `coverage.py` process
and can mutate its live data; the record's `caveat` names this boundary.

```bash
evo-guard verify-verdict verdict.json --pub evoguard-signing.pub \
  --expect-head-sha "$GITHUB_SHA" --expect-policy-sha "$EXPECTED_POLICY_SHA"
evo-guard verify-record verdict.json
```

Neither command silently strengthens the other: `verify-verdict` authenticates
its snapshot, while `verify-record` checks the claims inside its own snapshot.

For one authenticated, replay-resistant admission result, use:

```bash
evo-guard verify-bundle evidence.evb \
  --trusted-pub evoguard-signing.pub \
  --expect-context expected-context.json
```

That path authenticates a canonical envelope, requires external expected
context, and verifies semantics over the same snapshotted verdict bytes. See
[`EVIDENCE_BUNDLES.md`](EVIDENCE_BUNDLES.md).
