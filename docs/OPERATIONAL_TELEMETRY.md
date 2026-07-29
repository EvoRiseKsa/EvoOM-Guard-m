# Local operational telemetry

> **Availability:** this utility was introduced on the `4.4.0` source line and
> is included in the ledger-recorded `v4.4.2` release. The ledger binds the
> exact released artifact and publication chain; it does not validate the
> telemetry input population or make the utility a monitoring service. Verify
> the [release status](RELEASE_STATUS.md) and exact installed artifact.

`tools/telemetry/aggregate_verdicts.py` produces a small, local operational
summary from EvoOM Guard verdict-record JSON files. It is stdlib-only and has no
network or upload path. The current tool accepts frozen legacy records on
schema `1.11` and profile-bearing records on schema `1.12`. A record that puts
`operating_profile` in a `1.11` policy is rejected.

## Runbook

First verify records when their authenticity or cross-field correctness matters:

```bash
evo-guard verify-record evidence/run-1/record/verdict.json
```

Then aggregate explicit record files, or a directory containing only verdict
JSON files:

```bash
python tools/telemetry/aggregate_verdicts.py \
  evidence/run-1/record/verdict.json \
  evidence/run-2/record/verdict.json \
  > operational-telemetry.json
```

Policy versions are free-form configuration and could accidentally contain a
tenant, ticket, path, or secret. They are therefore reported as `other` unless
the operator explicitly approves a low-cardinality label:

```bash
python tools/telemetry/aggregate_verdicts.py \
  evidence/verdict-records \
  --allow-policy-version 2026.07 \
  > operational-telemetry.json
```

The command fails closed on malformed JSON, duplicate keys, non-finite numbers,
unsupported record vocabulary, symbolic-link inputs, oversized records, or
more than 10,000 records. Errors identify only an input ordinal and never echo
an input path or record value. Each record is checked with `lstat`, opened once
without following links where the platform supports that flag, bound to the
same regular-file identity with `fstat`, and read from that descriptor through
an 8 MiB bounded loop. Descriptor metadata must remain stable through the read.
Directory discovery also rejects any symbolic-link or Windows reparse entry at
any depth instead of silently omitting it; an unreadable or changing traversal
fails the whole aggregation. No partial JSON is written to stdout on failure.

## Output contract

The output contains only:

- total record count;
- counts by the frozen verdict, reason-code, isolation, and operating-profile
  vocabularies;
- policy-version counts for explicitly approved labels plus `other` and
  `unspecified`;
- `ERROR` count and rate, labelled as operational abstention;
- aggregate min/mean/p50/p95/max for
  `attestation.runtime_identity_elapsed_ms`, when records carry it.

That latency is the runtime-tree identity measurement, not end-to-end Guard
latency. A record without that field contributes only to
`records_without_measurement`.

The output never includes source paths, changed-file names, record filenames,
reason text, diagnostics, commands, test output, evidence objects, hashes,
timestamps, repository/commit identifiers, environment values, or arbitrary
unknown fields. Unapproved policy-version values are never hashed or copied;
they are counted only as `other`.

## Operational boundaries

- This is an aggregation utility, not a record verifier, admission decision,
  monitoring service, or exporter.
- Its denominator is the set of existing record files supplied to the command.
  It does not know how many runs were attempted and therefore cannot detect a
  missing terminal record or calculate terminal-decision availability.
- It does not ingest finalizer, publisher, object-retention, or orchestration
  events. It cannot measure end-to-end decision latency, finalizer/publisher
  failure rates, or evidence-retention lag. The reported latency is only the
  runtime-tree identity measurement described above.
- Keep raw verdict records under the evidence retention/access policy. The tool
  does not delete or modify them.
- Aggregates can still reveal operational posture when the sample is tiny.
  Apply normal access control before sharing them and combine enough runs for
  the intended audience.
- Review a generated JSON file before moving it outside the trusted
  environment. The implementation has no automatic network transmission.

## Production integration still required

This utility does not close the operational telemetry production gate. A
production orchestrator or append-only event stream must independently provide:

- an authoritative inventory of expected run and attempt identities;
- timestamps and terminal states for decision, finalization, publication, and
  required evidence retention;
- a fail-closed join from each expected attempt to one verified verdict record
  and its retained evidence objects;
- explicit detection of missing, duplicate, late, or contradictory events; and
- an operator-reviewed export and alert path using only approved
  low-cardinality dimensions.

That external source must be deployed and exercised against the actual CI,
finalizer, publisher, and evidence store. Until then, availability, end-to-end
latency, publication failure, and retention-lag SLOs remain unmeasured; this
local record summary must not be used as evidence that those SLOs are met.
