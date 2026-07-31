# Blast Radius V1

Blast Radius V1 is a deterministic description of change size and exposure. It
counts touched paths and changed lines, marks configured protected-path hits,
and projects those measurements to a bounded score and a `low`, `medium`, or
`high` level.

It is **advisory metadata**. It is not a probability of vulnerability,
maliciousness, correctness, regression, or production failure, and Guard does
not use it to decide `PASS`, `REJECTED`, `FAIL`, `ERROR`, or `TAMPERED`.

## Compatibility names

The Python names `BlastRadiusScore` and `blast_radius_score` are exact identity
aliases for the historical `RiskScore` and `risk_score` V1 API. The signed
verdict fields remain `risk_level` and `risk_score`. The aliases do not change
the measurement contract or the schema-1.11/1.12 wire format.

## Accepted inputs

`blast_radius_score`/`risk_score` accepts either:

1. a precomputed `{path: (lines_added, lines_removed)}` mapping; or
2. a string in the limited unified-diff subset described below.

The mapping form is the reliable V1 integration boundary. Paths must be
caller-trusted, normalized, repository-relative strings. Counts must be
non-negative integers; booleans, floats, non-finite numbers, malformed tuples,
and negative counts are rejected rather than allowed to violate the documented
`0..1` score range. V1 does not perform repository path-safety validation.

For default thresholds, the projection is:

```text
files_term     = min(1.0, files_touched / 8)
lines_term     = min(1.0, (lines_added + lines_removed) / 200)
protected_term = 0.25 when at least one protected path is hit, otherwise 0.0
score          = min(1.0, 0.5 * files_term + 0.5 * lines_term + protected_term)
```

The level is `high` for a protected hit, at least 8 paths, or at least 200
changed lines; `medium` for at least 3 paths or 40 changed lines; otherwise it
is `low`. Callers can change those thresholds through the Python API.

## Limited raw unified-diff parser

The V1 string parser is a compatibility convenience, not a strict Git-diff
validator. It follows the `+++` destination header, strips one leading `a/` or
`b/`, and counts following `+` and `-` content lines. Its known boundaries are:

- a pure deletion targets `+++ /dev/null`, so the old path and removed lines
  are not represented;
- header-only rename, copy, and mode-only changes are not represented;
- binary diff markers are not rejected by this API and can yield an empty
  `low`/`0.0` measurement;
- Git C-quoted or escaped paths are not decoded before matching protected
  globs;
- malformed input is not rejected reliably and can be partially counted; and
- a content line whose diff representation begins with `+++` or `---` can be
  mistaken for a file header.

Consequently, do not use the raw-string V1 API as a parser, path-safety gate, or
security decision over untrusted diff text. Derive a complete mapping from
trusted base/head material when deletion-aware measurement matters.

## Guard orchestration

Guard does not normally score its materialized candidate by sending the raw
unified diff to this parser. It builds a structured mapping for additions and
modifications and completes missing deletion entries from the trusted base
file before scoring. This is why a Guard run can count a deletion that the
direct raw-string V1 API cannot.

Some failures happen before a candidate can be represented completely. Such
pre-materialization errors can retain the compatibility `low`/`0.0` default;
that value does not claim that the rejected input had a small blast radius.

## V2 boundary

A deletion-aware V2 is tracked in
[#268](https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues/268). It requires a
versioned materialized-change contract, explicit rename/copy/mode/binary and
quoted-path behavior, golden vectors, and parity with Guard. V1 will not be
changed silently to approximate that contract, and schema 1.11/1.12 will not be
reinterpreted in place.
