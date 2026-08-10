# Blast Radius contracts

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

## Materialized Change V2 (unreleased development source)

Development source after `v4.5.0` adds a separate, additive contract with the
identity `EVOGUARD_BLAST_RADIUS_V2`. It is not a patch to the V1 raw-diff
parser. The public entry points are dependency-free domain contracts:

```python
from evoom_guard.domain import blast_radius_score_v2

measurement = blast_radius_score_v2(
    {
        "format": "EVOGUARD_BLAST_RADIUS_V2",
        "changes": [
            {
                "operation": "delete",
                "old_path": "src/retired.py",
                "new_path": None,
                "lines_added": 0,
                "lines_removed": 73,
                "binary": False,
            }
        ],
    },
    protected=("src/retired.py",),
)
```

`blast_radius_score_v2` accepts only a validated materialized-change object or
`MaterializedChangeSetV2`. Passing raw diff text, a Git header token, or a
partial mapping is an error. `canonical_materialized_change_v2_bytes` emits the
canonical UTF-8 JSON representation. The packaged JSON Schema is
`evoom_guard/schemas/blast-radius-materialized-change-2.schema.json`; runtime
validation is authoritative for NFC, UTF-8 byte bounds, path equality,
cross-platform case collisions, aggregate limits that JSON Schema cannot
express completely, and a two-million path/glob comparison ceiling. The last
bound rejects an otherwise valid but quadratic protected-path scan before the
scan begins.

### Operation semantics

The caller must derive each record from trusted base/head material. Counters
are explicit non-negative 64-bit signed-range integers; booleans are not
integers. A materialized set contains at most 10,000 net changes.

| Operation | Required paths | Counted affected paths | Line-counter meaning |
|---|---|---:|---|
| `add` | new only | new (1) | full new text lines added; removed is zero |
| `modify` | identical old/new | path (1) | exact text diff additions/removals |
| `delete` | old only | old (1) | full old text lines removed; added is zero |
| `rename` | distinct old/new | old and new (2) | full new text lines added plus full old text lines removed |
| `copy` | distinct source/destination | destination (1) | full destination text lines added; source is provenance, not a modified path |
| `mode` | identical old/new | path (1) | both counters are zero |

A binary record sets `binary=true` and both line counters to zero. It still
contributes its affected path and increments `binary_changes`; V2 does not
pretend that zero lines means zero bytes or infer a binary-size metric it was
not given. A mode-only record similarly contributes one affected path and
increments `mode_only_changes`.

Rename counts two paths because the old namespace entry disappears and the new
entry appears. Copy counts only its destination because the source entry is not
changed. Protected-glob matching follows the same affected-path rule, so a copy
source is not a protected hit while both sides of a rename can be hits.

### Paths and quoted Git output

V2 paths are already decoded repository paths, not raw Git presentation
tokens. They must be NFC-normalized, portable, forward-slash,
repository-relative paths without controls, format characters, Git
administrative segments, aliases, `.`/`..`, empty segments, or case-colliding
affected spellings. For example, the decoded path `docs/café guide.md` is
accepted. A C-quoted token such as `"docs/caf\303\251.md"` is rejected; the
trusted materializer must decode and verify Git bytes before constructing V2.
This avoids treating escape syntax as a real filename and avoids guessing when
raw output is incomplete.

Case-only renames and other platform-ambiguous names are deliberately
unsupported by this portable contract. That is a fail-closed portability
boundary, not a claim that Git itself cannot store such names.

### Measurement and compatibility

For text changes the default score projection retains the V1 formula so the
same explicit add/modify/delete materialization produces the same measured
fields in the direct V2 API and current Guard orchestration. Unlike V1, all four
thresholds must be positive, medium thresholds cannot exceed high thresholds,
and protected patterns are validated.

The V2 result has the distinct identity `EVOGUARD_BLAST_RADIUS_SCORE_V2` and
adds operation, binary, and mode-only counts. It remains advisory change-size
metadata, not a probability or an admission decision. Existing
`risk_score`/`blast_radius_score`, `RiskScore`/`BlastRadiusScore`, signed
`risk_level`/`risk_score` fields, and verdict schemas 1.11/1.12 are unchanged.
Guard does not silently write V2 fields into those signed records.

### Migration

1. Keep V1 for consumers that require the frozen API or signed verdict shape.
2. Materialize base and head with a trusted repository reader. Do not feed raw
   `git diff` text to V2.
3. Emit one explicit net operation per affected path using the table above;
   provide full old/new text counts for delete, rename, and copy.
4. Validate the object, retain its canonical bytes when evidence continuity is
   needed, and call `blast_radius_score_v2`.
5. Treat the V2 result as a separate advisory measurement until a future
   versioned verdict schema explicitly binds it.

Golden vectors cover add, modify, delete, rename, copy, mode-only, decoded
Git-quoted Unicode paths, binary changes, and malformed input. Focused parity
and mutation tests prevent unsupported input from degrading into a partial
`low` measurement. Issue
[#268](https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues/268) records the
design history.
