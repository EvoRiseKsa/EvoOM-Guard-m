<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# Candidate Text Map Identity V2

This document defines the normative byte framing used by
`EVOGUARD_CANDIDATE_TEXT_MAP_V2`. It is independent of Python and of the
historical human-readable FILE-block serialization.

## Input domain

The input is a finite map from Unicode path strings to Unicode content strings.
Every string must encode with strict UTF-8. No Unicode normalization, newline
conversion, case folding, path rewriting, or locale-dependent comparison is
performed.

## Canonical framing

The output is the following concatenation:

```text
ASCII("EVOGUARD_CANDIDATE_TEXT_MAP_V2")
00
U64BE(entry_count)
for each entry sorted lexicographically by its UTF-8 path bytes:
    ASCII("F")
    U64BE(path_utf8_byte_length)
    path_utf8_bytes
    U64BE(content_utf8_byte_length)
    content_utf8_bytes
```

`U64BE` is one unsigned 64-bit integer encoded in exactly eight bytes,
most-significant byte first. Lengths count bytes, not Unicode characters. The
literal `F` is one byte (`0x46`). The `00` after the ASCII domain is one NUL
byte. Empty maps and empty content values are valid; empty paths are representable
by this framing but are rejected by higher-level Agent Change path policy.

The entry count, per-entry tag, and byte lengths make the framing unambiguous
over valid input maps. The published identity is:

```text
format     = EVOGUARD_CANDIDATE_TEXT_MAP_V2
sha256     = lowercase hex SHA-256(framed_bytes)
size       = len(framed_bytes)
file_count = entry_count
```

Framing unambiguity and SHA-256 collision resistance are separate assumptions;
the digest is not claimed to be mathematically injective.

## Compatibility and authority

V1 FILE-block bytes and digests remain unchanged. V2 raw-Git bindings retain
the V1 Guard digest and size only to bind the existing execution/finalizer
context and its signed byte limit. Neither legacy value is V2 proposal identity.
V2 generation must be requested explicitly; V1 remains the default public API
and CLI generation.

The machine-readable cross-language vectors are in
[`candidate-text-map-v2.json`](vectors/candidate-text-map-v2.json). An
implementation must reproduce every `framed_hex`, `sha256`, `size`, and
`file_count` value byte-for-byte.

## Agent Change candidate-selection profile

The identity primitive accepts any finite path-to-text map. Agent Change V2
binds the separate literal profile
`EVOGUARD_AGENT_CHANGE_CANDIDATE_SELECTION_V1` so the choice of map members is
not an implicit implementation detail.

For this profile, every tracked path changed in the head is selected except a
path containing a segment exactly equal to one of:

```text
.git, __pycache__, .venv, venv, node_modules, .evo_runs,
.pytest_cache, .mypy_cache, dist, build
```

An ignored path remains present in the complete changed/touched arrays and in
authorization checks; it is excluded only from the Guard text map. Every
selected changed path must be a regular Git blob, must not make a mode/type
transition from an existing base path, must satisfy the bounded file and
aggregate byte limits, and must decode as strict UTF-8. Otherwise derivation
fails closed. A deletion-only change selects an empty map.

The profile limits are exact: at most 10,000 complete tracked change paths and
10,000 selected changed paths; at most 1,048,576 bytes per selected Git blob;
at most 67,108,864 aggregate selected blob bytes; at most 67,108,864 framed
identity bytes; and at most 67,108,864 legacy Guard serialized bytes. Counts
and sizes are integers, and byte limits count raw blob/framing bytes as stated,
not Unicode scalar values.

All V2 path arrays use unsigned lexicographic order of strict UTF-8 path bytes,
with no normalization, locale comparison, or UTF-16 code-unit ordering. The
schema checks their structure; authoritative runtime validation enforces this
canonical order and the selection-profile relationships.
The companion machine-readable vectors are in
[`agent-change-candidate-selection-v1.json`](vectors/agent-change-candidate-selection-v1.json).
