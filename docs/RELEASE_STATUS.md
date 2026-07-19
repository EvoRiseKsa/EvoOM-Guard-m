---
source_version: 4.0.0
latest_published_version: 3.8.0
state: pre-release
---

# Release status

The repository source currently declares **v4.0.0**, which is a prepared
release candidate and is **not yet a published GitHub Release**. Until v4.0.0
is published, the latest immutable consumer release is
[`v3.8.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v3.8.0).

Do not install, pin, or describe `v4.0.0` as released until the immutable tag,
GitHub Release assets, checksum, and provenance for that exact version have
been created and inspected. After publication, update this file and all
consumer-facing installation examples in the same reviewed follow-up.

While this source state is pre-release, `evo-guard init` deliberately writes
the latest published action ref, `v3.8.0`, rather than a nonexistent `v4.0.0`
tag. A caller may supply `--ref` only for an existing, independently inspected
ref.

Historical releases retain the license and notices that shipped with them. The
EvoRise Source-Available License 1.0 applies only to material first distributed
with a published v4 release carrying that license.
