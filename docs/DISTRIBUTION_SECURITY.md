<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see ../LICENSE for permitted use.
-->

# Distribution security

## One distribution, one release channel

EvoOM Guard currently has one complete Python distribution named
`evoom-guard`. It is dual-licensed by path under [`../LICENSING.md`](../LICENSING.md).
The consumer release channel remains the immutable GitHub Release containing
`evo-guard.pyz`, its SPDX inventory, and `SHA256SUMS`; the project is not
published on PyPI.

CI also builds the complete `evoom-guard` wheel as a **QA artifact only**. The
wheel is not uploaded, published, advertised as another edition, or installed
beside a second EvoOM distribution. Its purpose is to continuously audit the
packaging path used by Git/VCS installs.

A separate `evoom-guard-core` wheel is deliberately deferred. The current core
and platform share the `evoom_guard` import package and `evo-guard` console
script; publishing both would give two distributions ownership of the same
installed files. A core-only wheel may be reconsidered only after it has a
non-overlapping import namespace, console entry point, metadata identity, and
documented migration/coexistence contract.

## Resolver-disabled, locked build contract

CI first installs `requirements/ci.lock` with `--require-hashes` and then runs:

```bash
python -I tools/packaging/build_distribution.py \
  --output-dir "$RUNNER_TEMP/evoom-distribution-qa" \
  --reproducibility-check --verify
```

The builder requires the installed `setuptools` version to equal the exact pin
in that lock. The staged `pyproject.toml` must also name exactly
`setuptools.build_meta`, omit `backend-path`, and require that same exact
`setuptools==83.0.0` pin. The backend build runs with build isolation disabled
only after those checks, and with `PIP_NO_INDEX=1`, an empty pip configuration,
pip's `--isolated` mode, `--no-index`, `--no-cache-dir`, and `--no-deps`. The
subprocess environment is rebuilt from a small portable system/temporary-path
allowlist; it does not inherit home or user-profile paths, Python/pip/backend
selectors, or arbitrary caller variables. Both the pip parent and its PEP 517
child disable user-site imports and unsafe path prepending. Verification
installs only the locally built wheel into a fresh virtual environment with the
same controls. It does not install `pytest`; the smoke explicitly proves that
`pytest` is absent before exercising imports, `version`, and `doctor`.

These controls disable pip index/config/cache resolution; they are **not** an
operating-system network sandbox or an egress firewall. The CI runner may still
have network access, and this procedure makes no network-isolation claim.

This binds the backend used by the wheel to the hash-locked CI dependency set.
The Python interpreter, bundled pip frontend, operating system, and standard
library remain part of the recorded CI runner boundary; the procedure does not
claim a hermetic compiler or independently reproduced build.

## Exact-byte wheel audit

The build uses a separately validated staging tree and fails closed unless:

- every package member is a byte-exact copy of staging;
- the package and `.dist-info` member sets are exact, sorted, and duplicate-free;
- all four governing documents are exact staged bytes;
- the complete raw `METADATA` bytes and closed header set, `WHEEL`, the console
  entry point, top-level package, package identity, version, dependencies,
  extras, and license classifier match the reviewed contract;
- every non-`RECORD` member has the correct `sha256` digest and byte size in
  `RECORD`, while `RECORD` has the required empty self-hash fields;
- archive paths are safe regular files and the complete raw ZIP bytes equal the
  one canonical re-encoding, leaving no hidden inter-record padding, member,
  comment, ZIP trailer, or appended payload.

The final wheel is rewritten with lexicographic member order, the fixed ZIP
timestamp `1980-01-01T00:00:00`, fixed regular-file mode, no per-member extra
metadata, `ZIP_STORED`, and a canonical LF-only `RECORD`. Two builds from two
independent staging trees must be byte-identical. Tests separately prove that
the auditor rejects a modified member with a stale `RECORD`, a modified member
with a recomputed `RECORD`, an extra hidden member, hidden ZIP padding, and an
unknown `METADATA` field even when its `RECORD` entry is recomputed.

## Exact-byte zipapp audit

`ops/build_pyz.py` snapshots every staged member once, writes only that snapshot,
and audits the completed archive before atomically replacing its output. The
audit binds the exact member bytes and set, canonical order/timestamp/mode,
empty ZIP metadata, and the complete raw canonical encoding. All four governing
documents (`LICENSE`, `LICENSE-APACHE`, `LICENSING.md`, and `NOTICE`) are
mandatory members with canonical text bytes; none may be silently omitted. An
existing archive can be checked against the current source without executing it:

```bash
python -I ops/build_pyz.py --audit dist/evo-guard.pyz
```

This is distribution-integrity evidence. It does not establish vulnerability
absence, independent security review, correctness of the selected judge, or
authorization to publish a release.
