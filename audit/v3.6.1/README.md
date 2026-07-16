<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# EvoOM Guard v3.6.1 security-review companion

This directory is a **review aid**, not part of the frozen executable target.
The target is the immutable [v3.6.1 release][release], resolved to commit
`23c388773581e65501e733f88d158113e0095830`.  Its only release assets are
`evo-guard.pyz` and `SHA256SUMS`; their expected values are in
[`manifest.json`](manifest.json).

Do not use `main`, an unpinned release tag in a workflow, or this directory's
future contents as a substitute for verifying the target artifact.  A reviewer
must verify the immutable release first.

[release]: https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v3.6.1

## Start here

On Linux/WSL with GitHub CLI, Git, `sha256sum`, and Python 3.10 or newer:

```bash
bash audit/v3.6.1/reproduce.sh /tmp/evoguard-v3.6.1-review
```

On Windows PowerShell with GitHub CLI, Git, and Python:

```powershell
& .\audit\v3.6.1\reproduce.ps1 -OutputDirectory "$env:TEMP\evoguard-v3.6.1-review"
```

Each script does only the following:

1. verifies GitHub's release attestation with `gh release verify`;
2. downloads the two immutable assets and checks their exact SHA-256 values,
   sizes, and `SHA256SUMS` content;
3. clones the source by the fixed tag and checks its resolved commit; and
4. runs the released zipapp's `version` and `doctor` commands.

The scripts do not accept a candidate repository, do not download workflow
artifacts, and do not need a signing key.

## Review scope and evidence

Use [`TEST_MATRIX.md`](TEST_MATRIX.md) as the direct map from the requested
security properties to regression suites, runtime requirements, and manual
adversarial work.  The requested external review remains [issue #76][issue].
The test suite is developer-authored regression evidence; passing it is not an
independent security assessment and does not establish a field false-positive
or false-negative rate.

The separate Trusted Finalizer pilot is operational evidence only.  Its
published runs exercise a source-only ALLOW, a trust-root DENY, and a new
source-only ALLOW after governance maintenance, but its reviewer accounts have
the same owner.  It must not be represented as independent review.

[issue]: https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues/76

## Known reproducibility gap

The release executable is independently hash-verifiable, but the full source
test environment is **not yet dependency-locked**: `pyproject.toml` currently
uses version ranges for the `dev` extra, and the Docker E2E jobs use image tags
whose digests are not captured here.  Therefore this command is useful for a
developer regression replay but is **not** a byte-for-byte reproduction of the
historical release test environment:

```bash
python -m pip install -e ".[dev]"
python -m pytest tests/ -q
```

Before treating a rerun as reproducible, create and review a Python-3.12 Linux
lock with hashes, for example:

```bash
python -m pip install "pip-tools==7.5.0"
python -m piptools compile --extra dev --generate-hashes \
  --output-file audit/v3.6.1/requirements-py312-linux.lock pyproject.toml
```

Then capture the exact digest of every Docker image used by the Docker lane and
record both the lock-file SHA-256 and image digests in a reviewed manifest.
Those future files must be separately pinned; they cannot retroactively become
part of the immutable v3.6.1 release.

## Reporting a finding

Use the private reporting channel in [`SECURITY.md`](../../SECURITY.md).  A
useful report identifies the release asset SHA-256, source commit, OS, Python
version, Docker/image digest when applicable, exact commands, raw record or
evidence hashes, observed versus expected result, minimal proof of concept,
impact, and suggested fix.

The source-available license permits reading, studying, running, and internal
modification.  If a proposed proof of concept needs public redistribution of a
modified copy, ask the maintainer for written permission before publishing it.
This companion does not add a legal safe-harbor.
