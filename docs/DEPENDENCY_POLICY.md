<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# CI and release dependency-integrity policy

## Scope

EvoOM Guard's product runtime is standard-library-only: the package declares
`dependencies = []`. This policy does **not** claim that a consumer's runner,
interpreter, package installer, or network is trusted. It defines the narrower
rule for this repository's trusted CI and release workflows: their test and
build tooling must be resolved from reviewed, byte-checked inputs rather than
from open version ranges at workflow time.

## Python tooling

`requirements/ci.in` is the small, human-reviewed source declaration for the
build backend, the `dev` tools declared in `pyproject.toml`, and the exact
`tomli` compatibility parser imported by distribution tooling on Python 3.10.
`requirements/ci.lock` is generated from it with `pip-compile` on Python 3.10,
contains every transitive package and SHA-256 hash, and is the only Python
tooling input used by the CI and release workflows. Those workflows install it
with:

```bash
python -m pip install --only-binary=:all: --require-hashes -r requirements/ci.lock
python -m pip install --no-deps --no-build-isolation -e .
```

The first command permits only binary distributions, so a missing reviewed
wheel fails closed instead of building an sdist and executing its backend. The
second command installs this checkout only after the locked toolchain is
present; `--no-deps --no-build-isolation` prevents a second resolver or an
unlocked build-isolation environment. The lock is generated under the lowest
supported CI interpreter and is checked under Python 3.10 and 3.12 before a
change is accepted. The workflow matrix also exercises Python 3.11.

To intentionally update CI tooling, edit `requirements/ci.in`, regenerate the
lock with the reviewed generator version, and review the complete lock diff:

```bash
python3.10 -m pip install "pip-tools==7.5.3"
python3.10 -m piptools compile --allow-unsafe --generate-hashes \
  --strip-extras --output-file=requirements/ci.lock requirements/ci.in
```

The Docker black-box test image has a smaller independent input:
`requirements/docker-pytest.in` and its hash-locked
`requirements/docker-pytest.lock`. It is installed by the Dockerfile with
`--only-binary=:all:` and `--require-hashes`.

Python 3.10's immutable-parent validation also uses the narrow
`requirements/python310-compat.in` input and its independently hash-locked
`requirements/python310-compat.lock`. Dependabot is intentionally configured
not to update `importlib-resources`: it can edit the source declaration but
cannot regenerate and review the corresponding multi-wheel hashes. A maintainer
must update the declaration and lock together, run the Python 3.10 parent
validator tests, and review every resolved artifact before accepting a new
version. This is a manual integrity boundary, not a claim that the frozen
version should never change.

## Node tooling and Docker image

Vitest is a CI-only runner, not a product dependency. Its exact direct version
is declared in `tools/ci-vitest/package.json`; the committed npm v3 lockfile
contains integrity values for all resolved packages. CI uses:

```bash
npm ci --ignore-scripts --prefix tools/ci-vitest
```

`--ignore-scripts` removes package lifecycle hooks from this installation. The
black-box Docker base uses a reviewed immutable OCI index digest, not the
mutable `python:3.12-slim` tag. Both the workflow and
`ops/ci/docker/evoguard-e2e-pytest.Dockerfile` must keep the same digest.

## Deliberate boundary for Action consumers

In the ledger-recorded `v4.6.0` release, `action.yml` builds the reviewed
standard-library-only sources from `github.action_path` into a temporary
`evo-guard.pyz`, then runs that archive with Python isolated mode. The Action
bootstrap does not invoke a package resolver, build backend, or PyPI.

Optional changed-line measurement is deliberately not installed by the Action.
When a policy requests it, `coverage.py` must already be available in the
normal site-packages of the same Python 3.12 environment selected by the
Action; isolated mode does not load user-site packages. Missing advisory
coverage is recorded as `measured: false`. A configured minimum is a
requirement, so missing coverage fails closed with `ERROR`.

This is a resolver-free **bootstrap**, not a zero-network Action. The pinned
`setup-python` action may obtain an interpreter, a shallow checkout may fetch a
missing base object, and the consumer's own setup or test command may use the
network. The candidate-execution job does not post PR comments; a separately
designed metadata-only reporter may call GitHub. Consumers who need a fixed
Action revision should pin the Action itself to a release tag or full commit
SHA and manage the runner and optional coverage environment separately.
The temporary Action-built archive is also not a claim of same-user
anti-tampering between composite steps.

## Remaining limits

Hash locks verify a downloaded package's bytes; they do not independently
audit PyPI/npm publication, GitHub-hosted runner images, the installed Python
or npm client, Docker Hub's availability, or a maintainer-approved lock update.
All GitHub Actions in this repository are separately pinned to full commit
SHAs. After dependency changes are merged, the OpenSSF Scorecard result must be
re-run against the merged `main` commit and any remaining findings recorded
accurately rather than suppressed.
