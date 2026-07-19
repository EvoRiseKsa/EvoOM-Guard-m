# Third-party materials and dependency inventory

The EvoRise Source-Available License applies only to material that the
Licensor has the right to license. This inventory is a release gate, not a
substitute for checking the exact upstream terms and notices.

| Path / component | Upstream / origin | Version or source | License / governing terms | Notes |
| --- | --- | --- | --- | --- |
| `examples/case-study-charset-normalizer/fixtures/test_eq_regression.py` | `charset-normalizer` | Upstream `3.4.0` regression test; see `docs/CASE-STUDY.md` | MIT | Upstream-derived fixture; retain upstream attribution and do not add a proprietary source header. |
| `examples/case-study-charset-normalizer/candidates/1-honest-fix.txt` | `charset-normalizer` | Patch fixture representing the published `3.4.0` resolution of the `3.3.2` bug | MIT | Derived patch material; see `docs/CASE-STUDY.md`. |
| `examples/case-study-charset-normalizer/` run material | `charset-normalizer` | `3.3.2` sdist fetched at run time | MIT | The sdist is not vendored in this repository; its digest and source are recorded in the case-study documentation. |
| Optional development/test dependencies | Python packages declared in `pyproject.toml` and lock files | `cryptography`, `coverage`, `pytest`, `ruff`, `mypy`, `jsonschema` | Each dependency's own license | Not part of the stdlib-only runtime; review the locked dependency set before a release or customer delivery. |
| `tools/ci-vitest/` | Vitest and npm transitive dependencies | `vitest` `4.1.10` and `package-lock.json` | Each package's own license | Development tooling only; the lockfile is the authoritative dependency inventory. |
| GitHub Actions and hosted runners | `actions/*`, `github/*`, hosted runner images | Exact commit SHAs in workflow files | Each provider's terms/license | Workflow references are deliberately pinned. They are not first-party EvoOM source. |
| Python container image | Docker/OCI `python:3.12-slim` | Digest pinned in policy/workflows | Image and component notices apply | Used only where the configured isolation model selects it. |

## Rules

- A file carrying another explicit notice is governed by that notice for that
  file.
- Do not attach an EvoRise SPDX identifier or proprietary header to
  third-party-derived material unless the Licensor owns the applicable rights.
- Before v4 publication, reconcile this table against the exact source tree,
  lockfiles, generated assets, and any new corpora, fixtures, or candidate
  changes.
- Preserve required upstream copyright, attribution, patent, and license
  notices.
