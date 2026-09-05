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
| `tools/ci-live-runners/node/` | Jest, `jest-junit`, Mocha, and npm transitive dependencies | Jest `30.5.1`, `jest-junit` `17.0.0`, Mocha `12.0.0`, and npm v3 lock | Each package's own license | Extended conformance tooling only; installed with lifecycle scripts disabled. The lockfile integrity fields are the reviewed dependency inventory. |
| `tools/ci-live-runners/go/` | gotestsum and Go module dependencies | Go `1.27.1`, gotestsum `1.13.0`, `go.mod`, and `go.sum` | Each module's own license | Extended conformance tooling only; modules are downloaded and verified before the exact tool is built. |
| `tools/ci-live-runners/ruby/` | RSpec, `rspec_junit_formatter`, and RubyGem dependencies | RSpec `3.13.2`, formatter `0.6.0`, Ruby `3.4.10`, Bundler `4.0.20`, and checksum-bearing `Gemfile.lock` | Each gem's own license | Extended conformance tooling only; frozen installation uses the reviewed lock and gem checksums. |
| `tools/ci-live-runners/maven/` | Apache Maven, JUnit, Maven plugins, and Maven repository dependencies | Maven `3.9.16`, JUnit `5.14.0`, compiler plugin `3.14.1`, Surefire `3.5.6`, and exact 160-file JAR/POM SHA-256 inventory | Each component's own license | Extended conformance tooling only. Maven itself is not vendored; its downloaded ZIP is checked against the policy SHA-512. A fixed-origin stdlib fetcher verifies every repository artifact against `artifacts.sha256` before any Maven plugin executes, and all Maven runs are offline. The fixture POM carries the explicit `evoguard.surefire.reportsDirectory` compatibility bridge; this is not generic Maven support. |
| `.github/workflows/runner-live-conformance.yml` | [`ruby/setup-ruby`](https://github.com/ruby/setup-ruby) | Upstream `v1.321.0`, commit `95ef2b042f9d7a56d8268cba8559e2842e2ad01b` | MIT; Copyright Benoit Daloze | Extended conformance setup only. The workflow uses the exact full SHA. A repository using GitHub's selected-actions policy must separately admit `ruby/setup-ruby@*`; that admission does not relax the workflow pin. |
| GitHub Actions and hosted runners | `actions/*`, `github/*`, hosted runner images | Exact commit SHAs in workflow files | Each provider's terms/license | Workflow references are deliberately pinned. They are not first-party EvoOM source. |
| Python container image | Docker/OCI `python:3.12-slim` | Digest pinned in policy/workflows | Image and component notices apply | Used only where the configured isolation model selects it. |
| `tests/schema/spdx-2.3.schema.json` and its license/notice | [`spdx/spdx-spec`](https://github.com/spdx/spdx-spec) | Official `v2.3`, commit `aadf3b0b8dbbabdb4d880b0fc714255fea436ff7`, schema blob `ee61e6686e885f8139c132647fd0b4f483b8fb81` | Creative Commons Attribution 3.0 Unported | Unmodified test-only schema; exact upstream license and provenance are retained beside it. It is not packaged in the runtime. |

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
