# Runner adapter conformance

The runner conformance kit is a deterministic, offline check of EvoOM Guard's
command-instrumentation contract. It imports each adapter owner, feeds it known
commands, and compares the complete observed `argv` and report environment with
versioned expectations. It does not invoke pytest, Node, Vitest, Jest,
gotestsum, RSpec, Mocha, Maven, or a shell test suite.

## Run

From the repository root, choose a new output path:

```console
python -m tools.conformance.run_runner_conformance \
  --output runner-conformance.json
```

Results are create-only. The command refuses to replace an existing path, so a
previous result cannot be silently rewritten.

Verify a retained result against the trusted manifest and current source:

```console
python -m tools.conformance.run_runner_conformance \
  --verify runner-conformance.json
```

Verification rejects unknown fields, stale source digests, changed manifest
bytes, case/registry mismatches, contradictory PASS values, and inconsistent
summaries. It re-runs the offline adapter contract; it does not re-run optional
external tool-version discovery.

The `e2e-runners` CI job creates the result in runner temporary storage,
verifies that exact file, and retains it as an artifact for 30 days. That
artifact remains unsigned and workflow-produced; retention does not turn it
into independent evaluation or a release-ledger binding.

The optional discovery mode runs only each owner's bounded `--version` command:

```console
python -m tools.conformance.run_runner_conformance \
  --discover-tools \
  --output runner-conformance-with-versions.json
```

Discovery records each tool as `observed` with a parsed version or
`unsupported` with a bounded reason. It is non-gating. Missing tools, nonzero
version commands, timeouts, excessive output, and unparseable versions never
become PASS. A version observation does not prove that a suite was executed or
that the adapter works with that external version.

## What the offline result checks

The checked-in v1 manifest covers all nine adapter owners:

- the Shell wrapper;
- pytest;
- Node `--test`;
- Vitest;
- Jest;
- gotestsum;
- RSpec;
- Mocha;
- Maven.

Every owner has known accept, mismatch, and Windows-path cases. Every owner
whose contract can decline caller-owned reporter configuration has a known
decline case. Shell cases cover final-segment instrumentation, fixed-position
Node flags, embedded Jest report environment, and decline without registry
fall-through. Separate registry cases bind Shell-first order, the eight-owner
inner order, selected owner, unknown-command behavior, and exact output.

The canonical manifest currently produces 51 offline checks: nine owner
identity checks, one registry-order check, 37 owner cases, and four registry
dispatch cases.

## Evidence and claim boundary

Each result binds:

- the source manifest SHA-256;
- EvoOM Guard and kit versions;
- Python implementation/version and bounded OS facts;
- Git commit and dirty-state observation;
- repository-relative source-file sizes and SHA-256 digests, plus an aggregate
  source digest;
- exact expected and observed `argv`/environment for every case.

The JSON intentionally uses logical repository paths and the logical `python`
launcher. It does not publish the workspace, home directory, Python executable,
username, or hostname.

`status=pass` has one meaning: the imported adapter implementation matched the
offline v1 contract in that run. The result states
`status_basis=offline_adapter_contract_only` and always records:

```json
{
  "offline_adapter_contract_executed": true,
  "external_runner_suites_executed": false,
  "multi_os_real_runner_matrix_published": false
}
```

The separate `Runner live conformance` workflow complements this offline kit.
Its `live` job executes real Guard PASS/FAIL oracles for pytest, Node `--test`,
and Vitest, plus a protected-test tamper/rejection oracle for pytest, against
Node 22 and the locked Vitest version on Ubuntu (Python 3.10/3.11/3.12) and
Windows (Python 3.12). Every core cell must execute the exact 13 reviewed oracle
tests with zero skips, failures, or errors. Pytest third-party plugin autoload
is disabled. Each cell writes a create-only
`evoguard-live-runner-conformance-v1` JSON record bound to the exact JUnit
bytes, reviewed source subset, complete Git commit/tree, installed Python
package-inventory digest, tool versions, GitHub-hosted runner image/architecture,
workflow SHA, run, and attempt and verifies it immediately.

The workflow also defines an `extended` job with exactly two cells:

- `ubuntu-latest`, Python 3.12.10;
- `windows-latest`, Python 3.12.10.

Each extended cell runs the same reviewed 18-oracle set for Jest, gotestsum,
RSpec, Mocha, Maven, and Shell. The set contains explicit JUnit parsing,
honest-fix PASS, and broken-fix FAIL checks for each structured owner; Jest also
has a protected-test rewrite rejection oracle, while Shell has no JUnit parser
case. A skip, collection failure, test failure, missing executable, version
mismatch, or missing environment binding fails the cell.

Maven live conformance is an explicit project opt-in. Surefire does not expose
its `reportsDirectory` parameter as a generic Maven CLI user property. A
supported POM must define `evoguard.surefire.reportsDirectory` with its ordinary
default and map
`<reportsDirectory>${evoguard.surefire.reportsDirectory}</reportsDirectory>` in
the Surefire configuration. The adapter supplies only the namespaced
`-Devoguard.surefire.reportsDirectory=<judge-path>.d` override. The checked-in
Maven fixture contains that bridge. Without it, no judge-owned report appears
at the required path and Guard fails closed; neither offline adapter matching
nor a result from the bridged fixture is a generic Maven-project support claim.

The extended runtime is configured for exact Python 3.12.10, Node 22.23.2, Go
1.27.1, gotestsum 1.13.0, Ruby 3.4.10, Bundler 4.0.20, RSpec 3.13.2,
`rspec_junit_formatter` 0.6.0, Temurin 21.0.9+10 (reported Java 21.0.9), Maven
3.9.16, Jest package 30.5.1 (reported CLI 30.5.0), `jest-junit` 17.0.0, and
Mocha 12.0.0. Bash is the runner-provided executable at `/usr/bin/bash` on
Ubuntu or the Git for Windows path; its actual GNU Bash version is observed and
bound into the cell result rather than represented as a dependency lock.

Each extended cell writes a create-only
`evoguard-live-runner-extended-conformance-v1` record. The verifier requires the
exact 18 test names and zero skips, failures, or errors; exact tool versions;
the reviewed source inventory; the JUnit digest; the complete Git commit/tree;
the installed Python inventory; and GitHub workflow, runner-image, run, and
attempt identity. A fixed-origin stdlib downloader fetches Maven JAR/POM bytes
without executing Maven, rejects redirects, and verifies all 160 reviewed paths
and SHA-256 values in `tools/ci-live-runners/maven/artifacts.sha256` before the
offline fixture smoke run or any offline Maven oracle executes. The result binds
the downloader, manifest, and workflow source but does not embed the cache or
claim independent Maven Central provenance. Maven `-o` disables resolver
downloads; it is not a network sandbox for plugin code.

Both jobs upload only their JSON/JUnit pair, validate the immutable numeric
artifact ID and digest, download that exact artifact with digest mismatch
configured as fatal, and semantically re-verify the downloaded bytes. Artifacts
are retained for 30 days. The stable aggregate check
`runner-live-conformance` requires every core and extended cell.

This checked-in configuration is not itself evidence that a GitHub run has
succeeded. A live claim requires a successful run and retained records from the
exact reviewed commit. Even then, the result is same-owner GitHub-hosted
operational conformance evidence. It is not an independent evaluation, hostile
code production isolation, general correctness proof, Core GA or Enterprise
readiness, or a customer deployment result.

The verifier establishes unsigned self-consistency only. It does not establish
who ran the kit or prove independent launch. A release evidence bundle must
carry an external evidence authority's detached signature over the exact result
bytes, trusted manifest, source inventory, and CI/run identity.

## Files and validation

- `tools/conformance/runner-manifest.json`: canonical owners, orders, and cases.
- `tools/conformance/runner-manifest.schema.json`: manifest schema.
- `tools/conformance/runner-result.schema.json`: result schema.
- `tools/conformance/live-runner-result.schema.json`: one real matrix-cell
  result schema.
- `tools/conformance/live_runner_result.py`: exact JUnit/result validator.
- `tools/conformance/run_live_runner_conformance.py`: create/verify CLI.
- `tools/conformance/live-runner-extended-result.schema.json`: one extended
  matrix-cell result schema.
- `tools/conformance/live_runner_extended_result.py`: exact extended
  JUnit/result and tool-version validator.
- `tools/conformance/run_live_runner_extended_conformance.py`: create/verify
  CLI for an extended matrix cell.
- `tools/conformance/fetch_live_runner_maven_cache.py`: fixed-origin,
  digest-before-execution Maven cache fetcher.
- `tools/conformance/verify_live_runner_maven_cache.py`: exact Maven JAR/POM
  cache-inventory verifier.
- `tools/ci-live-runners/`: locked Node, Go, Ruby, and Maven fixtures used only
  by the extended live job.
- `tools/conformance/runner_kit.py`: offline evaluator and provenance collector.
- `tools/conformance/run_runner_conformance.py`: create-only CLI.

Validate retained JSON with the development `jsonschema` dependency:

```console
python -c "import json,jsonschema; from pathlib import Path; p=Path('tools/conformance'); jsonschema.Draft202012Validator(json.loads((p/'runner-result.schema.json').read_text())).validate(json.loads(Path('runner-conformance.json').read_text()))"
```

JSON Schema validation is structural and is not a substitute for semantic
`--verify`.

The runner kit is independent of the Docker/gVisor isolation kit. Neither
result implies that the other boundary passed.
