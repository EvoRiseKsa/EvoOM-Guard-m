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

Production support still requires a separately published, schema-versioned
matrix that executes real suites against declared runner versions on every
advertised operating system. This kit is the formal local contract layer for
that future matrix, not the matrix itself.

The verifier establishes unsigned self-consistency only. It does not establish
who ran the kit or prove independent launch. A release evidence bundle must
carry an external evidence authority's detached signature over the exact result
bytes, trusted manifest, source inventory, and CI/run identity.

## Files and validation

- `tools/conformance/runner-manifest.json`: canonical owners, orders, and cases.
- `tools/conformance/runner-manifest.schema.json`: manifest schema.
- `tools/conformance/runner-result.schema.json`: result schema.
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
