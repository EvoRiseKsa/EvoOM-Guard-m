# Conformance kits

This directory contains two independent, schema-versioned measurements. A
result from one kit does not imply that the other boundary passed.

## Runner adapters

Run the deterministic offline contract for the nine adapter owners and write a
create-only result:

```console
python -m tools.conformance.run_runner_conformance \
  --output runner-conformance.json
```

Add `--discover-tools` to observe bounded `--version` output. Discovery is
non-gating and reports only `observed` or `unsupported`; it does not execute
suites or prove real-runner compatibility. See
[`docs/RUNNER_CONFORMANCE.md`](../../docs/RUNNER_CONFORMANCE.md).

## Isolation

Run every declared profile and write a create-only JSON result:

```console
python -m tools.conformance.run_isolation_conformance \
  --output isolation-conformance.json
```

Use a reviewed image reference in CI. The tool resolves it to an immutable
`sha256:` image ID, runs that exact ID, records it, and puts the ID in the
machine-readable replay argv:

```console
python -m tools.conformance.run_isolation_conformance \
  --image python:3.12-slim@sha256:<reviewed-index-digest> \
  --require-gvisor \
  --output isolation-conformance.json
```

`--require-gvisor` is a gate, not an emulation flag. If Docker does not
advertise `runsc`, the gVisor profile is `unsupported` and the process exits 2.
Without that flag, the optional gVisor profile is still recorded as
`unsupported`; a passing required Docker profile may make the aggregate result
`pass`, but gVisor itself is never reported as passing.

The manifest and schemas are:

- `runner-manifest.json`: the nine owners, registry order, and exact offline
  command cases.
- `runner-manifest.schema.json` / `runner-result.schema.json`: runner contract
  schemas.
- `isolation-manifest.json`: exact settings, probes, profiles, timeouts, and
  cleanup proof requirements.
- `isolation-manifest.schema.json`: manifest schema.
- `isolation-result.schema.json`: emitted result schema.
- `probe/isolation_probe.py`: candidate-side active attempts; its SHA-256 is
  bound into every result.

See [`docs/ISOLATION_CONFORMANCE.md`](../../docs/ISOLATION_CONFORMANCE.md) for
status semantics, probe interpretation, and retention guidance.

Both kits expose semantic verification:

```console
python -m tools.conformance.run_runner_conformance --verify runner-conformance.json
python -m tools.conformance.run_isolation_conformance --verify isolation-conformance.json
```

Inputs are bounded, stable, and non-link; source inventories bind evaluator
helpers. Verification proves unsigned self-consistency only. An external
authority's detached signature remains a release evidence gate.
