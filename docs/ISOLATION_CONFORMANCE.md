# Isolation conformance

The isolation conformance kit measures the Docker boundary that EvoOM Guard
expects to use for candidate execution. It produces schema-versioned evidence
that can be retained and replayed. A successful result is deliberately narrow:
it means the listed negative probes were blocked under the recorded image,
daemon, runtime, kernel, and settings. It does not prove that Docker, gVisor, the
host kernel, or the image has no other escape path.

## Run and replay

From the repository root:

```console
python -m tools.conformance.run_isolation_conformance \
  --output isolation-conformance.json
```

File output is create-only. An existing file, symbolic link, or reparse-point
target is refused rather than replaced.

For a hostile-input gate, pass a reviewed immutable image reference and require
gVisor:

```console
python -m tools.conformance.run_isolation_conformance \
  --image python:3.12-slim@sha256:<reviewed-index-digest> \
  --require-gvisor \
  --output isolation-conformance.json
```

The result contains a path-portable, same-daemon `reproduce.argv` replay
vector. It uses the logical `python` launcher and repository-relative
module/manifest labels; when present, replace the `<result.json>` placeholder
with a new destination. Once the image has been resolved, that argv uses the
exact local `sha256:` image ID rather than the mutable input tag, so replay
requires that image to remain in the target daemon's cache. This is not a
cross-host retrieval reference. It also records:

- the manifest and candidate-probe SHA-256 digests;
- an exact size/SHA-256 inventory of the evaluator, CLI, schemas, stable-I/O
  helper, probe, execution kernel, and Docker/cleanup helpers;
- the current Git commit and whether the worktree was dirty;
- Docker client/server versions, daemon OS/architecture, registered runtimes,
  cgroup and security-option metadata;
- the requested image, exact image ID, and repository digests;
- host and in-container kernel/architecture facts;
- the delivered network mode, root filesystem mode, candidate mount mode,
  runtime, configured user, UID/GID observation, dropped capabilities,
  `no-new-privileges`, normalized tmpfs paths/options, PID and NanoCPU settings,
  and normalized soft/hard ulimits;
- bounded cleanup observations after both normal completion and a forced
  timeout.

Host source files are read once through bounded, stable, non-link descriptors
and remain digest-bound, but the portable result uses logical
repository paths and tool basenames. It does not publish the workspace, home
directory, Python executable, Docker installation path, Docker data-root path,
or the requested output path.

Keep the raw JSON result with the reviewed manifest, source commit, CI attempt,
and image provenance. Do not copy only the aggregate status.

The `blackbox-docker-e2e` CI job uses the pinned image digest with `--no-pull`,
verifies the exact result it creates, and retains it as an artifact for 30
days. The artifact is still unsigned and workflow-produced; upload retention is
not independent runtime attestation or release-ledger binding.

Verify a retained result against the trusted manifest and current source bytes:

```console
python -m tools.conformance.run_isolation_conformance \
  --verify isolation-conformance.json
```

The verifier rejects unknown fields, empty profiles, stale source/manifest/probe
digests, inconsistent required-probe flags, forged probe status, contradictory
profile/aggregate status, raw-inspect/security-summary contradictions, and
incorrect summaries. It reconstructs each no-container state exactly: daemon
unavailability must use `docker_available`, image-resolution failure must use
`image_available`, a missing requested runtime must use `runtime_available`,
and an execution exception must use `harness_execution`. Probe IDs, required
flags, status, expected/observed values, details, runtime evidence, and profile
reason must match that reconstructed state. The seven security probes in the
manifest are an exact mandatory set; misspelled, missing, or duplicate entries
are rejected before Docker runs.

## Active probes

The probe container uses the manifest controls and the resolved image ID. It
attempts all of the following:

| Probe | PASS requires |
|---|---|
| `network_none` | An outbound socket attempt is blocked and Docker inspect reports `NetworkMode=none`. |
| `candidate_mount_read_only` | A write under `/candidate` fails and Docker reports the bind mount as `RW=false`. |
| `root_filesystem_read_only` | A write at the container root fails and Docker reports `ReadonlyRootfs=true`. |
| `forbidden_path_read` | Reads from the declared judge-owned pack/report paths all fail and Docker reports no mount covering those paths. |
| `security_profile` | Docker inspect exactly matches the normalized declared capability drops, security options, every tmpfs path and option, `PidsLimit`, `NanoCpus = cpus × 1,000,000,000`, and each soft/hard ulimit. |
| `runtime_selection` | A requested non-default runtime is the runtime Docker actually records. |
| `user_identity` | When the host contract supplies UID/GID, the configured and observed IDs match and are non-root. |
| `normal_cleanup` | Production cleanup logic proves the named container stably absent. |
| `timeout_cleanup` | The container starts, the bounded Docker client times out, and production cleanup logic proves stable absence. |

The current runtime contract adds `--user <host UID>:<host GID>` only on hosts
that expose `os.getuid()` and `os.getgid()`. On platforms where that contract
does not apply, `user_identity` is `skip`, and the observed UID/GID are still
recorded. If the contract does apply with UID or GID zero, the non-root probe
fails rather than being softened.

## Status and exit semantics

- `pass`: every required probe for that available profile passed.
- `fail`: an active or daemon-inspection observation contradicted the manifest.
- `error`: the image could not be resolved or the probe could not produce
  trustworthy evidence.
- `unsupported`: the Docker executable/daemon or requested OCI runtime was not
  available.
- `skip`: a conditional probe did not apply; this status is never rewritten to
  PASS.

Process exit codes are 0 for aggregate `pass`, 1 for `fail` or `error`, and 2
for aggregate `unsupported`.

The `gvisor` profile requests Docker runtime `runsc`. Runtime availability is
read from the daemon's registered runtimes. If `runsc` is absent, the profile
and its `runtime_available` probe are emitted as `unsupported`; the kit does not
run ordinary `runc` and label it gVisor. The profile is optional in the default
manifest so a Docker measurement can still complete. Use `--require-gvisor`
when gVisor is a release requirement.

Unavailable-state evidence is deliberately unambiguous. An absent executable or
daemon yields an `unsupported` `docker_available` probe. A failed image
resolution yields an `error` `image_available` probe. A missing requested OCI
runtime yields an `unsupported` `runtime_available` probe. An exception before
container evidence exists yields an `error` `harness_execution` probe. These
states cannot be relabeled as one another while still passing semantic
verification.

## Schema validation

The development dependencies include `jsonschema`. Validate a retained result:

```console
python -c "import json,jsonschema; from pathlib import Path; p=Path('tools/conformance'); jsonschema.Draft202012Validator(json.loads((p/'isolation-result.schema.json').read_text())).validate(json.loads(Path('isolation-conformance.json').read_text()))"
```

The conformance tests validate both checked-in schemas and, when a Docker daemon
is explicitly enabled, validate a live result as well. The live pytest case is
opt-in so ordinary test matrices never pull or execute a mutable default image:

```console
EVOGUARD_RUN_ISOLATION_CONFORMANCE=1 \
EVOGUARD_E2E_IMAGE=python:3.12-slim@sha256:<reviewed-index-digest> \
python -m pytest tests/conformance/test_isolation_conformance.py -q
```

When opt-in is set, an absent or unpinned `EVOGUARD_E2E_IMAGE` is a test failure,
not a skip. The dedicated Docker CI job pre-pulls the reviewed image and runs
the command-line kit with `--no-pull`.

JSON Schema validation checks structure only. Semantic `--verify` checks
self-consistency, but both are unsigned: neither authenticates the actor that
ran Docker nor proves independent launch. A release evidence bundle must add an
external authority's detached signature over the exact result,
manifest/probe/source inventory, image identity, and CI/run identity.
