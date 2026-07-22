# Authenticated evidence bundles

An EvoOM Guard evidence bundle preserves one exact verdict and optional support
files in a deterministic envelope. Its purpose is offline consumption outside
the GitHub Action that produced the verdict. It does **not** turn producer
assertions into independently observed runtime facts, and `VERIFIED` does not
mean that the enclosed verdict is `PASS`.

For a pull-request merge gate, this general bundle format is **not sufficient
by itself**: never take a candidate-job artifact and sign it from a privileged
`workflow_run` job. Use the split [`Trusted Finalizer`](TRUSTED_FINALIZER.md)
reference workflow, which binds the PR control plane before candidate execution.

## Create in a trusted finalizer

Install the signing extra and generate an Ed25519 key once. `v4.1.0` is the
published immutable GitHub Release:

```bash
pip install "evoom-guard[sign] @ git+https://github.com/EvoRiseKsa/EvoOM-Guard-m.git@v4.1.0"
evo-guard keygen --key judge.pem --pub judge.pub
```

Create `context.json` from trusted workflow/event metadata, not from the verdict
alone:

```json
{
  "repository": "owner/project",
  "repository_id": "123456789",
  "run_id": "987654321",
  "run_attempt": 1,
  "base_sha": "1111111111111111111111111111111111111111",
  "head_sha": "2222222222222222222222222222222222222222",
  "base_tree_sha": "3333333333333333333333333333333333333333",
  "head_tree_sha": "4444444444444444444444444444444444444444",
  "candidate_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "policy_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "verifier_pack_sha256": null,
  "guard_artifact_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
}
```

`guard_artifact_sha256` must not be a placeholder. In evidence-context v1 its
portable meaning is the SHA-256 of the exact executable distribution bytes that
produced the verdict. For the standalone release, use the `evo-guard.pyz` digest
from `SHA256SUMS` after verifying the download. A source checkout or composite
Action install does not yet have a canonical cross-platform distribution digest;
do not claim that binding by inventing a value. Use the released zipapp for this
workflow until a future digest format and Action output are specified.

`run_attempt` is mandatory because GitHub keeps the same run ID when a workflow
is re-run. Together the two fields identify one execution attempt rather than
all attempts of a run. The candidate, policy, pack, commit, and tree values are
checked against every non-null matching field in the verdict. Repository
identity, run identity, and the Guard distribution digest are additional
finalizer bindings.

```bash
evo-guard bundle-evidence verdict.json \
  --out evidence.evb \
  --context context.json \
  --sign-key judge.pem \
  --material log=judge.log
```

The command strict-parses and semantically verifies schema 1.11 again inside the
bundle writer before signing the exact bytes. It refuses an inconsistent record.
Output publication is atomic and no-clobber by default; `--force` is explicit.
The Python `create_evidence_bundle()` API has the same fail-closed default;
forensic tooling may set `require_valid_record=False` only when it intentionally
needs to preserve an invalid record, which full `verify_evidence_bundle()` will
still refuse.

The private key must live in a trusted post-run finalizer that does not execute
candidate files. Do not expose it to a pull-request job, a candidate container,
`pull_request_target`, or any process that imports candidate code.

## Verify with independent inputs

```bash
evo-guard verify-bundle evidence.evb \
  --trusted-pub judge.pub \
  --expect-context expected-context.json
```

Both inputs are trust roots external to the bundle. A public key or context
copied out of the bundle cannot substitute for either one. Exit `0` and status
`VERIFIED` require all four machine claims to pass:

- canonical whole-container bytes;
- an Ed25519 signature under the external key;
- exact equality with the external expected context; and
- schema-1.11 structural and cross-field record semantics.

`INVALID` exits non-zero. Unusable or missing trust inputs are never converted
into `VERIFIED`. The JSON report also includes the authenticated key ID and
context plus the enclosed `verdict`, `passed`, `reason_code`, and `exit_code`, so
a consumer does not need to reopen the archive to see the authenticated decision.

By default exit `0` means the envelope and record are valid; it deliberately does
not mean the verdict was `PASS`. A merge/deploy gate should add `--require-pass`:

```bash
evo-guard verify-bundle evidence.evb --trusted-pub judge.pub \
  --expect-context expected-context.json --require-pass
```

An authenticated non-PASS then reports `DENIED`, retains `verified: true`, and
exits `1`. `pass_gate` is always emitted as `ALLOW` or `DENY`.

## Wire format

`EVOGUARD_EVIDENCE_BUNDLE_V1` is a stored, non-ZIP64 archive in this physical
order:

```text
bundle.json                 canonical signed manifest
bundle.sig                  exactly 88 ASCII base64 bytes, no newline
record/verdict.json         exact verdict bytes
materials/NNN-<role>        optional explicitly supplied regular files
```

The Ed25519 message is exactly:

```text
"EVOGUARD_EVIDENCE_BUNDLE_V1" || NUL || canonical bundle.json bytes
```

`key_id` is `sha256:` plus SHA-256 of the public key's DER SubjectPublicKeyInfo.
The signed manifest binds every payload by SHA-256 and byte length and binds the
external context. Material roles are unique within a bundle.

Inspection snapshots the input through a bounded descriptor and never extracts
it. It preflights the end record and central-directory count before `zipfile`
allocation, then rejects compression, encryption/flags, comments, extras,
special files, traversal, duplicate/undeclared entries, noncanonical metadata,
prefix/suffix bytes, reordering, ZIP64, and oversized inputs. Finally it rebuilds
the canonical archive and compares the complete byte sequence.

Hard limits are 8 MiB for the verdict, 32 MiB per material, 32 unique material
roles, 64 MiB total payload, 1 MiB for the manifest, and 64 KiB for the central
directory.

## What optional materials prove

A material's bytes are authenticated because its digest is in the signed
manifest. Its role label alone does not prove that it is the JUnit report, pack,
subject, or artifact named in the verdict. A consumer may make that stronger
claim only after recomputing the field's documented digest format. Missing raw
material is `NOT_PROVIDED`, not a successful recomputation.

The low-level `inspect_evidence_bundle()` API checks structure and self-
consistency only. `authenticate_evidence_bundle()` adds the external key and
exact-context checks but deliberately does not decide record semantics. Admission
code should use `verify_evidence_bundle()`, which performs all four checks, or the
CLI command above.

For a narrowly scoped relation between one regular file and an already verified
Trusted Finalizer `ALLOW`, see [`ARTIFACT_ADMISSION.md`](ARTIFACT_ADMISSION.md).
It is a separate format with a distinct key and signing domain; a generic
evidence-bundle material is not artifact admission or build provenance.

Machine-readable contracts:

- [`evidence-context-1.schema.json`](../evoom_guard/schemas/evidence-context-1.schema.json)
- [`evidence-manifest-1.schema.json`](../evoom_guard/schemas/evidence-manifest-1.schema.json)
- [`verdict-record-1.11.schema.json`](../evoom_guard/schemas/verdict-record-1.11.schema.json)
