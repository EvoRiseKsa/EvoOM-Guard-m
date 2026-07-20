# Module boundaries

## Package boundaries (current target)

- `domain/`: policy, lifecycle, verdict, assurance, request/result types.
- `policy/`: policy parsing, normalization, validation, profile identity.
- `candidate/`: candidate parsing, patch/diff, directory/file snapshot helpers.
- `workspace/`: safe file operations and runtime identity.
- `execution/`: process launch, limits, capture, cleanup, environment handling.
- `isolation/`: subprocess/docker/gVisor/container execution contracts.
- `verifiers/`: concrete verification engines (repo and blackbox) and adapters.
- `application/`: orchestration pipeline and evidence decision composition.
- `evidence/`: canonical types, record producers, bundles, signatures.
- `finalizer/`: PR/release source finalization workflows and handoff.
- `admission/`: admission adapters and output contracts.
- `api/` and `cli/`: thin public/CLI compatibility surfaces.
- `integrations/`: external platform adapters.

## Rule

- Modules above must not import from downstream layers except via explicit interfaces.
- The public API contract lives only in `evoom_guard/cli.py`, `evoom_guard/guard.py`,
  `evoom_guard/record_verifier.py`, and `evoom_guard/trusted_finalizer.py`.

## Current extraction boundaries

The first execution-kernel slice lives in `evoom_guard/execution/process.py`.
It owns the typed bounded-process request/result contracts, shared output cap,
timeout handling, and native process-tree cleanup. Verifiers may retain
compatibility aliases, but execution consumers must import these primitives
from `evoom_guard.execution`, not from `repo_verifier.py`.

The second execution-kernel slice lives in `evoom_guard/isolation/docker.py`.
It owns typed, bounded Docker control requests/results, image inspection and
pull facts, named-container start/absence/cleanup proofs, and validated CID
discovery/cleanup for black-box candidate containers. Existing modules retain
private compatibility facades so embedded callers and tests continue to patch
the same seams.

The two cleanup contracts are intentionally separate. Repo verification knows
the exact collision-resistant container name before launch; black-box candidate
cleanup learns one or more daemon-written 64-hex IDs from judge-owned cidfiles.
Conflating them would weaken what each absence proof means.

Docker argv and mount construction, image-resolution policy, isolation
selection, evidence composition, and verdict/schema/CLI behavior remain in the
existing callers. A later characterized phase may move the candidate runner to
`isolation/candidate.py`; this slice does not move it or add a `candidate/`
dependency.
