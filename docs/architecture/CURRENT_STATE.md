# Current architecture state

This page is the present-tense architecture entry point for the exact checked
out EvoOM Guard source tree. It is not a promise about a consumer release;
consult [`../RELEASE_STATUS.md`](../RELEASE_STATUS.md) for that boundary. Only
merged `main` is covered by the repository's protected-branch controls.

## Layer ownership

- `domain` owns immutable request, policy, lifecycle, verdict, evidence,
  execution, assurance, and decision values.
- `execution` owns process scheduling, command resolution, and judge-process
  primitives.
- `isolation` owns containment and invocation evidence.
- `candidate` and `workspace` own candidate intake and filesystem boundaries.
- `runners` owns runner recognition and judge-owned report instrumentation.
- `verifiers` owns repository and black-box execution orchestration and result
  interpretation.
- `application` owns policy, decision-gate, and finalization composition.
- `api`, `cli`, and `integrations` are compatibility boundaries.

The executable import-boundary ratchet in
`tests/architecture/test_import_boundaries.py` enforces the permitted
directions and prevents architectural debt from silently increasing.

## Refactor status

- The behavior-preserving R2 extraction is complete.
- All 41 CLI handlers delegate through typed command-family owners.
- The public CLI and API compatibility facades remain intentionally stable.
- The import ratchet currently permits zero dependency cycles and three
  cross-package private-symbol imports. Trusted Finalizer source validation is
  now an explicit public owner contract shared by Artifact Admission V1/V2;
  selected-path Raw-Git regular-blob projection is an explicit public Finalizer
  Derivation contract while its reader and entry types remain private.
  Release-source producer orchestration also obtains one immutable public
  snapshot of its finalizer primitives at module entry instead of importing
  those owner-private functions directly.
- The broader program is still in progress: evidence/finalizer domains,
  release engineering, repository-wide strict typing, independent external
  red-team evidence, and the end-to-end protected build-to-admission chain are
  not all complete.

For the time-ordered implementation record, see
[`REFACTOR_PROGRAM.md`](REFACTOR_PROGRAM.md). For the enforced dependency
contract, see [`DEPENDENCY_RULES.md`](DEPENDENCY_RULES.md). For trust and
authority separation, see [`TRUST_BOUNDARIES.md`](TRUST_BOUNDARIES.md).

## Documentation rule

Present-tense architecture belongs on this page. Historical slice notes remain
in the refactor program and must not be read as current status. User-facing
feature availability belongs in the release-status and getting-started
documents, not in architecture planning records.
