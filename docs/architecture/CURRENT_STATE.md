# Current architecture state

This page is the present-tense architecture entry point for the exact checked
out EvoOM Guard source tree. It is not a promise about a consumer release;
consult [`../RELEASE_STATUS.md`](../RELEASE_STATUS.md) for that boundary. Only
merged `main` is covered by the repository's protected-branch controls.

## Layer ownership

- `foundation` owns dependency-free, cross-cutting contracts and strict input
  decoding that are used by more than one domain layer.
- `domain` owns immutable request, policy, lifecycle, verdict, evidence,
  execution, assurance, and decision values.
- `execution` owns process scheduling, command resolution, and judge-process
  primitives.
- `isolation` owns containment and invocation evidence.
- `candidate` and `workspace` own candidate intake, filesystem boundaries, and
  canonical runtime-tree identity.
- `runners` owns runner recognition and judge-owned report instrumentation.
- `verifiers` owns repository and black-box execution orchestration, result
  interpretation, and the canonical verifier-pack manifest/snapshot contract.
- `application` owns policy, decision-gate, and finalization composition.
- `api`, `cli`, and `integrations` are compatibility boundaries.

The executable import-boundary ratchet in
`tests/architecture/test_import_boundaries.py` enforces the permitted
directions and prevents architectural debt from silently increasing.
Stable flat paths are classified only when the complete module has one owner:
`contracts.py` and `strict_json.py` are foundation-owned,
`runtime_identity.py` is workspace-owned, and `pack_manifest.py` is
verifier-owned. Mixed flat facades remain unclassified debt.

## Refactor status

- The behavior-preserving R2 extraction is complete.
- All 41 CLI handlers delegate through typed command-family owners.
- The public CLI and API compatibility facades remain intentionally stable.
- The import ratchet currently permits zero dependency cycles and zero
  cross-package private-symbol imports, with 17 mixed or not-yet-classified
  flat modules remaining. Trusted Finalizer source validation is
  now an explicit public owner contract shared by Artifact Admission V1/V2;
  selected-path Raw-Git regular-blob projection is an explicit public Finalizer
  Derivation contract while its reader and entry types remain private.
  Release-source producer orchestration also obtains one immutable public
  snapshot of its finalizer primitives at module entry instead of importing
  those owner-private functions directly. The CLI resolves the same unified
  immutable five-operation snapshot at command entry before reading untrusted
  arguments. Candidate-tree compatibility is likewise captured through one
  public immutable Guard snapshot, removing the final private cross-package
  import.
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
