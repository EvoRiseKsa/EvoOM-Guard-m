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
- `candidate` owns dependency-free candidate parsing, patch transforms and
  minimization, and advisory change characterization.
- `workspace` owns contained filesystem boundaries and canonical runtime-tree
  identity.
- `runners` owns runner recognition and judge-owned report instrumentation.
- `verifiers` owns repository and black-box execution orchestration, result
  interpretation, and the canonical verifier-pack manifest/snapshot contract.
- `application` owns policy, decision-gate, and finalization composition.
- `api`, `cli`, and `integrations` are compatibility boundaries.

The executable import-boundary ratchet in
`tests/architecture/test_import_boundaries.py` enforces the permitted
directions and prevents architectural debt from silently increasing.
Stable flat paths are classified only when the complete module has one owner.
In addition to the foundation, workspace, verifier, evidence, finalizer, and
admission owners already recorded by the ratchet, three compatibility facades
plus one pure flat owner now have executable dependency-closure ratchets:
`adapters.py` belongs to runners, `patch_applier.py` belongs to candidate,
`candidate_runner.py` belongs to isolation, and the pure `patchmin.py` owner
belongs to candidate. These tests make dependency or selected-shape drift
visible; semantic ownership still requires review. This is classification of
existing responsibility, not a file move or a runtime change. Mixed flat
facades remain unclassified debt.

## Refactor status

- The behavior-preserving R2 extraction is complete.
- All 44 CLI handlers delegate through typed command-family owners.
- The public CLI and API compatibility facades remain intentionally stable.
- The import ratchet currently permits zero dependency cycles and zero
  cross-package private-symbol imports, with 7 mixed or not-yet-classified
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
  import. The mixed public `record_verifier` facade now delegates nested
  assurance/attestation validation to a pure verifier-owned projection while
  retaining report sequencing and rendering itself. Its effective-policy
  type/shape phase also delegates to a pure immutable verifier projection;
  schema-contract selection, harness predicates, and the independent
  operating-profile decision remain in the facade at their original lookup
  points. Diff-coverage producer-shape validation now delegates to a separate
  stdlib-only verifier projection. Baseline producer-shape validation likewise
  delegates to its own stdlib-only projection while the facade retains the
  `baseline.shape` report, downstream policy/repair-effect interpretation, and
  verdict authority. Top-level envelope-type validation now delegates to a
  fourth stdlib-only type projection while the facade retains the historical
  mutable-list result and `envelope.types` sequencing. The extracted owners
  only return immutable ordered shape errors. Their measured facade hotspots
  fall from C901 26, 24, and 17 to 1 each; the current repository inventory
  falls from 94 through 93 and 92 to 91.
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
