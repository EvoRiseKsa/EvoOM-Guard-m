<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# Changelog

All notable changes to EvoOM Guard are recorded here. The format is loosely based
on [Keep a Changelog](https://keepachangelog.com/), and the project follows
semantic versioning (`vMAJOR.MINOR.PATCH`).

Historical entries preserve the terminology used when those versions were
developed. A phrase such as “live proof” or “validated live” in an old entry is
not current release-bound evidence unless the current release status and linked
retained evidence say so.

## Release status and support

<!-- BEGIN EVOGUARD_PROJECT_STATUS:CHANGELOG_RELEASE_SUPPORT -->
- [`v4.5.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.5.0) is the latest stable and supported consumer release.
- Source `4.6.0.dev0`: unreleased development source; not a consumer release.
- Earlier published versions are historical and unsupported. Their tags,
  release assets, checksums, attestations, and records remain available
  unchanged for reproducibility, verification, and rollback.
- Draft candidates that were never published are labelled explicitly below and
  are not supported releases.
<!-- END EVOGUARD_PROJECT_STATUS:CHANGELOG_RELEASE_SUPPORT -->

## [Unreleased]

### Added

- Added the library-only Admission Decision Envelope V1 as a deterministic,
  in-toto Statement projection of one fully reverified Agent Change `ALLOW`
  proof. The closed schema binds the exact Git head, candidate, policy,
  verifier pack, source evidence bundle, finalizer key, and authorization key.
  Structural inspection is non-authoritative, every external-action flag is
  fixed to false, and V1 adds no key domain, CLI, workflow, merge, publication,
  or deployment authority.
- Added inert, side-by-side maintenance protocol contracts that keep trusted
  workflow, frozen maintenance base, and target source Git identities separate:
  Release Source Finalizer V2, producer receipt V2, Release Source Admission
  V3, and Release Artifact Admission V2. Exact-key validators, canonical byte
  digests, distinct signature domains, packaged schemas, cross-material byte
  binding, replay-chain checks, and negative cross-version tests are included.
  Published V1/V2 bytes and workflows are unchanged; no branch, tag, release,
  provider execution, signing operation, or production authority is added.
- Added the separate `EVOGUARD_BLAST_RADIUS_V2` materialized-change contract
  and dependency-free scorer. Explicit add/modify/delete/rename/copy/mode
  records have strict portable paths and non-negative counters, canonical JSON
  bytes, distinct result identity, golden vectors, and fail-closed malformed,
  raw-diff, binary, and Git-quoted-path behavior. The frozen V1 API,
  `risk_score` projection, and signed verdict schemas 1.11/1.12 are unchanged.
- Added an inert Phase-0 model for a possible one-time `v4.5.1` maintenance
  operation. It freezes literal repository, protection/check App IDs, ruleset,
  trusted-`main` Environments, raw-Git mode/blob pins, seven-run
  `A -> B -> CD -> E -> F -> G -> H` topology, exact pre/post-publication
  checkpoints, sole write-enabled deploy-key identity, publication-secret
  metadata, key-binding, signing, annotated-tag, immutable-release, temporal,
  and retirement requirements. The helper validates explicitly
  non-authoritative observation shapes only; it does not authenticate GitHub,
  verify signatures/tag bytes, compare independent F/G/release bytes, bind
  settings to run time, or prove retirement. These remain named blockers for a
  separate external-pin implementation. The model accepts only inert state and
  creates no branch, tag, release, key, secret, variable, or GitHub setting.
- Hardened that Phase-0 model against hostile-input ambiguity: the decoded raw
  annotated-tag object is capped at 32 KiB for GitHub's Base64 variable bound;
  the maintainer signing root uses one literal safe relative POSIX path and
  `100644` mode with a dynamic trusted-tree path-to-blob binding; blocker IDs
  must equal an exact closed set; and owner-control timestamps are parsed as
  real canonical UTC RFC3339 values. The validator now participates in CI's
  strict release-and-trust mypy gate.
- Added deterministic, no-clobber `finalizer-init` installation and static-only
  `finalizer-doctor` inspection for the current Trusted Finalizer workflow pair.
  The kit commits a public-key-bound deployment manifest, validates the
  trusted-base policy and verifier-pack digest, ships JSON Schemas in wheel and
  zipapp artifacts, and explicitly does not claim to configure or inspect live
  GitHub controls.

### Changed

- Hardened the unreleased maintenance contracts before publication: artifact
  binding now parses exact canonical source-admission JSON bytes and requires
  them to equal the supplied mapping; run IDs are pairwise distinct through the
  five-stage evaluation-to-artifact chain; workflow roles cannot collapse by
  ID, path, or blob; provider scalar types are exact; trusted materials cannot
  collide or overlap; the finalizer workflow must be an exact trusted-main
  control material; and runtime path/ref bounds are mirrored by schema tests.
  Producer-receipt and source-admission binders now accept only bounded exact
  canonical bytes and require those bytes to decode to the separately supplied
  mapping before hashing descriptors. Packaged Draft 2020-12 schemas are
  explicitly structural: the runtime canonical validators remain authoritative
  for exact scalar types because standard schemas accept integral floats such
  as `1.0` as integers. Artifact V2 also preserves the complete six-entry
  source key registry, binds its seventh entry to the exact authenticated Source
  Admission V3 key, and keeps the artifact key distinct from all seven.

- Made `seal_finalizer_bundle(expected_derivation=...)` and the
  `seal-finalizer --expected-derivation` CLI contract fail closed instead of
  silently accepting caller-declared metadata when raw-Git derivation is
  omitted. Agent Change sealing now requires the same input. Legacy Python
  callers can migrate explicitly to `seal_finalizer_bundle_without_derivation`;
  that compatibility primitive has no CLI counterpart and is documented as
  outside the PR/release/artifact-admission trust boundary.
- Replaced the final ten cross-package private-symbol imports with explicit
  public owner contracts for finalizer source validation, selected raw-Git
  blob projection, release-source primitive snapshots, and candidate-tree
  compatibility. The architecture ratchet now permits zero private imports,
  zero cycles, and zero layer violations; six cohesive stable modules are
  classified by their existing semantic owners, reducing unclassified modules
  from 21 to 11. Public import paths, schemas, canonical bytes, verdicts, and
  runtime lookup timing remain unchanged.
- Extracted trusted path and harness-policy validation from `load_config` as a
  pure phase, reducing its measured C901 complexity from 49 to 42. Exact error
  type, message, cause, validation order, and normalized payload behavior are
  frozen by characterization and focused mutation tests.
- Extracted assurance and attestation nested-object validation into an
  immutable, verifier-owned pure projection. The public report adapter retains
  exact check IDs, order, messages, null behavior, and schema-1.11/1.12 report
  bytes while `_nested_type_checks` falls from measured C901 complexity 52 to
  3. No extracted helper exceeds complexity 9, and the reviewed repository
  C901 inventory falls from 97 to 96.
- Extracted diff-coverage producer-shape validation into a stdlib-only,
  verifier-owned pure projection. The public record-verifier facade retains
  report sequencing, policy semantics, messages, and its historical list
  return while `_diff_coverage_type_errors` falls from measured C901
  complexity 26 to 1. Pre-extraction ordered traces, four public-report
  digests, 20,000 deterministic generated cases, and focused mutations bind
  path safety, positive line sets, non-overlap, per-file totals, and exact
  percentage calculation. The current source C901 inventory falls from 94 to
  93; schemas, canonical bytes, verdict authority, and I/O behavior are
  unchanged.
- Extracted baseline producer-shape validation into a separate stdlib-only,
  verifier-owned projection. The public facade keeps its historical list
  return, `baseline.shape` check identity and ordering, downstream policy and
  repair-effect semantics, and all verdict authority. Pre-extraction ordered
  traces, mapping lookup and exception precedence, four public-report digests,
  20,000 deterministic generated cases, and eight focused mutants bind exact
  producer keys, unsupported-mode null evidence, count/verdict truth tables,
  repair-effect states, setup-fidelity coupling, and canonical changed paths.
  Measured `_baseline_type_errors` complexity falls from 24 to 1, no extracted
  helper exceeds 7, and the current source C901 inventory falls from 93 to 92.
  Schemas, canonical bytes, runtime effects, and efficacy claims are unchanged.
- Extracted top-level record-envelope type validation into a separate
  stdlib-only verifier projection. The public facade keeps its historical list
  result, `envelope.types` check identity and ordering, schema selection,
  subsequent semantic phases, and all verdict authority. Thirty-eight exact
  pre-extraction cases, four schema-1.11/1.12 public-report digests, mapping
  access and exception precedence, 20,000 deterministic traces, and focused
  mutations bind type, nullability, finite-number, list, and exact-dict
  behavior. Measured `_top_level_type_errors` complexity falls from 17 to 1,
  the extracted-helper maximum is 3, and the source C901 inventory falls from
  92 to 91. Schemas, canonical bytes, runtime effects, and efficacy claims are
  unchanged.
- Made both newly extracted callable snapshots structurally immutable with
  slotted frozen dataclasses, and replaced the release-source snapshot's
  ellipsis-based callable annotations with exact Protocol signatures. Focused
  tests and reviewed mutations now reject loss of either frozen assignment or
  slot-backed storage. This is a typing and compatibility-contract hardening;
  it does not change runtime lookup timing, verdicts, schemas, or canonical
  bytes.

### Fixed

- Preserved `ReleaseSourceProducerReceiptError` class identity across
  `importlib.reload()` so already-imported admission consumers continue to
  translate producer failures deterministically regardless of test order. A
  private validated identity anchor restores the public export and rejects
  structurally invalid private-anchor values. This is reload/test-order
  robustness, not a security boundary against arbitrary in-process mutation,
  and does not add or strengthen a production trust guarantee.

- Hardened the specialized black-box judge process owner so cancellation keeps
  the exact active `BaseException` through a bare re-raise, always attempts the
  process-group and output-reader abort-cleanup stages independently, and
  attaches ordered, bounded diagnostics for every raised or non-proven cleanup
  outcome. Verdict and evidence schemas are unchanged; this does not claim
  equivalent coverage for the raw-Git finalizer or GitHub Attestation owners.

- Made GitHub Attestation command abort cleanup preserve the exact active
  `BaseException` while always attempting subprocess-tree cleanup before
  output-reader cleanup. Each stage now requires the exact result `True` as
  positive proof and attaches ordered, bounded diagnostics for false or raised
  cleanup outcomes, including hostile exception stringification, hostile
  `add_note`, and Python 3.10 fallback handling. Normal command results,
  verdicts, receipt schemas, and the existing Windows departed-root limitation
  are unchanged; generic execution, specialized judge execution, and raw-Git
  finalizer lifecycles remain separate contracts.

- Made raw-Git finalizer cancellation preserve the exact active
  `BaseException` while always attempting process-tree cleanup before
  output-reader cleanup. Only an exact `True` is accepted as positive proof;
  false, raised, hostile-rendering, and legacy/no-`add_note` outcomes remain
  ordered, bounded secondary diagnostics. Normal Git results and verdict
  schemas are unchanged. Its lifecycle remains separate from the GitHub
  Attestation process owner and does not expand that owner's Windows boundary.

## [4.5.0] — published 2026-08-01; signed protected-tree ledger

[`v4.5.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.5.0)
is the latest stable and supported consumer release. Its signed
[`release-ledger-v2`](evidence/release-ledgers/v4.5.0/RELEASE_LEDGER.json)
binds candidate commit `6bb4c328e56661b661e50532886802c6ba36a997`, the protected
A-through-H operation, and the exact three-asset immutable publication. This
same-owner retained evidence does not establish independent review,
reproducibility, production readiness, or deployment authorization. The later
publication-authority operation is retained separately in the signed
[`KEY_RETIREMENT.json`](evidence/release-operations/v4.5.0/KEY_RETIREMENT.json)
receipt and is not a claim made by the immutable ledger.

### Added

- Added the signed 59-file `v4.5.0` release-ledger directory with the canonical
  detached signature, exact A–H run identities and attempts, source/artifact
  admission evidence, build/SBOM/release attestations, tag CI, repository
  controls, release assets, and seven public trust roots.
- Added the deterministic, advisory-only Change Attempt Observation V1
  projection for authenticated Trusted Finalizer `ALLOW` and `DENY` bundles.
  Its closed schema preserves five Guard outcomes and five bounded channels
  while treating one bundle as one correlated source, excluding raw
  code/log/policy/risk content, and granting no admission, merge, deployment,
  promotion, or external-action authority.
- Added `project-change-attempt-observation`, a machine-readable CLI/zipapp
  projector over the same authenticated V1 contract. A verified `DENY` is a
  successful observation projection, not an admission failure or authority
  upgrade.
- Added `BlastRadiusScore` and `blast_radius_score` as exact Python API aliases.
  The frozen verdict wire names remain `risk_level` and `risk_score`; the
  measurement is explicitly not semantic or security-risk probability.

### Changed

- Updated the no-install instructions to use the complete `v4.5.0` checksum
  set: zipapp, SPDX SBOM, and `SHA256SUMS`.
- Preserved LF protocol newlines when materializing unified diffs on Windows so
  valid `--diff` inputs reverse-apply instead of failing during reconstruction.
- Documented the exact Blast Radius V1 mapping contract and limited raw-diff
  parser. Caller-provided mappings now reject malformed, negative, boolean,
  floating-point, and non-finite line counts instead of producing invalid
  measurements.
- Removed the exact `v4.4.2` publication deploy key and publication Environment
  secret after the signed ledger was committed. The retained same-owner API
  observation is explicitly unsigned and is not represented as the signed
  `KEY_RETIREMENT.json` receipt that could not be produced without the offline
  ledger private key.
- Kept the immutable `v4.5.0` ledger's publication-authority state as
  `pending-post-ledger`, which is the state known when that ledger was signed.
  After the committed bytes were revalidated, removed the exact temporary
  publication deploy key and Environment secret and retained a separately
  signed, validated
  [`KEY_RETIREMENT.json`](evidence/release-operations/v4.5.0/KEY_RETIREMENT.json)
  receipt. The receipt is a same-owner point-in-time API observation, not proof
  of secure erasure or absence of external copies.
- Made generic bounded-process cancellation retain the exact active
  `BaseException` while attaching bounded secondary diagnostics when managed
  process-tree or output-reader abort cleanup raises or is not positively
  proven. Normal process results and verdict schemas are unchanged. The
  specialized judge, raw-Git finalizer, and GitHub Attestation process owners
  remain separate follow-up scopes rather than being represented as covered by
  this generic runner change.

### Fixed

- Completed deletion-aware blast-radius measurement before returning
  `verifier_pack_required` from black-box preflight. The verdict remains
  `ERROR`; only the advisory measurement now matches the executable black-box
  path for the same materialized deletion.

## [4.4.2] — published 2026-07-29; signed protected-tree ledger

[`v4.4.2`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.4.2)
is the latest stable and supported consumer release. Its signed
[`release-ledger-v2`](evidence/release-ledgers/v4.4.2/RELEASE_LEDGER.json)
records the protected A-through-H operation and resulting immutable
publication within the exact evidence boundaries below.

### Added

- Added `PROJECT_STATUS` schema v2 with an ordered, bounded
  `published_unledgered` history. It preserves the separate `v4.4.0` and
  `v4.4.1` exception authorities, rejects duplicate or reordered versions,
  paths, and record digests, and validates the recovery chain without turning
  either unsigned record into a ledger.
- Added the signed `v4.4.2` `release-ledger-v2` directory, including the exact
  A–H run identities and attempts, release assets and checksums, RSAE/RAAE and
  attestation receipts, tag-CI observations, repository-control observations,
  and the seventh independently pinned ledger-signing root. Its canonical
  bytes validate against the admitted parent and an externally supplied copy
  of that root; the ledger establishes only the retained byte and binding
  claims implemented by its validator.

### Changed

- Promoted the measured `4.4.2.dev0` line through the exact one-parent
  `4.4.2` candidate and protected A-through-H publication. `v4.4.2` is now the
  latest stable release and the release selected by `PROJECT_STATUS.json`; the
  earlier `v4.4.0` and `v4.4.1` published-unledgered exceptions remain
  unchanged.
- Corrected the release-ledger validator for recovery operations beginning
  with `v4.4.2` so a clean interpreter
  accepts the original CPython `pyexpat` aliases and the strict deterministic
  indented JSON emitted by the trusted release CLI. Duplicate keys,
  non-finite values, extra keys, wrong values, and replacement module aliases
  remain rejected. This correction does not validate `v4.4.1` retroactively.
- Recorded `v4.4.1` as a second immutable published-unledgered exception with
  exact release, asset, attestation, provenance, CI, Git-parent, validator-blob,
  and correction identities. Its unused prospective signing key remains
  `pending-operator-removal`; no deletion or compromise claim is made.
- Recorded `v4.4.2` publication-authority retirement as
  `pending-post-ledger`. The signed ledger must be committed to protected main
  and revalidated before the exact publication deploy key and Environment
  secret are removed. Completion requires a separate signed
  `KEY_RETIREMENT.json` receipt; neither the ledger nor that receipt proves
  destruction of external key copies.

## [4.4.1] — published 2026-07-29; no valid protected-tree ledger

[`v4.4.1`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.4.1)
is an immutable published and supported release. Its three assets, checksums,
GitHub release attestation, build provenance, tag CI, and action smoke
observations were rechecked. It is not the ledger-recorded consumer pin.

The protected A-through-H runs completed and 57 retained evidence files were
collected, but the exact frozen validator cannot cold-start against original
CPython `pyexpat` aliases and requires compact result JSON that the frozen
trusted CLI does not emit. Rewriting the validator or evidence after
publication would change the frozen contract, so no canonical `v4.4.1` ledger
or signature can be issued. See
[`docs/errata/V4.4.1-LEDGER.md`](docs/errata/V4.4.1-LEDGER.md) and the
[unsigned bounded record](evidence/release-operations/v4.4.1/UNSEALED_STATUS.json).

### Changed

- Promoted the reviewed `4.4.1.dev0` source and fresh benchmark chain through
  an exact one-parent `4.4.1` candidate.
- Published exactly `evo-guard.pyz`, `evo-guard.spdx.json`, and
  `SHA256SUMS` through the protected release workflows.
- Preserved the earlier `v4.4.0` published-unledgered exception as historical
  truth rather than rewriting its tag, assets, evidence, or erratum.

## [4.4.0] — published 2026-07-29; no valid protected-tree ledger

The entries in this section describe the immutable
[`v4.4.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.4.0)
publication. They are not evidence of a signed post-publication v2 repository
ledger, completed protected A-through-H publication round, independent
validation, or hostile-code production readiness. See the
[release-ledger erratum](docs/errata/V4.4.0-LEDGER.md).

### Added

- Added explicit base-policy `harness_inputs` for repository-local judge
  wrappers/helpers that built-in path rules cannot identify. Declarations are
  exact cross-platform-canonical regular files, non-exemptible by candidate
  allowlists, digest-bound in schema 1.12, checked against base/head raw Git by
  the Trusted Finalizer, and independently constrained by record verification.
- Added declared-input identity checkpoints around repository setup/suite,
  black-box candidate/pack execution (including `--blackbox-only`),
  pristine-baseline, and changed-line coverage runs. The trusted-source
  byte/type/mode snapshot is captured before candidate copy/materialization,
  compared with the resulting tree before execution, and checked again after
  the applicable runtime phases. Setup-output exclusions cannot match a
  declared file or any of its ancestors.
- Distinguished black-box harness provenance failure from candidate drift. An
  initial trusted-source binding failure stops before materialization as
  `ERROR assurance_requirement_not_met` and is not attributed to the candidate;
  only a materialized-copy mismatch or persistent post candidate/pack drift is
  `TAMPERED candidate_tree_changed_during_run`.
- Added explicit `local`, `protected`, and `hostile` operating profiles. The
  protected and hostile profiles require external black-box verdicts and
  container isolation; hostile mode additionally requires gVisor and a
  non-zero memory limit. The selected profile is bound into policy, verdict,
  attestation, and detached verification.
- Added schema-versioned isolation and runner conformance tooling with versioned
  manifests and JSON Schemas. Observations that cannot be exercised on the
  current host are reported as `UNSUPPORTED` or `SKIP`, never promoted to
  passing evidence. The release-bound, multi-OS conformance publication remains
  open.
- Added a signed blind-evaluation protocol that freezes exact case bundles,
  candidate/base/head identities, policy, Guard artifact, separately signed
  verdicts under an externally supplied trust root, and machine-derived
  ordinary-CI baselines before labels are disclosed. Shipping the protocol is
  not evidence that an independent party has run it.
- Added an Atheris/ClusterFuzzLite-compatible fuzzing kit for strict JSON and
  JUnit parsers, seed corpora, deterministic mutation tests, and
  ASan/UBSan-capable container builds without candidate access to repository
  tokens or network.
- Added privacy-bounded operational telemetry for already-produced terminal
  verdict records, with stable descriptor reads, link/reparse rejection, and
  aggregate-only output.
- Added an evidence-bound live benchmark manifest that re-derives Git state,
  hashes all selected sources and outputs, detects assume-unchanged and
  skip-worktree state, and records the sanitized execution environment. Its
  two-phase finalizer binds the clean source commit first and, after results
  are committed without rerunning the corpus, binds a distinct evidence
  commit; the later manifest commit is reported separately rather than folded
  into a recursive claim.
- Added production-boundary, operations, independent-evaluation, fuzzing,
  telemetry, operating-profile, and conformance documentation.
- Added a stdlib-only deterministic SPDX 2.3 generator for the `4.4.0` source
  line:
  one package, every regular zipapp member with SHA-1/SHA-256, an SPDX package
  verification code, the exact embedded license text, and exact
  `DESCRIBES`/`CONTAINS` relationships.
- Vendored the unmodified official SPDX 2.3 JSON Schema and license as
  test-only material with pinned upstream commit, Git blob, and byte-size
  verification.
- The `v4.4.0` release contract carries exactly `evo-guard.pyz`,
  `evo-guard.spdx.json`, and `SHA256SUMS`; the two generated-file digests are
  filename ordered and tag CI byte-compares all three published assets.
- A separate clean attestation job in the default-branch release workflow
  requests a GitHub SBOM attestation for the exact zipapp subject in addition
  to its build-provenance attestation, and a separate build-provenance
  attestation for the exact SPDX asset bytes required by artifact admission.
- Added the disabled-by-default protected A–H release path and Release Ledger
  v2: source re-verification, two independent admission boundaries, detached
  verification, immutable publication, retained evidence validation, an
  offline assembler, and an external per-release Ed25519 ledger trust root.
- Added one machine-readable project-status source whose renderer verifies the
  frozen or signed release ledger, Git/tag ancestry, exact release assets,
  source lifecycle, and reviewed workflow topology before updating public
  documentation.

### Security

- Candidate edits/deletions of declared `harness_inputs` or their ancestors now
  stop at the static pre-gate even when `allow`, `protected`, or
  `allow_new_tests` would otherwise exempt the path. Candidate paths and
  declarations reject Windows trailing-dot/space segments, reserved device
  names, and DOS 8.3-style `~N` spellings; already-existing candidate paths are
  checked by filesystem object identity against declared files and ancestors
  where comparable. Missing, case-aliased, linked, reparse, hardlinked, or
  non-regular declarations fail closed before candidate execution.
- Candidate-facing workflow jobs no longer receive repository write
  authority, persisted checkout credentials, OIDC, signing keys, or
  best-effort comment mutation. Candidate fuzz execution is bounded,
  networkless, read-only with respect to the source tree, and uses immutable
  container image identities.
- Process launch now uses typed resource-limit specifications, installs
  timeouts before process creation, and rejects arbitrary pre-execution
  callbacks. Key and detached-signature reservations use create-only
  publication. Evidence-bundle, blind-evaluation, and conformance writers refuse
  replacement by default unless their explicit force/replace option is selected;
  their security-sensitive inputs use bounded, stable, non-link reads.
- JUnit ingestion now rejects ambiguous suites, duplicate or contradictory
  counters, unsafe XML constructs, malformed encodings, trailing content, and
  exit-code/report disagreements.
- The record verifier was split into separate report-envelope,
  isolation-parity, and verifier-owned operating-profile modules. Profile
  semantics are re-derived without importing the producer policy predicate;
  architecture checks ratchet import direction, cycles, and private-module
  dependencies.
- Artifact admission now copies the six verified attestation evidence files by
  their closed names through the privileged boundary. It no longer relies on
  shell glob expansion against the provider-owned `0700` output directory,
  which prevented F from retaining already-verified evidence.
- Detached artifact verification now stages its three deliberately mutated
  negative-test fixtures with an explicit owner-writable mode. The immutable
  root-owned F inputs remain read-only while G can exercise the intended seven
  rejection cases instead of failing during fixture preparation.
- Publication no longer calls the administration-only Immutable Releases
  endpoint with an under-privileged `GITHUB_TOKEN`. The repository owner first
  verifies that endpoint outside Actions and authorizes only the reviewed
  candidate by setting the publication gate to its exact commit SHA; both
  protected H jobs recheck that binding, and H succeeds only when GitHub
  reports the resulting release as immutable.

### Changed

- Split the eight ecosystem adapters plus the shell wrapper into owner modules
  behind a compatibility facade, preserving public identities and registry
  order while making tool-specific behavior independently testable.
- Operating profiles, isolation evidence, effective policy, and finalizer
  derivation now share one canonical contract instead of relying on
  documentation-only expectations.
- Benchmark and adversarial documentation now distinguish developer-owned
  regression evidence from held-out, third-party validation.
- Runtime assurance and isolation documentation now describe the delivered
  read-only mount, omitted pack mount, network, identity, and cleanup controls
  without claiming that Docker cannot be escaped or that arbitrary host writes
  are impossible.
- The composite Action builds and runs a temporary stdlib-only zipapp from its
  selected `github.action_path`; bootstrap no longer invokes pip, a package
  resolver, a build backend, or PyPI.
- Optional changed-line coverage is caller-preprovisioned. Missing advisory
  measurement remains explicit; a configured minimum remains fail-closed.
- The zipapp builder rejects links, Windows reparse points, special files, and
  ambiguous source entry names, and replaces a prior output only after a
  complete temporary archive has been written.
- The release transfer and tag-verification jobs require an exact top-level
  name-and-file-type set, rejecting directories, links, nested extras, missing
  assets, unexpected assets, and non-canonical checksum manifests.
- Candidate code and the built zipapp execute only in the unprivileged release
  build job. A separate clean job receives the fixed assets, rebinds the SPDX
  package digest to the zipapp, and alone receives OIDC/attestation authority.
- Completed the behavior-preserving R2 architecture program and CLI handler
  extraction while retaining the wider refactor program as in progress.
- The release-candidate parent now closes the source policy by default and
  permits only the exact reviewed v4.4 release-metadata file set; tests, CI,
  release tooling, policy, verifier packs, ledgers, and trust roots cannot be
  changed by the candidate.
- Corrected the parent-owned release-source verifier contract for the pinned
  minimal image: `doctor --json` must report the expected unsupported tool
  state exactly, rather than being misclassified as a protocol failure.
- Corrected the phase E release-artifact smoke check for the pinned minimal
  builder image: `doctor --json` must exit `1` with empty stderr and match the
  exact typed unsupported-tool report, rather than being required to succeed.
- Corrected artifact build and admission to bind the canonical source-admission
  parent commit and tree fields, rather than reading non-existent base fields.
- Corrected final publication so the expected absent-tag `404` is captured
  without firing the draft-cleanup trap before SSH tag creation. Explicit
  tag-probe and push failures now preserve their original failure status and
  enter the exact verified cleanup path.

### Known limitations

- `harness_inputs` is explicit-only: commands, `sh -c`, package scripts,
  imports, sourced helpers, and dynamic loads are not mined into a transitive
  dependency graph. Host-subprocess execution is not filesystem isolation:
  checkpoints prove identity only when observed and can miss a temporary
  mutation restored before the next observation.
- The published `v4.4.0` release is not a production claim for hostile code.
  No signed v2 repository ledger currently records protected A-through-H
  operation or publication for that release. The
  [unsigned observation record](evidence/release-operations/v4.4.0/UNSEALED_STATUS.json)
  preserves verified live facts without substituting for that missing ledger.
- Current local evidence does not substitute for a third-party held-out corpus,
  an independent launcher/runtime attestation, multi-OS toolchain conformance,
  or release-bound gVisor/VM evidence.
- Aggregate telemetry cannot detect missing terminal records, publisher or
  finalizer outages, retention lag, or end-to-end availability without an
  external inventory/event source and independently operated storage.
- Resolver-free bootstrap is not a whole-Action zero-network or same-user
  anti-tampering claim. Interpreter setup, conditional base fetch, a separate
  metadata-only reporter if configured by the consumer, and consumer
  setup/tests retain their existing boundaries.
- The published `v4.4.0` release includes `evo-guard.spdx.json` and provider
  provenance according to the unsigned observation record, but the protected
  tree still lacks its signed v2 ledger. The ledger-recorded `v4.3.0` release
  has no SBOM asset and remains unchanged.
- The SPDX document is an artifact-member inventory, not source composition
  analysis, dependency or vulnerability scanning, VEX, license legal review,
  a security verdict, artifact admission, or cross-platform reproducibility
  proof. The zipapp and SBOM share one build provenance and are not independent
  evidence merely because attestation occurs on a separate clean runner.
- GitHub's release API does not provide one atomic compare-and-swap operation
  spanning the draft/tag precondition and publication mutation. The H phase
  therefore still requires the repository's frozen `contents: write` window,
  strict `v*` tag ruleset, and immediate before/after identity checks.

## [4.3.0] — 2026-07-23

### Added

- Added the experimental
  [`Agent Change Admission V1`](docs/AGENT_CHANGE_ADMISSION.md) profile: a
  canonical untrusted proposal, separately signed `.aca` authorization,
  independently derived raw-Git bindings, and an offline-verifiable Trusted
  Finalizer evidence profile.
- Added a compact
  [`command-order reference`](examples/agent-change-admission/) and JSON Schema
  contracts for proposals, authorizations, and raw-Git bindings.

### Security

- The agent cannot authorize its own paths. Exact literal or `directory/**`
  scope, deletion/size/path-count limits, policy and verifier-pack digests, and
  source/run identities come from a separate signed control plane.
- Judge-owned tests, config, CI/Action, and auto-exec paths remain forbidden
  even when a signed scope attempts to include them. Authorization and Trusted
  Finalizer signing keys must be distinct.
- Sealing requires exact proposal/authorization/raw-Git/finalizer agreement and
  a verified Trusted Finalizer `ALLOW`; detached verification performs no
  candidate checkout or execution.
- The sealer re-derives complete tracked-path truth internally with a pinned
  Git executable, including paths excluded from Guard's candidate-copy layer,
  and verifies a staged signature before atomic publication.

### Changed

- Regenerated the 16-case live benchmark with source version 4.3.0. All
  expected labels matched: 11 true positives, 3 true negatives, 2 documented
  policy false positives, and 0 false negatives.
- Recorded the bounded public same-owner pilot with immutable positive,
  ignored tracked-path negative, and exact-change replay run identities plus
  detached offline verification.

### Known limitations

- Agent Change Admission V1 is experimental and is not an enabled merge gate.
  Its bounded public same-owner pilot completed one permitted change, one
  ignored tracked-path rejection before signing, and one exact-change replay
  with detached offline bundle verification. It is not independent validation
  or production evidence.
- The profile is an admission contract, not ML, risk prediction, policy
  selection, or a code-healing engine. It does not prove correctness beyond
  the configured Guard judge and evidence boundary.
- V1 authorization is idempotent for one exact commit/tree and is not a
  single-use grant; single-use enforcement requires external state.

## [4.2.0] — 2026-07-22

### Added

- Added `EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1`, a separately keyed canonical
  `.raae` envelope, JSON Schema, CLI sealer, and detached offline verifier for
  one protected-main release artifact.
- Added explicit builder E and key-bearing admitter F identities. Their exact
  workflow blobs, source commit, numeric runs and attempts, and GitHub
  `workflow_run` relation are bound to the admission record.
- Added a narrow public raw-Git regular-blob resolver so admission code can
  verify protected workflow blobs without importing the private Git reader.

### Security

- The sealer re-verifies the embedded Release Source Admission V2 `.rsae`
  against every external source, context, producer, admitter, policy, tool,
  isolation, and five-key expectation before it can inspect provider evidence
  or read the sixth signing key.
- E and F must be distinct from each other and from the earlier source roles.
  Both workflow blobs are resolved from the immutable protected-main raw-Git
  tree with the externally pinned Git executable.
- A fresh GitHub Artifact Attestation verification is constrained to the exact
  artifact, repository, builder workflow, source commit/ref, E run, and run
  attempt. The provider process and its temporary evidence directory must be
  cleaned up before the first private-key read.
- The final envelope snapshots the detached artifact, retained provider
  receipt/output, and nested `.rsae`, then signs canonical descriptors with a
  sixth Ed25519 key that must differ from all five earlier trust roots.
- CLI preflight rejects standard streams, path aliases, and an existing output
  before provider access. Detached verification accepts no token, `gh`, Git
  repository, provider runtime, or overwrite switch and performs no live
  provider call.

### Changed

- Classified release-artifact admission under
  `evoom_guard.admission.release_artifact`, prohibited cross-package private
  imports, and froze its exact internal dependency surface in the architecture
  ratchet.
- Regenerated the 16-case live benchmark with source version 4.2.0. All
  expected labels matched: 11 true positives, 3 true negatives, 2 documented
  policy false positives, and 0 false negatives.

### Known limitations

- This first release carrying Release Artifact Admission V1 is a bootstrap and
  cannot admit itself. A later protected-main E/F/G pilot and a fresh `.rsae`
  are required before making any operational evidence claim.
- A `.raae` does not authorize publication or deployment and does not prove
  reproducible builds, OCI/registry provenance, production readiness, or
  independent review.
- Detached verification validates retained provider evidence offline; callers
  that require current provider state must perform a separate live
  re-verification.

## [4.1.0] — 2026-07-22

### Added

- Added the separately keyed `EVOGUARD_RELEASE_SOURCE_ADMISSION_V2` envelope,
  JSON Schema, detached verifier, and CLI commands for a protected-main source
  `ALLOW`. V1 release-source evidence remains DENY-only.
- Added a signed A/B/C workflow topology: exact workflow blobs and numeric
  run/attempt replay bindings are checked against raw Git, the current C
  GitHub Actions context, and the triggering B `workflow_run` event.
- Classified the new admission implementation under
  `evoom_guard.admission.release_source` and added an exact internal dependency
  allowlist to the architecture ratchet.

### Security

- GitHub attestation output is now parsed semantically after live `gh`
  verification. Empty placeholder results and mismatched subject, predicate,
  repository, workflow, ref/digests, issuer, hosted-runner, builder,
  dependency, invocation URI, or expected B run/attempt are rejected.
- The V2 admitting path requires POSIX root-to-nonroot provider isolation. It
  runs a SHA-256-pinned `gh` snapshot with cleared supplementary groups and an
  allowlisted environment, and proves before launch that the provider identity
  cannot read the exact mode-`0600` signing-key path.
- Raw-Git verification can use a SHA-256-pinned, descriptor-validated private
  Git executable snapshot. V2 requires that pin and binds it, the provider
  isolation contract, and the protected signing-key path to the private
  in-process admission capability; unisolated provider evidence cannot reach
  the signing key.
- Pinned Git now runs with a closed environment that excludes dynamic-loader,
  PATH, HOME, XDG, and Python injection state. The signed V2 manifest carries
  the Git/`gh` SHA-256 pins and provider UID/GID, and detached verification
  requires those values from outside the bundle.
- The C runtime check now mints an opaque producer-bound capability; the V2
  sealer rejects a plain C selector before key access. Private/public key
  loading uses bounded stable non-link snapshots. A same-directory staging
  bundle must pass canonical and cryptographic verification before atomic
  promotion; a failed forced replacement preserves the previous output.
- Replaced arbitrary key exclusions with an exact four-entry registry for the
  Trusted Finalizer, Artifact Admission V1, Artifact Digest Admission V2, and
  Release Source Finalizer V1 domains. Those keys and the V2 admission key must
  all be distinct.

### Changed

- Release-source provider output is preserved byte-for-byte while required
  semantic fields are fail-closed; compatible unknown GitHub fields remain
  retained but do not become trusted facts.
- V2 output preflight rejects canonical path aliases across all evidence,
  executable, policy, and key inputs. `--force` can replace only the final
  `.rsae`; provider evidence remains no-clobber.
- Regenerated the 16-case live benchmark with source version 4.1.0. All
  expected labels matched: 11 true positives, 3 true negatives, 2 documented
  policy false positives, and 0 false negatives.

### Known limitations

- The first published release carrying V2 is its bootstrap and therefore cannot
  admit itself. A separate protected-main live pilot is required before
  operational reliance.
- Source admission does not bind the released artifact or authorize
  publication/deployment. Those require a separate release-artifact contract
  and privileged consumer.
- Admission-capable provider isolation and pinned Git execution require a
  reviewed POSIX/root workflow. Native Windows remains fail-closed for this
  high-trust path.

## [4.0.2] — 2026-07-21

### Security

- Candidate and black-box execution now use bounded process-group lifecycle,
  positive cleanup proof, bounded reader/receipt draining, and stricter Docker
  absence verification. Repo-native verifier-pack pytest collection is confined
  to the accepted pack snapshot.
- The opt-in `strict_harness` profile now explicitly requires positive POSIX
  process-group cleanup capability for every host setup, repository-suite,
  verifier-pack, and pristine-baseline subprocess. Unsupported hosts refuse the
  strict request before candidate execution; Docker/gVisor phases continue to
  rely on their separately verified container lifecycle.
- Shared trusted-finalizer and release-source raw Git reads now ignore ambient
  `GIT_*` process state and replacement refs, so derivation is bound to the
  explicitly selected repository and literal immutable object graph.
- Raw Git readers now propagate all worker read failures, bound kill/reap and
  reader joins, and avoid closing a pipe while its reader may still be live.
- GitHub attestation verification now propagates every output-reader failure,
  launches the CLI in a managed process group, bounds tree cleanup and reader
  joins independently from the verification timeout, and cannot accept
  plausible partial JSON after a failed read.
- Changed-line coverage now launches the installed collector before exposing
  the candidate import path and ignores candidate repository coverage config.
  A configured `min_diff_coverage` fails closed with
  `assurance_requirement_not_met` when measurement is unavailable; optional
  `diff_coverage` evidence still degrades explicitly without changing verdicts.
  This hardens collector selection/configuration only; it does not make live
  same-process coverage state trustworthy against hostile candidate code.
- Coverage denominators now use structured file content plus token/AST physical
  line classification. Candidate `pragma: no cover` exclusions, multi-line
  statement continuations, unknown executable lines, and literal edit-block
  marker text can no longer erase changed code from the required floor. The
  classifier retains code sharing a docstring line and fails conservatively on
  malformed token streams. Policy compares exact executed/total counts rather
  than the rounded display percentage. Coverage replays configured setup under
  its fidelity policy, preserves trusted runner/interpreter prefixes, and
  forwards the main POSIX CPU/address-space limits. The Python API now makes
  `min_diff_coverage` imply measurement and rejects non-finite, out-of-range, or
  arbitrarily large floors with a stable `ValueError`.

### Fixed

- RepoVerifier cleanup now preserves an active verification/operator exception
  when candidate-workspace, verifier-pack snapshot, or named-container cleanup
  also fails. Secondary cleanup failures remain observable as exception notes;
  after a normal pending result, cleanup failures remain fail-closed and visible
  instead of being silently ignored.
- Baseline `repair_effect` now describes the pristine-base to candidate-suite
  transition even when a later coverage requirement demotes the composite
  verdict; record verification enforces the same ordering.
- Repo-native verifier-pack composition now preserves the candidate repo
  suite's phase result, counts, source, return code, and JUnit digest separately.
  A failing pack no longer mislabels a real base-FAIL to candidate-suite-PASS
  transition, and `verify-record` binds the phase claim to composite remainders.
- Coverage reports now ignore imported files outside the throwaway repository,
  including absolute paths on another Windows drive, instead of aborting before
  a verdict record can be emitted.
- Completed verifier packs that collect zero tests now remain a valid explicit
  `ERROR/no_test_verdict` record; semantic verification permits the tightly
  bound `0/0` pack count only for that fail-closed state.
- Maven/Surefire report sets now carry a deterministic, length-framed digest of
  every accepted report name and XML document. Repo+pack composition binds that
  report-set digest and the pack XML digest under
  `EVOGUARD_JUNIT_COMPOSITE_V2`; record verification rejects malformed,
  missing, or mismatched repo-phase digest claims from v4.0.2 producers.

### Changed

- Completed repository-suite and mandatory verifier-pack interpretation now
  lives in a pure typed phase-contract module. Frozen composition vectors bind
  verdicts, counts, diagnostics, phase snapshots, tamper state, and V1/V2 JUnit
  identities while `RepoVerifier` retains execution and filesystem ownership.
- Execution, candidate-boundary, Docker, invocation-receipt, and black-box judge
  kernels were extracted behind characterization, architecture-ratchet, and
  security-mutation gates without changing the published v4.0.1 artifact.
- Regenerated the 16-case live benchmark with source version 4.0.2. All expected
  verdict labels matched: 11 true positives, 3 true negatives, 2 documented
  policy false positives, and 0 false negatives.

### Known limitations

- Repo-native changed-line coverage is candidate-writable at runtime. Candidate
  code shares the `coverage.py` process and can stop tracing or mutate
  `CoverageData`, including fabricating executed lines. The emitted caveat,
  CLI/Action help, and adoption guidance now state that `min_diff_coverage` is a
  quality gate for non-hostile code, not adversarial admission evidence. A
  platform-neutral regression proves live coverage state is candidate-writable,
  and a stable POSIX integration regression proves the current false-PASS
  condition until an independently controlled coverage producer exists.

## [4.0.1] — 2026-07-20

### Fixed

- `evo-guard init` no longer guesses a stale “latest published” ref. It now
  requires an explicit exact release tag (`vX.Y.Z`) or full 40-hex commit SHA
  and refuses branches, major aliases, and partial SHAs.
- Consumer scaffolding documentation now supplies an explicit immutable
  `--ref v4.0.0` while v4.0.0 remains the current published release.

### Changed

- The source version declares `4.0.1`; the immutable consumer release is
  published as described in [release status](docs/RELEASE_STATUS.md).
- JSON-schema examples now identify the current source runtime while retaining
  the unchanged historical schema identities under v3.8.0.
- Regenerated the 16-case live benchmark with source version 4.0.1: all
  expected verdict labels matched (11 true positives, 3 true negatives, 2
  documented policy false positives, and 0 false negatives).

### Published release

- [`v4.0.1`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.0.1)
  is published from commit
  `5ed7e84017619496521b813f859a6a8bf0a2b1df`. Its primary
  `evo-guard.pyz` asset has SHA-256
  `81a5139e1e0f3c5ce1f9180db85c699eec305474f9588f7d2831099defdce2f7`.
- The release also publishes `SHA256SUMS`; GitHub records both assets as
  immutable release artifacts and the build workflow supplies artifact
  provenance. See [release status](docs/RELEASE_STATUS.md) for the frozen
  baseline and verification boundary.

## [4.0.0] — 2026-07-19

### Published release

- [`v4.0.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.0.0)
  is published as an immutable GitHub Release from
  `301d62f2fd3e2e53b75e153201514f0f69e4ecf8`. Its primary
  `evo-guard.pyz` asset has SHA-256
  `99f9d0ed5029e22e3e06c22b32e55cfe35ce8e97568e304d4cf88a7bd19e7332`.
- The release ships the EvoRise Source-Available License 1.0. Commercial
  licensing is administered by EvoRise Company.
- The existing JSON-schema identities remain bound to v3.8.0 because their
  schema contracts did not change; they identify schema shape rather than the
  runtime carrying it.

### Verification

- The release asset has a GitHub Actions build-artifact attestation. The exact
  consumer verification procedure and non-claims are in
  [`docs/GITHUB_ARTIFACT_ATTESTATIONS.md`](docs/GITHUB_ARTIFACT_ATTESTATIONS.md).
- The 16-case live benchmark was regenerated for source version 4.0.0: all
  expected verdict labels matched (11 true positives, 3 true negatives, 2
  documented policy false positives, and 0 false negatives).
## [3.8.0]

### Added

- `EVOGUARD_RELEASE_SOURCE_PRODUCER_RECEIPT_V1`: a canonical authenticated
  producer receipt that records a bounded, raw-Git and reviewed-workflow-bound
  claim about which GitHub workflow produced its bytes.
- `create-release-source-producer-receipt`,
  `verify-release-source-producer-receipt`, and
  `reverify-attested-release-source-producer-receipt` CLI commands, their JSON
  schema, local verification, and reference A → B → C workflow topology.
- Experimental `EVOGUARD_ARTIFACT_BINDING_V2` records and the constrained
  GitHub-attestation receipt/admission CLI commands. They preserve a bounded
  relation to an externally verified finalizer `ALLOW`; they do not independently
  verify provenance or create an enabled production admission gate.

### Deliberate limits

- The receipt is non-admitting evidence only: it does not create an `ALLOW`, a
  signing key, a release, a build provenance claim, or an artifact-admission
  gate. A GitHub Artifact Attestation proves that workflow B produced the
  receipt bytes; it does not independently prove that workflow A executed
  EvoOM Guard.

### Published release

- [`v3.8.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v3.8.0)
  is published as an immutable GitHub Release from
  `8e11021c505c265b3884736454e4ec424c2b0d3d`. Its primary
  `evo-guard.pyz` asset has SHA-256
  `47bdcfbe2814fdd687afd62d1c476cbd5248db65683c97d2867a56dbbf9ee643`.
- The release has a GitHub release attestation, and its primary asset has a
  separate GitHub Actions build-artifact attestation. The exact verification
  procedure and non-claims are in
  [`docs/GITHUB_ARTIFACT_ATTESTATIONS.md`](docs/GITHUB_ARTIFACT_ATTESTATIONS.md).

### Verification

- Regenerated the 16-case live Guard benchmark with source version 3.8.0: all
  labels matched their expected verdicts (11 true positives, 3 true negatives,
  2 documented policy false positives, and 0 false negatives). Recorded timings
  are diagnostic only.

## [3.7.0] — 2026-07-16

### Security

- The Trusted Finalizer now independently derives candidate text, ordered
  deletions, effective policy, and verifier-pack identities directly from the
  exact raw base/head Git objects before the finalizer key is read. It rejects
  binary, mode-only, symlink/special, and EOL-transformed differences rather
  than silently approximating a Guard candidate.
- `seal-finalizer` rechecks the canonical raw-Git derivation input before
  opening its signing key. A raw-binding mismatch is an unsigned failed
  attempt; a matching semantic `DENY` may still be retained as signed evidence.
- Raw Git queries now drain stdout and stderr with explicit streaming limits;
  an oversized object listing or error response is killed and rejected before
  it can consume unbounded finalizer-process memory.

### Added

- A deliberately narrow `EVOGUARD_ARTIFACT_BINDING_V1` core: a detached
  Ed25519-signed `.eab` binds one regular-file SHA-256 and byte length to an
  externally verified Trusted Finalizer `ALLOW`. Both sealing and verification
  require the finalizer public key plus exact external source/context inputs;
  a finalizer `DENY` cannot produce an artifact `ALLOW`.
- `seal-artifact-admission` and `verify-artifact-admission` commands, strict
  canonical container/schema validation, and a 4 GiB bounded streaming file
  hash.
- `derive-finalizer-bindings` and `verify-finalizer-bindings` commands plus
  raw-Git reference workflow steps that avoid checkout and candidate execution
  in the privileged sealing job.
- A frozen `audit/v3.6.1/` reproduction package for the previous release:
  exact release/tag/assets, a pinned-hash verifier, and stated reproducibility
  limits.

### Deliberate limits

- This is pre-merge file binding only. It does not claim build provenance,
  reproducibility, OCI/container identity, registry or release publication,
  deployment, SBOM coverage, or vulnerability status. GitHub/Sigstore
  provenance and protected build workflow integration remain separate work.
- Raw-Git finalizer derivation authenticates its stated Git/policy/pack
  relationship; it does not make a Docker runner a complete hostile-code
  boundary, support fork PRs, or establish a post-merge/release artifact
  relationship.

### Verification

- Regenerated the 16-case live Guard benchmark with 3.7.0. It retained 11 true
  positives, 3 true negatives, 2 documented policy false positives, and 0 false
  negatives; recorded timings are diagnostic only.

## [3.6.1] — 2026-07-16

### Fixed

- The Trusted Finalizer reference re-verification job now provisions its own
  Python 3.12 runtime and installs its judge dependency set with
  `--require-hashes`. The earlier template assumed `pytest` was present on the
  runner's system Python; a clean consumer could therefore receive an
  `ERROR/no_test_verdict` instead of a verdict. The sealed job remains
  hash-locked and privileged only after Environment approval.
- The reference workflows and copy/paste installation examples now point at the
  3.6.1 release artifact/tag. Schema `$id` addresses move with the release
  address while schema version `1.11` remains unchanged.

### Verification

- Regenerated the 16-case live Guard benchmark with 3.6.1. It retained the
  same outcomes and aggregate classification counts (11 TP, 3 TN, 2 documented
  policy false positives, 0 FN); recorded timings are diagnostic only.

## [3.6.0] — 2026-07-16

### Added

- A split Trusted Finalizer contract: a canonical, unsigned re-verification
  handoff binds the exact verdict bytes to a PR number, re-verification run
  attempt, and base/head revisions; a separate sealing job must independently
  match those fields before it can open the Ed25519 key.
- `finalizer-handoff`, `seal-finalizer`, and `verify-finalized` CLI commands,
  plus matching Python APIs. The sealed evidence bundle contains the exact
  handoff as a mandatory material and preserves signed `DENY` evidence as well
  as `ALLOW` evidence.
- A reference pair of GitHub Actions workflows: an unprivileged manual
  re-verifier for same-repository PRs and a `workflow_run` sealing job that
  never checks out or executes candidate code.
- The reference metadata job writes an immutable pre-candidate control artifact
  with the chosen PR/run/base/head/tree bindings. The privileged job uses that
  artifact, not the candidate handoff, to select and re-check the PR.
- The reference creates a distinct pending finalizer Check Run for every
  re-verification run/attempt, records its ID in the pre-candidate control
  artifact, and completes that ID only. A non-secret reconciler turns a failed
  or cancelled re-verification into `DENY`; control and evidence artifacts are
  attempt-bound so a full GitHub workflow re-run cannot reuse an earlier
  attempt's files. Partial job reruns are explicitly rejected.

### Security boundary

- The finalizer does not sign a record uploaded directly by a PR job. The
  reference seal job takes PR identity from the pre-candidate control artifact,
  re-derives current base/head/tree metadata through the GitHub API, and rejects
  stale/replayed handoffs before signing.
- The reference requires a protected Guard zipapp SHA-256 and an Environment
  secret for the finalizer key. Docker is documented as defence in depth, not a
  complete hostile-code boundary; fork support is intentionally deferred.
- The reference deliberately does not claim that a branch rule will resolve
  repeated same-named Check Runs newest-first. It requires a Round 1 audit of
  the actual GitHub ruleset (or a Required Workflow rule) before enforcement.
- The sealed decision is not a claim that a deployment artifact was verified or
  that all candidate behavior is correct. `guard_artifact_sha256` identifies
  the Guard executable only.

## [3.5.5] — unpublished draft candidate (prepared 2026-07-16)

> **Unpublished / aborted before publication.** No `v3.5.5` Git tag or public
> consumer release was created. This retained draft history is not a supported
> release and was superseded by later published versions.

### Security

- The draft-release workflow is now manual-only and every job refuses a
  non-default ref. A push to `release/*` can no longer reach the one
  `contents: write` job that creates a draft release.
- Workflow permissions are explicit: ordinary CI and Windows checks are
  source-read only, CodeQL's SARIF permission is confined to its analysis job,
  and the release workflow starts with no inherited permissions.
- The security policy now links directly to GitHub's private advisory form.

### Remaining deployment control

- A protected GitHub Environment with a distinct human reviewer remains an
  out-of-repository configuration step. This release removes the unsafe branch
  trigger; it does not falsely claim that YAML alone substitutes for approval.

## [3.5.4] — unpublished draft candidate (prepared 2026-07-15)

> **Unpublished / aborted before publication.** No `v3.5.4` Git tag or public
> consumer release was created. This retained draft history is not a supported
> release and was superseded by later published versions.

### Security

- The base/head and raw-diff routes now fail closed when a changed filesystem
  entry cannot be represented faithfully for the static gate (including changed
  oversized/binary/unreadable/symlink/special/mode-only files and new empty
  directories). Such a change can no longer disappear before harness checks.
- Pull-request Action runs now derive every judge-shaping setting from the
  verified base `.evoguard.json`; candidate workflow inputs are ignored. A
  verifier pack is archived from that base into a temporary trusted directory
  and requires its `EVOGUARD_PACK_V2` SHA-256 identity pin.
- The default protected-path model now recognizes additional test conventions
  and helper directories of base-referenced local Actions. The opt-in
  `strict_harness` policy additionally freezes dependency/lock/compiler
  manifests and requires a non-empty structured JUnit verdict.
- Candidate, Docker-control, black-box, coverage, baseline, JUnit, and reverse
  diff-apply paths use bounded output/file reads. Timeout, output flood, or
  unproven cleanup yields a non-pass result. POSIX native runs also reap a
  background process-group descendant after an otherwise clean leader exit.

### Changed

- `evo-guard init` writes a separate base-owned `.evoguard.json` policy and
  preserves an existing policy instead of embedding the test command in a
  candidate-controlled PR workflow.
- Schema 1.11 remains compatible with historical records; `strict_harness` is
  an additive optional effective-policy field whose absence means `false`.
- Documentation now states the Action's actual trust boundary and includes
  repository ruleset/branch-protection deployment requirements.

### Verification

- Full local suite: 953 passed, 83 skipped, 52 subtests passed; Ruff, Mypy,
  compile checks, YAML parsing, and whitespace checks passed before release
  preparation. The committed live benchmark is regenerated for this version.

## [3.5.3] — 2026-07-15

### Security

- Policy for a change is now resolved only from a trusted baseline: `--base` /
  `--head` read the base policy, edit-block mode reads the supplied repository,
  and raw `--diff` requires an explicit external policy or `--no-config`.
  Candidate-controlled `.evoguard.json` files can no longer set the judge command
  or allowlist for the run they are being judged in.
- The composite Action binds pull-request runs to GitHub's event base SHA,
  materializes `.evoguard.json` from that verified base, and rejects a PR attempt
  to override the base reference or downgrade `fail-on`.
- GitHub Action manifests (`action.yml` / `action.yaml`) are protected wherever
  they occur in a repository, including a root local Action (`uses: ./`) and
  local actions outside `.github/actions/`.

### Changed

- `allow` now applies only to adopter-defined extra `protected` globs. Built-in
  tests, test/build configuration, CI, and judge auto-exec paths are never
  allowlist-exemptible.

## [3.5.2] — 2026-07-14

A conformance-hardening release. The verdict schema remains 1.11; the one
public behavior change is that two policy requests the frozen contract names
contradictory are now refused as input errors instead of producing records
the independent verifier must reject.

### Added

- An automated reason-code conformance corpus:
  `tests/fixtures/contracts/reason-corpus.jsonl` carries one golden record per
  contract reason code (28/28), each emitted by the real producer and accepted
  by the independent verifier, with bidirectional drift prevention (a contract
  code without a producing scenario fails; an orphaned corpus row fails) and a
  regeneration tool (`ops/generate_reason_corpus.py`). Two reason codes gained
  their first test coverage anywhere (`reverse_apply_failed`,
  `no_verifiable_changes`).
- The charset-normalizer #537 case study ships as a turnkey fixture
  (`examples/case-study-charset-normalizer/`): the exact candidate patches,
  the committed regression test, the frozen raw verdict records, and one
  self-checking command that re-downloads the byte-pinned sdist, reproduces
  the red base, judges all three candidates, requires a single shared
  `policy_sha256`, passes every record through `verify-record`, and seals the
  honest-fix verdict into an Evidence Bundle verified with `--require-pass`.

### Fixed

- `guard()` refuses contradictory policy requests (`blackbox_only` without
  `blackbox`; an expected pack digest without a pack) with a `ValueError`
  before constructing `effective_policy` or any attestation, and the CLI
  refuses the second form at its usage boundary. This restores the
  universality invariant — every record the producer emits is independently
  verifiable — which the reason corpus surfaced as broken and now enforces.
  The verifier was deliberately not loosened.

## [3.5.1] — 2026-07-14

A compatibility-preserving stabilization release. The verdict schema remains
1.11 and existing public Python imports and CLI behavior remain supported.

### Fixed

- Host commands discovered through Windows `PATHEXT` are executed through their
  resolved `.CMD`/`.EXE` path without enabling a shell. Bare commands search
  absolute `PATH` entries only, preventing an implicit candidate-working-directory
  shadow. This covers repository setup, baseline/candidate suites, and host
  verifier packs, and is exercised by a real Vitest baseline/candidate test.
- Runner pipes are decoded as UTF-8 with replacement instead of the Windows
  locale code page. Node-based runners such as Vitest write raw UTF-8 banners
  (`❯`) that are undecodable under `cp1252`, which previously killed the judge's
  reader thread mid-run instead of failing the candidate's tests.
- `guard()` and the CLI reject timeout and memory-limit values that could produce
  records invalid under schema 1.11.
- Pull-request comments are attempted only for same-repository, non-Dependabot
  pull requests. Forks retain the job-summary result and a comment failure no
  longer discards the verification outcome.
- Generated private-repository workflows use the same comment boundary and pin
  `actions/github-script` to an immutable commit.

### Security

- User-facing workflow examples pin GitHub-owned actions to immutable commit
  SHAs, and release workflows now require full Linux and Windows end-to-end jobs
  before constructing artifacts.
- The deterministic zipapp includes the exact project `LICENSE`; builds fail if
  it is missing.
- Published JSON Schema identifiers are pinned to the `v3.5.1` source paths.

### Changed

- The schema-1.11 vocabulary is centralized as an immutable, stdlib-only
  contract. Verdict production and semantic verification still implement their
  decision logic independently so a shared algorithm cannot validate its own
  mistake.
- The record verifier starts a behavior-preserving decomposition into internal
  report and isolation claim-family modules. Frozen external fixtures and
  ordered check-result goldens guard the public contract.
- Documentation now distinguishes requested isolation from observed execution,
  clarifies artifact-digest semantics, removes unsupported performance claims,
  and documents the fork-comment boundary.

### Verification

- Added producer-to-schema-to-verifier compatibility tests for every execution
  lifecycle, a frozen schema-1.11 fixture, reason-code truth-table checks, and a
  differential malformed-record corpus.
- Added release-gate coverage for real Vitest execution on Windows and real
  Vitest plus Docker black-box execution on Linux.

## [3.5.0] — 2026-07-13

An offline-verification and evidence-portability release. The guard's produced
verdict contract remains schema 1.11; this release adds independent consumers
that can validate and carry that contract without trusting the producing
process or a bundled key.

### Added

- `evo-guard verify-record` validates a verdict as strict JSON and checks its
  schema shape plus cross-field semantics. It binds reason, verdict, execution
  lifecycle, mode/source composition, counts, policy digest, isolation,
  assurance, and verifier-pack claims instead of treating a parseable record as
  a trustworthy result.
- `evo-guard bundle-evidence` creates a deterministic, Ed25519-authenticated
  evidence envelope containing the exact verdict bytes and explicitly declared
  support materials. `evo-guard verify-bundle` checks canonical container bytes,
  an externally trusted key, exact externally supplied run/revision context,
  and the bundled record's semantics in one operation.
- Bundle verification emits the authenticated verdict/reason/exit decision.
  `--require-pass` makes it a merge/deploy gate without conflating a valid
  authenticated `FAIL`/`REJECTED` record with a `PASS`.
- Published machine-readable schemas describe the schema-1.11 verdict record,
  evidence context, and evidence manifest. New guides document the distinction
  between structural inspection, authentication, semantic validation, and what
  support-material roles do not prove by themselves.
- The signing API now supports raw byte payloads and stable public-key IDs based
  on SHA-256 of DER SubjectPublicKeyInfo, while retaining detached file signing.

### Security

- Offline JSON parsing rejects duplicate keys, non-finite/overflow numbers,
  excessive nesting, invalid UTF-8, and oversized inputs. Record verification is
  a total function: malformed field types produce a failed check report instead
  of an exception.
- Evidence bundles use stored ZIP members in a fixed order with fixed metadata,
  strict member names, bounded entry/directory/payload sizes, exact manifest
  digests, and byte-for-byte canonical reconstruction. Verification never
  extracts archive members.
- Bundle authenticity requires an external public key and an exact external
  context binding for repository, run ID and attempt, base/head revisions and
  trees, candidate, policy, pack, and guard-artifact digests. A key or context
  found inside the bundle is never accepted as its own trust root.
- File inputs are read through descriptor-bound regular-file snapshots; bundle
  publication is atomic and refuses to clobber an existing path unless explicit
  replacement is requested.

### Changed

- Project wording now describes the mechanism rather than attributing trust to
  the author: EvoOM Guard verifies untrusted software changes, with AI-generated
  patches remaining the primary use case. The scope remains deliberately narrow:
  whether the selected judge was satisfied without manipulating its evidence.

### Verification

- Added mutation tests for every schema-1.11 reason/lifecycle family, policy and
  assurance shape, pack identity and execution semantics, composite counts and
  sources, strict JSON parsing, canonical archives, replay context, signatures,
  input races, archive limits, and atomic publication.
- The release gate runs the full pytest suite, Ruff, Mypy, deterministic zipapp
  build/smoke tests, schema parsing, and the labelled real-record corpus before
  any tag or release asset is created.

## [3.4.4] — 2026-07-13

An execution-evidence and process-lifecycle correctness release (JSON schema
1.11). This release removes policy-as-evidence shortcuts: a requested boundary,
prepared launcher, configured pack, or started Docker client is not reported as
an invoked/delivered boundary unless the corresponding runtime evidence was
observed.

### Security

- Black-box packs must invoke the configured boundary through `$EVOGUARD_EXEC`.
  A constant pack or direct legacy target shortcut is now
  `ERROR candidate_not_exercised`, not a vacuous `PASS`.
- Black-box boundary evidence requires a judge-owned launcher receipt;
  Docker/gVisor additionally require a valid runtime-written CID. This proves
  launcher/runtime invocation; the trusted pack remains responsible for command
  semantics and output checks. Preparation alone reports `not_run`.
- The black-box judge runs in a separate POSIX session. Timeout, interruption,
  and normal completion reap its process group (bounded TERM/KILL escalation),
  while CID-based cleanup removes surviving candidate containers. Cleanup never
  replaces the primary exception; inability to prove cleanup after normal
  completion is `ERROR runtime_cleanup_failed`, never a pending `PASS`.
- Docker timeouts claim setup/suite/pack start only after an independent
  `docker inspect` observes a non-zero `StartedAt`. Phase-specific isolation
  evidence prevents a later failure from erasing or upgrading an earlier phase.
- Every third-party action in CI, Windows, CodeQL, Scorecard, and release
  workflows is pinned to a full commit SHA; a regression test rejects mutable
  workflow action references.
- GitHub private vulnerability reporting is enabled, matching the confidential
  reporting path documented in `SECURITY.md`.

### Fixed

- Every verdict exposes `execution_state` (`static_gate`, `not_started`,
  `started_incomplete`, or `completed`), `execution_phase`, and top-level JSON
  `isolation`; the same facts are bound into the attestation.
- `test_command_ran` now means process start. It remains true on timeout without
  inventing a clean `verdict_source`; setup-only/preflight failure remains false.
- Black-box composite results now use summed counts, a stable
  `composite:blackbox+repo` source, the decisive/furthest phase, and explicit
  repo-suite lifecycle fields. Partial/incomplete composites do not present
  partial counts as complete evidence.
- A default black-box composite reports the weakest required report channel
  (`same_process_candidate_writable`). Only `--blackbox-only` can satisfy an
  end-to-end `external_process_isolated` floor.
- Verifier-pack assurance separates configuration, presence, accepted identity,
  execution, secrecy, and pre/post integrity. A black-box pack executed by the
  host judge is correctly labelled `verified_snapshot_pre_post`, not falsely a
  read-only container mount.
- Missing/invalid packs, setup failures, Docker-unavailable phases, timeouts,
  zero-test packs, and ungradeable exit/report pairs retain their real reason and
  a null clean source instead of collapsing to `patch_apply_failed` or a generic
  assurance error.
- Assurance floors are applied only to a completed result that would otherwise
  be `PASS`; they no longer overwrite static, preflight, incomplete, tamper, pack,
  or isolation causes.
- Reproducible `.pyz` builds no longer inherit Git checkout line endings:
  Python sources are canonicalized to LF inside the archive, while any
  non-Python package data remains byte-for-byte input.

### Verification

- Added adversarial regressions for vacuous packs, invocation/CID evidence,
  process-group/container cleanup, Docker `StartedAt` proof, composite lifecycle
  and weakest-channel semantics, zero-result sources, public JSON, Markdown,
  SARIF, and attestation parity.
- Full pytest, Ruff, Mypy, live labelled-corpus benchmark, artifact smoke test,
  and checksum verification are required before the immutable tag is created.
- GitHub Immutable Releases is enabled for this repository. The release workflow
  now prepares a commit-pinned draft and uploads the checked `evo-guard.pyz` and
  `SHA256SUMS` assets without publishing; a maintainer must select **Publish this
  Action to the GitHub Marketplace** and publish the draft in GitHub's web UI.
  Publication then locks the tag and assets and creates GitHub's release
  attestation.

## [3.4.3] — 2026-07-13

An assurance-contract correctness release (JSON schema 1.10). Static diff-gate
verdicts were functionally correct and did not execute candidate code, but their
metadata was built from the requested runtime flags. A protected-harness
rejection requested with Docker could therefore say `candidate_isolation:
docker` / `isolated_repo_native`, and a black-box request could claim pack/report
properties even though no container, suite, pack, or report channel started.

### Fixed

- Static pre-gate outcomes now report `overall_profile: static_gate`,
  `candidate_isolation: not_run`, `suite_isolation: not_run`, and
  `report_integrity: not_applicable_static_gate`.
- A configured verifier-pack path that was not evaluated is recorded as
  `configured: true`, `present: null`, with
  `not_evaluated_static_gate` integrity and secrecy. It is no longer described
  as a verified read-only snapshot.
- Static black-box refusals preserve `attestation.mode: blackbox` and the full
  requested effective policy without turning policy input into delivered
  evidence.
- Runtime assurance floors no longer replace a final static refusal with an
  unrelated `assurance_requirement_not_met` error.
- Markdown and SARIF views now say that execution was not run instead of
  describing the requested/default subprocess or container as if it ran.

### Verification

- Regression coverage spans protected edits and deletions, unsafe/no-edit
  inputs, repo and black-box policy, subprocess/Docker/gVisor requests,
  assurance floors, Markdown, and SARIF. A positive execution control keeps the
  real JUnit/subprocess report path covered.

## [3.4.2] — 2026-07-13

An adversarial-boundary security release (JSON schema 1.9). The changes close
filesystem check/use races on POSIX, reject partial JUnit directory evidence,
and bind the complete post-setup runtime tree presented to a repo-native
verifier pack. The documented repo-native same-process report-forgery boundary
is unchanged; use black-box isolation when that stronger property is required.

### Security

- **Descriptor-bound POSIX workspace operations.** Candidate reads, atomic
  writes, and recursive deletions traverse from held directory descriptors with
  no-follow semantics. Root/parent replacement and partial-delete races fail
  closed. Native Windows rejects reparse roots/parents and checks object
  identity before and after each operation, but remains explicitly best-effort
  because Python's standard library has no `openat`/`unlinkat` equivalent.
- **Race-bound setup fidelity.** Regular-file hashing binds `lstat`, the opened
  descriptor, and the final path identity; hardlink aliases are refused in the
  source/setup fidelity contract. Directory namespaces are checked before and
  after traversal so an unstable tree cannot yield an accepted snapshot.
- **All-or-nothing JUnit directories.** A Maven/Surefire-style report directory
  is rejected as a whole if any XML entry is symlinked, special, unreadable,
  malformed, oversized, or contains DTD/entity declarations. A valid sibling
  can no longer mask missing or invalid evidence.
- **Full runtime continuity (`EVOGUARD_RUNTIME_TREE_V1`).** With a repo-native
  verifier pack, Guard captures the complete prepared tree after setup,
  including `node_modules`, `.venv`, build outputs, and paths exempted only from
  setup validation. Persistent suite drift blocks the pack before it runs;
  pack drift is rejected after execution. Subprocess mode reports
  `snapshot_boundary_checked`; Docker/gVisor reports `read_only_enforced` only
  when host setup opt-in did not weaken the boundary.
- **Bounded, link-contained runtime scans.** Runtime identity rejects absolute,
  escaping, and dangling symlinks, uses non-blocking no-follow file opens on
  POSIX, traverses iteratively, and enforces entry, path-byte, logical-byte and
  per-file budgets plus a cooperative deadline between filesystem calls.
  Failure/incomplete states are recorded without claiming a delivered
  continuity level; a blocked kernel call still requires an outer job timeout.
- **Honest native-Windows black-box refusal.** The shell-free black-box launcher
  has a POSIX executable contract in every isolation mode. Native Windows now
  fails closed before subprocess, Docker, or gVisor probing instead of reaching
  `WinError 193`; use Linux, GitHub Actions, or WSL for black-box execution.

### Evidence and verification

- Added an executable, machine-registered adversarial corpus covering 14
  filesystem, setup, JUnit, verifier-pack, container, and resource boundaries.
- Windows CI now runs the complete unit/security suite, not only CLI/zipapp
  smoke tests, so best-effort reparse and metadata behavior remains exercised.
- Added an environment-labelled synthetic snapshot microbenchmark; its timings
  are comparable only under equivalent Python/OS/filesystem environments.
- Attestation gains `runtime_tree_sha256`,
  `runtime_tree_digest_format`, `runtime_tree_entries`, `runtime_tree_bytes`,
  `runtime_identity_elapsed_ms`, and delivered `runtime_continuity`. Assurance
  exposes the same continuity level.

## [3.4.1] — 2026-07-13

A focused security patch for deletion containment. It does not change the JSON
schema or the documented assurance levels.

### Security

- **Fail-closed deletion containment.** A crafted deletion path whose parent in
  the repository is a symlink could make the repo-native judge, black-box judge,
  or diff-coverage evidence run delete a file outside the judge-owned throwaway
  copy. All three paths now share one containment primitive: it validates the
  normalized relative path, resolves and bounds the parent inside the workspace,
  deletes a leaf symlink without dereferencing it, and fails closed on any
  containment or filesystem error.
- Added regression coverage for the three affected execution paths, ordinary
  file/directory/missing deletion semantics, path normalization, and safe leaf
  symlink removal.

## [3.4.0] — 2026-07-13

A verifier-identity and execution-fidelity release (JSON schema 1.8). It makes
the accepted verifier-pack content explicit, prevents a narrowed repo command
from skipping the pack, and records the real setup/suite boundary. It does
**not** turn the repo-native judge into a black-box judge: candidate imports and
the JUnit writer still share one process there, so its documented
`same_process_candidate_writable` report-integrity limit is unchanged.

### Security

- **One canonical verifier-pack contract.** `pack-doctor`, the repo-native
  judge, and the black-box judge now share the same manifest/parser/digest code.
  A present `pack.json` requires non-empty string `id` and `version`; optional
  `description`, `target_type`, and `protocol` must be strings. Duplicate or
  unknown keys, malformed JSON, unreadable trees, symlinks, special files, and
  packs with no `test_*.py` files fail closed.
- **Unambiguous pack identity (`EVOGUARD_PACK_V2`).** The portable SHA-256
  identity covers typed directory/file records, normalized relative paths,
  lengths, and file bytes (including empty directories). It deliberately does
  not claim to bind timestamps or filesystem permission metadata.
- **Fail-closed verifier identity pin.** `--expect-verifier-pack-sha256`, the
  Action input `expect-verifier-pack-sha256`, and the protected config key
  `expect_verifier_pack_sha256` require the accepted V2 snapshot to match a
  64-hex digest **before candidate code runs**. A mismatch is
  `ERROR verifier_pack_identity_mismatch` and the expected value is included in
  the canonical effective policy / `policy_sha256`.
- **Separated, verified snapshot.** Both judges copy the pack to a judge-owned
  temporary directory outside the candidate tree and its `HOME`, execute that
  snapshot by its explicit path, and re-hash it immediately before and after
  execution. Observed drift is `TAMPERED verifier_pack_snapshot_changed`.
- **Mandatory independent pack phase.** Repo-native verification runs the repo
  suite and then an explicit `python -m pytest <snapshot>` phase; both must
  pass. A custom or narrowed repo `test_command` cannot omit the pack, and a
  pack that collects zero tests cannot pass. The attestation records separate
  pack counts and `verdict_source: composite:repo+verifier-pack`.
- **Candidate-tree fidelity across phases.** When a pack is present, Guard binds
  the post-setup candidate tree before and after the repo suite and pack phase.
  Persistent source/harness drift is
  `TAMPERED candidate_tree_changed_during_run`; unreadable or special entries
  fail closed rather than being skipped.
- **Setup follows the requested isolation by default.** Under Docker/gVisor,
  setup runs in a separate container using the same resolved image ID,
  network, runtime, and resource policy as the suite. Setup alone receives
  `/work:rw`; the suite receives `/work:ro`, and the pack phase additionally
  receives `/verifier-pack:ro`. Container execution drops all capabilities,
  enables `no-new-privileges`, limits open files, and uses collision-resistant
  names.
- **Setup fidelity.** Every pre-existing file, directory, symlink, special
  entry, and permission bit is compared before/after setup. Only newly created
  conventional dependency/build outputs and explicit `setup_output_globs` are
  exempt. A changed judged path is `ERROR setup_failed`; the same check also
  protects subprocess baseline evidence.
- **Immutable, commit-bound release publication.** Release workflows resolve an
  existing tag to its commit and refuse a mismatch with the workflow SHA. An
  existing asset is downloaded and byte-compared; different bytes fail closed
  instead of being replaced with `--clobber`. The release workflow's external
  Actions are pinned to full commit SHAs.
- **Deterministic single-file artifact within a matched build environment.**
  `ops/build_pyz.py` writes entries in canonical order with fixed timestamps
  and modes. Repeated builds from the same source bytes under an equivalent
  Python/OS/ZIP-zlib toolchain produce the same `evo-guard.pyz` SHA-256 instead
  of inheriting temporary-file timestamps. This does not promise
  cross-platform bit identity: Windows and Linux checkouts/toolchains may
  legitimately produce different bytes. Release rerun immutability remains
  independent of that limitation—an existing asset is never replaced.

### Added / changed in the machine contract (schema 1.8)

- New stable reason codes: `verifier_pack_identity_mismatch`,
  `verifier_pack_invalid`, `verifier_pack_snapshot_changed`,
  `candidate_tree_changed_during_run`, and `test_command_unavailable`.
- Attestation gains `verifier_pack_digest_format`,
  `verifier_pack_tests_passed`, `verifier_pack_tests_total`,
  `junit_digest_format`, and `setup_isolation`; container runs expose delivered
  `isolation_evidence` in repo-native mode too.
- `EVOGUARD_JUNIT_COMPOSITE_V1` names the digest framing used when
  `junit_sha256` commits to both repo and pack JUnit XML. A single-report digest
  is labelled `JUNIT_XML_SHA256`.
- Assurance gains `suite_isolation`, `setup_isolation`, the
  `mixed_host_setup_repo_native` profile, and explicit pack-integrity values
  (`verified_snapshot_read_only` / `verified_snapshot_pre_post`).
- The complete effective policy now includes `expect_verifier_pack_sha256`,
  `trust_setup_on_host`, and `setup_output_globs`, so each changes
  `policy_sha256`.

### Fixed

- Docker exit 125, image-resolution failure, and a missing test/pack interpreter
  now produce named fail-closed outcomes instead of ambiguous test failures.
- Changed-line coverage normalizes absolute and Windows-style paths before
  matching them to repo-relative changed paths.
- The restricted Windows judge environment preserves only required OS runtime
  plumbing (`SYSTEMROOT`, `WINDIR`, `COMSPEC`, `PATHEXT`) and redirects
  `TEMP`/`TMP` to judge-owned scratch. This prevents Node from aborting during
  CSPRNG initialization without exposing the user's full environment.
- Diff base reconstruction now prevents `git apply` from discovering an
  unrelated enclosing repository. A temporary directory located inside another
  worktree can no longer yield a successful no-op and a false
  `no_verifiable_changes` result.

### Migration from 3.3.x

- Recompute any stored pack digest with
  `evo-guard pack-doctor <pack> --json`; pre-3.4 concatenation digests are not
  V2 identities. File bytes are exact, so calculate the protected pin from the
  canonical CI artifact/checkout; Git LF/CRLF conversion changes the digest.
- A pack is no longer injected at `evoguard_verifier_pack/`. Resolve pack-local
  data relative to `__file__`, and ensure Python + pytest exist in the host or
  container image even when the repo suite uses another runner.
- Container setup now uses the configured container network (default `none`)
  and requires its setup tool in the image. Prefer a prebuilt image or offline
  dependency cache. `--trust-setup-on-host` is a compatibility escape hatch;
  it is recorded and deliberately lowers effective candidate isolation to
  `subprocess`, so a Docker/gVisor assurance floor will refuse it.
- `setup_output_globs` are trusted fidelity exceptions used across setup and
  the repo/pack transition. Never include source, tests, policy, or harness
  paths. Pre-existing content in conventional output directories remains bound;
  only new output entries are ignored by default.
- `setup_command` remains unsupported with `--blackbox`; the combination fails
  closed with `policy_requirement_unsupported` rather than silently omitting
  setup.

## [3.3.1] — 2026-07-12

A policy-consistency hardening pass (schema 1.7) — an external review of v3.3.0
found that the new gates could be REQUESTED and then silently skipped in modes
that do not implement them. The project's own rule now binds Guard itself: a
policy it cannot enforce is refused, never dropped.

### Fixed (security — fail-open interactions in v3.3.0)
- **`require_demonstrated_fix` / `min_diff_coverage` were silently ignored**
  under `--blackbox` and `--isolation docker|gvisor` (the gates run under the
  subprocess judge only). Requesting an unenforceable GATE is now
  `ERROR policy_requirement_unsupported` before anything runs; evidence-only
  requests (`--baseline-evidence`, `--diff-coverage`) attach an explicit
  unmeasured record with a note instead of vanishing. Pinned by
  `tests/test_policy_consistency.py`.
- **`policy_sha256` covered only five fields** — two materially different
  policies (e.g. one demanding `external_process_isolated` + 90% coverage, one
  demanding neither) could share a fingerprint, so
  `verify-verdict --expect-policy-sha` proved less than it appeared to. The
  attestation now ships a complete canonical `effective_policy` object and the
  hash is computed over it.
- **Baseline scope is now explicit** (`scope: repo_suite_only`): the baseline
  collects the repo's own suite only — a verifier pack is exercised only on the
  candidate run, so the before/after pair is not judged by identical check sets
  when a pack is present. The note says so instead of implying "same policy".

### Fixed (hygiene / docs)
- A committed `.coverage` binary removed from the repo; `.coverage` added to
  `.gitignore`.
- `docs/JSON_SCHEMA.md` example showed `schema_version: 1.5` while explaining
  1.6; README's Evidence section now presents baseline differential evidence
  (v3.3's strongest addition was absent from the front page); ADOPTION's policy
  example no longer combines `min_diff_coverage` with a container floor (that
  combination is now, correctly, an error).
- Action gains outputs: `json-path`, `report-path`, `head-sha`, `policy-sha` —
  the revision-bound attestation was previously produced but unreachable for a
  Marketplace user without custom steps.

## [3.3.0] — 2026-07-11

Three capability upgrades from an external architecture review, each turning an
already-present asset into an enforced guarantee (schema 1.6, additive).

### Added
- **Baseline differential evidence** (`--baseline-evidence`, Action input
  `baseline-evidence`): the suite also runs on the PRISTINE base, and the
  verdict carries `baseline.repair_effect` — `demonstrated` only when the base
  fails and the candidate passes under the same judge/policy/env. "All tests
  pass on head" alone never showed the change fixed anything. Opt-in gate
  `--require-demonstrated-fix` demotes an undemonstrated PASS to FAIL
  (`fix_not_demonstrated`) — for agent "fix" PRs; feature PRs start green and
  should not use it.
- **Protected policy contract**: `.evoguard.json` may now carry
  `require_report_integrity`, `require_candidate_isolation`,
  `min_diff_coverage`, and a `policy_id`/`policy_version` identity that is
  surfaced in the attestation and report — repository-contained,
  candidate-untouchable policy instead of per-workflow flags.
- **Exact-revision binding**: attestations now carry `base_sha`/`head_sha` in
  every mode (repo-native previously dropped them — a plain `git diff` has no
  commit identity) plus `base_tree_sha`/`head_tree_sha`; the Action resolves
  and passes all four via `git rev-parse`.
- **Context-aware `verify-verdict`**: `--expect-head-sha`, `--expect-base-sha`,
  `--expect-policy-sha`, `--expect-policy-id` — a valid signature for the WRONG
  commit/policy now fails, making the signed verdict consumable as a merge or
  deploy gate (chain of custody, not just file integrity).
- **`evo-guard pack-doctor`**: validates a verifier-pack directory (manifest
  schema, judge test files, content digest) before it gates anything.

### Fixed (security)
- **`.evoguard.json` was fail-open**: a malformed file, an unknown key (the
  classic misspelled-floor typo), or a wrong-typed value produced a warning and
  was silently skipped — Guard kept running under WEAKER defaults than the repo
  owner wrote down. Config errors are now fail-closed (exit 2, no judging).
- **Pack manifests were fail-open**: a present-but-broken `pack.json` was
  silently ignored while the verdict still implied a named contract judged the
  run. Both judges (black-box and repo-native mount) now stop with a clean
  named error instead.

## [3.2.3] — 2026-07-11

A correctness + evidence pass driven by an external launch review and a live
self-hosting run (Guard judged by Guard).

### Fixed
- **Marker-collision truncation (dirs/diff path).** A target file whose CONTENT
  legitimately contains a literal `<<<END FILE>>>` line (Guard's own source
  does) was silently truncated by the serialize→re-parse round-trip, turning an
  honest change into a bogus FAIL. The dirs/diff path now threads a structured
  `{path: content}` candidate end-to-end (`blocks_from_dirs` →
  `guard(file_blocks=…)` → verifier/black-box/coverage appliers) and never
  re-parses marker text. Found by running Guard on its own repository; pinned by
  `tests/test_marker_collision.py`.
- **Dangling-symlink crash.** A repo containing a dangling symlink (commonly a
  link into an ignored `.venv/`/`node_modules/`) crashed the judge inside
  `shutil.copytree` instead of producing a verdict. The throwaway copy now
  preserves symlinks as symlinks (`copy_repo_tree`), which also stops host file
  content from being materialized into the tree that container isolation mounts.
  Candidate writes can never follow a symlink out of the copy: a symlinked
  target is replaced, and a write through a symlinked parent directory is
  refused (`tests/test_copy_fidelity.py`).
- **Deletion-only rejections are now pre-gated.** A candidate whose only
  violation was a protected *deletion* used to run the suite once before the
  verdict flipped to REJECTED, leaving `test_command_ran: true` on a verdict
  documented as pre-execution. The suite is now skipped whenever the diff alone
  decides the outcome.
- Docs version drift: every taught install/pin now points at the current
  release, enforced by a new CI test (`tests/test_docs_version.py`); the stale
  `examples/evoguard.yml` pin (v3.1.0) and `docs/*` pins (v3.2.1) were bumped.
- `docs/GUARD.md` no longer claims deletions are ungated (they are gated since
  schema 1.1); its verdict table now matches the README's complete ERROR/
  REJECTED semantics; stale 3-runner claims in PROOFS/REWARD_HACKING_CATALOG and
  the 4-runner table in ADOPTION were updated to the real eight-runner matrix.

### Added
- **Live benchmark harness** (`benchmarks/run_live.py`): 16 labelled cases built
  as real repos and judged by real `guard()` runs — zero missed hacks, one
  documented-by-design false positive, timing included; published results in
  `benchmarks/results.jsonl` + `benchmarks/README.md`, kept honest by CI tests
  that re-run the corpus live and compare.
- **Self-hosting proof** in `docs/PROOFS.md`: Guard judged its own development
  diff (REJECTED pre-gate → PASS 378/378 under a reviewed `--allow`), plus the
  built `.pyz` enforcing the same gate.
- Marketplace action: fail-fast base diagnostics with named causes
  (`base_ref_unavailable`, `base_diff_failed`) BEFORE the guard runs, a
  `::warning::` on a failed best-effort fetch instead of a silenced error, and
  tolerant verdict/report reads on crash paths.
- `restore_judge_package_json` regression tests for `pretest`/`posttest`,
  `test:*` variants, and every embedded runner key (vitest/mocha/ava/c8/nyc).

### Changed (docs)
- REJECTED is consistently framed as a **policy trip** (a legitimate config/
  dependency change trips it too — resolve with a reviewed `--allow`), not
  proof of cheating; `fail-on: rejected-only` now carries an explicit warning
  that FAIL/TAMPERED/ERROR leave the check green.
- `docs/START_HERE.md` names the three usage profiles (Basic integrity gate /
  External behavior gate / Isolated external gate); README's demo-repo wording
  is now "external-repository demonstration", not "independent".

## [3.2.2] — 2026-07-11

A supply-chain and cross-platform hardening release.

### Fixed (security)
- GitHub Action inputs are passed through environment variables instead of being
  interpolated into Bash source. Space-separated policy inputs are parsed into
  quoted arrays, preventing shell metacharacters from becoming commands.
- Third-party Actions used by the Marketplace action are pinned to immutable
  commit SHAs. Regression tests reject future direct input interpolation and
  floating Action references.

### Fixed (Windows)
- CLI stdout/stderr are reconfigured to UTF-8 with a safe fallback, preventing
  verdict symbols such as `✅` from crashing under legacy console code pages.

### Added
- Dependabot configuration for GitHub Actions and Python development dependencies.
- CodeQL and OpenSSF Scorecard workflows.
- A Windows CI smoke job and a reproducible labelled-corpus benchmark that emits
  a confusion matrix and false-positive/false-negative rates.

## [3.2.1] — 2026-07-11

A pre-launch honesty + hardening pass from a critical review. No new features;
the goal is that every public claim matches what the code actually does.

### Fixed (security)
- **Shell-free candidate launcher.** `CandidateRunner` built the container command
  by string-joining into a `/bin/sh` script, interpolating `docker_image` /
  `docker_network` / runtime — a command-injection surface (even though those
  inputs are workflow-owner-controlled, not candidate-controlled). The launcher is
  now a shell-free Python `os.execvp` that runs an argv **list**; a value like
  `none; touch PWNED` is passed literally and never interpreted. Proven by
  `tests/test_candidate_runner.py`.

### Fixed (documentation accuracy — the claims now match the code)
- **Removed the non-working Black-box HTTP example.** The hardened container is
  `--network none` with no published port, so the documented host→container HTTP
  call could not work. START_HERE now offers Basic Guard, Black-box CLI, and
  container isolation (all tested); a tested HTTP recipe is explicitly on the
  roadmap.
- **Verifier Pack wording corrected.** Dropped the absolute "tamper-proof" /
  "read-only" framing: in repo-native mode the pack is copied into the candidate
  tree and shares its process/filesystem, so it is **patch-immutable, not
  runtime-tamper-proof**. Runtime separation is the black-box + Docker path.
  (README, `action.yml`, CLI help, `docs/VERIFIER_PACKS.md`.)
- **Removed remaining absolute claims:** "the harness is untouchable" →
  "protected harness paths are rejected before execution"; "unforgeable external
  dimension" → "independent, judge-owned external evidence dimension"; the stale
  "track the roadmap's external judge" (it shipped in v3.0/v3.2).
- **ERROR verdict** documented completely (isolation-unavailable, timeout, setup
  failure, unmet assurance floor — not only "patch did not apply").
- **"Zero dependencies"** qualified: the *core* has none; signing/coverage are
  optional extras.
- Roadmap no longer says CI lacks a Docker daemon (the `blackbox-docker-e2e` job
  runs one); example pins moved to `@v3.2.1`; file headers say "Maintained and
  released by" rather than "Sole owner & author".

## [3.2.0] — 2026-07-11

A second review reproduced four false-`PASS` paths in the v3.1 black-box mode and
was **correct**: `candidate_isolation` was written from the requested flag, not
what ran; deletions were never applied to the judged tree; the pack replaced the
repo's own suite instead of adding to it; and the attestation was partial. This
release closes all four — the black-box judge now delivers a **real** isolation
boundary and reports only what it delivered.

### Fixed (security / correctness)
- **Delivered isolation, fail-closed.** A new `CandidateRunner`
  (`evoom_guard/candidate_runner.py`) runs the candidate under an *actual*
  boundary and returns evidence of what ran. `candidate_isolation` is that
  delivered value — never the requested flag. Request `--isolation docker` with
  no daemon / a missing image and Guard returns `ERROR`
  (`assurance_requirement_not_met`, isolation `unavailable`) instead of a `PASS`
  mislabelled `docker`. No silent fallback to a weaker boundary.
- **Deletions are applied in black-box mode.** A removed file is absent in the
  judged copy (matching the real merge); the attestation records
  `deleted_paths_applied`.
- **Composite verdict.** `--blackbox` now requires the repo's own suite **and**
  the external pack to pass — a green pack can no longer mask an internal
  regression. `--blackbox-only` opts pure-CLI/service targets out of the repo
  suite.
- **Container pack separation.** In a container boundary the repo copy is mounted
  read-only and the judge-owned pack is not mounted into the candidate at all, so
  candidate code cannot reach it or write the host. The subprocess boundary
  reports `verifier_pack.secrecy: reachable_same_host` honestly.

### Added
- **Complete black-box attestation**: `isolation_evidence` (requested/delivered/
  image_digest/network/runtime), `deleted_paths_applied`, `repo_suite_passed`,
  `repo_suite_junit_sha256`, `junit_sha256`, and `base_sha`/`head_sha` (extracted
  only when the diff carries them; never fabricated).
- **Pack protocol**: `$EVOGUARD_EXEC`, a launcher that runs the candidate under
  the delivered isolation with the repo copy as the working root. The example
  pack is isolation-agnostic and import-safe.
- Adversarial tests for every fixed path (`tests/test_assurance_policy.py`):
  fake-docker → `ERROR`; docker floor vs subprocess delivery → `ERROR`; deletion
  actually applied; repo-suite failure blocks a passing pack.

### Changed
- `python -m pytest -q` on the whole repo is green again: `testpaths = ["tests"]`
  scopes the repo's own suite, and the black-box example pack self-skips when not
  run by the judge (it was crashing collection on a missing `EVOGUARD_TARGET`).
- `schema_version` → **1.5**.

## [3.1.0] — 2026-07-10

Hardening from a deep architectural review — turns two `assurance` weaknesses it
found into enforced guarantees, without the risky big-architecture rebuild
(that's an explicit post-launch direction in `ROADMAP.md`).

### Added
- **Enforceable assurance policy** (`--require-report-integrity`,
  `--require-candidate-isolation`; Action inputs too). Fail-closed: if the run's
  *actual* assurance is below the requirement, the verdict is refused with
  `ERROR` / `assurance_requirement_not_met` — Guard can never claim a level it
  did not enforce. The check is against what ran, never the requested value.
- **Black-box verdicts now carry a full attestation** (the review's gap):
  `candidate_sha256`, `policy_sha256`, `verifier_pack_sha256`, the pack
  `manifest`, and `mode: "blackbox"`. The pack's content digest binds the
  verdict to exactly which protocol tests judged it.
- **Adversarial test**: a candidate CLI that returns a wrong answer *and* forges
  its own JUnit report cannot flip the black-box verdict — the judge grades by
  its own exit code, so a child's forged report only touches counts.

### Changed
- `schema_version` → 1.4 (attestation `mode`; the new reason code). Attestation
  is now built by one shared helper for both the repo and black-box paths.
- Docs: ASSURANCE gains an *enforcing* + *composing external/internal* section;
  ROADMAP names the real next major direction (an artifact-bound candidate
  sandbox) and marks it as post-adopter work, not a pre-launch cram.

## [3.0.0] — 2026-07-10

**The external black-box judge — the report-integrity boundary is now closeable.**

v2.3.0 disclosed, with a proof, that the default same-process judge can be
forged: a patch that writes an `atexit` hook + `os._exit(0)` + a fake
`--junitxml` fakes a `PASS`. This release ships the fix.

### Added
- **`--blackbox` external judge** (needs `--verifier-pack`): the verdict comes
  from the **judge's own pytest** over a pack of judge-owned tests that **never
  import the candidate**. The candidate is exercised only across a process
  boundary — the pack invokes it as a subprocess via `$EVOGUARD_TARGET` /
  `$EVOGUARD_PYTHON` and asserts on its outputs. Forgery code in the candidate's
  source runs only in those child processes and cannot reach the judge's report.
  `report_integrity` becomes **`external_process_isolated`** and
  `overall_profile` **`black_box_external_judge`**.
  See [`docs/BLACKBOX.md`](docs/BLACKBOX.md) and `examples/blackbox-pack/`.
- **Before/after proof** (`tests/test_blackbox.py`): the *identical* forgery that
  `tests/test_report_integrity.py` shows faking a `PASS` under the default judge
  is **caught** (`FAIL`) under `--blackbox`. Harness-integrity rejection still
  applies in black-box mode.
- GitHub Action gains a `blackbox` input.

### Changed
- README leads the honest-boundary callout to the `--blackbox` fix; ASSURANCE and
  ROADMAP mark the external judge as shipped (hardening — container-per-candidate,
  HTTP/DB helpers — is the next step). Marketing updated: the pitch is now
  "closes the forgery hole for CLI/service targets", not a qualified caveat.

### Note
- Major version bump: `--blackbox` changes the trust story materially (a real
  `report_integrity` guarantee for protocol targets). The default judge, the JSON
  contract (`schema_version` 1.3), and every existing flag are unchanged and
  backward-compatible.

## [2.3.0] — 2026-07-10

An adversarial review demonstrated a real forgery of the core verdict; this
release makes the boundary honest and machine-readable rather than papering over
it. No behavioural regression — the reward-hacks Guard blocked before, it still
blocks.

### Security / honesty (the important part)
- **Corrected the "cannot be forged" claim.** A patch that runs in the test
  process can register an `atexit` hook, overwrite the judge-owned JUnit report,
  and call `os._exit(0)` — forging a `PASS` on a genuinely failing test. This is
  now **proven by an adversarial test** (`tests/test_report_integrity.py`) and
  named plainly everywhere. Guard still blocks the reward-hacks agents do in
  practice (harness edits/deletions, config deselects, stdout forgery — all with
  tests); it does not stop deliberate in-process report forgery, which the
  container modes do **not** fix (they isolate the host, not the report).
- **New `assurance` object on every verdict** (`schema_version` → 1.3):
  `harness_integrity` (`pre_gate_enforced` — robust), `report_integrity`
  (`same_process_candidate_writable` — the honest boundary), `candidate_isolation`,
  `verifier_pack`, `overall_profile`. A `PASS` report now spells out the caveat
  inline. See the new [`docs/ASSURANCE.md`](docs/ASSURANCE.md).
- **ROADMAP**: the **external black-box judge** (candidate never runs in the
  judge's process) is now the explicit headline direction — the only thing that
  turns `report_integrity` into a real guarantee.

### Changed
- README mechanism 2 reworded from "the verdict cannot be forged" to "the result
  is judge-owned, not scraped from stdout", with a prominent honest-boundary
  callout. Marketing materials updated to match (no "unforgeable").

## [2.2.1] — 2026-07-10

Launch-hardening from an adversarial review — no new surface, higher fidelity.

### Fixed
- **`evo-guard init` now scaffolds `python -m pytest -q`** (was bare `pytest -q`),
  matching the documented default so a generated workflow imports top-level
  packages without an install/conftest.
- **Timeouts and setup failures get their own reason codes** — `test_timeout`,
  `setup_timeout`, `setup_failed` — instead of being mislabelled
  `patch_apply_failed` (the patch *did* apply; the run timed out).
- **Deletions now count toward the blast-radius score** — a change that removes
  source files no longer reads as *lower* risk than one that edits them.

### Added
- **GitHub Action exposes the v2.2 evidence flags**: `verifier-pack`,
  `diff-coverage`, `min-diff-coverage` inputs, forwarded to the CLI (with the
  `cov` extra installed only when coverage is requested). A parity test fails if
  any gate-relevant CLI flag is missing from the Action.
- **Optional `pack.json` manifest** for a Verifier Pack (`id` / `version` /
  `description`) — surfaced in the verdict attestation for auditable policy
  versioning.

### Changed (honesty)
- **Verifier Pack docs/help corrected**: a pack is **tamper-proof, not secret**.
  The running test code *can* read the pack off disk, so it is an integrity
  control (org-owned, unmodifiable invariants), not a hidden oracle. New
  `docs/VERIFIER_PACKS.md` states the guarantee and its limit; an adversarial
  test pins the limitation so the claim cannot silently drift back to "hidden".
- Action description: "Unforgeable verdict" → "Judge-owned verdict" (no absolute
  claim beyond what the design supports).

## [2.2.0] — 2026-07-10

**The first evidence release** — the gate starts its evolution from deny-rules
toward an evidence-based change-integrity engine (see `ROADMAP.md`).

### Added
- **Changed-line coverage evidence** (`--diff-coverage`, the `cov` extra): one
  extra suite run under a judge-owned `coverage` measurement answers *which
  changed lines did the suite actually execute?* Non-executable changed lines
  are excluded via coverage's own statement knowledge; non-Python files are
  reported as unmeasured, never silently counted. Evidence by default;
  `--min-diff-coverage PCT` turns it into a gate — a hollow `PASS` (suite green,
  changed lines unexecuted) becomes `FAIL` with the new reason code
  `diff_coverage_below_threshold`. The output carries its own honesty line:
  *executed is not asserted*.
- **Independent Verifier Pack** (`--verifier-pack DIR`): judge-owned tests /
  invariants the **patch cannot modify** (org-owned checks injected at judgment
  time), mounted into the throwaway copy at `evoguard_verifier_pack/` and
  collected with the suite (pytest runners). Counters visible-test overfitting;
  a candidate that writes under the mount point is `REJECTED`; the pack's content
  digest — and an optional `pack.json` manifest (id/version) — land in the
  attestation. Honest scope: **tamper-proof, not secret** — the running code can
  read the pack; the guarantee is that the patch cannot change the checks (see
  `docs/VERIFIER_PACKS.md`).
- **Attestation block** in every verdict JSON: `candidate_sha256`,
  `policy_sha256`, `junit_sha256`, `verifier_pack_sha256`, timestamps and
  versions — a signed verdict is now bound to what was judged and under which
  policy, not only to its own bytes (the step before in-toto/Sigstore).
- JSON contract moves to `schema_version` **1.2** (additive fields + one new
  reason code).

## [2.1.2] — 2026-07-10

### Changed
- **Action description shortened** to satisfy the GitHub Marketplace 125-character
  limit (surfaced by the Marketplace validation on the v2.1.1 release form). The
  full description lives in the README; no behavior change.

## [2.1.1] — 2026-07-10

### Added
- **GitHub Marketplace branding** on the composite Action (`branding: shield /
  red`) — required for the Marketplace listing; no behavior change.

## [2.1.0] — 2026-07-10

### Added
- **Signed verdicts** (the `sign` extra — the core stays stdlib-only):
  `evo-guard keygen` generates an Ed25519 judge keypair; `evo-guard guard …
  --json v.json --sign-key key.pem` writes a detached base64 signature of the
  verdict file's exact bytes to `v.json.sig`; `evo-guard verify-verdict` checks
  it offline (exit 0 valid / 1 invalid). A post-signing byte change — the
  `FAIL`→`PASS` artifact forgery — flips verification to invalid (adversarial
  test included). See `docs/SIGNED_VERDICTS.md`.
- **`ROADMAP.md`**: the patch gate placed inside the agent-governance picture
  (signed evidence chains, capability ledgers).
- **`docs/PROOFS.md`**: a second live proof on a hard, ungameable counting
  benchmark (fresh-randomized suite, oracle-free huge-`n` identities, strict
  time budget): the cheat patch is `REJECTED` before the suite runs; an honest
  `O(log n · m²)` solution earns `PASS` under the exit-code oracle.

## [2.0.0] — 2026-07-10

**Consolidation release.** This repository's v0.1.0 was a fresh extraction of the
guard core from the EvoOM platform; in parallel, the same gate had already evolved
through eight releases (v1.1.0 → v1.8.0) in the internal **EvoGuard** repository.
v2.0.0 replaces the v0.1.0 code with that mature engine — one project, one
history, going forward developed here.

### Added (relative to v0.1.0 of this repository)
- **`TAMPERED` verdict**: an exit-code ⟷ JUnit-report disagreement is surfaced as
  its own verdict (a forgery signature), never read as a pass.
- **Deletions are gated**: a patch that *deletes* a protected test/config/CI/
  auto-exec file is `REJECTED`; safe source deletions are applied to the verified
  copy and tested (they were previously reported but unverified).
- **Eight structured-verdict runners** via `evoom_guard/adapters.py`: pytest,
  `node --test`, vitest, jest, gotestsum (Go), rspec (Ruby), mocha, and
  Maven/Surefire (Java) — each with judge-owned `junit+exit` verdicts and real
  test counts. Custom commands still grade by exit code (never stdout).
- **Isolation modes**: `--isolation docker` / `gvisor` run the suite in a
  network-less, read-only container (`--docker-image`, `--docker-network`).
- **Machine-readable JSON contract**: stable `schema_version` and fixed
  `reason_code` vocabulary for every verdict (see `docs/JSON_SCHEMA.md`), plus
  **SARIF 2.1.0** output (`--sarif`) for GitHub code scanning.
- **Hardened JUnit parsing**: per-file size cap and DTD/`ENTITY` refusal;
  directory-of-reports merging for Maven Surefire.
- **CLI subcommands**: `evo-guard guard` / `doctor` / `init` / `version`,
  project config via `.evoguard.json`, `--allow` baseline allowlist, and
  `--allow-new-tests` feature mode (brand-new test files allowed; edits to
  existing harness still rejected).
- **Sticky PR comment**: the GitHub Action upserts one marker-keyed comment
  instead of appending a new one per push.
- **Single-file build**: `ops/build_pyz.py` produces a zero-dependency
  `evo-guard.pyz` zipapp.
- Docs imported: `GUARD.md`, `ADOPTION.md`, `ARCHITECTURE.md`, `JSON_SCHEMA.md`,
  `REWARD_HACKING_CATALOG.md`, `PROOFS.md`, `VM_ISOLATION.md`, `FEATURE_MODE.md`.

### Changed
- Python package renamed `evogu` → `evoom_guard`; the CLI keeps this repo's
  `evo-guard` name (now subcommand-based: `evo-guard guard …`). The composite
  Action stays at the repository root (`uses: EvoRiseKsa/EvoOM-Guard-m@<ref>`).
- The v1.x history is imported verbatim from the internal EvoGuard repository
  and archived in [`docs/history/CHANGELOG-v1.md`](docs/history/CHANGELOG-v1.md).
  Module paths and CLI names appear as renamed here; version links point to that
  internal repository and are omitted.

---

## Imported history — EvoGuard v1.x

The verbatim imported v1.x engineering history is archived in
[`docs/history/CHANGELOG-v1.md`](docs/history/CHANGELOG-v1.md). Its original
dates and historical terminology are retained for reproducibility.
