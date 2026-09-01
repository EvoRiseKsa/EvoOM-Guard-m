<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see ../LICENSE for permitted use.
-->

# EvoOM Guard documentation

Use this index to choose documentation by task and audience. EvoOM Guard is the
product, `evo-guard` is the CLI, and `evoom_guard` is the Python package.

## Version boundary

- **Latest published stable release:** [`v4.7.1`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.7.1).
- **Consumer pin:** `v4.7.1`, or commit
  `b222c7df0a3eaef6e89287cd1354625b88ac8b8b` for the strictest immutable
  identity. Its maintained, detached-maintainer-signed
  [`DIRECT_RELEASE.json`](../evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json)
  and [detached signature](../evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json.sig)
  records the successful `simple-release-v1` publication. This same-owner
  record is not an A-through-H release ledger or independent review.
- **Historical A-through-H evidence:** `v4.6.0` remains the newest validated
  release of that archived lane, recorded by its canonical signed
  [`RELEASE_LEDGER.json`](../evidence/release-ledgers/v4.6.0/RELEASE_LEDGER.json).
- **Repository source:** use the exact checked-out commit; its lifecycle is
  reported by the status authorities below.
- **Status authority:** [`PROJECT_STATUS.md`](PROJECT_STATUS.md) and
  [`RELEASE_STATUS.md`](RELEASE_STATUS.md).
- **Exception records:** [`errata/V4.4.0-LEDGER.md`](errata/V4.4.0-LEDGER.md)
  and [`errata/V4.4.1-LEDGER.md`](errata/V4.4.1-LEDGER.md) record the separate
  verified publication facts, frozen validator defects, and new-release
  recovery boundaries without claiming to be ledgers.
- **Documentation erratum:** [`errata/V4.6.0-MARKETPLACE-README.md`](errata/V4.6.0-MARKETPLACE-README.md)
  records the pre-ledger README text frozen in the immutable `v4.6.0` tag; it
  does not invalidate or amend the signed release ledger.

Repository documentation follows the source tree and may describe behavior
absent from the latest consumer release. Advanced pages state their
implementation and evidence boundary. Use the immutable release tag or its
full commit SHA in consumer repositories, and do not use `@main` as a
production channel.

## Pick a path

| You want to… | Start here | Then read |
|---|---|---|
| Evaluate the product quickly | [`START_HERE.md`](START_HERE.md) | [`ASSURANCE.md`](ASSURANCE.md) |
| Add the gate to a repository | [`ADOPTION.md`](ADOPTION.md) | [`GUARD.md`](GUARD.md) |
| Check readiness and stage a non-blocking rollout | [`PREFLIGHT.md`](PREFLIGHT.md) | [`ADOPTION.md`](ADOPTION.md) |
| Judge a CLI externally | [`BLACKBOX.md`](BLACKBOX.md) | [`VERIFIER_PACKS.md`](VERIFIER_PACKS.md) |
| Design a production deployment | [`PRODUCTION_BLUEPRINT.md`](PRODUCTION_BLUEPRINT.md) | [`PRODUCTION_OPERATIONS.md`](PRODUCTION_OPERATIONS.md) |
| Review security claims | [`ASSURANCE.md`](ASSURANCE.md) | [`REWARD_HACKING_CATALOG.md`](REWARD_HACKING_CATALOG.md) |
| Inspect the prospective semantic extraction boundary | [`SEMANTIC_CORE_EXTRACTION_PLAN.md`](SEMANTIC_CORE_EXTRACTION_PLAN.md) | [`CANDIDATE_TEXT_MAP_IDENTITY_V2.md`](CANDIDATE_TEXT_MAP_IDENTITY_V2.md) |
| Integrate machine-readable evidence | [`JSON_SCHEMA.md`](JSON_SCHEMA.md) | [`RECORD_VERIFICATION.md`](RECORD_VERIFICATION.md) |
| Consume signed positive and negative attempts | [`CHANGE_ATTEMPT_OBSERVATION.md`](CHANGE_ATTEMPT_OBSERVATION.md) | [`adr/0009-change-attempt-observation-v1.md`](adr/0009-change-attempt-observation-v1.md) |
| Maintain or release the project | [`RELEASING.md`](RELEASING.md) | [`GOVERNANCE.md`](GOVERNANCE.md) |
| Understand the implementation | [`architecture/OVERVIEW.md`](architecture/OVERVIEW.md) | [`adr/0001-layered-architecture.md`](adr/0001-layered-architecture.md) |

## Getting started

- [`START_HERE.md`](START_HERE.md) — choose the basic, black-box, isolated, or
  Trusted Finalizer path.
- [`ADOPTION.md`](ADOPTION.md) — install, configure, and interpret the gate in a
  consumer repository.
- [`PREFLIGHT.md`](PREFLIGHT.md) — statically diagnose runner risks and move
  from read-only observation to a required blocking check.
- [`CASE-STUDY.md`](CASE-STUDY.md) — reconstruct a bounded historical upstream
  bug-fix demonstration.
- [`../SUPPORT.md`](../SUPPORT.md) — route product questions, bug reports,
  vulnerability reports, and commercial support requests.

## User guide

- [`GUARD.md`](GUARD.md) — primary CLI, input forms, base-owned policy, protected
  paths, execution, and output behavior.
- [`BLACKBOX.md`](BLACKBOX.md) — external judge channel and the difference
  between composite `--blackbox` and `--blackbox-only`.
- [`VERIFIER_PACKS.md`](VERIFIER_PACKS.md) — candidate-independent,
  organization-owned tests and pack identity.
- [`FEATURE_MODE.md`](FEATURE_MODE.md) — safely allow new test files without
  allowing edits to existing judge inputs.
- [`OPERATING_PROFILES.md`](OPERATING_PROFILES.md) — named assurance profiles
  and their prerequisites; check the page's release boundary.
- [`SIGNED_VERDICTS.md`](SIGNED_VERDICTS.md) — Ed25519-signed verdict records.
- [`EVIDENCE_BUNDLES.md`](EVIDENCE_BUNDLES.md) — authenticated portable bundles
  with external context.
- [`RECORD_VERIFICATION.md`](RECORD_VERIFICATION.md) — offline consistency and
  admission-oriented record checks.

## Reference and admission contracts

These pages define narrow contracts. An `ALLOW` or verified result under one
contract does not authorize another stage such as publication or deployment.

- [`JSON_SCHEMA.md`](JSON_SCHEMA.md) — stable verdict JSON fields,
  `schema_version`, reason codes, and execution-state semantics.
- [`BLAST_RADIUS.md`](BLAST_RADIUS.md) — frozen advisory V1 plus the
  `v4.6.0` materialized-change V2 contract, migration, and non-claims.
- [`ARTIFACT_ADMISSION.md`](ARTIFACT_ADMISSION.md) — narrow file-artifact
  admission V1.
- [`ARTIFACT_DIGEST_ADMISSION_V2.md`](ARTIFACT_DIGEST_ADMISSION_V2.md) —
  digest-bound artifact admission V2.
- [`ARTIFACT_PROVIDER_V3.md`](ARTIFACT_PROVIDER_V3.md) — `v4.6.0`
  library-only public-GHCR OCI provider relation layered over V2.
- [`GITHUB_ATTESTATION_ADMISSION.md`](GITHUB_ATTESTATION_ADMISSION.md) —
  protected-boundary adapter for GitHub Artifact Attestations.
- [`AGENT_CHANGE_ADMISSION.md`](AGENT_CHANGE_ADMISSION.md) — bind an untrusted
  agent proposal to signed scope, re-derived facts, and finalization.
- [`ADMISSION_DECISION_ENVELOPE.md`](ADMISSION_DECISION_ENVELOPE.md) —
  `v4.6.0` library-only, proof-bound in-toto decision projection for a fully verified Agent
  Change admission; it grants no external-action authority by itself.
- [`CHANGE_ATTEMPT_OBSERVATION.md`](CHANGE_ATTEMPT_OBSERVATION.md) — project
  authenticated `ALLOW` and `DENY` attempts into one correlated,
  advisory-only, privacy-bounded contract.
- [`evidence/change-attempt-corpus-v1.md`](evidence/change-attempt-corpus-v1.md)
  — same-owner engineering evidence for the signed five-case development
  corpus, with exact identities, outcomes, and non-claims.
- [`AUTHENTICATED_PRODUCER_RECEIPT.md`](AUTHENTICATED_PRODUCER_RECEIPT.md) —
  non-admitting producer receipt contract.
- [`RELEASE_SOURCE_FINALIZER.md`](RELEASE_SOURCE_FINALIZER.md) — release-source
  finalization boundary V1.
- [`RELEASE_SOURCE_ADMISSION_V2.md`](RELEASE_SOURCE_ADMISSION_V2.md) — protected
  source admission with signed A/B/C bindings.
- [`RELEASE_ARTIFACT_ADMISSION_V1.md`](RELEASE_ARTIFACT_ADMISSION_V1.md) —
  source-bound external artifact admission.
- [`RELEASE_LEDGER_V2.md`](RELEASE_LEDGER_V2.md) — protected release-ledger
  schema and evidence semantics.

## Security assurance

- [`ASSURANCE.md`](ASSURANCE.md) — what each verdict can and cannot establish.
- [`REWARD_HACKING_CATALOG.md`](REWARD_HACKING_CATALOG.md) — modeled attacks,
  defenses, tests, and residual risks.
- [`REPOSITORY_PROTECTION.md`](REPOSITORY_PROTECTION.md) — why branch, workflow,
  policy, and review protection are part of the gate.
- [`VM_ISOLATION.md`](VM_ISOLATION.md) — VM-class isolation design and current
  implementation boundary.
- [`ISOLATION_CONFORMANCE.md`](ISOLATION_CONFORMANCE.md) — isolation adapter
  requirements and conformance evidence.
- [`../evidence/runtime-observations/v4.5.0-gvisor-31298956172/`](../evidence/runtime-observations/v4.5.0-gvisor-31298956172/)
  — closed, byte-bound public subset from one same-owner GitHub-hosted gVisor
  run; not independent, production, field, or hostile-host evidence.
- [`RUNNER_CONFORMANCE.md`](RUNNER_CONFORMANCE.md) — runner adapter behavior and
  fail-closed checks.
- [`TRUSTED_FINALIZER_HARDENING.md`](TRUSTED_FINALIZER_HARDENING.md) — raw-Git
  derivation and finalizer hardening.
- [`FUZZING.md`](FUZZING.md) — fuzz targets, execution, and scope.
- [`DEPENDENCY_POLICY.md`](DEPENDENCY_POLICY.md) — CI and release dependency
  integrity.
- [`GITHUB_ARTIFACT_ATTESTATIONS.md`](GITHUB_ARTIFACT_ATTESTATIONS.md) —
  provenance scope and bounded verification procedure.
- [`SBOM.md`](SBOM.md) — SPDX member inventory and its explicit non-claims.
- [`INDEPENDENT_EVALUATION.md`](INDEPENDENT_EVALUATION.md) — blind evaluation
  protocol for evidence beyond same-owner testing.
- [`AGENT_ORIGIN_EVALUATION.md`](AGENT_ORIGIN_EVALUATION.md) — canonical
  agent-origin metadata, attestation semantics, and separation of gate-efficacy
  from agent-behaviour studies.

For vulnerability reporting, use [`../SECURITY.md`](../SECURITY.md). Do not
publish secrets, private keys, credentials, customer policy, held-out labels,
unannounced vulnerabilities, or private operational logs.

## Operators

- [`PRODUCTION_BLUEPRINT.md`](PRODUCTION_BLUEPRINT.md) — deployment profiles,
  prerequisites, and production-readiness criteria.
- [`PRODUCTION_OPERATIONS.md`](PRODUCTION_OPERATIONS.md) — production operating
  contract, fail-closed conditions, and evidence retention.
- [`TRUSTED_FINALIZER.md`](TRUSTED_FINALIZER.md) — split re-verification and
  sealing boundary for admission.
- [`FINALIZER_DEPLOYMENT_KIT.md`](FINALIZER_DEPLOYMENT_KIT.md) — deterministic
  no-clobber installation and static inspection of the v4.5.0 workflow pair.
- [`OPERATIONAL_TELEMETRY.md`](OPERATIONAL_TELEMETRY.md) — privacy-allowlisted
  local summaries; not complete run inventory or an SLO system.
- [`PROJECT_STATUS.md`](PROJECT_STATUS.md) — implementation state, public/private
  boundary, pilots, and evidence map.
- [`RELEASE_STATUS.md`](RELEASE_STATUS.md) — current source-to-release
  relationship and published asset boundary.

## Maintainers and release operators

These documents are public for reviewability, but they are maintainer runbooks
rather than end-user setup instructions. Live credentials, key locations,
customer configuration, and incident contacts remain private.

- [`GOVERNANCE.md`](GOVERNANCE.md) — role separation, public/private evidence,
  change review, and release-history policy.
- [`RELEASE_TRUST_PIPELINE.md`](RELEASE_TRUST_PIPELINE.md) — protected A–H
  pipeline and distinct decision boundaries.
- [`V4.5.1_MAINTENANCE_LANE.md`](V4.5.1_MAINTENANCE_LANE.md) — inert,
  one-time stable-patch contract and the verified blockers to safe activation.
- [`RELEASE_GATE_CHECKLIST.md`](RELEASE_GATE_CHECKLIST.md) — release hardening
  and acceptance checklist.
- [`RELEASE_LEDGER_V2_ASSEMBLY.md`](RELEASE_LEDGER_V2_ASSEMBLY.md) — offline
  assembly and verification procedure.

Repository-level maintainer documents:

- [`../CONTRIBUTING.md`](../CONTRIBUTING.md) — contribution and review policy.
- [`../GOVERNANCE.md`](../GOVERNANCE.md) — project governance summary.
- [`../SECURITY.md`](../SECURITY.md) — vulnerability disclosure process.
- [`../CHANGELOG.md`](../CHANGELOG.md) — chronological product changes.

## Architecture

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — public architectural overview and trust
  boundaries.
- [`architecture/CURRENT_STATE.md`](architecture/CURRENT_STATE.md) — short
  present-tense map of the current development architecture.
- [`architecture/OVERVIEW.md`](architecture/OVERVIEW.md) — layered architecture
  and refactor posture.
- [`architecture/MODULE_BOUNDARIES.md`](architecture/MODULE_BOUNDARIES.md) —
  module responsibilities and allowed collaboration.
- [`architecture/DEPENDENCY_RULES.md`](architecture/DEPENDENCY_RULES.md) —
  dependency direction and enforcement.
- [`architecture/INVARIANTS.md`](architecture/INVARIANTS.md) — behavior and
  security invariants.
- [`architecture/TRUST_BOUNDARIES.md`](architecture/TRUST_BOUNDARIES.md) —
  candidate, judge, policy, key, and provider boundaries.
- [`architecture/STATE_MACHINE.md`](architecture/STATE_MACHINE.md) — execution
  state and reason-code contracts.
- [`architecture/COMPATIBILITY_MATRIX.md`](architecture/COMPATIBILITY_MATRIX.md)
  — compatibility commitments during the behavior-preserving refactor.
- [`architecture/REFACTOR_PROGRAM.md`](architecture/REFACTOR_PROGRAM.md) —
  maintainer execution plan and historical refactor record.

### Architecture decision records

- [`adr/0001-layered-architecture.md`](adr/0001-layered-architecture.md) —
  layered architecture and boundaries.
- [`adr/0002-public-api-compatibility.md`](adr/0002-public-api-compatibility.md) —
  public API compatibility first.
- [`adr/0003-execution-kernel.md`](adr/0003-execution-kernel.md) — execution
  kernel extraction.
- [`adr/0004-producer-verifier-separation.md`](adr/0004-producer-verifier-separation.md)
  — producer/verifier separation.
- [`adr/0005-canonical-evidence-primitives.md`](adr/0005-canonical-evidence-primitives.md)
  — canonical evidence primitives.
- [`adr/0006-error-taxonomy.md`](adr/0006-error-taxonomy.md) — error taxonomy
  and reason-code integrity.
- [`adr/0007-key-access-ordering.md`](adr/0007-key-access-ordering.md) —
  key-access ordering.
- [`adr/0008-release-truth.md`](adr/0008-release-truth.md) — release truth and
  ledger discipline.

## History and evidence

- [`evidence/change-attempt-corpus-v1.md`](evidence/change-attempt-corpus-v1.md)
  — sanitized development-snapshot conformance record for Change Attempt
  Observation V1.
- [`PROOFS.md`](PROOFS.md) — historical same-owner demonstrations and their
  stated limitations.
- [`CASE-STUDY.md`](CASE-STUDY.md) — historical real-bug reconstruction.
- [`../CHANGELOG.md`](../CHANGELOG.md) — release and development history.
- [`history/CHANGELOG-v1.md`](history/CHANGELOG-v1.md) — archived imported v1.x
  history from the internal repository.
- [`../LICENSE_HISTORY.md`](../LICENSE_HISTORY.md) — license carried by
  historical release lines.
- [`PROJECT_STATUS.md`](PROJECT_STATUS.md) — current map of frozen pilots and
  external demonstration repositories.

Historical releases, tags, assets, checksums, ledgers, and attestations are
retained for reproducibility. Their presence does not mean they remain
supported; use the current stable release for new consumer integrations.
