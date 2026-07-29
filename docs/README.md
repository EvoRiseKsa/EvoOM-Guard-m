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

- **Latest published stable release:** [`v4.4.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.4.0);
  it has no valid protected-tree ledger.
- **Ledger-recorded consumer pin:** [`v4.3.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.3.0).
- **Repository source:** use the exact checked-out commit; its lifecycle is
  reported by the status authorities below.
- **Status authority:** [`PROJECT_STATUS.md`](PROJECT_STATUS.md) and
  [`RELEASE_STATUS.md`](RELEASE_STATUS.md).
- **Exception record:** [`errata/V4.4.0-LEDGER.md`](errata/V4.4.0-LEDGER.md)
  records verified live facts, the frozen validator mismatch, and the
  new-release recovery boundary without claiming to be a ledger.

Repository documentation follows the source tree and may describe behavior
absent from the latest ledger-recorded consumer release. Advanced pages state
their implementation and evidence boundary. Use the immutable release tag or
its full commit SHA in consumer repositories, and do not use `@main` as a
production channel.

## Pick a path

| You want to… | Start here | Then read |
|---|---|---|
| Evaluate the product quickly | [`START_HERE.md`](START_HERE.md) | [`ASSURANCE.md`](ASSURANCE.md) |
| Add the gate to a repository | [`ADOPTION.md`](ADOPTION.md) | [`GUARD.md`](GUARD.md) |
| Judge a CLI externally | [`BLACKBOX.md`](BLACKBOX.md) | [`VERIFIER_PACKS.md`](VERIFIER_PACKS.md) |
| Design a production deployment | [`PRODUCTION_BLUEPRINT.md`](PRODUCTION_BLUEPRINT.md) | [`PRODUCTION_OPERATIONS.md`](PRODUCTION_OPERATIONS.md) |
| Review security claims | [`ASSURANCE.md`](ASSURANCE.md) | [`REWARD_HACKING_CATALOG.md`](REWARD_HACKING_CATALOG.md) |
| Integrate machine-readable evidence | [`JSON_SCHEMA.md`](JSON_SCHEMA.md) | [`RECORD_VERIFICATION.md`](RECORD_VERIFICATION.md) |
| Maintain or release the project | [`GOVERNANCE.md`](GOVERNANCE.md) | [`RELEASE_TRUST_PIPELINE.md`](RELEASE_TRUST_PIPELINE.md) |
| Understand the implementation | [`architecture/OVERVIEW.md`](architecture/OVERVIEW.md) | [`adr/0001-layered-architecture.md`](adr/0001-layered-architecture.md) |

## Getting started

- [`START_HERE.md`](START_HERE.md) — choose the basic, black-box, isolated, or
  Trusted Finalizer path.
- [`ADOPTION.md`](ADOPTION.md) — install, configure, and interpret the gate in a
  consumer repository.
- [`CASE-STUDY.md`](CASE-STUDY.md) — reconstruct a bounded historical upstream
  bug-fix demonstration.

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
- [`ARTIFACT_ADMISSION.md`](ARTIFACT_ADMISSION.md) — narrow file-artifact
  admission V1.
- [`ARTIFACT_DIGEST_ADMISSION_V2.md`](ARTIFACT_DIGEST_ADMISSION_V2.md) —
  digest-bound artifact admission V2.
- [`GITHUB_ATTESTATION_ADMISSION.md`](GITHUB_ATTESTATION_ADMISSION.md) —
  protected-boundary adapter for GitHub Artifact Attestations.
- [`AGENT_CHANGE_ADMISSION.md`](AGENT_CHANGE_ADMISSION.md) — bind an untrusted
  agent proposal to signed scope, re-derived facts, and finalization.
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
