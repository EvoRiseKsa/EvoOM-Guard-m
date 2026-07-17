<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Operating the v3.7 trust boundary

This document is the operational companion to the repository-level
[governance statement](../GOVERNANCE.md). It describes the controls that are
needed before an EvoOM Guard result is relied on for a merge or release decision.
It deliberately separates implemented mechanisms from controls that a consumer
must provide.

## What v3.7.0 implements

The `v3.7.0` release contains the raw-Git Trusted Finalizer derivation contract.
Before a key-bearing seal job may sign, the reference flow independently derives
the candidate text, ordered deletions, effective policy, and verifier-pack
identity from exact base/head Git objects, then compares those values with the
unprivileged record. The release also contains Artifact Admission V1: a narrow
binding between one regular-file digest and an externally verified pre-merge
finalizer `ALLOW`.

Neither feature changes the following facts:

- this repository does not use the reference finalizer as its own required merge
  gate;
- `ALLOW` is an admission decision for the recorded judge, policy, and bindings,
  not proof of universal correctness or a hostile-code sandbox guarantee; and
- Artifact Admission V1 does not prove build provenance, reproducibility, OCI
  identity, publication, deployment, SBOM contents, or vulnerability status.

The full protocol and limitation statements remain canonical in
[TRUSTED_FINALIZER.md](TRUSTED_FINALIZER.md),
[TRUSTED_FINALIZER_HARDENING.md](TRUSTED_FINALIZER_HARDENING.md),
[ASSURANCE.md](ASSURANCE.md), and
[ARTIFACT_ADMISSION.md](ARTIFACT_ADMISSION.md).

## Change classes

| Change class | Examples | Required handling |
| --- | --- | --- |
| Ordinary maintenance | CLI wording, isolated bug fix, non-security documentation | Tests proportional to the change and normal pull-request review. |
| Verification semantics | Verdict parsing, protected paths, assurance fields, record schema | State the invariant, add a positive and negative test where feasible, and assess record compatibility. |
| Policy or execution authority | Workflow/action pins, `.evoguard.json`, pack digest, token scope, Environment/key/reviewer | Treat as a security-policy change; re-run affected open PRs/finalizer evidence after it lands. |
| Finalizer or artifact authority | Raw-Git derivation, handoff/control record, signing, artifact binding | Threat-model review, adversarial or regression coverage, and explicit documentation of the remaining boundary. |
| Release record | Tag, zipapp, published checksum, release notes | Create a new immutable record. Never modify or replace a released asset to retroactively change evidence. |

## Technical review identity

The protected-path mapping in [`.github/CODEOWNERS`](../.github/CODEOWNERS)
assigns `@MANA-awam` to the trust-root paths. `@MANA-awam` and `@EvoRiseKsa`
are controlled by the same project owner. This supplies a separate GitHub
identity for a technical review workflow; it is not independent review,
third-party validation, or a substitute for a distinct production approver.

The mapping has no enforcement effect unless GitHub branch protection or a
ruleset requires code-owner review and protects `CODEOWNERS` itself. A consumer
using a finalizer for production admission must use a real reviewer distinct
from the candidate author and a protected Environment for the signing key.

## Evidence discipline

1. Keep the `v3.7.0` tag and its published release asset immutable.
2. Identify a record by the version, source revision, Guard executable digest,
   policy/pack identity, and relevant base/head/run context; a version label
   alone is not enough.
3. Record failed, denied, and incomplete executions as such. Do not collapse
   them into successful evidence or omit them from an evaluation result.
4. Preserve historical benchmarks and pilot evidence as versioned snapshots.
   A later result may supersede their operational relevance, but cannot rewrite
   what an earlier release did.
5. Describe same-owner cross-account tests as operational evidence only. An
   independent security or efficacy claim needs independent case selection,
   labels, and interpretation.

## Production adoption checklist

Before making an EvoOM Guard or Trusted Finalizer result merge-blocking, the
consumer should confirm the repository controls in
[REPOSITORY_PROTECTION.md](REPOSITORY_PROTECTION.md), then verify that:

- the required workflow/check cannot be disabled by the candidate pull request;
- policy, pack, workflow, code-owner mapping, Guard executable digest, and
  signing Environment are protected from the candidate author;
- all Actions and the Guard release are pinned to reviewed immutable revisions;
- the finalizer Environment has a genuinely distinct required reviewer;
- a current, repeated-run operational audit was performed for the deployed
  GitHub configuration; and
- finalizer results are invalidated and re-run after any trust-input change.

Without these controls, a Guard verdict is still useful test evidence, but it
is not sufficient by itself to authorize a merge or deployment.
