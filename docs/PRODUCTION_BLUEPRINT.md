<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# Production blueprint

> **Audience:** product maintainers and architecture reviewers. This is an
> intended-state blueprint, not a claim that every capability below is present
> in the latest consumer release. See [`RELEASE_STATUS.md`](RELEASE_STATUS.md)
> for current release truth.

This document defines the product EvoOM Guard is intended to become, the
boundaries it must keep, and the gates that must be satisfied before describing
an installation as production admission for hostile changes.

## Product definition

EvoOM Guard is an **evidence-bound change-admission gateway**.

It answers one narrow question:

> Did this exact change satisfy a protected judge and policy without obtaining
> authority over the evidence or final admission decision?

The product is deliberately narrow in purpose and broad only at its integration
edges:

- any author may produce the change: AI agent, human, bot, or dependency tool;
- any language may be supported through a versioned runner protocol;
- any execution boundary may be supported through a versioned isolation
  provider;
- any source-control system may be supported through a provider adapter;
- the core verdict remains policy-bound and deterministic.

EvoOM Guard is not a general code reviewer, vulnerability scanner, autonomous
healer, deployment platform, or probabilistic quality score. Those products
need different evidence and must not share the `ALLOW` authority.

## Source-enforced profile settings and deployment obligations

The profile is part of the security contract, not a convenience flag. The
source validates only the option combinations in the middle column. It cannot
observe repository permissions, credential delivery, policy ownership, branch
protection, finalizer independence, or evidence retention; those remain
external deployment obligations and are not certified by selecting a profile.

| Profile | Settings enforced by this source | External obligations not proven by the profile |
|---|---|---|
| `local` | no additional runtime settings; direct signing still requires explicit key-exposure acknowledgement | keep inputs and workstation trusted; treat the verdict as advisory |
| `protected` | black-box-only; Docker/gVisor; image and network `none`; no setup command/host setup; digest-pinned verifier pack; matching report-integrity and isolation floors; direct CLI signing forbidden | candidate job has no write token or secrets; policy is protected; candidate-free finalizer re-derives bindings; only that wider system may decide merge eligibility |
| `hostile` | every protected setting plus gVisor, a gVisor isolation floor, and a non-zero memory limit; direct CLI signing forbidden | deployed runtime and controls are independently conformance-tested; candidate has no secrets/write authority; protected finalizer and immutable retention produce the admission record |

A result from a weaker profile must never be relabelled as a stronger one.
Docker without a hardened kernel boundary is useful defence in depth, but it is
not the final hostile profile.

## Authority model

Production admission uses five capability-separated components:

1. **Policy authority** publishes an immutable policy and test-manifest digest.
   It cannot run the candidate or write a verdict.
2. **Candidate runner** receives only the candidate, immutable inputs, and a
   one-run execution grant. It has no signing key, repository write token, or
   policy mutation capability.
3. **Judge** consumes bounded runner outputs and protected reports. It emits a
   deterministic unsigned decision and cannot publish, merge, or sign.
4. **Finalizer/sealer** independently re-derives repository and policy bindings,
   verifies the judge output, and signs the exact decision. It never checks out
   or executes candidate code.
5. **Evidence publisher** appends the sealed record to immutable storage. It
   cannot change policy, tests, or verdict bytes.

GitHub jobs, environments, tokens, keys, artifact scopes, and retention rules
must implement these capabilities literally. Separate function names inside one
token-bearing process do not constitute authority separation.

## Target package architecture

The current compatibility surface remains supported while implementation moves
toward these owned packages:

| Package | Sole responsibility |
|---|---|
| `domain/` | dependency-free verdict, lifecycle, and reason contracts |
| `policy/` | strict policy parsing, canonicalization, and digest binding |
| `candidate/` | change grammar and pure transforms; no filesystem/process effects |
| `workspace/` | bounded snapshot, materialization, and cleanup effects |
| `runners/` | versioned runner protocol and ecosystem adapters |
| `execution/` | bounded host-process execution and resource contracts |
| `isolation/` | Docker, gVisor, and future remote/VM provider contracts |
| `verifiers/` | protected harness checks and structured report oracles |
| `application/` | use-case orchestration without provider credentials |
| `evidence/` | canonical records, bundles, signatures, and detached verification |
| `admission/` | finalizer and artifact/source admission state machines |
| `integrations/` | GitHub and future SCM/CI provider adapters |
| `cli/` | thin parsing and projection only |

### Refactor priorities

1. **Completed:** the flat adapter implementation is now split into
   `runners/protocol.py`, `runners/registry.py`, shared command grammar, and one
   owner module per runner. `runners.adapters` and `evoom_guard.adapters` remain
   import-only compatibility facades, with identity, registry, wildcard,
   monkeypatch, and platform grammar regression tests.
2. Move provider-specific GitHub attestation and workflow composition under
   `integrations/github/`; core admission must consume provider-neutral typed
   facts rather than call `gh` directly.
3. **Completed:** the former `record_verification/` package was split by
   responsibility into `verifiers/record_report.py`,
   `verifiers/record_isolation.py`, and verifier-owned
   `verifiers/record_policy.py`, with the public verifier API preserved. The
   profile checker does not import the producer policy predicate.
4. Finish migration of flat compatibility modules into their owning packages.
   Keep flat modules as import-only facades during one documented deprecation
   window; do not add new behavior to them.
5. Group the 41 CLI handlers into stable command families:
   `guard`, `evidence`, `finalize`, `artifact`, `release`, and `diagnose`.
   Release commands remain an advanced extension rather than the onboarding
   surface.
6. Keep the release A-H workflows out of the core verdict engine. They are one
   consumer of admission records, not the definition of EvoOM Guard.
7. Remove the disabled `--private-evoguard` PAT scaffold in the next major
   release. Private distribution must use a pinned private Action made
   available by the provider, or a prebuilt artifact produced by a separately
   protected workflow whose definition is not candidate-controlled.
8. Replace the retained `preexec_fn` compatibility spelling with an explicit
   `posix_rlimits` data contract in the next major release. Arbitrary callbacks
   must never return to the post-fork/pre-exec path.

## Implemented controls and open production evidence

The following are not optional polish:

- **Offline runner conformance is implemented; full publication remains open:**
  `tools/conformance/runner-manifest.json` and its create-only CLI exercise all
  nine adapter owners against known accept, decline, mismatch, Windows-path,
  Shell, exact `argv`/environment, owner-identity, and registry-order cases.
  CI now verifies and retains one Linux offline result. Optional `--version`
  discovery is explicitly non-gating and never claims a suite ran. A
  schema-versioned matrix that executes real supported tool versions on every
  advertised OS is still required as release evidence.
- **Isolation conformance tooling is implemented:** `tools/conformance/`
  records bounded network, mount, rootfs, forbidden-path, security-profile,
  runtime, identity, and cleanup probes with runtime/kernel/image metadata.
  Its verifier re-derives support states and security/resource settings from
  captured runtime facts instead of trusting self-reported labels. CI verifies
  and retains the Docker result it creates, but upload alone is not independent
  authentication or ledger binding. A retained result bound to the final
  commit/runtime is still required for a release claim, and a release-bound
  gVisor/VM result remains mandatory for the hostile profile.
- **Provider-neutral repository contract:** immutable base/head, protected
  policy source, workflow identity, attempt identity, and raw-object retrieval.
- **Immutable evidence storage deployment:** the vendor-neutral storage,
  key-lifecycle, incident, SLO, upgrade, and rollback contract is defined in
  `docs/PRODUCTION_OPERATIONS.md`; a production gate still requires exercises
  against the actual provider and retained evidence.
- **Operational telemetry deployment:** the local privacy-allowlisted
  aggregator in `tools/telemetry/aggregate_verdicts.py` reports reason codes,
  ERROR/abstention rate, bounded latency, policy version, profile, and isolation
  delivery without copying private evidence. Production still requires an
  operator-reviewed export/alert path and privacy exercise.
- **SLO exercises and fail-closed behaviour:** availability targets may never
  turn an `ERROR`, timeout, missing finalizer, or missing evidence into `ALLOW`.
- **Independent evaluation execution:** the signed commit/freeze/reveal
  implementation verifies complete signed verdicts, exact effective policy,
  profile, case and artifact digests, and derives the ordinary-CI baseline from
  bounded exit evidence. The production gate still requires a blind, held-out,
  multi-ecosystem corpus labelled before execution by a party that cannot tune
  the product against it, plus an independently controlled launcher when actual
  artifact execution must be attested. See `docs/INDEPENDENT_EVALUATION.md`.
- **Upgrade and rollback exercise:** schema compatibility, key rotation, policy
  migration, workflow migration, and rollback to the last admitted release
  must be demonstrated under `docs/PRODUCTION_OPERATIONS.md`.

## Evidence protocol

Every published evaluation must include:

- corpus manifest and SHA-256;
- case source, base/head commit, ecosystem, and pre-registered truth label;
- exact EvoOM Guard commit and release asset digest;
- effective policy and verifier-pack digest;
- command, environment, OS/runtime/container image digest, seed, and timeout;
- raw verdict/evidence bytes and run/attempt identifiers;
- false positives, false negatives, ERROR abstentions, coverage, and confidence
  intervals;
- separate results for `local`, `protected`, and `hostile` profiles;
- baselines using ordinary CI exit status, default Guard, black-box container,
  and the strongest available isolation profile.

`ERROR` is an abstention. It may block admission operationally, but must not be
counted as a successful attack classification.

## Production release gates

All gates are mandatory for a hostile-input production claim:

| Gate | Required evidence |
|---|---|
| P0 authority | candidate jobs contain no write token, persisted checkout credential, PAT, OIDC, signing key, or later privileged step |
| P0 signing | direct local signing is explicitly trusted-only; protected admission uses a candidate-free finalizer |
| Correctness | adapter-registry, JUnit contradiction/namespace, atomic key creation, and process-launch tests pass across supported OS versions |
| Isolation | black-box-only execution under gVisor or VM-class isolation with bounded negative probes and no network by default |
| Policy | policy and test selection come from protected base bytes and are digest-bound before candidate execution |
| Evidence | known gaps are present in the corpus; ERROR is reported separately; raw reproducible results are retained |
| Independence | blind external review/evaluation is complete and the report names conflicts of interest |
| Operations | key rotation, evidence retention, incident response, observability, upgrade, and rollback have been exercised |
| Release | one exact source-to-artifact-to-publication A-H run completes for the release commit and its detached verification succeeds |

Until all gates close, release notes must use **release candidate**, **beta**, or
**bounded operational evidence**, not “production hostile-code assurance”.

## Release sequence

1. **v4.4.2 release foundation — completed, bounded:** the protected A-H
   publication record closes the release-chain work claimed by that ledger. It
   does not establish reproducibility, independent efficacy, hostile-code
   production readiness, or external adoption.
2. **[Current field-pilot gate #266](https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues/266)
   — open:** pre-register 50–100 held-out cases from
   multiple projects and ecosystems before execution. Freeze the sampling
   unit, duplicate rule, label balance, exclusions, policy, profile, baseline,
   authority identities, key separation, and ownership/control disclosure.
   Measure onboarding, ERROR abstentions,
   false-reject/false-accept counts, p50/p95 latency, configuration effort, and
   delivered isolation. This is a protocol and onboarding pilot, not a
   production-accuracy claim.
3. **5.0 profile enforcement:** require an explicit profile for protected
   deployments, remove the unprofiled compatibility path from admission, and
   complete the runner/isolation conformance matrix and migration guide.
4. **5.0 production candidate:** complete blind external evaluation, hostile
   isolation audit, operational runbooks, and one exact A-H release exercise.
5. **Production:** enable only the profile whose complete evidence is retained.
   Other profiles remain clearly advisory or beta.

Feature expansion stops whenever a production gate is open. In particular, ML
risk scoring, automatic healing, deployment authorization, and new provider
surfaces do not outrank authority separation, conformance, or independent
evidence.
