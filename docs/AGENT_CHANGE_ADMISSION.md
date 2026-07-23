<!--
  Copyright (c) 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Source-available - see LICENSE for permitted use.
-->

# Agent Change Admission V1

Agent Change Admission is an experimental admission profile for one exact
change proposed by an automated agent. It does not trust the agent to define
the scope it may change, and it does not turn an agent's claims into facts.

This implementation is included in the **v4.3.0 source candidate** after
[#147](https://github.com/EvoRiseKsa/EvoOM-Guard-m/pull/147). It is not in the
immutable v4.2.0 release and is not enabled as a required check in this
repository. A bounded public same-owner pilot has completed; that evidence is
not a production or independent-validation claim.

## The decision being made

The profile answers a narrow question:

> Does this exact base-to-head change match a separately signed authorization,
> independently derived Git facts, the required policy and verifier pack, and
> a verified Trusted Finalizer `ALLOW`?

An affirmative answer is an admission record for that exact input set. It is
not proof that the patch is correct, secure, optimal, or free of behavior that
the configured judge did not test.

## Trust separation

The profile keeps four inputs distinct:

1. **Proposal (`EVOGUARD_AGENT_CHANGE_PROPOSAL_V1`) - untrusted.** The agent
   declares its identity, intent, paths, observed policy, and evidence claims.
   Canonical validation makes the document bounded and unambiguous; it does
   not make any claim authoritative.
2. **Authorization (`EVOGUARD_AGENT_CHANGE_AUTHORIZATION_V1`) - trusted control
   plane.** A separate Ed25519 key signs one repository, PR, base/head and tree
   pair, authorization run/attempt, permitted path scope, deletion policy,
   size limits, and required policy/pack digests. The agent must not possess
   this key or produce these inputs.
3. **Raw-Git bindings (`EVOGUARD_AGENT_CHANGE_GIT_BINDINGS_V1`) - independently
   derived facts.** The protected sealer derives the candidate digest and size,
   complete tracked changed/deleted/touched paths, commits, trees, policy
   digest, and verifier-pack digest from immutable Git objects using a pinned
   Git executable. It does not accept an uploaded bindings document as sealing
   authority. The proposal is never the source of those facts.
4. **Trusted Finalizer `ALLOW` - decision authority.** The existing finalizer
   verifies the exact handoff and Guard verdict. The proposal, signed
   authorization, and raw-Git bindings become mandatory evidence materials in
   the signed `.evb` bundle. The authorization key and finalizer key must be
   different.

The resulting bundle can be verified offline against both public keys,
external source/context values, and raw-Git bindings independently re-derived
by the verifier. Offline verification does not checkout, import, or execute
candidate code.

## Fail-closed checks

Before an Agent Change `ALLOW` can be sealed, the implementation requires:

- exact agreement on repository, PR, base/head commits and base/head trees;
- exact agreement on candidate digest/size and the sorted changed, deleted,
  and touched path sets. Tracked paths ignored by Guard candidate copying (for
  example `dist/` or `build/`) remain visible to authorization;
- `intent.declared_paths` equal to the complete raw-Git touched-path set;
- exact agreement on the policy and verifier-pack digests across proposal,
  authorization, raw-Git bindings, and finalizer context;
- every path to match a control-plane pattern. A pattern is either one literal
  path or one directory prefix ending in `/**`; general glob syntax is not
  accepted;
- path-count and candidate-size limits, plus explicit deletion authorization;
- unconditional rejection of judge-owned tests, test configuration, CI/local
  Action files, and judge auto-execution paths, even if a signed authorization
  attempts to allow them;
- evidence digests for `PASS` and `FAIL` proposal claims, and no evidence
  digest for `NOT_RUN` or `UNKNOWN`; and
- a verified Trusted Finalizer `ALLOW`. `DENY`, a malformed handoff, mismatched
  external metadata/bindings, or key reuse cannot produce an Agent Change
  admission; and
- verification of the staged signed bundle before atomic publication, so a
  wrong public/private key pairing cannot create or replace an admission file.

The evidence digest attached to an agent claim only binds bytes named by the
claim. It does not independently prove that the claim is true. Authority still
comes from the trusted judge, authorization, raw-Git derivation, and finalizer.

Authorization V1 is scoped to an exact repository, PR, commit/tree pair,
policy, pack, and path policy; it is deliberately idempotent for that exact
change. `authorization_run_id` and `authorization_run_attempt` bind the
authorization producer's provenance, not a one-time finalizer invocation.
Deployments that require single-use grants need external consumption state or
a future expiry/nonce contract; V1 must not be described as providing that.

## Deployment sequence

A safe deployment uses separate jobs or security domains:

```text
untrusted producer        unprivileged verifier       protected control/finalizer
------------------        ---------------------       ---------------------------
write proposal       ->   run Guard on exact head ->  derive raw Git again
no trusted scope          create verdict/handoff      sign exact authorization
no signing key            no signing key              require finalizer ALLOW
no write authority        no admission authority      seal mandatory materials
```

Do not combine these roles in one candidate-controlled job. In particular, do
not expose either private key to a PR job, accept allowed paths from the
proposal, or sign an uploaded proposal/verdict without re-deriving source and
Git identities in the protected job.

The authorization source, scope, and required-digest JSON files are trusted
control inputs. Protect their workflow, repository variables, environment,
reviewer policy, and signing key with the same care as a merge gate. Existing
Trusted Finalizer deployment requirements still apply; see
[`TRUSTED_FINALIZER.md`](TRUSTED_FINALIZER.md).

## Observed public pilot

The public
[`evoom-guard-agent-change-pilot`](https://github.com/EvoRiseKsa/evoom-guard-agent-change-pilot)
exercised this candidate through protected GitHub Environments and two
same-owner accounts. The exact inputs, retained digests, local offline checks,
and limitations are recorded in
[`PILOT_RESULTS.md`](https://github.com/EvoRiseKsa/evoom-guard-agent-change-pilot/blob/main/PILOT_RESULTS.md).

Three observations are fixed in that record:

1. [run 29983466826](https://github.com/EvoRiseKsa/evoom-guard-agent-change-pilot/actions/runs/29983466826)
   admitted one exact `calc/ops.py` change after separate authorization and
   finalizer approvals. Its retained `.evb` independently verified as
   `ALLOW`.
2. [run 29983731021](https://github.com/EvoRiseKsa/evoom-guard-agent-change-pilot/actions/runs/29983731021)
   rejected a candidate that also tracked `dist/hidden.txt`. Guard's
   candidate-copy optimization ignored that path, but authoritative raw-Git
   derivation retained it. Authorization failed before signing, finalization
   was skipped, and no `.aca` or `.evb` artifact was published.
3. [run 29983835620](https://github.com/EvoRiseKsa/evoom-guard-agent-change-pilot/actions/runs/29983835620)
   replayed the unchanged permitted base/head pair. The raw-Git binding bytes
   remained identical while the signed artifacts were bound to the new run
   identity, confirming V1 idempotency rather than single-use semantics.

Both GitHub accounts are controlled by the same owner. The result tests
permissions, approvals, artifact flow, fail-closed path derivation, and
detached verification. It is not independent review, proof of arbitrary
hostile-code isolation, or a production merge gate.

## CLI surface

The unreleased candidate exposes five profile commands:

- `validate-agent-change-proposal`
- `derive-agent-change-bindings`
- `seal-agent-change-authorization`
- `seal-agent-change-finalized`
- `verify-agent-change-finalized`

See the small command-order reference in
[`examples/agent-change-admission/`](../examples/agent-change-admission/).
The JSON contracts are described by:

- [`agent-change-proposal-1.schema.json`](../evoom_guard/schemas/agent-change-proposal-1.schema.json)
- [`agent-change-authorization-1.schema.json`](../evoom_guard/schemas/agent-change-authorization-1.schema.json)
- [`agent-change-git-bindings-1.schema.json`](../evoom_guard/schemas/agent-change-git-bindings-1.schema.json)

## Explicit non-goals and current limits

Agent Change Admission is **not** machine learning, anomaly detection, risk
prediction, an autonomous policy selector, or a code healer. It neither
creates nor improves a patch. It does not learn from PRs and does not infer
whether an agent's natural-language intent is honest.

It also does not replace:

- Guard execution and an appropriate independent verifier pack;
- strong isolation for hostile candidate execution;
- GitHub rulesets, required-check behavior, protected environments, or key
  management;
- human or independent security review; or
- artifact, release, publication, or deployment admission.

The protected commands require an absolute Git executable and externally
configured SHA-256 pin. Stable executable snapshotting is currently a POSIX
finalizer requirement; Windows remains suitable for development tests, not
for the protected sealing boundary.

The public pilot supplies bounded protected-workflow, positive, ignored-path
negative, and exact-change replay evidence. Before production enforcement, the
profile still needs an independently controlled consumer, a reviewed
hostile-code isolation boundary, explicit authorization revocation/single-use
requirements where needed, and validation of the exact production ruleset and
failure-recovery behavior. The source candidate requires a new immutable
v4.3.0 tag and regenerated release evidence before it becomes a consumer
release; this document does not move or redefine v4.2.0.
