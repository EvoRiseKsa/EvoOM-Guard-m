<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# Agent-origin contract and evaluation-track separation

> **Implementation status:** the local agent-origin schema, semantic validator,
> and adversarial tests are implemented. No external agent-behaviour round has
> been run. The planned 80-case independent gate-efficacy round remains
> **`INPUTS_REQUIRED`**. This document neither changes issue
> [#266](https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues/266) nor supplies,
> reviews, labels, executes, or scores any of its cases.

This contract closes one measurement ambiguity: a candidate digest alone does
not say which provider, model, agent wrapper, prompt, tools, permissions, retry,
or randomization settings produced it. Those facts matter when studying agent
behaviour, but they must not be mistaken for evidence that the candidate is
correct or that EvoOM Guard accepted it safely.

The closed structural schema is
[`agent-origin-1.schema.json`](../tools/evaluation/schemas/agent-origin-1.schema.json).
The fail-closed semantic validator is
[`tools.evaluation.agent_origin`](../tools/evaluation/agent_origin.py).

## Two questions, two datasets

### Track A — gate efficacy

Question: for the **same exact candidate bytes**, how often do ordinary CI,
Guard's declared default profile, and the stronger black-box profile accept or
block the independently assigned truth label?

The unit is a pre-frozen candidate case. Agent origin is not a truth label and
is not needed to compare the three gates. The current public plan is exactly 80
cases across eight non-overlapping repositories: 32 tuning cases from four
repositories and 48 held-out cases from four different repositories, spanning
Python, Node, Go, and JVM. Report false accepts, false rejects, abstentions,
Wilson intervals, p50/p95 latency, per-repository results, and
leave-one-repository-out sensitivity. Do not count correlated reruns as new
independent cases.

### Track B — agent behaviour

Question: under a predeclared prompt, tool, permission, retry, and
randomization contract, how often does a particular agent run produce an
ordinary defect, a valid change, an evidence-gaming attempt, or an
infrastructure/unsupported outcome?

The unit is an agent **run**, clustered by repository, task, provider/model,
and prompt family. Every run binds one agent-origin record to the externally
frozen repository, task, prompt descriptor, and candidate descriptor. Retries
must pass `validate_agent_origin_retry_chain`; the chain requires one root,
consecutive attempts, exact parent links, monotonic time, and stable
model/prompt/tool/permission/randomization and assurance identities. The
launcher must also supply an externally frozen exact attempt count and ordered,
unique run-ID roster; the validator rejects truncated suffixes and alternate
branches against that roster. The chain API accepts raw record bytes plus each
attempt's external candidate/prompt descriptors and attestation trust inputs;
it reruns the full byte and Ed25519 validator instead of trusting an in-memory
result object. They are not silently promoted to independent
observations. This track needs its own preregistered sampling and labeling
protocol. It must not reuse Track A's 80 cases as though they were 80
independent observations of agent behaviour, and the first round must not be
presented as a leaderboard of model vendors.

Track A establishes whether a gate catches fixed classes of changes. Track B
establishes how agents generate those classes under controlled conditions. A
positive result in either track cannot substitute for the other.

## Agent-origin V1 claims

Every record is canonical UTF-8 JSON with exactly three root fields. Object
keys are sorted, separators contain no insignificant whitespace, strings use
NFC-normalized Unicode without leading/trailing whitespace where they identify
entities, and the byte sequence has **no final line feed**:

- `schema_version`: `evoguard-agent-origin-v1`;
- `claims`: provider, model and versions; agent wrapper and version; externally
  frozen repository and task digests; run ID and UTC interval; retry lineage;
  prompt digest and size; canonically sorted tool and permission descriptors;
  randomization mode/seed/settings digest; and the exact candidate format and
  digest;
- `assurance`: exactly `declared_unverified` or `attested`.

Tool descriptors and permission scopes are represented by SHA-256 bindings so
the public record need not reveal secrets, command text, or sensitive resource
names. The evaluator must retain the preimages if later reproduction is part of
the claim. A digest whose preimage was not retained still binds a declaration;
it does not make the run reproducible.

The repository/task digests, prompt digest and size, and candidate format and
digest are always compared with external expectations supplied by the
evaluation launcher. A self-contained record cannot validate its own input or
candidate identity. A verified result retains canonical bytes and an immutable
deep projection; callers cannot mutate claims after signature verification.

## Assurance semantics

`declared_unverified` means exactly that: the metadata is a bounded declaration.
The validator rejects an attestation object in this mode and refuses to
"upgrade" the record merely because unrelated key material was passed to it.

`attested` is accepted only when all of the following hold:

1. the record contains the expected attestation descriptor and trusted-key ID;
2. the descriptor digest binds the domain-separated canonical statement,
   including both `claims` and the displayed attester name;
3. the caller supplies a trusted Ed25519 public key from outside the record;
4. the detached signature verifies under that exact key.

The signed bytes are framed as the length of the domain, the literal domain
`EVOGUARD_AGENT_ORIGIN_ATTESTATION_V1`, the length of a canonical statement,
and the statement bytes. The statement contains the literal format, attester,
and claims. This prevents a signature from floating into another protocol or
leaving the displayed attester name unsigned.

An authenticated key proves that its holder attested the claims. It does not by
itself prove that the key belongs to the named model provider, that the runtime
executed those settings, that the attester is independent, or that the
candidate is correct. Those statements need provider/runtime evidence and
externally established key ownership.

Minimal validation:

```python
from pathlib import Path

from tools.evaluation.agent_origin import validate_agent_origin_bytes

verified = validate_agent_origin_bytes(
    Path("agent-origin.json").read_bytes(),
    expected_candidate_sha256="<digest derived by the launcher>",
    expected_candidate_format="EVOGUARD_CANDIDATE_TEXT_MAP_V2",
    expected_prompt_sha256="<digest frozen before the run>",
    expected_prompt_size_bytes=1234,
    expected_repository_sha256="<digest of frozen repository descriptor>",
    expected_task_sha256="<digest of frozen task descriptor>",
)
assert verified.status == "declared_unverified"
```

For `attested`, also pass `trusted_attestation_public_key_path` and the raw
64-byte `attestation_signature`. The validator fails closed if either is
missing or if the statement digest, trusted-key ID, or signature differs.

## Successor-round readiness

The existing commit/freeze/reveal mechanism in
[`INDEPENDENT_EVALUATION.md`](INDEPENDENT_EVALUATION.md) remains the Track A
execution protocol. A post-v4.7 successor registration should bind the exact
released v4.7 artifact, commit, ledger digest, policies, profiles, case
inventory, agent-origin schema digest where Track B applies, and all authority
keys **before** outcomes are visible. It should be a new preregistration rather
than a silent rewrite of the v4.6-targeted plan.

Current closure state:

| Required external input or role | State | Why local implementation cannot close it |
|---|---|---|
| Eight non-overlapping repositories and exact 80-case inventory | `INPUTS_REQUIRED` | The product owner must not choose a supposedly independent held-out corpus after seeing outcomes. |
| External case/label authority and hidden signed label commitment | `INPUTS_REQUIRED` | Schemas and demo labels are not independent judgments. |
| External reviewer of case selection, duplicate rules, exclusions, and label rationale | `INPUTS_REQUIRED` | Same-owner review cannot establish external validity. |
| Distinct execution authority with frozen artifact/policy/profile/baseline | `INPUTS_REQUIRED` | A local run can prove mechanics, not independent execution control. |
| Distinct result verifier and conflict-of-interest disclosure | `INPUTS_REQUIRED` | Distinct keys do not prove distinct people or organizations. |
| Published freeze, reveal, raw evidence inventory, and score report | `INPUTS_REQUIRED` | No outcomes exist until the external inputs above are supplied and executed. |

Therefore the implemented claim is limited to: **EvoOM Guard now has a strict,
candidate-bound metadata contract suitable for a future agent-behaviour
evaluation.** It has no new independent-efficacy, agent-ranking, external
adoption, or production-readiness result.
