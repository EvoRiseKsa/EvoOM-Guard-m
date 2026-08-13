# Agent Change Admission command-order reference

This is a compact reference for the experimental Agent Change Admission
profile. V1 shipped in v4.3.0; `v4.6.0` ships the V2 bindings.
This reference is not an enabled workflow or a production gate. The archived
same-owner V1 pilot remains bounded evidence, not independent validation.

Keep the roles separate: the agent writes only `proposal.json`; a protected
control plane owns the authorization inputs and key; the finalizer independently
derives Git facts, verifies Guard, and owns a different signing key.

The proposal generation step must use the same contract generation as the
raw-Git bindings. For V2, the producer computes `candidate_identity` directly
from its structured path-to-text map and declares the bound
`EVOGUARD_AGENT_CHANGE_CANDIDATE_SELECTION_V1` profile. The protected raw-Git bindings retain the
historical Guard digest and size only as `legacy_guard_candidate_sha256` and
`legacy_guard_candidate_size`; the producer must not calculate V2 by parsing
the ambiguous FILE-block text. The protected side independently re-derives all
values. V1 proposals remain verifiable with V1 bindings, but
V1/V2 mixing is rejected.

V1 remains the default CLI contract. Add `--contract-version 2` to proposal
validation, raw-Git derivation, finalizer sealing, and offline verification
when using V2. The command sequence below is the V1-default form; add that
flag to those four commands for an end-to-end V2 run.

## Required inputs

| Input | Owner |
|---|---|
| `proposal.json` | Untrusted agent/producer |
| trusted base/head Git object stores and pinned Git executable | Protected finalizer |
| `agent-bindings.json` | Independent offline verifier (not sealing authority) |
| `authorization-source.json`, `authorization-scope.json`, `authorization-required.json` | Protected control plane |
| `authorization.aca` | Authorization signer |
| `handoff.json`, `verdict.json`, `finalizer-bindings.json` | Trusted Finalizer flow |
| `expected-source.json`, `expected-context.json` | Protected finalizer inputs |

An authorization scope is deliberately simple and deterministic:

```json
{
  "allow_deletions": false,
  "allowed_patterns": ["src/repair.py", "src/safe/**"],
  "maximum_candidate_bytes": 65536,
  "maximum_touched_paths": 8
}
```

The profile still rejects judge-owned tests, config, CI/Action, and auto-exec
paths even when one of these patterns appears to include them.

## Command order

The placeholders below must come from protected metadata and immutable Git
objects, not from the proposal:

```bash
python evo-guard.pyz validate-agent-change-proposal proposal.json

python evo-guard.pyz derive-agent-change-bindings \
  --base-repo BASE_GIT --head-repo HEAD_GIT \
  --git-executable /usr/bin/git \
  --git-executable-sha256 TRUSTED_GIT_SHA256 \
  --base-sha BASE_SHA --head-sha HEAD_SHA \
  --base-tree-sha BASE_TREE_SHA --head-tree-sha HEAD_TREE_SHA \
  --out agent-bindings.json

python evo-guard.pyz seal-agent-change-authorization \
  --source authorization-source.json \
  --scope authorization-scope.json \
  --required authorization-required.json \
  --sign-key authorization.private.pem \
  --out authorization.aca

python evo-guard.pyz seal-agent-change-finalized \
  proposal.json authorization.aca handoff.json verdict.json \
  --base-repo BASE_GIT --head-repo HEAD_GIT \
  --git-executable /usr/bin/git \
  --git-executable-sha256 TRUSTED_GIT_SHA256 \
  --finalizer-bindings finalizer-bindings.json \
  --authorization-source authorization-source.json \
  --authorization-pub authorization.public.pem \
  --expected-source expected-source.json \
  --expected-context expected-context.json \
  --sign-key finalizer.private.pem \
  --trusted-pub finalizer.public.pem \
  --out agent-change.evb

python evo-guard.pyz verify-agent-change-finalized agent-change.evb \
  --agent-bindings agent-bindings.json \
  --authorization-source authorization-source.json \
  --authorization-pub authorization.public.pem \
  --expected-source expected-source.json \
  --expected-context expected-context.json \
  --trusted-pub finalizer.public.pem
```

The sealing command deliberately re-derives Git truth and has no
`--agent-bindings` input. The last command accepts `agent-bindings.json` only
as expected data independently re-derived by the offline verifier.

`authorization.private.pem` and `finalizer.private.pem` must be distinct and
must never enter a candidate-execution job. The last command is offline and
does not execute candidate code. For the complete trust model and deployment
limits, read
[`docs/AGENT_CHANGE_ADMISSION.md`](../../docs/AGENT_CHANGE_ADMISSION.md).
