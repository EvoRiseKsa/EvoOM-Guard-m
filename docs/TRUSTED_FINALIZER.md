<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# Trusted Finalizer — a split decision boundary

This is the higher-assurance deployment path for pull requests from untrusted
or semi-trusted authors. It separates two jobs that must not share authority:

```text
fixed metadata preflight          unprivileged re-verification     privileged sealing
------------------------          ----------------------------     -----------------
validate PR + create pending  ->  fetch base + exact head     ->   re-derive PR metadata and raw Git
attempt-bound Check Run           run Guard with no secrets        compare exact handoff + verdict bytes
write control record              write verdict + handoff          derive candidate/policy/pack/deletions, then sign
narrow checks:write only          no write token / signing key     never checkout or execute candidate code
```

The final check is an admission decision, not a proof of universal correctness.
`ALLOW` means a semantic Guard `PASS` was sealed against the configured
external bindings. `DENY` is also signed and retained, rather than being
discarded as a failed job.

## Deployment status

The paired workflows are available both as:

- a frozen historical reference in `examples/trusted-finalizer/`
- implementation-ready copies in `.github/workflows/evoguard-reverify.yml` and
  `.github/workflows/evoguard-seal.yml`; and
- byte-bound packaged v4.5.0 templates used by the no-clobber
  [`Finalizer deployment kit`](FINALIZER_DEPLOYMENT_KIT.md).

<!-- BEGIN EVOGUARD_PROJECT_STATUS:TRUSTED_FINALIZER_RELEASE_PIN -->
They are not enforced as required merge gates by default in this repository.
Each consumer must apply its own branch protection, Environment/reviewer
controls, protected Guard-artifact digest, and audit.

The repository-level implementation-ready workflow copies download
maintained immutable release `v4.8.1`. Before enabling those copies, download
that release's `evo-guard.pyz` and `SHA256SUMS`, verify the manifest and
release attestation, and copy the reviewed runtime digest into protected
variable `EVOGUARD_GUARD_ARTIFACT_SHA256`. The workflow must not derive its
trust root from the downloaded executable or a mutable URL.

The `examples/trusted-finalizer/` pair remains a frozen v3.7.0 reference and
must not be silently rewritten. The packaged no-clobber deployment kit
remains byte-bound to release `v4.5.0`; `finalizer-init` does not silently
upgrade that kit. New deployments built directly from the repository-level
workflow copies should use `v4.8.1` (version `4.8.1`) or its exact commit
pin and complete the audit before enforcement. The direct release record is
not an A-through-H ledger or independent authorization.
<!-- END EVOGUARD_PROJECT_STATUS:TRUSTED_FINALIZER_RELEASE_PIN -->
The `finalizer-init`/`finalizer-doctor` commands are included in `v4.6.0`; their
packaged kit targets the `v4.5.0` runtime and must not be described as commands
already present in the immutable `v4.5.0` tag or as a silent kit upgrade.
The raw-Git derivation contract is specified in
[`TRUSTED_FINALIZER_HARDENING.md`](TRUSTED_FINALIZER_HARDENING.md). A consumer
must deploy a release that contains this command set and update the protected
Guard zipapp SHA together with the templates; a pinned implementation reference
file change does not alter trust behavior by itself.

## The threat model this closes

A normal `pull_request` job must be treated as candidate-adjacent. Its workflow,
workspace, stdout, and uploaded artifacts are not a place to expose a signing
key or a write-capable token. In particular, this is unsafe:

```text
PR job uploads guard.json -> workflow_run downloads it -> workflow_run signs it
```

`workflow_run` has the base repository's security context, so downloading a
candidate-controlled artifact and signing it merely gives an attacker-selected
record stronger-looking provenance. The finalizer API therefore requires a
source object and evidence context at sealing time:

- a **source** object: PR number, re-verification workflow run/id attempt, and
  exact base/head commits; and
- an **evidence context**: repository identity, base/head trees, record
  candidate/policy/pack bindings, and the SHA-256 of the verified Guard zipapp.

The reference metadata job writes an immutable control artifact **before**
candidate execution begins. The seal job uses it—not the handoff—to select the
PR and re-fetches current PR/tree identities from GitHub. In a bare object
store with no checkout, it fetches the exact base/head objects and derives the
candidate text digest, ordered deletion list, effective policy, and pinned
verifier-pack identity from raw Git blobs. Only then does it semantically
validate and compare the untrusted verdict and handoff. The Guard executable
digest comes from a protected variable. A raw-binding mismatch stops before
the private key is read; a passing raw binding can still seal a semantic DENY
as evidence. The raw binding file and canonical handoff are mandatory materials
in the resulting `.evb` evidence bundle.

The current template first creates a fresh pending Check Run, records its
numeric ID in that pre-candidate control artifact, and has only the narrow
`checks: write` scope necessary for this operation. The candidate-execution job
itself has no write token. The seal job validates the Check Run ID against the
current `workflow_run` attempt and completes only that exact ID. If the
unprivileged job fails before sealing, a separate non-secret reconciler marks
the same Check Run `DENY`; if the control artifact cannot be read, it stays
pending (fail closed).

The supplied reference workflows begin with **open same-repository PRs that
target the protected default branch only**. Fork support and non-default base
branches need their own checkout, runner, and policy review; neither is a safe
one-line extension.

## What the raw-Git finalizer proves — and what it does not

On a successful `verify-finalized` call, the consumer has checked:

- canonical bundle bytes and an Ed25519 signature under an external public key;
- exact external repository/run/revision/tree and Guard-executable bindings;
- independently derived candidate text, ordered deletion list, effective-policy,
  and base-anchored verifier-pack bindings;
- a canonical handoff that identifies the re-verification run and PR;
- exact equality between the handoff record digest and the enclosed verdict;
- semantic validity of that verdict; and
- `ALLOW` only when that verdict is `PASS` with `passed: true`.

The candidate, deletion, policy, and verifier-pack values are not accepted as
authority merely because an untrusted record carries them. The no-checkout seal
step derives them from exact raw Git objects, then rejects any mismatch before
the finalizer key is opened.

It does **not** by itself prove that a candidate program is correct, that a
Docker daemon/kernel is impossible to escape, or that a deployment artifact was
the one tested. `guard_artifact_sha256` identifies the Guard executable; it is
not the SHA of the candidate container, package, binary, or release asset.

## Narrow file artifact admission

The optional [`Artifact Admission`](ARTIFACT_ADMISSION.md) primitive can bind a
single regular-file digest to an already externally verified finalizer `ALLOW`.
It is intentionally a **pre-merge** relation: its source is the exact PR
`head_sha` accepted by this finalizer, not a later merge/rebase commit or a
published release. It uses a separate artifact-admission key and requires the
consumer to supply the finalizer public key, exact source/context, and final
bundle again when verifying the file binding.

It does not replace the limitations above and does not prove build provenance,
reproducibility, registry identity, release publication, deployment, OCI image
integrity, SBOM contents, or vulnerability status. The reference finalizer
workflows do not create or publish artifact bindings. Those integrations require
independent canonical finalizer derivation and a separately reviewed,
provider-specific build-provenance boundary.

### `v4.6.0` public-GHCR provider relation

Release `v4.6.0` includes the library-only
[`Artifact Provider V3`](ARTIFACT_PROVIDER_V3.md) follow-on for one canonical,
digest-qualified public GHCR subject. It requires the attested repository and
source digest to equal the externally supplied finalizer repository and
`head_sha`; it also requires a direct same-revision branch workflow, an exact
builder run/attempt distinct from the finalizer invocation, provider isolation,
and a provider-inaccessible artifact-admission key path. The canonical V3
receipt is then bound through the unchanged V2 subject/finalizer signature.

This does not make the Trusted Finalizer a build witness. Retained V3
verification checks byte continuity and the signed external relation without a
provider call; only explicit fresh reverification contacts GitHub/GHCR. There
is no V3 CLI, protected reference workflow, or live OCI pilot yet, and the path
makes no SLSA, reproducibility, image-safety, vulnerability, registry-retention,
publication, deployment, or runtime-identity claim.

The reference re-verifier requires an external black-box path with a
network-less container before it will create a handoff. Docker is defense in
depth, not a complete hostile-code boundary. For public/forked untrusted code,
use a separately administered runner with gVisor or a stronger isolation layer;
do not upgrade the claim merely because the YAML says `docker`.

A raw-binding mismatch is not a signed denial because the signing key has not
entered that execution path. It is an attempt-bound failed finalizer Check Run,
with logs but no signed evidence bundle. A semantic Guard rejection that does
match raw bindings may be sealed as a signed DENY evidence bundle.

## Required repository controls

On first installation, the workflow-ID variable is intentionally empty, so the
first metadata/reverify run cannot reach the key-bearing seal job and its
non-secret reconciler completes the attempt as `DENY`. Record the numeric workflow ID, set
`EVOGUARD_REVERIFY_WORKFLOW_ID`, then launch a **new dispatch** or **Re-run all
jobs**; a partial rerun is rejected as described below.

Before enabling the final check as a merge requirement:

1. Use a protected branch/ruleset that protects the workflow and policy paths
   described in [`REPOSITORY_PROTECTION.md`](REPOSITORY_PROTECTION.md). Prefer
   a Required Workflow rule when GitHub offers it; it avoids relying only on a
   reusable check name. The reference creates a separate Check Run for every
   re-verification attempt, so do **not** make its display name a required
   check until the Round 1 audit below proves your GitHub ruleset resolves
   repeated names as intended. Also require the branch to be up to date before
   merge: the finalizer binds a specific base SHA and cannot make an old
   base/head verdict apply to a newer merge base by itself. A merge queue is an
   alternative only if it invokes an equivalent finalizer against its merge
   candidate; the supplied manual template does not add that integration.
2. Store `EVOGUARD_FINALIZER_KEY` as an **Environment secret** with a real,
   distinct required reviewer. A normal repository secret is not an equivalent
   approval boundary. Do not use a second account controlled by the same person
   as evidence of independent review.
3. Store `EVOGUARD_GUARD_ARTIFACT_SHA256` as a protected repository or
   organization variable. It must be the exact SHA-256 of the reviewed
   `evo-guard.pyz` release asset. The reference workflow checks it before use.
4. Pin every GitHub Action to a full reviewed commit SHA. Do not change a pin,
   the policy, or a verifier pack in an ordinary candidate PR.
5. Run the Round 1 audit before enabling a required check: on one unchanged
   head, produce a pass, start a fresh manual dispatch (or use **Re-run all
   jobs**) and deliberately fail or cancel it, then start another full attempt
   that passes. Record which check GitHub/ruleset treats as required at each
   point. Do not assume it selects the newest result by display name. If it is
   ambiguous, use a Required Workflow/ruleset integration or change the
   check-concurrency design before enforcing it.
6. Keep the metadata job, the `evoguard-reverify-control-v1-<attempt>` artifact
   prefix, and the workflow dependency intact. Each retry gets a distinct
   immutable artifact name; changing it requires a new security review of both
   templates. The reference retains the data-only control and evidence for 30
   days; the repository or organization retention ceiling must allow that
   duration. Actions artifacts remain temporary evidence, not a durable ledger.
7. Treat every Guard SHA, finalizer Environment/key/reviewer, reverify workflow
   ID, policy, and verifier-pack change as a security-policy change. Re-run the
   finalizer for every open PR before merge; an old success on an unchanged
   head was not computed under the new configuration.
8. For a Node project, set `mem_limit` explicitly in the base policy (normally
   `0` for V8). The ordinary Guard CLI has a checkout-based Node default; the
   raw-Git finalizer refuses to guess it from a candidate-controlled working
   tree, so an implicit Node memory setting fails closed.

### Retry invariant

Use a new manual dispatch or GitHub's **Re-run all jobs** for a finalizer retry.
Do not use **Re-run failed jobs** or **Re-run job**: GitHub increments the run
attempt but can skip the already-successful metadata job, which would leave no
new control artifact and attempt-bound Check Run. The reference reverify job
detects and rejects that partial rerun rather than silently attaching evidence
to an older attempt.

There is no automatic merge in the reference design. A signed result informs a
protected merge rule; GitHub repository governance still decides whether a merge
is possible.

## Library and CLI contract

The small primitives are intentionally separate:

```bash
# No-secret re-verification: derive from the exact raw base/head Git objects.
evo-guard derive-finalizer-bindings \
  --base-repo base --head-repo candidate \
  --base-sha "$BASE_SHA" --head-sha "$HEAD_SHA" \
  --base-tree-sha "$BASE_TREE_SHA" --head-tree-sha "$HEAD_TREE_SHA" \
  --repository "$GITHUB_REPOSITORY" --repository-id "$REPOSITORY_ID" \
  --pr-number "$PR_NUMBER" --run-id "$GITHUB_RUN_ID" \
  --run-attempt "$GITHUB_RUN_ATTEMPT" \
  --guard-artifact-sha "$GUARD_ARTIFACT_SHA256" --out bindings.json
evo-guard verify-finalizer-bindings verdict.json --bindings bindings.json \
  --source-out trusted-source.json --context-out trusted-context.json
evo-guard finalizer-handoff verdict.json --out handoff.json \
  --source trusted-source.json --context trusted-context.json

# Privileged job: repeat raw-Git derivation from a bare object store, compare,
# then let this command recheck the same bindings before it reads the key.
evo-guard seal-finalizer handoff.json verdict.json \
  --out final.evb --expected-source expected-source.json \
  --expected-context expected-context.json \
  --expected-derivation bindings.json \
  --sign-key finalizer.pem --require-pass

# An independent consumer uses external trust inputs again.
evo-guard verify-finalized final.evb \
  --trusted-pub finalizer.pub \
  --expected-source expected-source.json \
  --expected-context expected-context.json \
  --require-pass
```

`finalizer-handoff` has no key and does not make a trust claim. The handoff
format is fixed as `EVOGUARD_TRUSTED_FINALIZER_HANDOFF_V1` and contains only:

```json
{
  "format": "EVOGUARD_TRUSTED_FINALIZER_HANDOFF_V1",
  "source": {
    "pull_request_number": 42,
    "workflow_run_id": "123456789",
    "workflow_run_attempt": 1,
    "base_sha": "<40-or-64-lowercase-git-digest>",
    "head_sha": "<40-or-64-lowercase-git-digest>"
  },
  "context": { "<evidence-context-v1>": "..." },
  "record": { "sha256": "<64-lowercase-hex>", "size": 1234 }
}
```

The source base/head values must equal the evidence context values exactly;
branch names and movable refs are rejected. The raw binding is canonical JSON,
not a trust root: the sealing code recomputes its relation to the semantic
verdict and requires its output source/context to match exactly. `seal-finalizer`
reserves both `trusted-finalizer-handoff` and
`trusted-finalizer-git-bindings`, then automatically signs the exact canonical
bytes it verified under those roles. Callers cannot supply either reserved
material themselves.

### Python API migration in v4.6.0

The high-assurance Python API now makes that raw-Git comparison impossible to
omit accidentally:

```python
seal_finalizer_bundle(
    handoff_path,
    verdict_path,
    output_path,
    expected_source=source,
    expected_context=context,
    expected_derivation=raw_git_bindings,
    private_key_path=private_key_path,
)
```

`expected_derivation` is a required keyword for `seal_finalizer_bundle` and for
`seal_agent_change_finalizer_bundle`. The `seal-finalizer` CLI likewise requires
`--expected-derivation`. Omitting the Python keyword is a normal signature
error; explicitly passing `None` is rejected before the handoff, verdict, or
private key is read.

Legacy Python integrations that intentionally seal only against externally
declared source/context metadata must migrate to the conspicuously named
`seal_finalizer_bundle_without_derivation`. That function preserves the old
capability for compatibility, but it cannot attach the reserved derivation role
and its output is rejected by `verify_finalized_bundle`. Historical consumers
that intentionally accept that lower assurance must call the equally explicit
`verify_finalized_bundle_without_derivation`; neither compatibility function
establishes the raw-Git invariant or may be used as a PR, release, or
artifact-admission trust boundary. There is deliberately no weaker CLI
counterpart. For a generic provenance primitive, prefer `finalize-record`.

For lower-level uses, `finalize-record` seals a semantically valid record
against a context and returns `ALLOW` or `DENY`. It is a provenance primitive,
not a replacement for the split workflow; use `finalizer-handoff` plus
`seal-finalizer` for a PR finalizer.

## Reference workflows

Copy the reviewed templates as a pair, then adapt them through a protected
policy-maintenance change:

- [`examples/trusted-finalizer/reverify.yml`](../examples/trusted-finalizer/reverify.yml)
- [`examples/trusted-finalizer/seal.yml`](../examples/trusted-finalizer/seal.yml)
- [`examples/trusted-finalizer/README.md`](../examples/trusted-finalizer/README.md)
- (This repository implementation copies):  
  [`.github/workflows/evoguard-reverify.yml`](../.github/workflows/evoguard-reverify.yml),
  [`.github/workflows/evoguard-seal.yml`](../.github/workflows/evoguard-seal.yml)

They deliberately use a manual `workflow_dispatch` re-verification step first.
This is a safety-first MVP: a maintainer chooses the PR, checks the resulting
record, and the sealed job then runs automatically from that exact completed
workflow. An auto-dispatcher is possible later, but it needs separate API and
recursion tests; it is not quietly bundled into a signing path.
