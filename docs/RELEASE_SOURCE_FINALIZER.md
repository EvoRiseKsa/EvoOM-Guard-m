<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Release Source Finalizer V1

`Trusted Finalizer` is a **pull-request** contract.  Its source is a PR number,
base commit, head commit, and re-verification run.  After a squash merge, the
commit on `main` is different from the PR head.  A PR `ALLOW` therefore does
not truthfully prove that a later release artifact came from an admitted
protected-branch commit.

Release Source Finalizer V1 is a separate **source-binding** primitive for that
missing boundary.  It has its own JSON formats, material role, ZIP envelope,
signature domain, signature purpose, and release-only signing key.  It does
not accept a PR source object and does not reuse `evidence-context-1`, `.evb`,
or artifact-admission V1/V2.

V1 is deliberately **DENY-only**.  It can prove that the supplied record's
source and material fingerprints match the raw Git objects it read, but it
cannot prove that the unprivileged producer actually ran Guard.  An attacker
can fabricate a semantically valid `PASS` record and assurance fields.  Until
the producer execution itself is independently authenticated, allowing a
release from that record would be false assurance.

## V1 scope

V1 binds one exact source only:

```text
refs/heads/main
  + current target commit SHA
  + target tree SHA
  + immediate parent commit/tree
  + a specific re-verification workflow run and attempt
```

The external control plane supplies repository/run metadata from the GitHub
API.  The privileged finalizer itself resolves `refs/heads/main`, its tree and
its single parent from a trusted raw-Git object store, then recomputes the
candidate, policy, and verifier-pack digests from immutable blobs.  It refuses
to open `EVOGUARD_RELEASE_SOURCE_FINALIZER_KEY` (or an equivalent release-only
key) unless those derived values exactly match the handoff and expected context.
The unprivileged handoff is never authority.

The context binds the Guard record's parent/target revisions, candidate digest,
policy digest, and verifier-pack digest.  A changed `main` tip, tree, run
attempt, record, policy, or pack digest fails closed.  The resulting signed
evidence has decision `DENY` even for a semantic `PASS`; the record remains
audit material only. V1 deliberately makes **no claim** about the
binary/runtime that executed Guard: that requires a separate bootstrap-runtime
material and is not represented by this schema.

The signed container is `.rse` and contains exactly these stored ZIP members:

```text
bundle.json
bundle.sig
record/verdict.json
materials/release-source-finalizer-handoff
```

`bundle.sig` covers canonical `bundle.json` under the distinct
`EVOGUARD_RELEASE_SOURCE_EVIDENCE_V1` signing domain.  A PR finalizer bundle
cannot be replayed as a release-source bundle even if a deployment accidentally
points at the same key; the integration must additionally configure the
release key as distinct from PR-finalizer and artifact-admission key IDs.

## Commands

```bash
# Unprivileged producer stage: writes an unsigned canonical descriptor.
evo-guard release-source-handoff verdict.json \
  --out handoff.json \
  --source trusted-source.json \
  --context trusted-context.json

# Privileged stage: source/context are independently re-derived here from the
# trusted raw-Git store, not copied from the artifact. Key exclusions are required.
evo-guard seal-release-source-finalizer handoff.json verdict.json \
  --out release-source.rse \
  --expected-source independently-derived-source.json \
  --expected-context independently-derived-context.json \
  --git-repository /trusted/object-store \
  --sign-key "$EVOGUARD_RELEASE_SOURCE_FINALIZER_KEY" \
  --must-differ-from-key-id "$PR_FINALIZER_KEY_ID" \
  --must-differ-from-key-id "$ARTIFACT_ADMISSION_KEY_ID"

# Detached consumer: verifies the signed bytes against source/context supplied
# by its own control plane. It does not itself query GitHub or raw Git.
evo-guard verify-release-source-finalized release-source.rse \
  --trusted-pub release-source-finalizer.pub.pem \
  --expected-source independently-derived-source.json \
  --expected-context independently-derived-context.json \
  --must-differ-from-key-id "$PR_FINALIZER_KEY_ID" \
  --must-differ-from-key-id "$ARTIFACT_ADMISSION_KEY_ID"
```

Sensitive verdict, source and context arguments must be regular files; the CLI
rejects standard input.  Outputs use atomic no-clobber publication unless
`--force` is explicitly supplied.  A V1 `DENY` exits nonzero by default, both
when sealing and when verifying.  An archival-only caller can opt in to a zero
exit status with `--allow-deny-evidence`; that flag must never be used by a
release, deployment, or merge gate.

## Required admitting workflow boundary (not enabled by this repository yet)

The library contract is intentionally delivered before an admitting workflow.
An installation needs four separate stages:

```text
protected-main source
  -> unprivileged isolated reverify
  -> canonical handoff
  -> independent authenticated producer receipt
  -> privileged workflow_run source finalizer + raw-Git derivation
  -> signed .rse evidence
  -> separately privileged draft-release consumer
```

An admitting version must verify a producer receipt signed by a key that the
candidate cannot access. That receipt must bind the exact source, raw-derived
context, verdict digest, bootstrap-runtime digest, workflow run/attempt, and
producer identity. A signature over a verdict artifact alone is insufficient:
it proves possession of a key, not that Guard ran.

The final key-bearing stage must then:

1. receive a `workflow_run` only from the exact configured builder workflow;
2. verify its numeric workflow ID, `workflow_dispatch` event, successful
   conclusion, run ID/attempt, repository identity and `main` head;
3. verify that authenticated producer receipt before key access, then re-fetch
   `refs/heads/main`, the target commit/tree, and a single parent from
   GitHub/raw Git before key access; the V1 module performs the raw-Git
   comparison itself but its object store must be prepared by the trusted job;
4. never check out, import, or execute source code or the new release artifact
   after key access; and
5. use a pre-existing pinned bootstrap runtime, not the new artifact being
   admitted.

The current core repository does **not** yet enable that workflow.  This code
is a reviewed building block, not a claim that its own releases are finalized.

## Explicit non-claims

V1 issues **no `ALLOW` decision**. It signs a `DENY` source-binding record for
audit, even when the enclosed record says `PASS`. Its detached verifier compares
the bundle to caller-supplied expected JSON; it does not fetch GitHub state or
raw Git itself. V1 does not by itself prove:

- GitHub branch protection or CODEOWNERS settings were cryptographically
  enforced;
- that the local raw-Git object store was fetched from GitHub correctly (the
  key-bearing workflow must establish that control-plane boundary);
- an artifact was built from the source, is reproducible, or passed GitHub
  Artifact Attestation verification;
- a draft/tag/release is immutable or has not been changed by an administrator;
- a release was published, a Marketplace listing was updated, or a deployment
  was admitted; or
- that MANA-awam is an independent reviewer (it is a same-owner technical
  separation only).

Those require a later release-artifact admission adapter, a constrained GitHub
Attestation bridge for `source_digest == target_commit_sha`, protected
Environment policy, and a read-only post-publication verifier.

## Bootstrap boundary

The first release containing this command cannot finalize itself by executing
its own new artifact in a privileged job.  It is a bootstrap release and must
be reviewed and released under the existing process.  Only a later release can
use an immutable, separately established prior runtime to execute this path.
