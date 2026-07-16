# Reference Trusted Finalizer workflows

These are a paired reference deployment for the v3.6.1 split finalizer. They
are intentionally not activated inside EvoOM Guard itself; copy them to the
consumer repository in one protected change and test them on a disposable PR.

1. Copy `reverify.yml` to `.github/workflows/evoguard-reverify.yml`.
2. Copy `seal.yml` to `.github/workflows/evoguard-seal.yml`.
3. Create protected variable `EVOGUARD_GUARD_ARTIFACT_SHA256` with the reviewed
   SHA-256 of the v3.6.1 `evo-guard.pyz` asset.
4. Create Environment `evoguard-finalizer`, add the PEM private key as
   `EVOGUARD_FINALIZER_KEY`, and configure a genuine required reviewer.
5. Run **EvoGuard Reverify** manually **from the protected default branch** for
   an open same-repository PR targeting that branch. Copy the numeric workflow ID shown in Actions
   into protected variable
   `EVOGUARD_REVERIFY_WORKFLOW_ID`; after that, only that workflow ID can
   trigger the key-bearing seal job. The bootstrap run cannot seal because that
   variable was empty when its `workflow_run` condition was evaluated; its
   non-secret reconciler records `DENY`. After saving the variable, start a new
   dispatch or use **Re-run all jobs**.
6. Run the Round 1 audit on one unchanged PR head: complete a pass, start a
   new manual dispatch (or use **Re-run all jobs**) and deliberately fail or
   cancel it, then start another full attempt that passes. Record which result
   the GitHub ruleset treats as required at each point. Do not assume repeated
   Checks named `EvoGuard Trusted Finalizer` resolve newest-first.
7. Prefer a Required Workflow/ruleset integration. Only after the Round 1 audit
   proves the actual enforcement behavior should any finalizer requirement be
   enabled. In the branch rule, require the branch to be up to date before
   merge, then advance the base branch and verify that re-verification is
   required again.

`seal.yml` deliberately installs its Ed25519 signing dependency with
`--require-hashes` on GitHub-hosted Linux x86_64 / Python 3.12. Keep that lock
intact: changing the runner platform or Python version requires reviewing and
re-locking the exact wheels before this privileged workflow is used.

The metadata job creates an attempt-bound pending Check Run and uploads
`evoguard-reverify-control-v1-<attempt>` before the candidate job begins.
Retain that job, its attempt-bound artifact prefix, and its dependency: the
seal job uses this immutable control-plane record rather than an untrusted
handoff to select the PR it will seal. If the re-verification job fails before
sealing, the non-secret reconciler completes that same Check Run as `DENY`.

The candidate-execution job carries no secrets or write permission. Its fixed
metadata preflight has only `checks: write`, solely to create the pending Check
Run before candidate execution. The seal job has the key but does not checkout
or execute candidate code. Do not collapse those jobs, move the key into the
reverify job, or replace the handoff comparison with an artifact signature
shortcut.

Treat changes to `EVOGUARD_GUARD_ARTIFACT_SHA256`, the finalizer Environment or
key/reviewer, `EVOGUARD_REVERIFY_WORKFLOW_ID`, policy, or verifier pack as
security-policy changes. Re-run the finalizer for every open PR before merging;
an existing success on an unchanged head was computed under older inputs.

For retries, use a new dispatch or **Re-run all jobs** only. Do not use
**Re-run failed jobs** or an individual-job rerun: GitHub increments the run
attempt while it can skip successful metadata, so the reference deliberately
rejects that partial rerun rather than reuse a prior control record.

The templates enforce a network-less container black-box policy as a minimum
for their own re-verification path. Docker is not a complete hostile-code
boundary. For public fork PRs or stronger adversaries, use a separately managed
gVisor/stronger runner and extend the deployment only after testing that exact
boundary.

See [`docs/TRUSTED_FINALIZER.md`](../../docs/TRUSTED_FINALIZER.md) for the
complete guarantees and limits.
