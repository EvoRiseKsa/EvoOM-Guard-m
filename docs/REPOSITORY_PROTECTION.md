<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Repository protection is part of the gate

This document states a limit that a composite GitHub Action cannot solve from
inside its own code:

> EvoGuard cannot judge a pull request if that pull request prevents the
> EvoGuard workflow from starting.

A pull request can edit, delete, disable, or replace a workflow file in its
candidate merge result. The Action's base-policy handling protects the judge
*after the job starts*; it cannot force GitHub to start a job that no longer
exists, nor can it prevent a different workflow from reporting the same-looking
status. This is a repository-governance problem, not a verifier-pack or Python
implementation problem.

## What the Action does protect

When the intended `pull_request` workflow starts, EvoGuard resolves the event
base SHA, materializes `.evoguard.json` from that base revision, and takes the
active verifier pack from that same trusted revision. Candidate workflow `with:`
values cannot weaken those judge settings. See [`GUARD.md`](GUARD.md) and
[`VERIFIER_PACKS.md`](VERIFIER_PACKS.md).

That does **not** make the workflow invocation, its `uses:` reference, or the
repository's merge rule immutable. Configure those separately.

## Required controls

1. **Require the gate outside the PR.** Use a GitHub ruleset or branch
   protection so the EvoGuard job/check must succeed before merging. Prefer an
   organization-managed **required workflow** when your GitHub plan supports
   it; it is stronger than relying on a workflow file the contributor can edit.
   Otherwise require the exact, protected job/status check and confirm with a
   test PR that removing the workflow cannot make the PR mergeable. A status
   check name by itself is weaker if another workflow can mint the same name.

2. **Require trusted review for policy surfaces.** Put at least these paths
   under protected CODEOWNERS review, and protect the base `CODEOWNERS` file
   itself:

   ```text
   .github/workflows/**
   .evoguard.json
   security/evoguard-pack/**        # or the path used by verifier_pack
   ```

   Update a verifier pack and its V2 digest in a reviewed policy-maintenance
   change. Do not let an ordinary candidate PR choose its own verifier pack.

3. **Pin every Action by full commit SHA.** A tag is convenient but movable. Pin
   `EvoRiseKsa/EvoOM-Guard-m` and all third-party Actions used by the workflow
   to reviewed full SHAs. Review changes to those pins as supply-chain changes.

4. **Use minimal token permissions.** The normal gate needs
   `contents: read`. Add `pull-requests: write` only when you want its optional
   PR comment. Do not give the candidate job `contents: write`, deployment
   credentials, `id-token: write`, package-publish permission, or long-lived
   secrets merely to run the verifier.

5. **Run candidate code on `pull_request`, not `pull_request_target`.** A
   `pull_request_target` workflow executes with the base repository's trust
   context. Never checkout or execute the candidate branch there, and never use
   it as a shortcut to give an untrusted test run secrets or write authority.
   If `pull_request_target` is used for metadata-only automation, keep it
   separate from code checkout and judgment.

6. **Audit the merge rule, not only the YAML.** Confirm that administrators
   cannot silently bypass the rule, that the required check is actually required
   for the protected branch, and that the first run after a workflow/policy
   change is reviewed. The GitHub UI configuration is part of the security
   boundary and is not versioned with this repository.

## Minimal PR workflow

The workflow deliberately contains reporting/delivery options only. The judge
policy belongs in the base-owned `.evoguard.json`:

```yaml
permissions:
  contents: read
  pull-requests: write # omit if PR comments are not wanted

steps:
  - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
    with: { fetch-depth: 0 }
  - uses: EvoRiseKsa/EvoOM-Guard-m@<reviewed-full-sha>
    with:
      comment: "true"
      fail-on: "any-non-pass"
```

Example base policy:

```json
{
  "test_command": ["python", "-m", "pytest", "-q"],
  "verifier_pack": "security/evoguard-pack",
  "expect_verifier_pack_sha256": "<64-hex-EVOGUARD_PACK_V2-digest>"
}
```

The workflow YAML and the policy above are necessary but not sufficient. The
repository rule that requires the workflow is the component that closes the
"workflow was removed before it ran" bypass.
