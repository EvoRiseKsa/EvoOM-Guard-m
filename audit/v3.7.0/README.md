<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# EvoOM Guard v3.7.0 external-review companion

This directory is a review aid, not part of the frozen executable target. The
target is the immutable [v3.7.0 release][release], resolved to commit
1f0ceae5009198b1bf161a3a07fced54c1f01337. Its only release assets are
evo-guard.pyz and SHA256SUMS. Exact identifiers, asset sizes, and checksums are
in [manifest.json](manifest.json).

This companion is frozen separately as
[`review-v3.7.0-r1`][companion-release]. It is a review-instruction snapshot,
not a new Guard version, Marketplace release, or amendment to v3.7.0. Verify
the companion tag before relying on its instructions; the target and companion
are two distinct immutable identities. [`REVIEWER_RUNBOOK.md`](REVIEWER_RUNBOOK.md)
states the exact order and the boundaries of an authorized review.

Do not use main, a newer documentation revision, an unpinned Marketplace
reference, or this directory as a substitute for verifying the release asset
first. The review target is the published zipapp plus the commit named above.
The target request is public in [issue #80][issue].

[release]: https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v3.7.0
[issue]: https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues/80
[companion-release]: https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/review-v3.7.0-r1

## Start with target verification (no target execution)

On Linux or WSL with GitHub CLI, Git, and sha256sum:

~~~
bash audit/v3.7.0/reproduce.sh /tmp/evoguard-v3.7.0-review
~~~

On Windows PowerShell with GitHub CLI and Git:

~~~
& .\audit\v3.7.0\reproduce.ps1 -OutputDirectory "$env:TEMP\evoguard-v3.7.0-review"
~~~

By default, the scripts download data into a new local output directory and do
only identity checks. They do **not** execute the released zipapp, a candidate
repository, or a finalizer artifact:

1. verify GitHub's release attestation;
2. download the two release assets and verify exact SHA-256 values, sizes, and
   SHA256SUMS bytes;
3. clone the fixed release tag and verify the resolved source commit.

Use `--smoke` on Linux/WSL or `-Smoke` on PowerShell only in a disposable,
authorized environment if you also want to execute `version` and `doctor` from
the released zipapp. `-I` isolates Python imports; it is not a no-side-effects
or sandbox guarantee. The optional smoke run is not needed to establish target
identity.

The scripts do not accept a candidate repository, request a GitHub token,
download a finalizer artifact, or use any signing material. A passing script
verifies target identity; it does not complete a security review.

## Threat model and review boundary

Guard is designed to decide whether an untrusted change satisfied a selected
judge without changing the authority or evidence used by that judge. The
candidate controls its head revision and may try to alter files, reports,
runtime behaviour, or untrusted workflow artifacts. The trusted side is
supposed to control the base policy, protected paths, verifier-pack identity,
workflow authority, and — in a consumer deployment — the finalizer
Environment/key/reviewer.

Version 3.7.0 adds two narrow mechanisms that deserve adversarial review:

- The reference Trusted Finalizer re-derives candidate text, ordered deletions,
  effective policy, and verifier-pack identity from exact raw base/head Git
  objects before it reads a signing key. It is a reference template, not an
  enabled required merge gate in this repository.
- Artifact Admission V1 binds one observed regular-file SHA-256 and byte length
  to an externally verified pre-merge finalizer ALLOW. It is not build
  provenance, reproducibility, OCI/registry identity, release publication,
  deployment evidence, SBOM coverage, or vulnerability status.

The default same-process repository judge is intentionally candidate-writable.
A subprocess is not a sandbox, and Docker or gVisor is not VM-equivalent
hostile-code isolation. A review should distinguish a defect in a claimed
guarantee from these documented boundaries. The canonical limitation statements
are in [SECURITY.md](../../SECURITY.md),
[docs/ASSURANCE.md](../../docs/ASSURANCE.md),
[docs/TRUSTED_FINALIZER.md](../../docs/TRUSTED_FINALIZER.md), and
[docs/ARTIFACT_ADMISSION.md](../../docs/ARTIFACT_ADMISSION.md).

## Review questions and evidence

[TEST_MATRIX.md](TEST_MATRIX.md) maps the seven requested review properties to
focused regression entry points and adversarial questions. It covers:

1. base-owned authority and protected-harness refusal;
2. verdict, record, and evidence integrity;
3. truthful assurance and isolation labeling;
4. verifier-pack identity and actual candidate execution;
5. raw-Git Trusted Finalizer replay and key-separation resistance;
6. narrow Artifact Admission V1 binding semantics; and
7. Action and release supply-chain handling.

Use [REVIEW_REPORT_TEMPLATE.md](REVIEW_REPORT_TEMPLATE.md) to preserve target
identity, environment details, command inputs, expected versus observed
behaviour, evidence hashes, and limitations. A report should explicitly mark a
question as not evaluated rather than silently omitting it.

## Evidence collection and reproducibility limits

Record the OS, CPU architecture, Python, Git, GitHub CLI, Docker/runtime, image
digest, dependency resolver output, and exact commands. Preserve raw verdicts,
bundles, pack manifests, and workflow logs only after checking them for
credentials. Hash every retained artifact.

The executable is hash-verifiable, but the full source test environment is not
a byte-for-byte reproduction of the historical release environment: the dev
extra uses dependency version ranges, and this companion does not freeze every
Docker image used by every test lane. A source replay can be useful developer
evidence without proving historical build reproducibility.

## Independence and safe reporting

The core repository has one owner. MANA-awam is a second GitHub identity
controlled by that same owner. Any review or pilot using those identities is
technical role-separation evidence only, not independent security review,
third-party validation, or a separate security authority.

An independent assessment requires a reviewer who does not control the product,
case selection, labels, or interpretation. It must say how that independence
was established; a clean report must not be converted into a general
endorsement.

Do not request, paste, upload, or publish a finalizer private key,
EVOGUARD_FINALIZER_KEY, personal access token, GitHub Actions token, cookie,
environment export, time-limited credential-bearing URL, or unredacted log
that might contain one. No core-release test needs these credentials. If a
finding needs a key-bearing deployment, provide a non-secret reproducer and
request a controlled reproduction instead.

Report a potential bypass or vulnerability through the private route in
[SECURITY.md](../../SECURITY.md), not in issue #80 or a public pull request.
Use a disposable repository you control; do not test against third-party
repositories, shared runners, or GitHub infrastructure beyond ordinary
documented API/release use. The license does not add a vulnerability
safe-harbor, bug bounty, or permission to redistribute modified copies.

## Completion criteria for a useful external handoff

A handoff is review-ready when it includes all of the following:

- verification of the frozen tag, commit, asset hash, asset size, and release
  attestation before testing;
- a declared reviewer relationship to the project and whether it is genuinely
  independent;
- an explicit result or non-result for every requested property;
- a minimal reproducer, exact commands, inputs, expected result, observed
  result, and safe evidence hashes for every finding;
- the environment and reproducibility limitations needed to interpret a
  negative result; and
- private disclosure for any potentially exploitable issue until the maintainer
  agrees that public disclosure is safe.

A report that finds no issue only reports the paths it exercised. It is not a
claim of broad correctness, a field false-positive/false-negative rate, or
immunity from hostile runners.
