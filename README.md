<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# EvoOM Guard

[![CI](https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/workflows/ci.yml/badge.svg)](https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/workflows/ci.yml)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-EvoOM%20Guard-B93A2B?logo=github)](https://github.com/marketplace/actions/evoom-guard)
[![Release](https://img.shields.io/github/v/release/EvoRiseKsa/EvoOM-Guard-m?color=1E7B4F)](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/latest)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: Apache-2.0 (core) | EvoRise Source-Available 1.0 (platform)](https://img.shields.io/badge/license-Apache--2.0%20%28core%29%20%7C%20Source--Available%201.0%20%28platform%29-1E7B4F)](LICENSING.md)

**A reward-hack-resistant test gate for untrusted software changes, with
AI-generated patches as the primary use case.**

Most CI gates reduce to one bit: did the test command exit `0`? Any author who
can edit the repository can make that bit say yes without making the change
good — rewrite the judging test to `assert True`, plant a `pytest.ini` that
deselects everything, drop a `conftest.py` that empties collection, add a
`sitecustomize.py` that exits `0`, or neuter the CI workflow itself. Coding
agents optimize for the green check and can find these moves; a naive
exit-code gate accepts every one of them.

EvoOM Guard is the narrow answer. It asks one question: **did this change
satisfy the selected judge without editing or deleting an evidence path
protected by the active policy?** It applies the change to a throwaway copy,
reads the verdict from a judge-owned JUnit report plus the exit code — never
stdout — rejects judging-file tampering before the suite runs, and can emit
machine-readable evidence for CI and offline verification.

It is narrow on purpose, and honest about it: Guard does not infer who wrote a
change, and a `PASS` is not proof of complete correctness or security — it
means only that the selected judge passed within the recorded policy and
assurance boundary. The project is **open-core**: the core gate is Apache-2.0
and free to use, including as a required CI/merge gate in commercial settings;
the trust platform is source-available (see [License](#license)).

> **Naming:** EvoOM Guard is the product, `evo-guard` is the CLI, and
> `evoom_guard` is the Python package.

## Install and run

EvoOM Guard is not distributed through PyPI. Install the recorded release
directly from GitHub and run the gate on your current branch:

<!-- BEGIN EVOGUARD_PROJECT_STATUS:README_QUICKSTART_PIN -->
```bash
pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m@v4.6.0"   # ledger-recorded release; pin a SHA for strictest CI

# From the branch you want checked (the diff is reverse-applied to a
# throwaway copy; your working tree is never modified):
git diff main...HEAD | evo-guard guard --diff - --no-config --test-command "python -m pytest -q"
```
<!-- END EVOGUARD_PROJECT_STATUS:README_QUICKSTART_PIN -->

The command never edits the checked working tree: it applies the diff to a
throwaway copy and runs the selected judge there. Pin an immutable release tag
or full commit SHA; a moving branch is not a release channel (see
[Release channel and accountability](#release-channel-and-accountability)).

For a no-install path, download
[`evo-guard.pyz`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/download/v4.6.0/evo-guard.pyz),
[`evo-guard.spdx.json`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/download/v4.6.0/evo-guard.spdx.json),
and [`SHA256SUMS`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/download/v4.6.0/SHA256SUMS)
from the [`v4.6.0` release](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.6.0).
Run `sha256sum -c SHA256SUMS`, then `python -I evo-guard.pyz ...`. The core is
stdlib-only, so no clone and no install are needed.

## Reward-hack resistance, measured on real code

Guard's resistance is not tuned to a benchmark. Run
[`benchmarks/real_repo_eval.py`](benchmarks/real_repo_eval.py): it turns the gate
on this repository's own real ~69k-LOC / ~5.5k-test codebase, then runs a battery
of real reward-hacks against its real files, comparing Guard to a naive "apply the
change, trust the exit code" gate.

| Candidate change | Naive exit-code gate | EvoOM Guard |
|---|---|---|
| A benign source edit | accept | **PASS** |
| Rewrite the judging test to `assert True` | accept | **REJECTED** |
| Plant a `pytest.ini` that deselects to a passing test | accept | **REJECTED** |
| Plant a `conftest.py` that empties collection | accept | **REJECTED** |
| Plant a `sitecustomize.py` that exits `0` | accept | **REJECTED** |
| Neuter the CI workflow | accept | **REJECTED** |

These are the **judging-file tamper** class: edits that rewrite, deselect, or
neuter the tests, their config, the auto-run import hooks, or the CI that runs the
gate. Guard classifies judging-file *paths*, so it rejects every one of them in
roughly 300 ms — before the suite runs — while the naive gate accepts them all.
The rejections reproduce unchanged against third-party repositories (verified
against Pallets `click` and `toml`), so the protection is not specific to this
project.

What the **default** same-process profile does *not* close is the **in-process**
class: a candidate may edit an unprotected source file that the suite imports and,
from inside the test process, neuter assertions or co-forge the JUnit report and
exit code together. Defending that requires the hardened profile — an external
black-box judge with isolation, plus after-suite tree-continuity. A default
`PASS` therefore carries `report_integrity: same_process_candidate_writable` and
must not be read as tamper-proof; gate untrusted code with `--blackbox-only`. See
[Honest limits](#honest-limits) and the [threat model](docs/THREAT_MODEL.md).

## Prove it yourself

A gate that claims to resist gaming should not ask for trust on the
maintainer's word. Five seeded, byte-reproducible proof harnesses live in
[`benchmarks/self_proof/`](benchmarks/self_proof/README.md), each with a stored
results JSON and an exact reproduction command (prerequisite: `pip install -e .`):

| Proof | Measured result | Reproduce |
|---|---|---|
| Invariants hold under fuzzing | 2,000 seeded candidate cases, 0 violations of the four gate invariants (protected-path edits rejected before the suite runs; `PASS` implies an all-pass judge-owned JUnit; honest breaks never `PASS`; every run yields a valid verdict + reason code) | `python benchmarks/self_proof/invariant_fuzz.py --cases 2000 --seed 1 --workers 8` |
| Efficacy on a mechanically-labeled corpus | 400 cases: gate catch rate 1.0 (95% CI 0.987–1.0), zero false accepts; a fair naive exit-code baseline false-accepts 17.1% of must-block cases | `python benchmarks/self_proof/efficacy_eval.py --per-category 100 --seed 1 --workers 8` |
| The tests actually bite | 827/827 injected security-core mutants killed in CI (50/50 in a local sample) | `python tools/ci/run_security_mutation_gate.py --workers 8` |
| Verdict stability and reference agreement | 80/80 verdict-invariant under semantics-preserving perturbations; 80/80 agreement with an honest-suite reference oracle | `python benchmarks/self_proof/metamorphic_diff.py --bases 80 --perturbations 6 --seed 1 --workers 8` |
| A defense closes the assertion-neutering boundary | the false `PASS` produced without the judge-owned canary becomes `FAIL` with it; honest suites still pass | `python benchmarks/self_proof/assert_liveness.py --seed 1` |

The trust model behind these numbers is deliberate
([`docs/SELF_PROOF.md`](docs/SELF_PROOF.md)). Claims with **mechanical** ground
truth — did the candidate touch a protected path, did the honest suite
genuinely fail, did the tree drift — are provable fully self-contained: anyone
reruns the fixed seeds and reads the verdict, so no one has to trust the
maintainer's labels. Run-it-yourself reproduction is the closest practical
substitute for a third-party attestation, and it is the model here: any
skeptic is their own verifier on demand.

**Judgment** claims — whether a change is "correct", whether a corpus is
"representative" of real-world agent behavior — are different: they require an
independent party, and these harnesses do not substitute for that. Same-owner
runs, however extensive, remain reproducible operational evidence, never
independent validation.

Independent third-party evaluation is a valued but optional, additive
credibility milestone — not a precondition for release, adoption, or any
in-scope claim ([`ROADMAP.md`](ROADMAP.md)). Near-term external assurance
comes from run-it-yourself reproduction and an open "make the gate lie"
red-team.

Scope of the numbers: the fuzzing and efficacy corpora cover **non-forgery**
candidates. In-process report forgery remains a documented boundary of the
default profile, and assertion-neutering is a boundary of the canary-less
default that the shipped canary closes. The 400-case table above is a synthetic
mechanically-labeled corpus; the ~69k-LOC / ~300 ms numbers are the separate
real-code demo covering the judging-file tamper class. Both are same-owner,
self-contained evidence.

## Supported test runners and languages

The gate is not Python-only. Guard detects the runner from your
`--test-command`, injects a **judge-owned JUnit reporter**, and reads the
verdict from that report plus the process exit code — never from stdout. The
same evidence-gaming resistance therefore applies across languages, not just to
`pytest`. Pass your project's natural test command; no EvoOM Guard-specific
flags are required.

| Language | Runner | Example `--test-command` | JUnit reporter |
|---|---|---|---|
| Python | pytest | `python -m pytest -q` | built-in `--junitxml` |
| JavaScript / TypeScript | Vitest | `npx vitest run` | built-in `--reporter=junit` |
| JavaScript / TypeScript | Jest | `npx jest` | `jest-junit` |
| JavaScript / TypeScript | Mocha | `npx mocha` | `mocha-junit-reporter` |
| JavaScript / TypeScript | `node --test` | `node --test` | built-in reporter |
| Go | gotestsum | `gotestsum ./...` | built-in `--junitfile` |
| Java | Maven Surefire | `mvn -q test` | Surefire XML reports |
| Ruby | RSpec | `bundle exec rspec` | `rspec_junit_formatter` |
| Any of the above | `sh -c "…"` | `sh -c "npx jest && go test ./..."` | wraps the inner runner |

pytest, Vitest, `node --test`, and Maven need no extra plugin; Jest, Mocha,
RSpec, and Go require their reporter package (`jest-junit`,
`mocha-junit-reporter`, `rspec_junit_formatter`, `gotestsum`) to be installed in
the environment where the suite runs. Any other command still runs but grades
on the exit code alone. For the exact instrumented `argv` and report
environment per runner, and how to add a new one, see
[Runner adapter conformance](docs/RUNNER_CONFORMANCE.md).

## Read the verdict

| Verdict | Meaning | Exit |
|---|---|---:|
| `PASS` | The selected judge passed and no effective-policy protected path was edited or deleted. | 0 |
| `REJECTED` | The change tripped the protected-path policy before the suite ran. This is a policy result, not proof of intent. | 1 |
| `FAIL` | The change was applied and the selected judge failed. | 1 |
| `TAMPERED` | Recorded execution facts disagree, or a trusted identity changed during judgment. | 1 |
| `ERROR` | Verification could not complete safely, including invalid input, setup failure, timeout, unavailable isolation, or an unmet assurance floor. | 1 |

Every run can write JSON with a stable `schema_version`, fixed `reason_code`,
execution state, policy identity, and assurance profile:

```bash
git diff main...HEAD |
  evo-guard guard --diff - --no-config \
    --test-command "python -m pytest -q" \
    --json verdict.json --report verdict.md --sarif verdict.sarif
```

Integrations should use `verdict`, `reason_code`, and the documented schema,
not parse terminal text. See [JSON contract](docs/JSON_SCHEMA.md).

## Use it in GitHub Actions

Generate a workflow and a base-owned `.evoguard.json` policy:

<!-- BEGIN EVOGUARD_PROJECT_STATUS:README_INIT_PIN -->
```bash
evo-guard init --ref v4.6.0 --test-command "python -m pytest -q"
```
<!-- END EVOGUARD_PROJECT_STATUS:README_INIT_PIN -->

Review and commit both generated files. On pull requests, the Action derives
the policy from the verified base revision rather than candidate-controlled
workflow inputs.

Alternatively, add the Action directly:

<!-- BEGIN EVOGUARD_PROJECT_STATUS:README_ACTION_PIN -->
```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
    with:
      fetch-depth: 0
      persist-credentials: false
  - uses: EvoRiseKsa/EvoOM-Guard-m@v4.6.0   # ledger-recorded release; pin a SHA for strictest CI
    with:
      comment: "false"   # explicit for older releases; candidate jobs never comment
      fail-on: "any-non-pass"
```
<!-- END EVOGUARD_PROJECT_STATUS:README_ACTION_PIN -->

Protect the workflow with repository rules, required checks, and appropriate
review controls — otherwise a PR could bypass the gate by removing the workflow.
A candidate job should not receive secrets or PR-write permissions. If comments
are required, use a separate metadata-only job that never checks out or
executes candidate code.

### Stage a new rollout safely (current source)

Repository source after `v4.6.0` adds a static readiness command and explicit
workflow presets. Confirm they exist in the exact installed build before use:

```bash
git clone https://github.com/EvoRiseKsa/EvoOM-Guard-m.git
cd EvoOM-Guard-m
git checkout <reviewed-40-hex-SHA>
python -m pip install .
evo-guard version  # expect 4.7.0 on this source line (release candidate)
evo-guard preflight . --strict --json
evo-guard init --ref <immutable-release-tag-or-40-hex-SHA> --preset advisory \
  --path <workflow-path> --policy-path <trusted-policy-path>
```

`preflight` is a static readiness check — it never applies a patch, runs
candidate code, or issues an admission verdict, and a ready report is never
equivalent to `PASS`. The advisory workflow preserves the real fail-closed
verdict and uploads its JSON/Markdown evidence; an explicit completeness step
makes the job red if either file is absent or empty. It is not an admission
check and must not be required in branch protection, because requiring it
admits completed non-`PASS` verdicts by design. After the reported
prerequisites are fixed and representative outcomes are reviewed, regenerate
with the same `--ref`, `--path`, and `--policy-path` plus
`--preset blocking --force`, review the diff, and then require that check. See
[Preflight and staged adoption](docs/PREFLIGHT.md).

## Choose an assurance path

| Need | Path | Start with |
|---|---|---|
| Block edits to modeled test, configuration, CI, and judge paths | Basic integrity gate | [`GUARD.md`](docs/GUARD.md) |
| Add organization-owned checks outside the candidate tree | Verifier pack | [`VERIFIER_PACKS.md`](docs/VERIFIER_PACKS.md) |
| Judge a CLI through an external report channel | Black-box, preferably `--blackbox-only` | [`BLACKBOX.md`](docs/BLACKBOX.md) |
| Add a delivered container or gVisor boundary | Isolated execution | [`BLACKBOX.md`](docs/BLACKBOX.md#boundary-evidence-is-observed-never-inferred-from-policy) |
| Evaluate named assurance profiles in ledger-recorded `v4.6.0` | `v4.6.0` profiles (verify runtime evidence) | [`OPERATING_PROFILES.md`](docs/OPERATING_PROFILES.md) |
| Produce portable, authenticated evidence | Signed verdict or evidence bundle | [`SIGNED_VERDICTS.md`](docs/SIGNED_VERDICTS.md) |
| Separate re-verification, signing, and final admission | Trusted Finalizer | [`TRUSTED_FINALIZER.md`](docs/TRUSTED_FINALIZER.md) |
| Project signed `ALLOW` and `DENY` attempts for advisory analysis | Change Attempt Observation V1 *(included in v4.5.0)* | [`CHANGE_ATTEMPT_OBSERVATION.md`](docs/CHANGE_ATTEMPT_OBSERVATION.md) |

Assurance floors make the profile a contract:
`--require-report-integrity external_process_isolated` and
`--require-candidate-isolation docker` cause Guard to return `ERROR` rather
than ship a weaker guarantee.

The bounded, same-owner development-snapshot corpus for Change Attempt
Observation V1 is recorded with exact hashes and explicit non-claims in
[`change-attempt-corpus-v1.md`](docs/evidence/change-attempt-corpus-v1.md).

The ledger-recorded `v4.6.0` release also contains a library-only
[Artifact Provider V3](docs/ARTIFACT_PROVIDER_V3.md) path for one canonical,
digest-qualified public GHCR subject (not an anonymous-registry-access claim).
It relates one exact GitHub Artifact Attestation direct same-revision branch
build and builder run/attempt to external Trusted Finalizer context, then uses
unchanged V2 to bind the exact subject and receipt. It has no CLI, protected
workflow, or live OCI pilot and must not be described as SLSA compliance,
reproducibility, image safety, vulnerability status, registry retention,
publication, deployment, or runtime identity. The isolated path does not
inherit Docker registry configuration, and no live pilot has yet proved a
compatible protected registry-auth mechanism.

For an adoption decision, start with the
[production blueprint](docs/PRODUCTION_BLUEPRINT.md). Advanced release-source,
artifact-admission, and publication contracts are separate boundaries; none
should be treated as proof of another.

## Minimal trusted policy

Store judge-shaping settings in the protected base version of
`.evoguard.json`:

```json
{
  "test_command": ["python", "-m", "pytest", "-q"],
  "timeout": 180,
  "strict_harness": true,
  "harness_inputs": ["ci/run-tests.sh"]
}
```

`.evoguard.json` is itself a built-in protected path: a candidate that edits it
is `REJECTED`, so the policy is a repository-contained contract no patch can
weaken. EvoOM Guard recognizes conventional test, build, CI, configuration, and
auto-execution paths. It does not discover a complete transitive harness graph.
Declare repository-owned wrappers and helpers explicitly as `harness_inputs`.
Built-in protected paths and declared harness inputs cannot be waived by
`allow`; legitimate changes require a separately trusted policy-maintenance
path.

## Honest limits

- `PASS` is evidence about the selected judge, policy, candidate, and delivered
  assurance profile. It is not merge authority or proof of correctness,
  security, deployment, authorship, or complete harness discovery.
- The repository-native test channel shares a process with candidate code. A
  deliberate process-level report forgery can fake that channel. Use a
  meaningful judge-owned verifier pack with `--blackbox-only` to remove it.
- Host-subprocess execution shares an OS identity and filesystem. Container or
  gVisor modes add a boundary only when the verdict records that the requested
  isolation was actually delivered.
- The base policy, workflow, verifier pack, keys, and final admission step must
  remain outside candidate control. A tool cannot compensate for an
  unprotected deployment.
- Published same-owner demonstrations and pilots are reproducible operational
  evidence, not independent validation. See the
  [independent evaluation protocol](docs/INDEPENDENT_EVALUATION.md).
- Source admission, artifact admission, publication, and deployment are
  distinct decisions. Evidence for one does not silently authorize another.

The gate is resistant, not immune: only modelled vectors are claimed. The full
threat and evidence model is in
[Assurance](docs/ASSURANCE.md), [Reward-hacking catalog](docs/REWARD_HACKING_CATALOG.md),
and [Repository protection](docs/REPOSITORY_PROTECTION.md).

## Release channel and accountability

Use an immutable release tag or full commit SHA in consumer repositories; do
not treat a moving branch as a production release channel.

<!-- BEGIN EVOGUARD_PROJECT_STATUS:README_RELEASE_CHANNEL -->
Source version `4.7.0` is a **release candidate** and is not yet a consumer release. The
latest immutable consumer release recorded by the protected source tree is
[`v4.6.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.6.0) at commit
`d65f25f386fe6f4646ea8dd3cbbe1d5d889f73d4`. Its `evoguard-release-ledger-v2` ledger
records the release assets `evo-guard.pyz`, `evo-guard.spdx.json`, `SHA256SUMS`. Its
release attestation binds `evo-guard.pyz`, `evo-guard.spdx.json`, `SHA256SUMS`, while
its build-provenance attestation binds `evo-guard.pyz`. The ledger records the SPDX SBOM
release asset and its provenance. Canonical ledger:
`evidence/release-ledgers/v4.6.0/RELEASE_LEDGER.json`.

Releases ship through the manually dispatched draft-release workflow
(`.github/workflows/release.yml`): tag-equals-version validation, the full test suite,
Linux and Windows end-to-end checks, a reproducible artifact build with checksums, and
asset attestation, ending in a draft the maintainer publishes by hand. No release step
is gated on dates, elapsed time, or stabilization windows. The archived A-H signed lane
is implemented in source but inert with every activation flag false; it is a design
reference, not a release path. The externally anchored signed v2 ledger records a
completed protected A-H operation. That validated ledger also records the resulting
publication. An admitted release is contracted to exactly `evo-guard.pyz`,
`evo-guard.spdx.json`, `SHA256SUMS`; this source contract is not evidence that those
assets were published.
<!-- END EVOGUARD_PROJECT_STATUS:README_RELEASE_CHANNEL -->

The two post-publication correction records are
[`docs/errata/V4.4.0-LEDGER.md`](docs/errata/V4.4.0-LEDGER.md) and
[`docs/errata/V4.4.1-LEDGER.md`](docs/errata/V4.4.1-LEDGER.md). Their linked
`UNSEALED_STATUS.json` files are separate unsigned observations, not the
missing release ledgers. `v4.4.1` is the later exception.

The repository documentation follows the repository source and may describe
features not present in the latest ledger-recorded consumer release. Confirm
each page's version and evidence boundary before copying a command.

The open [independent-review request](https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues/141)
targets the immutable `v4.6.0` release. It is a request for external review,
not evidence that such a review has occurred. The immutable
[`review-v4.5.0-r1` reviewer companion](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/review-v4.5.0-r1)
remains a historical review aid for the now-unsupported `v4.5.0` release and
does not cover `v4.6.0`. `EvoRiseKsa` and `MANA-awam` are controlled by the same
owner; their cross-account evidence is not independent validation.

The immutable `v4.6.0` tag preserves the README bytes that existed before its
post-publication ledger was committed. See the bounded
[`v4.6.0` Marketplace/README erratum](docs/errata/V4.6.0-MARKETPLACE-README.md);
the tag, release assets, checksums, attestations, and signed ledger are unchanged.

## Documentation

Use the [documentation index](docs/README.md) to choose a path by audience.

| Entry point | Purpose |
|---|---|
| [Start here](docs/START_HERE.md) | Choose the basic, black-box, isolated, or finalizer path. |
| [Adoption guide](docs/ADOPTION.md) | Introduce the gate into a repository and interpret results. |
| [Guard reference](docs/GUARD.md) | CLI, policy, input forms, and execution behavior. |
| [Self-contained proofs](docs/SELF_PROOF.md) | What is mechanically provable without an external party, and how to rerun it. |
| [Assurance](docs/ASSURANCE.md) | Trust boundaries, failure modes, and non-claims. |
| [JSON contract](docs/JSON_SCHEMA.md) | Stable machine-readable verdict fields. |
| [Production blueprint](docs/PRODUCTION_BLUEPRINT.md) | Deployment profiles and readiness requirements. |
| [Project and release status](docs/PROJECT_STATUS.md) | Current implementation, evidence, and release boundary. |

Historical demonstrations, release procedures, architecture decisions, and
advanced admission contracts remain public and discoverable through the index
without crowding this landing page.

## Release provenance

<!-- BEGIN EVOGUARD_PROJECT_STATUS:README_ATTESTATION_SCOPE -->
Historical `v3.7.0` has a GitHub release attestation but no GitHub Actions
build-artifact attestation. The validated `v4.6.0` ledger records build provenance whose
subject is `evo-guard.pyz` under
`.github/workflows/evoguard-build-release-artifact.yml`. Its release attestation
separately binds `evo-guard.pyz`, `evo-guard.spdx.json`, `SHA256SUMS` and records SPDX
SBOM provenance. Provider attestations are provenance evidence, not an EvoOM Guard
verdict, artifact-admission decision, or proof of deployment. See
[`docs/GITHUB_ARTIFACT_ATTESTATIONS.md`](docs/GITHUB_ARTIFACT_ATTESTATIONS.md) for the
bounded procedure.
<!-- END EVOGUARD_PROJECT_STATUS:README_ATTESTATION_SCOPE -->

Release assets, checksums, tags, ledgers, and attestations are retained as
historical evidence. See [release status](docs/RELEASE_STATUS.md),
[governance](docs/GOVERNANCE.md), and [SBOM scope](docs/SBOM.md).

## Security, contribution, and feedback

Use [SUPPORT.md](SUPPORT.md) to choose the correct support or reporting route.
Report vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue.
The public/private operating boundary is documented in
[governance](docs/GOVERNANCE.md). Never publish signing keys, credentials,
customer policy, held-out evaluation data, or private operational logs.

Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md).

## License

EvoOM Guard is **open-core**, dual-licensed by path.
[`LICENSING.md`](LICENSING.md) is the authoritative path→license map — where a
file header disagrees during the header migration, the map governs — and
[`NOTICE`](NOTICE) describes the dual structure.

- **Core gate — [Apache-2.0](LICENSE-APACHE).** The engine that answers the
  gate's one question: the domain, policy, candidate, verifier, runner,
  execution, isolation, workspace, application, and integration modules,
  `guard.py`, `signing.py`, the CLI dispatch layer, `action.yml`, and the core
  subcommands (`guard`, `init`, `preflight`, `pack-doctor`, `doctor`,
  `version`, `keygen`, `verify-verdict`, `verify-record`, `verify-bundle`).
  The core gate is **free to use, including as a required CI/merge gate, in
  commercial and non-commercial settings**.
- **Trust platform — [EvoRise Source-Available License 1.0](LICENSE)**
  (source-available, not open source): the multi-key trust machinery — the
  finalizer and admission modules, the platform operator command families
  (`seal-*` / `verify-*` / `derive-*` / `reverify-*`), the protected release
  workflows, release-ledger tooling, and trust roots and ledgers. Production
  or commercial platform use requires a separate agreement; see
  [commercial licensing](COMMERCIAL-LICENSING.md) (EvoRise Tech,
  evoriseksa@icloud.com).

Material the map does not assign defaults to the source-available license, and
neither license grants a trademark license. The single `evoom-guard`
distribution deliberately declares the more restrictive umbrella license in its
package metadata so automated scanners never read the whole package as Apache;
the Apache grant on core paths is carried by the bundled `LICENSING.md`.

Copyright © 2026 EvoRise Tech. Mana Alharbi is the author and original
creator; EvoRise Tech is the Licensor. Historical releases retain the license
shipped with their exact version; see [license history](LICENSE_HISTORY.md).
