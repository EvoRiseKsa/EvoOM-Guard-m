<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# Start here — choose a deployment path

For a merge-blocking or hostile-input deployment, read
[`PRODUCTION_BLUEPRINT.md`](PRODUCTION_BLUEPRINT.md) first. The quick paths
below demonstrate mechanisms; only the documented operating profile and
separate finalizer determine whether a result is advisory or admissible.

For a new rollout using the current `v4.8.0` release, first run the non-executing
[`preflight`](PREFLIGHT.md) check and use the generated advisory preset to
observe real verdicts without making them merge authority. Promote to the
blocking preset only through a trusted policy change after the evidence is
understood. These commands are present in `v4.8.0`; the older immutable
`v4.6.0` CLI predates `preflight` and the new `init --preset` option.

EvoOM Guard has one job: *did this software change satisfy the selected judge
without gaming the evidence?* AI-generated patches are the primary use case, but
the mechanism does not depend on whether an AI, a human, or a bot authored the
change. There are four operating paths. Pick one — you do **not** need the others
to start.

> **Release boundary:** use [`RELEASE_STATUS.md`](RELEASE_STATUS.md) as the
> authority. Commands below apply to the direct-release-recorded `v4.8.0`
> consumer release. Named `--operating-profile` policies and verdict schema
> `1.12` were introduced on the `4.4.0` source line and remain included. The
> same-owner direct release record authenticates the exact published artifact
> and workflow readback; it does not establish that a particular run delivered
> its requested profile or constitute independent validation.

## Decision table

| Your need | Profile | Command flag |
|---|---|---|
| Detect protected test/config edits and run a trusted or semi-trusted change locally | **Basic integrity gate** (Path 1) | *(none — the default; optional `--verifier-pack` adds org checks)* |
| Also verify a **CLI's** external behaviour with a judge-owned external verdict | **External behavior gate** (Path 2) | `--blackbox` + `--verifier-pack` |
| Run the black-box candidate behind a real OS isolation boundary | **Isolated external gate** (Path 3) | `--isolation docker` (fail-closed) |
| Admit a semi-trusted PR only after a separate re-verification/sealing boundary | **Trusted Finalizer** (Path 4) | split GitHub workflows |

Quick tree:

```
Want to block edits to modelled/configured judge paths? → Basic Guard
Want to check a CLI's behaviour from outside?         → Black-box CLI
Need a delivered container boundary?                  → add --isolation docker (fail-closed)
Using named profiles from `v4.8.0`?                   → verify runtime evidence; see OPERATING_PROFILES.md
Need a signed PR admission record with separated key?  → Trusted Finalizer
```

A future/external VM-class provider is a separate deployment boundary. The
`v4.8.0` `hostile` contract implements gVisor only,
and release-bound hostile evidence remains open. See
[`OPERATING_PROFILES.md`](OPERATING_PROFILES.md) for that contract.

Already have a verdict and need an offline admission/audit result? Use
`evo-guard verify-record` for internal consistency, or the authenticated
`bundle-evidence`/`verify-bundle` path when external key and replay-resistant
context are required. See [`RECORD_VERIFICATION.md`](RECORD_VERIFICATION.md) and
[`EVIDENCE_BUNDLES.md`](EVIDENCE_BUNDLES.md). The `v4.8.0` verifier accepts
schemas `1.11` and `1.12`; confirm the exact installed version before verifying
a record.

> **Using the GitHub Action on a PR?** Commit the judge policy in
> `.evoguard.json` on the base branch; `evo-guard init` creates it alongside the
> workflow. The Action reads that base policy, not candidate-controlled `with:`
> values. Protect the workflow itself with a required workflow/status check, or
> a PR could prevent the gate from starting. Details:
> [`GUARD.md`](GUARD.md#pull-request-policy-source-security-critical).

> **Need a final admission decision for semi-trusted PRs?** The ordinary Action
> is not the place for a signing key. Use the split re-verification + sealing
> deployment in [`TRUSTED_FINALIZER.md`](TRUSTED_FINALIZER.md), after configuring
> branch rules and a protected Environment. It is deliberately stronger and more
> operationally involved than Paths 1–3.
>
> For a new consumer, use the deterministic, no-clobber setup and static
> inspection procedure in
> [`FINALIZER_DEPLOYMENT_KIT.md`](FINALIZER_DEPLOYMENT_KIT.md). Those commands
> are included in `v4.8.0`; their packaged no-clobber workflow kit remains
> byte-bound to the `v4.5.0` runtime and is not silently rewritten.

---

## Path 1 — Basic integrity gate ("Basic Guard")

**When:** your own repo, trusted authors, you want the common reward-hacks blocked.

**Guarantees:** a candidate edit/deletion targeting the built-in protected set
or an exact regular base path explicitly declared in `harness_inputs` is
`REJECTED` **before the suite runs**. Runtime code cannot alter that completed
path-classification decision; this is not a claim of transitive discovery or
continuous byte immutability. The verdict is read from a judge-owned JUnit
report + exit code, never stdout.

**Does NOT guarantee:** a patch that writes deliberate `atexit`+`os._exit` forgery
into *source* can still fake a `PASS` (`report_integrity:
same_process_candidate_writable`). Use `--blackbox-only` with a meaningful
judge-owned pack to remove that report channel; add delivered container/gVisor
isolation when same-identity filesystem/process tampering is in scope.

**Try it:**
```bash
git diff main...HEAD | evo-guard guard --diff - --no-config --test-command "python -m pytest -q"
```
**Expected:** `✅ PASS` if the suite passes and the patch does not edit or delete
a path covered by the active harness policy; `⛔ REJECTED` if it does; `❌ FAIL`
if tests fail. This does not claim that Guard inferred every wrapper/helper from
the command. Put custom repository-local judge files in base-policy
`harness_inputs`; see [Guard](GUARD.md#explicit-repository-local-harness-inputs).

**Optional candidate-independent checks:** adding a pinned
`--verifier-pack /secure/pack --expect-verifier-pack-sha256 <digest>` snapshots
that pack outside the candidate tree and runs it as a **separate mandatory
phase**. Repo suite and pack must both pass, and zero collected pack tests cannot
produce `PASS`. Here independent means judge-owned and not selected by the
candidate; it does not mean third-party review or evaluation.

---

## Path 2 — External behavior gate (black-box CLI)

**When:** the target has a command-line boundary (`python -m tool`, a binary) and
you need a separate external report channel resistant to in-process
`atexit`/`os._exit` report forgery. Host-subprocess mode still shares the OS
identity and filesystem; it is not tamper-proof without delivered
container/gVisor isolation (or a future external VM provider).

**Guarantees:** the external phase comes from the **judge's own pytest** over a
judge-owned protocol pack that never imports your code. Use `--blackbox-only`
for an end-to-end `report_integrity: external_process_isolated` verdict. By
default it is **composite** — your repo's own suite **and** the pack must both
pass — so the overall profile honestly reports the weaker repo-native channel.
The pack must call `$EVOGUARD_EXEC`; a constant pack/direct target shortcut is
`ERROR candidate_not_exercised`. With explicit `harness_inputs`, the black-box
runner snapshots their trusted-source identity before materialization, checks
the materialized copy before execution, and checks again after candidate/pack
execution. An initial binding failure stops before materialization as `ERROR` /
`assurance_requirement_not_met` and is not attributed to the candidate. Only a
materialized-copy mismatch or persistent post-execution drift is `TAMPERED` /
`candidate_tree_changed_during_run`, including under `--blackbox-only`.

**Does NOT guarantee (without `--isolation docker`):** OS isolation — the candidate
runs as a host subprocess and shares the filesystem. Snapshot equality is
observation-point evidence, so a temporary mutation restored between checks may
escape detection. The shell-free black-box launcher has a POSIX executable
contract in every isolation mode; native Windows fails closed before subprocess,
Docker, or gVisor delivery, so use Linux/GitHub Actions or WSL for this path.

**Try it (a complete, runnable example ships in the repo):**
```bash
cd examples/blackbox-cli
evo-guard guard ./sample_repo --patch patches/honest.txt --verifier-pack ./pack --blackbox
```
**Expected:** `✅ PASS` (pack 2/2 **and** repo suite). Swap `honest.txt` for
`cheat.txt` → `⛔ REJECTED`; for `regression.txt` → `❌ FAIL` (the composite catches a
broken `mul` the pack never checks). Full walkthrough:
[`examples/blackbox-cli/README.md`](../examples/blackbox-cli/README.md).

---

## Path 3 — Isolated external gate (black-box + container)

**When:** you run the black-box CLI path against semi-trusted code and want the
candidate confined at the OS level, not just judged out-of-process.

**Scoped evidence:** on a completed `PASS`, a judge-owned receipt and runtime
CID establish that the trusted pack invoked the candidate launcher through a
network-less container with a read-only candidate mount; the pack's assertions
establish only the behavior they test. The pack is not mounted into the
candidate. Isolation is **observed, not requested**: a missing daemon/image,
absent launcher call, or failed cleanup is `ERROR`, never a mislabelled `PASS`.
The conformance kit exercises and replay-checks the listed mount, network,
identity, resource, and cleanup probes, and CI is configured to run the
corresponding end-to-end test when its daemon supports the boundary
(`tests/test_blackbox_docker_e2e.py`). A release claim requires retaining a
result bound to the final commit and runtime. This is not proof that Docker
cannot be escaped. The immutable `v4.5.0` release ledger contains no gVisor
result; a later same-owner observation using the exact released zipapp is
retained under
[`evidence/runtime-observations/v4.5.0-gvisor-31298956172`](../evidence/runtime-observations/v4.5.0-gvisor-31298956172).
That supplemental observation is not independent, production, hostile-host, or
field-efficacy evidence.

**Does NOT guarantee:** that the exact built artifact you deploy is the one judged
(the verdict binds to the runtime image digest, not a separately built artifact —
see [`ROADMAP.md`](../ROADMAP.md)).

**Try it (same example, now containerised):**
```bash
cd examples/blackbox-cli
evo-guard guard ./sample_repo --patch patches/honest.txt --verifier-pack ./pack --blackbox \
    --isolation docker --docker-image python:3.12-slim \
    --require-candidate-isolation docker
```
**Expected:** `✅ PASS` at `candidate_isolation: docker`; `⚠️ ERROR` if the daemon or
image is missing (fail-closed).

The candidate launcher uses the exact resolved image ID, not a mutable tag.
`setup_command` is currently rejected with `--blackbox` rather than being
silently applied to only one side of the composite; bake required runtime
dependencies into the image/environment.

> **HTTP / networked services:** a documented, tested recipe ships in
> [`examples/blackbox-http/`](../examples/blackbox-http/) — the pack launches the
> service via `$EVOGUARD_EXEC` and asserts on live HTTP responses (in-process
> forgery lands in the *server* process and moves nothing). It uses the
> **subprocess** black-box boundary: the hardened `--network none` container
> deliberately severs the judge↔candidate channel, so for container-level
> isolation wrap the behaviour behind a CLI entry point instead.

---

## Path 4 — Trusted Finalizer (split re-verification and signing)

**When:** a PR author is semi-trusted or untrusted and a normal Guard job must
not receive a signing key, deployment credential, or write-capable token.

**Guarantees:** a metadata job writes the PR/run/base/head/tree control record
before candidate execution; the unprivileged job re-verifies that exact pair;
then a separate job re-fetches current PR/tree metadata, matches the exact
handoff and verdict bytes, and signs a final `ALLOW` or `DENY` evidence bundle.
The signing job never checks out or runs candidate code.

The fixed metadata preflight creates one pending Check Run per re-verification
attempt before candidate execution; the candidate job has no write permission.
Test the resulting repeated Check Runs against the actual GitHub ruleset before
requiring their shared display name, or prefer a Required Workflow rule.

**Does NOT guarantee:** universal correctness, a fully hostile-code-safe Docker
kernel boundary, or verification of your deployment artifact. It starts with
open same-repository PRs targeting the protected default branch and manual
maintainer dispatch. These limits are intentional and fail closed rather than
being hidden behind an automatic workflow.

**Start here:** [`TRUSTED_FINALIZER.md`](TRUSTED_FINALIZER.md) and the current
implementation-ready
[`evoguard-reverify.yml`](../.github/workflows/evoguard-reverify.yml) /
[`evoguard-seal.yml`](../.github/workflows/evoguard-seal.yml) pair. The separate
[`examples/trusted-finalizer/`](../examples/trusted-finalizer/) pair is the
frozen v3.7.0 reference used by the historical pilot.

---

## Pin a verifier pack (Paths 1–3)

```bash
evo-guard pack-doctor /secure/pack
# Set PACK_SHA256 to the reported "pack sha256" in protected CI/policy.
evo-guard guard . --diff patch.diff --no-config --verifier-pack /secure/pack \
  --expect-verifier-pack-sha256 "$PACK_SHA256"
```

V2 binds the pack's typed directory/file paths and content; symlinks and special
files are refused. Guard verifies the accepted snapshot before and after it runs
and records the digest, manifest and pack test counts in the attestation.

For a direct `--diff` run, `/secure/pack` must be outside the candidate checkout.
For the GitHub Action on `pull_request`, put the pair in the base policy instead:

```json
{
  "verifier_pack": "security/evoguard-pack",
  "expect_verifier_pack_sha256": "<64-hex-EVOGUARD_PACK_V2-digest>"
}
```

The Action stages that repository-relative directory from the base SHA, never
from the candidate checkout. Do not put these judge settings in workflow
`with:` fields; candidate workflow values are not policy. See
[`VERIFIER_PACKS.md`](VERIFIER_PACKS.md) for the exact source rules.

For repo-native docker/gVisor runs, `setup_command` runs inside a writable setup
container by default, then suite and pack receive the candidate read-only. New
conventional dependency/build outputs are permitted. Additional
`setup_output_globs` in protected `.evoguard.json` are **trusted exceptions**;
keep them narrow. They do not exempt base-owned paths declared in
`harness_inputs` or their ancestors. For a repo-native channel, its trusted
snapshot precedes candidate materialization and is compared at the documented
observation points; in subprocess mode this is not continuous immutability.
`trust_setup_on_host` is an explicit recorded downgrade to effective
`subprocess` isolation.

---

## Enforce a floor (any path)

Make the assurance a contract — Guard refuses rather than ship a weaker guarantee:

```bash
--require-report-integrity external_process_isolated   # must be --blackbox-only
--require-candidate-isolation docker                   # must be a container
```

See [`ASSURANCE.md`](ASSURANCE.md) for exactly what each level proves.
