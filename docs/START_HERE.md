<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Start here — pick your path in 30 seconds

EvoOM Guard has one job: *did this software change satisfy the selected judge
without gaming the evidence?* AI-generated patches are the primary use case, but
the mechanism does not depend on whether an AI, a human, or a bot authored the
change. There are three ways to run it. Pick one — you do **not** need the others
to start.

## Decision table

| Your need | Profile | Command flag |
|---|---|---|
| Stop an untrusted change (including an AI patch) from editing/deleting tests, and run your suite | **Basic integrity gate** (Path 1) | *(none — the default; optional `--verifier-pack` adds org checks)* |
| Also verify a **CLI's** external behaviour with a judge-owned external verdict | **External behavior gate** (Path 2) | `--blackbox` + `--verifier-pack` |
| Run the black-box candidate behind a real OS isolation boundary | **Isolated external gate** (Path 3) | `--isolation docker` (fail-closed) |
| Admit a semi-trusted PR only after a separate re-verification/sealing boundary | **Trusted Finalizer** (Path 4) | split GitHub workflows |

Quick tree:

```
Just want to block test-harness tampering?           → Basic Guard
Want to check a CLI's behaviour from outside?         → Black-box CLI
Need a guaranteed OS isolation boundary?              → add --isolation docker (fail-closed)
Need a signed PR admission record with separated key?  → Trusted Finalizer
```

Already have a verdict and need an offline admission/audit result? Use
`evo-guard verify-record` for internal consistency, or the authenticated
`bundle-evidence`/`verify-bundle` path when external key and replay-resistant
context are required. See [`RECORD_VERIFICATION.md`](RECORD_VERIFICATION.md) and
[`EVIDENCE_BUNDLES.md`](EVIDENCE_BUNDLES.md).

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

---

## Path 1 — Basic integrity gate ("Basic Guard")

**When:** your own repo, trusted authors, you want the common reward-hacks blocked.

**Guarantees:** any edit/deletion of tests, their config, CI, or auto-exec files is
`REJECTED` **before the suite runs** (static, runtime code can't undo it); the
verdict is read from a judge-owned JUnit report + exit code, never stdout.

**Does NOT guarantee:** a patch that writes deliberate `atexit`+`os._exit` forgery
into *source* can still fake a `PASS` (`report_integrity:
same_process_candidate_writable`). Use a black-box path to close that.

**Try it:**
```bash
git diff main...HEAD | evo-guard guard --diff - --no-config --test-command "python -m pytest -q"
```
**Expected:** `✅ PASS` if the suite passes and the harness is untouched; `⛔ REJECTED`
if the patch touches a test/config; `❌ FAIL` if tests fail.

**Optional independent checks:** adding a pinned
`--verifier-pack /secure/pack --expect-verifier-pack-sha256 <digest>` snapshots
that pack outside the candidate tree and runs it as a **separate mandatory
phase**. Repo suite and pack must both pass, and zero collected pack tests cannot
produce `PASS`.

---

## Path 2 — External behavior gate (black-box CLI)

**When:** the target has a command-line boundary (`python -m tool`, a binary) and
you want a verdict a patch can't forge from inside its own process.

**Guarantees:** the external phase comes from the **judge's own pytest** over a
judge-owned protocol pack that never imports your code. Use `--blackbox-only`
for an end-to-end `report_integrity: external_process_isolated` verdict. By
default it is **composite** — your repo's own suite **and** the pack must both
pass — so the overall profile honestly reports the weaker repo-native channel.
The pack must call `$EVOGUARD_EXEC`; a constant pack/direct target shortcut is
`ERROR candidate_not_exercised`.

**Does NOT guarantee (without `--isolation docker`):** OS isolation — the candidate
runs as a host subprocess. The shell-free black-box launcher has a POSIX
executable contract in every isolation mode; native Windows fails closed before
subprocess, Docker, or gVisor delivery, so use Linux/GitHub Actions or WSL for
this path.

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

**Guarantees:** on a completed `PASS`, a judge-owned receipt and runtime CID
establish that the trusted pack invoked the candidate launcher through a
network-less, read-only container; the pack's assertions establish the intended
candidate behaviour. The repo copy is mounted read-only and the pack is **not
mounted into the candidate at all**. Isolation is **observed, not requested**: a
missing daemon/image, absent launcher call, or failed cleanup is `ERROR`, never a
mislabelled `PASS`. Proven against a real daemon in CI, where a malicious
candidate cannot write the host or reach the pack
(`tests/test_blackbox_docker_e2e.py`).

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
keep them narrow. `trust_setup_on_host` is an explicit recorded downgrade to
effective `subprocess` isolation.

---

## Enforce a floor (any path)

Make the assurance a contract — Guard refuses rather than ship a weaker guarantee:

```bash
--require-report-integrity external_process_isolated   # must be --blackbox-only
--require-candidate-isolation docker                   # must be a container
```

See [`ASSURANCE.md`](ASSURANCE.md) for exactly what each level proves.
