<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Assurance — how much a verdict can be trusted

Every Guard verdict carries an `assurance` object. It exists because two
integrity properties are routinely conflated, and only one of them is a strong
guarantee:

```json
"assurance": {
  "execution_state": "completed",
  "execution_phase": "repo_suite",
  "harness_integrity": "pre_gate_enforced",
  "report_integrity": "same_process_candidate_writable",
  "candidate_isolation": "subprocess",
  "suite_isolation": "subprocess",
  "setup_isolation": null,
  "verifier_pack": null,
  "overall_profile": "repo_native_same_process",
  "note": "..."
}
```

For a protected-harness edit or another result decided by the diff pre-gate,
the runtime axes are explicitly not delivered:

```json
"assurance": {
  "execution_state": "static_gate",
  "execution_phase": "pre_gate",
  "harness_integrity": "pre_gate_enforced",
  "report_integrity": "not_applicable_static_gate",
  "candidate_isolation": "not_run",
  "suite_isolation": "not_run",
  "setup_isolation": null,
  "runtime_continuity": "not_applicable",
  "verifier_pack": {
    "configured": true,
    "present": null,
    "integrity": "not_evaluated_static_gate",
    "identity_verified": null,
    "execution_state": "static_gate",
    "secrecy": "not_evaluated_static_gate",
    "snapshot_sha256": null
  },
  "overall_profile": "static_gate"
}
```

Here `configured: true` records policy input only. `present: null` means Guard
did not open or validate the path before the static decision. The requested
isolation remains in `attestation.effective_policy`; it is not delivered
evidence.

Schema 1.11 also separates static policy decisions from runtime preflight and
incomplete execution:

- `not_started` means runtime evaluation was requested but no test/judge process
  started. Its assurance profile is `preflight`, both isolation axes are
  `not_run`, and `report_integrity` is `not_applicable_not_run`.
- `started_incomplete` means a setup, suite, or judge process started but the
  required sequence did not finish. Its profile is
  `execution_incomplete_before_tests` when only setup began, otherwise
  `execution_incomplete`.
- `completed` means required execution returned and post-execution checks ran;
  it does not imply that the verdict passed.

The top-level `execution_phase` names the furthest/decisive phase. The
top-level `test_command_ran` records process start, so it remains `true` on a
suite/judge timeout even when `verdict_source` is `null`. A setup-only timeout
has `test_command_ran: false`. Requested mode/isolation is kept
in `attestation.effective_policy`; no-run assurance never repeats it as
delivered evidence.

## The two integrity properties

### `harness_integrity` — can the patch change the *checks*?

**`pre_gate_enforced` — a robust guarantee.** Guard inspects the patch's file
list *before running anything* and rejects any edit or deletion of the tests,
their configuration, the gate's CI, or an auto-executed file. This is a static
analysis of the diff, so runtime code cannot undo it. The reward-hacks agents do
in practice — deleting a failing test, adding a `-k`/`--ignore` deselect,
dropping a `sitecustomize.py` — are all caught here, before the suite runs.

### `report_integrity` — can the code under test forge the *result*?

**`same_process_candidate_writable` — NOT a guarantee.** The verdict is read
from a judge-owned JUnit report plus the process exit code. That defeats
stdout-scraping (`print("9999 passed")` moves nothing). But the code under test
runs **in the same process** as pytest and the report writer. A patch that
writes deliberate forgery into source — for example:

```python
import atexit, os, sys
def _forge():
    for a in sys.argv:
        if a.startswith("--junitxml="):
            open(a.split("=", 1)[1], "w").write("<testsuite tests='1' failures='0' errors='0'/>")
    os._exit(0)
atexit.register(_forge)
```

can overwrite the judge-owned report and force a zero exit, producing a **false
`PASS` on a genuinely failing test**. Guard ships an adversarial test
(`tests/test_report_integrity.py`) that proves this, so the claim can never
silently drift back to "unforgeable".

**The container isolation modes do not fix this.** `--isolation docker`/`gvisor`
protect the *host* from the candidate; inside the container the candidate,
pytest, and the report still share one process and authority. `candidate_isolation`
is therefore a separate axis from `report_integrity`.

## Why there is no in-process fix

Anything a process produces — its exit code, the files it writes, the streams it
emits — can be controlled by code running in that process at shutdown. Streaming
results to a parent over a pipe does not help either: the candidate's module is
imported *before* the tests run, so it can monkeypatch the runner or the
reporting plugin. Same-process authority means same-process control. The only
robust fix is to stop running the candidate in the judge's own process.

## The fix, shipped: an external black-box judge

**Shipped in v3.0 as `--blackbox`, hardened through v3.4** (see [`BLACKBOX.md`](BLACKBOX.md)):
the verdict comes from the judge's own pytest over a pack of judge-owned tests
that never import the candidate; the candidate is exercised only across a process
boundary. That phase has `external_process_isolated` report integrity, and the
same forgery that fakes a PASS under the default judge is caught. A default
composite verdict also requires the repo-native channel and therefore reports
its weaker `same_process_candidate_writable` level; `--blackbox-only` is the
fully external profile. v3.2 added a real `CandidateRunner` and a **composite**
repo-suite + pack verdict. Schema 1.11 makes candidate isolation evidence
invocation-based: launcher receipt (plus a runtime-written CID for containers),
never configuration or preparation alone. v3.4 adds canonical V2 pack identity,
optional digest pinning, verified external snapshots and mandatory separate pack
execution. The remaining direction — binding the
verdict to an immutable built **artifact digest** — is in [`ROADMAP.md`](../ROADMAP.md).

## `overall_profile` levels

| Level | Meaning |
|---|---|
| `static_gate` | the diff pre-gate alone decided the result; candidate, suite, setup, report channel, and verifier pack did not run (`not_run` / `not_applicable_static_gate`) |
| `preflight` | runtime verification was requested but stopped before any test/judge process started (`not_run` / `not_applicable_not_run`) |
| `execution_incomplete_before_tests` | setup or another prerequisite started, but no test/judge process started and the required sequence did not complete |
| `execution_incomplete` | a suite, pack, or black-box judge process started but the required sequence did not complete; no clean verdict source is implied |
| `repo_native_same_process` | suite ran; candidate + report share one process (subprocess mode) |
| `isolated_repo_native` | suite ran in a container (host isolated); report still same-process |
| `mixed_host_setup_repo_native` | suite ran in docker/gVisor, but explicit `trust_setup_on_host` ran setup on the host; effective candidate isolation is therefore only `subprocess` |
| `black_box_external_judge` | `--blackbox-only`: the completed verdict has only the judge-owned external report channel (`report_integrity: external_process_isolated`) |
| `composite_blackbox_repo_native` | default completed `--blackbox`: external pack plus required repo-native suite; overall report integrity is the weaker `same_process_candidate_writable` channel |
| `blackbox_composite_short_circuit` | default `--blackbox` where one required phase stopped the pipeline before the repo-native report channel started; that channel is not claimed as executed |

## Enforcing assurance (fail-closed policy)

`assurance` is not just a description — you can make it a **contract**. Require a
floor, and Guard refuses (returns `ERROR` / `assurance_requirement_not_met`)
rather than shipping a weaker guarantee than you asked for:

```bash
# CI insists every required verdict channel is external; skip the repo-native channel.
evo-guard guard ./repo --patch p.txt \
    --verifier-pack ./pack --blackbox --blackbox-only \
    --require-report-integrity external_process_isolated
```

The floor is checked against **observed evidence from the required execution
phases**, never the requested value or preparation alone, and is applied only
when an otherwise successful execution has reached a completed `PASS`. It does
not overwrite a more specific static, preflight, setup,
timeout/incomplete, invalid/missing/mismatched pack, tamper, or isolation error.
For example, a protected-test edit remains
`REJECTED protected_harness_edit` even if Docker was required, and its runtime
axes say `not_run`; a suite timeout remains `test_timeout` with
`execution_state: started_incomplete` instead of becoming a synthetic assurance
error. `--require-candidate-isolation` orders delivered execution as
`subprocess < docker < gvisor`. If Docker is requested but the daemon/image is
unavailable before the suite starts, the verdict keeps that specific error,
top-level and assurance isolation stay `not_run`, and the unavailable delivery
attempt is recorded separately in attestation `isolation_evidence`—never as a
`PASS` labelled `docker`.

`suite_isolation` and `setup_isolation` make a mixed run visible. Under
docker/gVisor, `setup_command` runs inside the same resolved image by default,
with the candidate workspace writable only for setup; suite and verifier-pack
phases receive read-only candidate mounts. The compatibility opt-in
`trust_setup_on_host` is recorded as `subprocess_host_opt_in` and lowers
`candidate_isolation` to `subprocess`, so a required docker floor fails closed.
`setup_output_globs` are trusted repository policy: matching paths are excluded
from setup-fidelity comparison, so broad patterns weaken what that check proves.
They apply only to **setup validation**. Once setup finishes, they do not exempt
matching content from repo-suite/verifier-pack runtime-continuity identity.

### Filesystem and runtime-continuity boundary

Workspace operations have deliberately different platform claims:

- On POSIX, Guard opens the workspace root and every parent with
  descriptor-relative, no-follow operations. Reads bind the opened object;
  writes use a temporary file plus descriptor-relative replacement; deletion
  uses the held parent descriptor. A parent swap cannot redirect the operation,
  and a POSIX runtime missing the required primitives fails closed.
- On Windows, Python's standard library exposes no atomic equivalent of
  `openat`/`unlinkat`. Guard rejects symlink/junction parents and compares parent
  and file identity before and after the protected operation. This narrows the
  race window but is explicitly **best effort, not an atomic guarantee**.

For a repo-native verifier pack, the accepted post-setup runtime tree has the
content identity format `EVOGUARD_RUNTIME_TREE_V1`. It includes dependency/build
outputs created by setup, including paths allowed during setup validation. The
identity accepts relative symlinks only when their resolved referent remains
inside the runtime root; absolute, escaping, and dangling links fail closed.
For Python environments that would create an absolute interpreter link, use
`python -m venv --copies`. Scans also fail closed above 500,000 entries, 128 MiB
of canonical path bytes, 32 GiB of logical regular-file bytes, or 8 GiB in one
file. The 120-second scan deadline is cooperative between filesystem calls; it
cannot interrupt a kernel/filesystem call that itself hangs, so untrusted or
network filesystems still require an outer process/job timeout. The
continuity evidence states what was actually enforced:

- `unavailable` means the initial runtime identity could not be captured;
  `incomplete` means execution stopped before every required boundary was
  checked; and `verification_failed` means a later identity could not be
  reproduced or differed. These are failure states, not delivered-continuity
  claims.
- `snapshot_boundary_checked` in subprocess mode means the runtime identity was
  compared at suite/pack phase boundaries. It detects persistent drift but does
  not stop a lingering process from mutating and restoring bytes between those
  observations.
- `read_only_enforced` means Docker/gVisor suite and pack phases received the
  accepted runtime tree read-only. It is used only when setup stayed inside the
  requested container boundary (or no setup command ran). If a configured setup
  command ran on the host through `trust_setup_on_host`, that process could
  outlive setup, so the stronger label is not claimed even though later
  container mounts themselves are read-only.

Runtime continuity is separate from `report_integrity`: a read-only candidate
tree does not make a repo-native same-process JUnit writer unforgeable.

For directory-report runners such as Maven/Surefire, the whole directory is one
evidence set. Any `*.xml` sibling that is symlinked, special, unreadable,
malformed, oversized, or contains DTD/ENTITY declarations invalidates the set;
Guard never computes a pass from only the remaining files.

In black-box mode the verdict is **composite** by default: your repo's own suite
*and* the external pack must both pass (harness-integrity always applies first).
The pack adds an independent, judge-owned external evidence dimension; it never
replaces the internal suite. Pure-CLI targets with no in-repo suite opt out with
`--blackbox-only`. Because assurance is an end-to-end minimum, the completed
composite reports `same_process_candidate_writable`; only `--blackbox-only`
delivers an overall `external_process_isolated` report channel.

## Verifier-pack identity and execution

A configured pack is not just copied next to the candidate. Guard creates a
snapshot outside the candidate tree, validates the canonical manifest, rejects
symlinks/special files, and calculates a framed `EVOGUARD_PACK_V2` SHA-256 over
typed path/content records. `--expect-verifier-pack-sha256 <64-hex>` (or the
equivalent protected config/Action input) pins the accepted identity before
candidate code runs. The attestation records that digest, manifest, digest
format and pack test counts.

Schema 1.11 exposes the pack lifecycle without converting policy into evidence:

| Field | Evidence represented |
|---|---|
| `configured` | a path was requested in policy only |
| `present` | observed path presence (`null` when the static gate did not inspect it) |
| `integrity` | missing, invalid, identity mismatch, accepted pre-execution, verified pre/post or read-only, or changed snapshot state |
| `identity_verified` | whether the accepted snapshot identity was established (`null` when not evaluated) |
| `execution_state` | independent pack state: `static_gate`, `not_started`, `started_incomplete`, or `completed` |
| `secrecy` | delivered reachability, or explicitly not evaluated when execution did not start |
| `snapshot_sha256` | observed accepted `EVOGUARD_PACK_V2` digest, never the expected policy pin |

The exact `integrity` labels are `not_evaluated_static_gate`,
`not_evaluated_missing`, `invalid`, `snapshot_identity_mismatch`,
`verified_snapshot_pre_execution`, `verified_snapshot_pre_post`,
`verified_snapshot_read_only`, `snapshot_changed`, and `not_evaluated`.
Therefore a missing path cannot look like an invalid-but-present pack, a digest
mismatch cannot look verified, a timeout after snapshot acceptance cannot claim
the post-execution check, and observed drift cannot look like a stable snapshot.

In repo-native mode the repo suite and pack execute as separate mandatory
phases and both must pass; zero collected pack tests is not a verdict. The
snapshot and candidate tree are checked around execution. In container modes,
the candidate and pack mounts are read-only. This is an integrity boundary, not
repo-native secrecy: imported candidate code still shares the pack's pytest
process. In black-box mode the judge executes its private snapshot on the host
and verifies it before/after (`verified_snapshot_pre_post`). When container
isolation is selected, a judge-owned launcher receipt plus a runtime CID records
use of that candidate boundary; the trusted pack's assertions establish the
candidate semantics. The pack is not mounted into the candidate boundary; this
is recorded as secrecy, not falsely as a read-only pack mount.

## Composing external + internal coverage

`--blackbox` is **composite by default**: it runs the repo's own unit suite *and*
the pack's external protocol tests, and both must pass. A narrow protocol test
can therefore never hide an internal regression:

```yaml
- uses: EvoRiseKsa/EvoOM-Guard-m@v3.5.2      # repo suite AND external pack (composite)
  with: { verifier-pack: ./pack, blackbox: "true",
          require-report-integrity: same_process_candidate_writable }
```

The attestation records both results (`repo_suite_passed`,
`repo_suite_junit_sha256`) next to the pack's. A pure-CLI/service target that has
no in-repo suite passes `blackbox-only: "true"` to judge the pack alone.
Set that input when requiring `external_process_isolated`; the default
composite cannot honestly satisfy that floor.

## How to use it

- **Trusted authors / your own code** (the primary use case): a `PASS` at
  `repo_native_same_process` is exactly what you want — it means the suite passed
  and nobody touched the harness. Forging the report would require writing
  blatant `os._exit(0)` forgery into a source file, which code review catches
  loudly.
- **Untrusted or semi-trusted authors**: a same-process `PASS` means "the common
  cheats were blocked", not "correctness proven". Require human review of the
  diff, and use the shipped external judge (`--blackbox`, with `--isolation
  docker` for a delivered boundary) for a report-integrity guarantee the code
  under test cannot forge.

The shell-free `$EVOGUARD_EXEC` used by every black-box isolation mode is a
POSIX executable launcher. Native Windows fails closed before subprocess,
Docker, or gVisor delivery rather than claiming a boundary it did not deliver;
use Linux/GitHub Actions or WSL for that path. Ordinary repo-native Guard
execution on Windows is separate, but POSIX CPU/memory rlimits are unavailable
there (the wall timeout still applies).
