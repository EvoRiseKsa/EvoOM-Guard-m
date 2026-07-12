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
boundary. `report_integrity` becomes `external_process_isolated`, and the same
forgery that fakes a PASS under the default judge is caught. v3.2 added a real
`CandidateRunner` with **delivered, fail-closed isolation** (a container the
verdict can prove it ran under, or `ERROR` — never a mislabelled `docker`) and a
**composite** repo-suite + pack verdict. v3.4 adds canonical V2 pack identity,
optional digest pinning, verified external snapshots and mandatory separate pack
execution. The remaining direction — binding the
verdict to an immutable built **artifact digest** — is in [`ROADMAP.md`](../ROADMAP.md).

## `overall_profile` levels

| Level | Meaning |
|---|---|
| `static_gate` | only the harness-integrity check ran (no suite) |
| `repo_native_same_process` | suite ran; candidate + report share one process (subprocess mode) |
| `isolated_repo_native` | suite ran in a container (host isolated); report still same-process |
| `mixed_host_setup_repo_native` | suite ran in docker/gVisor, but explicit `trust_setup_on_host` ran setup on the host; effective candidate isolation is therefore only `subprocess` |
| `black_box_external_judge` | **shipped (`--blackbox`)** — verdict from the judge's own process; the candidate runs only across a process boundary. `report_integrity: external_process_isolated`. See [`BLACKBOX.md`](BLACKBOX.md). |

## Enforcing assurance (fail-closed policy)

`assurance` is not just a description — you can make it a **contract**. Require a
floor, and Guard refuses (returns `ERROR` / `assurance_requirement_not_met`)
rather than shipping a weaker guarantee than you asked for:

```bash
# CI insists the verdict came from the external judge; a same-process run is refused.
evo-guard guard ./repo --patch p.txt \
    --verifier-pack ./pack --blackbox \
    --require-report-integrity external_process_isolated
```

The check is against **what actually ran**, never the requested value — so Guard
can never claim a level it did not enforce. `--require-candidate-isolation` does
the same for `subprocess < docker < gvisor`, and it reads the isolation the
runner **delivered**: request `--isolation docker` with the daemon down or the
image missing and Guard returns `ERROR` (`candidate_isolation` reported as
`unavailable`), never a `PASS` mislabelled `docker`. The delivered boundary and
its evidence (`image_digest`, `network`, `runtime`) are recorded in the
attestation's `isolation_evidence`.

`suite_isolation` and `setup_isolation` make a mixed run visible. Under
docker/gVisor, `setup_command` runs inside the same resolved image by default,
with the candidate workspace writable only for setup; suite and verifier-pack
phases receive read-only candidate mounts. The compatibility opt-in
`trust_setup_on_host` is recorded as `subprocess_host_opt_in` and lowers
`candidate_isolation` to `subprocess`, so a required docker floor fails closed.
`setup_output_globs` are trusted repository policy: matching paths are excluded
from setup-fidelity comparison, so broad patterns weaken what that check proves.

In black-box mode the verdict is **composite** by default: your repo's own suite
*and* the external pack must both pass (harness-integrity always applies first).
The pack adds an independent, judge-owned external evidence dimension; it never
replaces the internal suite. Pure-CLI targets with no in-repo suite opt out with
`--blackbox-only`.

## Verifier-pack identity and execution

A configured pack is not just copied next to the candidate. Guard creates a
snapshot outside the candidate tree, validates the canonical manifest, rejects
symlinks/special files, and calculates a framed `EVOGUARD_PACK_V2` SHA-256 over
typed path/content records. `--expect-verifier-pack-sha256 <64-hex>` (or the
equivalent protected config/Action input) pins the accepted identity before
candidate code runs. The attestation records that digest, manifest, digest
format and pack test counts.

In repo-native mode the repo suite and pack execute as separate mandatory
phases and both must pass; zero collected pack tests is not a verdict. The
snapshot and candidate tree are checked around execution. In container modes,
the candidate and pack mounts are read-only. This is an integrity boundary, not
repo-native secrecy: imported candidate code still shares the pack's pytest
process. Black-box + delivered container isolation is the mode in which the
pack is not mounted into the candidate boundary at all.

## Composing external + internal coverage

`--blackbox` is **composite by default**: it runs the repo's own unit suite *and*
the pack's external protocol tests, and both must pass. A narrow protocol test
can therefore never hide an internal regression:

```yaml
- uses: EvoRiseKsa/EvoOM-Guard-m@v3.4.0      # repo suite AND external pack (composite)
  with: { verifier-pack: ./pack, blackbox: "true",
          require-report-integrity: external_process_isolated }
```

The attestation records both results (`repo_suite_passed`,
`repo_suite_junit_sha256`) next to the pack's. A pure-CLI/service target that has
no in-repo suite passes `blackbox-only: "true"` to judge the pack alone.

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

The shell-free `$EVOGUARD_EXEC` used by black-box subprocess mode is a POSIX
executable launcher. Native Windows subprocess mode fails closed rather than
claiming a boundary it did not deliver; use Linux/GitHub Actions or WSL for that
path. Ordinary repo-native Guard execution on Windows is separate, but POSIX
CPU/memory rlimits are unavailable there (the wall timeout still applies).
