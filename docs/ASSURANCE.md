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

**Shipped in v3.0 as `--blackbox`, hardened in v3.2** (see [`BLACKBOX.md`](BLACKBOX.md)):
the verdict comes from the judge's own pytest over a pack of judge-owned tests
that never import the candidate; the candidate is exercised only across a process
boundary. `report_integrity` becomes `external_process_isolated`, and the same
forgery that fakes a PASS under the default judge is caught. v3.2 added a real
`CandidateRunner` with **delivered, fail-closed isolation** (a container the
verdict can prove it ran under, or `ERROR` — never a mislabelled `docker`) and a
**composite** repo-suite + pack verdict. The remaining direction — binding the
verdict to an immutable built **artifact digest** — is in [`ROADMAP.md`](../ROADMAP.md).

## `overall_profile` levels

| Level | Meaning |
|---|---|
| `static_gate` | only the harness-integrity check ran (no suite) |
| `repo_native_same_process` | suite ran; candidate + report share one process (subprocess mode) |
| `isolated_repo_native` | suite ran in a container (host isolated); report still same-process |
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

In black-box mode the verdict is **composite** by default: your repo's own suite
*and* the external pack must both pass (harness-integrity always applies first).
The pack adds an unforgeable external dimension; it never replaces the internal
suite. Pure-CLI targets with no in-repo suite opt out with `--blackbox-only`.

## Composing external + internal coverage

`--blackbox` is **composite by default**: it runs the repo's own unit suite *and*
the pack's external protocol tests, and both must pass. A narrow protocol test
can therefore never hide an internal regression:

```yaml
- uses: EvoRiseKsa/EvoOM-Guard-m@v3.2.0      # repo suite AND external pack (composite)
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
- **Untrusted or semi-trusted authors**: treat a `PASS` as "the common cheats
  were blocked", not "correctness proven". Require human review of the diff, and
  track the roadmap's external judge for a hard guarantee.
