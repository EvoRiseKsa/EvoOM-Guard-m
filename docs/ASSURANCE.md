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

## The fix on the roadmap: an external black-box judge

**Shipped in v3.0 as `--blackbox`** (see [`BLACKBOX.md`](BLACKBOX.md)): the
verdict comes from the judge's own pytest over a pack of judge-owned tests that
never import the candidate; the candidate is exercised only across a process
boundary. `report_integrity` becomes `external_process_isolated`, and the same
forgery that fakes a PASS under the default judge is caught. The remaining work
is hardening (container-per-candidate, HTTP/DB target helpers) — see
[`ROADMAP.md`](../ROADMAP.md).

## `overall_profile` levels

| Level | Meaning |
|---|---|
| `static_gate` | only the harness-integrity check ran (no suite) |
| `repo_native_same_process` | suite ran; candidate + report share one process (subprocess mode) |
| `isolated_repo_native` | suite ran in a container (host isolated); report still same-process |
| `black_box_external_judge` | **shipped (`--blackbox`)** — verdict from the judge's own process; the candidate runs only across a process boundary. `report_integrity: external_process_isolated`. See [`BLACKBOX.md`](BLACKBOX.md). |

## How to use it

- **Trusted authors / your own code** (the primary use case): a `PASS` at
  `repo_native_same_process` is exactly what you want — it means the suite passed
  and nobody touched the harness. Forging the report would require writing
  blatant `os._exit(0)` forgery into a source file, which code review catches
  loudly.
- **Untrusted or semi-trusted authors**: treat a `PASS` as "the common cheats
  were blocked", not "correctness proven". Require human review of the diff, and
  track the roadmap's external judge for a hard guarantee.
