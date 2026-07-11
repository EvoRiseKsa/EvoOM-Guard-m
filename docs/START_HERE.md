<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Start here — pick your path in 30 seconds

EvoOM Guard has one job: *did this patch fix the code without gaming the tests?*
There are three ways to run it. Pick one — you do **not** need the others to start.

## Decision table

| Your need | Path | Command flag |
|---|---|---|
| Stop an AI agent from editing/deleting your tests, and run your suite | **Basic Guard** | *(none — the default)* |
| Also verify a **CLI's** external behaviour, unforgeable | **Black-box CLI** | `--blackbox` + `--verifier-pack` |
| Verify an **HTTP service** behind a real isolation boundary | **Black-box HTTP** | `--blackbox` + `--isolation docker` |

Quick tree:

```
Just want to block test-harness tampering?           → Basic Guard
Want to check a program's behaviour from outside?    → Black-box
   target is a CLI / `python -m tool`?               → Black-box CLI
   target is an HTTP service?                        → Black-box HTTP
Need a guaranteed OS isolation boundary?             → add --isolation docker (fail-closed)
```

---

## Path 1 — Basic Guard

**When:** your own repo, trusted authors, you want the common reward-hacks blocked.

**Guarantees:** any edit/deletion of tests, their config, CI, or auto-exec files is
`REJECTED` **before the suite runs** (static, runtime code can't undo it); the
verdict is read from a judge-owned JUnit report + exit code, never stdout.

**Does NOT guarantee:** a patch that writes deliberate `atexit`+`os._exit` forgery
into *source* can still fake a `PASS` (`report_integrity:
same_process_candidate_writable`). Use a black-box path to close that.

**Try it:**
```bash
git diff main...HEAD | evo-guard guard --diff - --test-command "python -m pytest -q"
```
**Expected:** `✅ PASS` if the suite passes and the harness is untouched; `⛔ REJECTED`
if the patch touches a test/config; `❌ FAIL` if tests fail.

---

## Path 2 — Black-box CLI

**When:** the target has a command-line boundary (`python -m tool`, a binary) and
you want a verdict a patch can't forge from inside its own process.

**Guarantees:** the verdict comes from the **judge's own pytest** over a judge-owned
protocol pack that never imports your code (`report_integrity:
external_process_isolated`); by default it is **composite** — your repo's own suite
**and** the pack must both pass.

**Does NOT guarantee (without `--isolation docker`):** OS isolation — the candidate
runs as a host subprocess.

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

## Path 3 — Black-box HTTP (isolated)

**When:** the target is an HTTP service and you want it judged behind a real
container boundary.

**Guarantees:** everything Path 2 gives, **plus** delivered isolation — the
candidate runs in a network-less, read-only container with the pack unmounted;
requesting `docker` with no daemon/image **fails closed** (`ERROR`), never a
mislabelled `PASS`. Proven against a real daemon in CI
(`tests/test_blackbox_docker_e2e.py`).

**Does NOT guarantee:** that the exact built artifact you deploy is the one judged
(the verdict binds to the runtime image digest, not a separately built artifact —
see [`ROADMAP.md`](../ROADMAP.md)).

**The pack shape** — start the service via `$EVOGUARD_EXEC`, hit it over the loopback,
assert on responses (adapt the CLI pack in `examples/blackbox-cli/pack/`):
```python
# pack/test_http.py  (sketch)
import os, subprocess, sys, time, urllib.request

def test_health():
    exec_, py = os.environ["EVOGUARD_EXEC"], os.environ.get("EVOGUARD_PYTHON", "python3")
    srv = subprocess.Popen([exec_, py, "-m", "myservice", "--port", "8080"])
    try:
        time.sleep(1.0)
        body = urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=3).read()
        assert body == b"ok"
    finally:
        srv.terminate()
```
```bash
evo-guard guard ./repo --patch p.txt --verifier-pack ./pack --blackbox \
    --isolation docker --docker-image python:3.12-slim \
    --require-candidate-isolation docker
```
**Expected:** `✅ PASS` at `candidate_isolation: docker`; `⚠️ ERROR` if the daemon or
image is missing (fail-closed).

---

## Enforce a floor (any path)

Make the assurance a contract — Guard refuses rather than ship a weaker guarantee:

```bash
--require-report-integrity external_process_isolated   # must be black-box
--require-candidate-isolation docker                   # must be a container
```

See [`ASSURANCE.md`](ASSURANCE.md) for exactly what each level proves.
