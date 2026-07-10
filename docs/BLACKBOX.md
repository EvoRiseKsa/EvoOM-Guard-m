<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# The external black-box judge (`--blackbox`)

The default judge runs your tests **in the same process** as the code under
test, so a patch that writes deliberate forgery into source — an `atexit` hook
that overwrites the JUnit report and calls `os._exit(0)` — can fake a `PASS`
(see [`docs/ASSURANCE.md`](ASSURANCE.md)). The black-box judge closes that hole
by construction, and ships with a before/after proof: the *identical* forgery
that yields a false `PASS` under the default judge yields the correct `FAIL`
here.

```bash
evo-guard guard ./repo --patch candidate.txt \
    --verifier-pack examples/blackbox-pack --blackbox
```

## How it works

- The **verdict-producing process is the judge's own pytest over the pack** — it
  never imports the candidate's code, so the candidate cannot register an
  `atexit` hook in it, cannot `os._exit` it, cannot rewrite its report. Its exit
  code is authoritative.
- The candidate is exercised **only across a process boundary**. Guard applies
  the patch to a throwaway copy and sets two environment variables for the pack:

  | env var | meaning |
  |---|---|
  | `EVOGUARD_TARGET` | path to the patched repo copy |
  | `EVOGUARD_PYTHON` | interpreter to launch the candidate with |

  The pack invokes the candidate as a subprocess (a CLI, `python -m tool`, an
  HTTP server it starts, …) and asserts on its **observable outputs**. Forgery
  code in the candidate's source runs only inside those child processes, where
  `os._exit(0)` affects the child, not the judge — and the pack checks outputs,
  not the child's exit code, so a lying child changes nothing.

## Writing a pack (the one rule)

**Invoke the candidate across a process boundary — never `import` it.** If a pack
test does `import calc` and calls it in-process, the candidate's code runs in the
judge's process again and the guarantee is gone. Use `subprocess` (CLI/`-m`),
`requests`/`httpx` against a server the pack starts, a DB client, etc. See
[`examples/blackbox-pack/`](../examples/blackbox-pack/).

## What it guarantees — and the one edge

- `report_integrity` becomes **`external_process_isolated`**: the demonstrated
  same-process report/exit forgery is defeated (proven in
  `tests/test_blackbox.py`).
- **Edge, stated plainly:** a candidate child could spawn a *detached* grandchild
  that sleeps and races the judge's read of its report. The judge reads its own
  report the instant pytest returns (all pack subprocesses have exited by then)
  and grades primarily by its **own exit code**, so the race is already
  impractical. Run with `--isolation docker` to remove it entirely — the
  container is torn down after the run, reaping any lingering process.

## Scope

Black-box mode fits targets with a **process / protocol boundary**: CLIs, HTTP
services, DB-backed programs, anything with a defined I/O contract. A pure
library that the pack must `import` is back in-process and gets the
same-process assurance instead — wrap it behind a thin CLI (a few lines) to get
the black-box guarantee.
