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
# Set PACK_SHA256 to the EVOGUARD_PACK_V2 value reported by pack-doctor.
evo-guard guard ./repo --patch candidate.txt \
    --verifier-pack examples/blackbox-pack --blackbox \
    --expect-verifier-pack-sha256 "$PACK_SHA256"
```

## How it works

- The **verdict-producing process is the judge's own pytest over the pack** — it
  never imports the candidate's code, so the candidate cannot register an
  `atexit` hook in it, cannot `os._exit` it, cannot rewrite its report. Its exit
  code is authoritative.
- Before the runner is prepared, Guard validates the canonical `pack.json`,
  snapshots the pack outside the candidate tree and calculates its framed
  `EVOGUARD_PACK_V2` identity. Symlinks/special files and packs with no
  `test_*.py` are refused; zero collected results cannot pass. The snapshot is
  verified before and after execution; the optional
  expected SHA-256 pin must match before candidate code runs.
- The candidate is exercised **only across a process boundary**. Guard applies
  the patch (including **deletions** — a removed file is absent in the judged
  tree, matching the real merge) to a throwaway copy and sets these environment
  variables for the pack:

  | env var | meaning |
  |---|---|
  | `EVOGUARD_EXEC` | a launcher that runs its argv **under the delivered isolation** (host subprocess, or a read-only container) with the repo copy as the working root — **prefer this** |
  | `EVOGUARD_PYTHON` | the interpreter token to launch a python candidate with |
  | `EVOGUARD_TARGET` | path to the patched repo copy (used only in the no-launcher fallback) |

  The pack invokes `subprocess.run([EVOGUARD_EXEC, EVOGUARD_PYTHON, "-m", "tool", …])`
  and asserts on the candidate's **observable outputs**. Forgery code in the
  candidate's source runs only inside those child processes, where `os._exit(0)`
  affects the child, not the judge — and the pack checks outputs, not the child's
  exit code, so a lying child changes nothing.

## Isolation is *delivered*, never merely requested

`candidate_isolation` in the verdict is the boundary the runner **actually
delivered**, read from the run — not the flag you passed. If you ask for
`--isolation docker` and the daemon is down, the image is missing, or the runtime
is absent, Guard **refuses** (`ERROR` / `assurance_requirement_not_met`) rather
than silently running on the host and *labelling* it docker. Pair it with the
fail-closed floor and a container boundary becomes a contract:

```bash
evo-guard guard ./repo --patch p.txt --verifier-pack ./pack --blackbox \
    --isolation docker --docker-image python:3.12-slim \
    --require-candidate-isolation docker
```

In a container boundary the repo copy is mounted **read-only** and the
judge-owned pack is **not mounted into the candidate at all** — so candidate code
can neither write the host nor reach the pack to tamper with it. (In the
`subprocess` boundary the candidate shares the host and user with the judge;
`assurance.verifier_pack.secrecy` says so honestly — `reachable_same_host`.)
The launcher executes the exact resolved image ID that was probed, rather than a
mutable tag.

The shell-free `$EVOGUARD_EXEC` file has a **POSIX executable contract**. Native
Windows black-box subprocess mode fails closed with guidance instead of claiming
that it ran; use Linux/GitHub Actions or WSL. The ordinary repo-native Windows
judge is a different path.

## The pack ADDS a dimension — it does not replace your suite

By default `--blackbox` runs a **composite** verdict: the harness-integrity check,
**your repo's own test suite**, *and* the external pack must all pass. A green
pack can never mask an internal regression the pack does not exercise. For a
pure-CLI/service target that has no in-repo suite, pass `--blackbox-only` to judge
the pack alone. The attestation records the repo suite's result
(`repo_suite_passed`, `repo_suite_junit_sha256`) alongside the pack's.

`setup_command` is not silently applied to only part of this composite. In 3.4,
combining setup with `--blackbox` returns
`ERROR policy_requirement_unsupported`; place runtime dependencies in the
environment/container image until a single explicit setup boundary exists for
both sides.

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

With delivered docker/gVisor isolation the candidate network defaults to
`none`. A pack outside that candidate container therefore cannot reach an HTTP
server inside it without a deliberately designed judge↔candidate channel. Use a
CLI/stdio boundary today, or a reviewed network topology that matches your
policy; do not infer HTTP reachability merely from `target_type` in `pack.json`.
