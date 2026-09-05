<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# The external black-box judge (`--blackbox`)

> **Release boundary:** the black-box and Docker/gVisor mechanisms documented
> here are available in the current direct-release-recorded `v4.8.1` release
> (and were already present in ledger-recorded `v4.6.0`). Unprofiled records
> use the frozen schema `1.11`; explicit operating profiles use schema `1.12`.
> The same-owner direct release record authenticates the exact published
> artifact and workflow readback, not that any particular deployment delivered
> the requested isolation boundary; confirm the exact artifact and its runtime
> evidence.

The default judge runs your tests **in the same process** as the code under
test, so a patch that writes deliberate forgery into source — an `atexit` hook
that overwrites the JUnit report and calls `os._exit(0)` — can fake a `PASS`
(see [`docs/ASSURANCE.md`](ASSURANCE.md)). The black-box phase closes that
channel-local hole by construction, and ships with a before/after proof: the *identical* forgery
that yields a false `PASS` under the default judge yields the correct `FAIL`
here. The default policy is composite and still contains the weaker repo-native
report channel; use `--blackbox-only` for end-to-end external report integrity.

```bash
# Set PACK_SHA256 to the EVOGUARD_PACK_V2 value reported by pack-doctor.
evo-guard guard ./repo --patch candidate.txt \
    --verifier-pack examples/blackbox-pack --blackbox \
    --expect-verifier-pack-sha256 "$PACK_SHA256"
```

## How it works

- The **verdict-producing process is the judge's own pytest over the pack** — it
  never imports the candidate's code, so the candidate cannot register an
  `atexit` hook in it or call `os._exit` in the judge. In host-subprocess mode,
  however, candidate and judge still share an OS identity and filesystem; the
  external process alone does not prove the candidate cannot discover or modify
  judge files. Require container/gVisor/VM isolation for that boundary. The
  judge's exit code is authoritative only within the delivered isolation.
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
  | `EVOGUARD_TARGET` | legacy host path to the patched repo; direct use bypasses the launcher and cannot prove a requested candidate-isolation floor |

  The pack invokes `subprocess.run([EVOGUARD_EXEC, EVOGUARD_PYTHON, "-m", "tool", …])`
  and asserts on the candidate's **observable outputs**. Forgery code in the
  candidate's source runs only inside those child processes, where `os._exit(0)`
  affects the child, not the judge — and the pack checks outputs, not the child's
  exit code, so a lying child changes nothing.

## Boundary evidence is observed, never inferred from policy

`candidate_isolation` names the boundary selected for an **observed trusted-pack
call to `$EVOGUARD_EXEC`**, not the flag you passed and not a successfully
prepared launcher. The launcher sends a judge-owned invocation receipt;
Docker/gVisor additionally requires a valid runtime-written container CID. This
proves launcher/runtime invocation, not by itself the argv meaning or successful
execution of candidate logic; the trusted pack must assert the intended outputs.
In host-subprocess mode the candidate shares the judge's UID and can send noise
to a discovered receipt socket, so each receiver-lock hold is stop-aware and
bounded to 256 datagrams. Exact-token filtering prevents false evidence; under
pathological flooding a receipt may be conservatively undercounted and the run
fails closed instead of allowing verdict or cleanup to wait without bound.
A pack that returns a constant PASS without
invoking `$EVOGUARD_EXEC` is refused as `ERROR candidate_not_exercised`, even
without an isolation floor. If the diff pre-gate rejects first, the
judge, candidate, pack,
and container do not start: assurance reports `static_gate`, runtime isolation
reports `not_run`, and `attestation.mode=blackbox` plus the effective policy
record only what was requested. If you ask for
`--isolation docker` and the daemon is down, the image is missing, or the runtime
is absent, Guard **refuses** (`ERROR` / `assurance_requirement_not_met`) rather
than silently running on the host and *labelling* it docker. The container
launcher also overrides any image-level `GOCACHE` with
`/tmp/go-build` on the container's fresh `/tmp` tmpfs. A pre-populated,
read-only, or disabled Go cache baked into the image therefore cannot cross the
black-box candidate boundary. Pair it with the fail-closed floor and a
container boundary becomes a contract:

```bash
evo-guard guard ./repo --patch p.txt --verifier-pack ./pack --blackbox \
    --isolation docker --docker-image python:3.12-slim \
    --require-candidate-isolation docker
```

Schemas 1.11 and 1.12 make process progress explicit. Profile-free records
remain on the frozen 1.11 contract; records with an explicit operating profile
use 1.12. In either contract, `execution_state` is
`not_started` for black-box preflight failures such as a missing/invalid pack,
an expected-digest mismatch, patch preparation failure, or unavailable runner;
`candidate_isolation` remains `not_run`. A judge timeout is
different: its state is `started_incomplete`, phase is `blackbox_pack`, and
`test_command_ran` is `true` because pytest actually started, even though
`verdict_source` remains `null` because no clean black-box verdict completed.
That flag proves the judge started; the separate receipt proves whether the
trusted pack invoked the configured launcher boundary.
Normal return plus post-execution checks gives `completed`; that state still may
produce `FAIL`, `ERROR`, or `TAMPERED` rather than `PASS`.

Requested black-box/isolation settings live only in
`attestation.effective_policy`. Runtime assurance reports delivered facts. The
assurance floors are evaluated only when completed execution would otherwise be
`PASS`; they do not replace a static, preflight, timeout/incomplete, pack, or
isolation cause with a generic floor failure.

In a delivered container boundary the candidate tree is mounted **read-only**
and the judge-owned pack is **not mounted into the candidate**. The conformance
kit can record and replay-check those mount properties and network denial; a
release claim still requires retaining a result bound to the final commit and
runtime. The probes do not prove the absence of a container escape, and
Docker's shared kernel is not the hostile profile's final isolation boundary.
(In the `subprocess` boundary
the candidate shares the host and user with the judge;
`assurance.verifier_pack.secrecy` says so honestly —
`reachable_same_host`.) The launcher executes the exact resolved image ID that
was probed, rather than a mutable tag.

Pack evidence is equally phase-aware. `assurance.verifier_pack` independently
records `configured`, observed `present`, `integrity`, `identity_verified`, pack
`execution_state`, delivered `secrecy`, and observed `snapshot_sha256`. Missing,
invalid, expected-identity mismatch, accepted-before-execution,
verified-pre/post (or read-only), and changed-snapshot states remain distinct;
configuration alone never claims that a pack exists or was verified.

The shell-free `$EVOGUARD_EXEC` file has a **POSIX executable contract in every
black-box isolation mode**. Native Windows therefore fails closed before
subprocess, Docker, or gVisor delivery instead of reaching `WinError 193` or
claiming a boundary that did not run; use Linux/GitHub Actions or WSL. The
ordinary repo-native Windows judge is a different path.

## The pack ADDS a dimension — it does not replace your suite

After static effective-policy protected-path admission passes, `--blackbox` runs
a **composite** verdict: that admission result,
**your repo's own test suite**, *and* the external pack must all pass. A green
pack can never mask an internal regression the pack does not exercise. For a
pure-CLI/service target that has no in-repo suite, pass `--blackbox-only` to judge
the pack alone. The attestation records the repo suite's result
(`repo_suite_passed`, `repo_suite_junit_sha256`) alongside the pack's.
`--blackbox-only` still validates trusted-base `harness_inputs` declarations
and runs static non-exemptible candidate-path admission first. The black-box
runner receives the explicit declarations, captures their trusted-source
byte/type/mode identity before candidate materialization, compares the
materialized copy before candidate or pack code runs, and compares it after
candidate/pack execution. If the first trusted-source binding cannot be
established, the run stops before materialization as `ERROR` /
`assurance_requirement_not_met`; this is an assurance/provenance failure, not a
candidate action. A materialized-copy mismatch or persistent post-execution
drift is `TAMPERED` / `candidate_tree_changed_during_run`. Black-box-only skips
the repo-native setup/suite checkpoints, not these black-box checkpoints.
The completed composite's overall `report_integrity` is
`same_process_candidate_writable`, because assurance is the minimum of its
required external and repo-native channels. Use `--blackbox-only` when policy
requires the end-to-end `external_process_isolated` level.

`setup_command` is not silently applied to only part of this composite.
Currently, combining setup with `--blackbox` returns
`ERROR policy_requirement_unsupported`; place runtime dependencies in the
environment/container image until a single explicit setup boundary exists for
both sides.

## Writing a pack (the one rule)

**Invoke the candidate through `$EVOGUARD_EXEC` — never import it or run directly
from `$EVOGUARD_TARGET`.** If a pack
test does `import calc` and calls it in-process, the candidate's code runs in the
judge's process again and the guarantee is gone. Use `subprocess` (CLI/`-m`),
`requests`/`httpx` against a server the pack starts, a DB client, etc. See
[`examples/blackbox-pack/`](../examples/blackbox-pack/).

## What it guarantees — and the one edge

- The completed black-box phase has
  **`external_process_isolated`** report integrity: the demonstrated
  same-process report/exit forgery is defeated (proven in
  `tests/test_blackbox.py`). That is also the overall level for
  `--blackbox-only`; the default composite reports the weaker required
  repo-native channel. A static refusal instead records
  `not_applicable_static_gate`; it does not claim an external judge result.
- Failure to establish the initial trusted `harness_inputs` identity occurs
  before candidate materialization and returns `ERROR` /
  `assurance_requirement_not_met`. It is not labelled tampering. Only a
  materialized-copy mismatch or persistent post candidate/pack drift maps to
  `TAMPERED` / `candidate_tree_changed_during_run`.
- **Edge, stated plainly:** on POSIX the judge terminates and verifies its whole
  process group after normal completion and on abort, but a hostile host-mode
  child can deliberately create a new session and escape that group. The judge
  reads its own report immediately and grades primarily by its **own exit code**;
  use delivered Docker/gVisor isolation to contain that escape. Host
  `subprocess` also shares the filesystem: declared-input checkpoints detect
  persistent observed drift, not a temporary mutation restored before the next
  snapshot. Candidate containers are removed by CID, and inability to prove
  their absence is `ERROR runtime_cleanup_failed`, never `PASS`. The candidate
  copy and verifier-pack snapshot roots are also claimed immediately after
  trusted allocation, removed in all exit paths, and checked by a fresh root
  lookup. If either root's absence cannot be proven, a pending verdict is
  replaced by `ERROR runtime_cleanup_failed`; an already-active exception keeps
  its identity and receives bounded cleanup notes.

The owned-root check binds allocation-time root and parent identity before
recursive removal. Windows READONLY repair is confined to observed regular
files/directories and rejects symlinks, junctions, reparse objects, and multiply
linked files. These checks assume a quiescent workspace tree; they are not an
atomic Win32 handle-based deletion guarantee against concurrent path replacement.

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
