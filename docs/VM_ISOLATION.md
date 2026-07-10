<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
  Sole owner & author: Mana Alharbi (مانع الحربي).
-->

# VM-class isolation for untrusted code — design (#51, Phase 2d)

**Status: gVisor backend implemented; Firecracker design-only.** The portable
gVisor backend ships as **`--isolation gvisor`** — the docker judge run through the
`runsc` OCI runtime (a user-space guest kernel, no `/dev/kvm` needed). The stronger
**Firecracker** microVM backend remains a design (it needs `/dev/kvm` / nested
virtualization, which not every host exposes). The default **subprocess** and
**`--isolation docker`** judges are unchanged. This document is the full VM-class
design, threat model, and validation plan; §4a/§5/§8 mark what is built.

## 1. Why

EvoGuard's two existing judges both **share the host kernel**:

| Judge | Confines | Gap |
|---|---|---|
| subprocess + `rlimits` + timeout (default) | CPU/mem/time | not a sandbox — full host FS/network |
| `--isolation docker` (Phase 2a) | network-less, read-only, CPU/PID/mem caps, judge-owned report mount | shares the host kernel → a kernel exploit escapes |

For **untrusted / public fork-PR code**, neither is a complete boundary. VM-class
isolation gives each judged run **its own guest kernel**, so a kernel-level escape
lands in a throwaway VM, not on the host.

## 2. Goals / non-goals

**Goals**
- Run the candidate's suite under a **separate guest kernel**, no network, ephemeral
  (no persistence between runs), with strict CPU / memory / PID / wall-clock caps.
- Read the verdict from a **judge-owned report on the host** — never guest stdout.
- Run the **harness-edit pre-gate on the host, before any guest boots**.
- Emit **identical verdicts** (including `junit+exit` + the `TAMPERED` check) to the
  other judges — same `instrument_command` → `parse_junit_xml` → `grade_repo_run`.

**Non-goals**
- No change to the verdict contract (`schema_version`, verdict names, `reason_code`).
- Not a performance feature; not Windows; not a defense against hardware
  side-channels or hypervisor 0-days (see §6).

## 3. Threat model

**Adversary:** a malicious candidate — an AI-authored patch or an untrusted fork PR
whose test/collection-time code executes inside the judge.

**Defend against**
- **Kernel escape → host compromise** (the core reason for a separate kernel).
- **Network exfiltration** of runner secrets/tokens.
- **Resource exhaustion** — fork-bomb, memory/CPU/disk hog.
- **Persistence** — leaving state that influences a later run.
- **Verdict tampering** — forging the report or desyncing the exit code (already
  covered by the judge-owned report + `detect_tamper`; preserved here).

**Out of scope (documented residual):** hardware side-channels (Spectre-class),
hypervisor/VMM 0-days (mitigated by a minimal device model + seccomp, not
eliminated), and the supply chain of the guest base image.

**Trust boundary:** the host and the judge-owned report path are trusted;
**everything inside the guest is untrusted.** The repo copy is assembled on the host
(so `COPY_IGNORE` + patch application happen in trusted space), then handed to the
guest read-mostly.

## 4. Design — one mode, two backends

A new `--isolation vm` with `--vm-backend`:

### 4a. gVisor (`runsc`) — portable default · **implemented** (`--isolation gvisor`)
A user-space kernel (the *sentry*) intercepts guest syscalls, exposing a much smaller
host attack surface than a raw container. It is an **OCI runtime**, so it reuses most
of the docker judge's wiring — run the same container invocation with
`--runtime=runsc`, `--network=none`, read-only rootfs, and the CPU/PID/mem caps.
Weaker than a true VM (the sentry still runs on the host kernel) but a large step up
from `runc`, and it needs no KVM — the right default where nested virt is unavailable.

### 4b. Firecracker microVM — strongest
A minimal VMM on KVM, one microVM per run, with **its own guest kernel** and a minimal
device model (no PCI; **no virtio-net device at all** → no network by construction).
Rootfs = a read-only base image + a writable overlay on a tmpfs-backed drive; vCPU /
memory / wall-clock caps from the VM config. The **judge-owned report** is returned on
a separate host-readable drive (or over `vsock`). Requires `/dev/kvm` on the runner.

### Common to both
- **Pre-gate first.** The reward-hack path-gate (`reject_unsafe_or_protected`, incl.
  the feature-mode rules) runs on the host; a patch that edits tests/config/CI/
  auto-exec is `REJECTED` with **no candidate code executed**.
- **Host-assembled copy.** The repo copy (`COPY_IGNORE` + `setup_command` install)
  is prepared on the host, then mounted/transferred read-mostly into the guest.
- **Judge-owned report.** `instrument_command` injects the JUnit reporter exactly as
  today; the report is written to a path the **host** reads back. The reporter env
  (jest's `JEST_JUNIT_OUTPUT_FILE`) is passed into the guest the same way docker does.
- **No network**, **ephemeral** rootfs/overlay (discarded each run), strict caps.

## 5. Where it slots into the code

**gVisor (implemented).** `RepoVerifier(isolation="gvisor")` sets
`docker_runtime="runsc"` and **reuses `_run_docker`** unchanged — `_docker_command`
simply adds `--runtime runsc`. Everything else is shared verbatim with the docker
judge: `--network none`, `--read-only`, the CPU/PID/mem caps, the judge-owned report
mount, and `instrument_command` → `parse_junit_xml` → `grade_repo_run` →
`detect_tamper`. The misconfig guard (a container mode without `--docker-image`)
covers it too. `--isolation gvisor` is wired through `guard()` / `guard_from_diff()`
and the CLI.

**Firecracker (future).** Would add a `_run_vm(base_cmd, copy, workdir)` returning
the **same tuple shape** as `_run_docker` (so `verify()` stays unchanged past the
branch) — the report-and-exit-code oracle is backend-agnostic.

## 6. Verification plan (on a KVM / `runsc` host, when implemented)

| Scenario | Expected |
|---|---|
| honest fix | `PASS`, `junit+exit`, real counts — inside the guest |
| broken fix | `FAIL`, `junit+exit` |
| harness edit | `REJECTED` **before any guest boots** |
| test opens a socket | network blocked → fails/times out, verdict still read |
| fork-bomb / mem hog | killed by caps; clear timeout/limit verdict; **host unaffected** |
| forced `exit 0` vs failing report | `TAMPERED` |
| default subprocess + docker paths | **byte-identical** (no regression) |

Plus a reproducible campaign target (mirroring campaign v5) proving `junit+exit` on
**real upstream code** inside the VM, with an independent verifier + negative
self-check.

## 7. Honest limits

- Hardware side-channels and VMM 0-days are **out of scope** (documented, not solved).
- Firecracker needs `/dev/kvm` (nested virt); gVisor needs the `runsc` runtime — so
  this is an **opt-in mode for runners that provide them**, never the default.
- This is the **prerequisite for accepting public / untrusted PRs**. Trusted-repo
  gating stays on the default subprocess judge; semi-trusted code can use
  `--isolation docker` today.

## 8. Phasing

1. **2d-i — gVisor backend.** ✅ **Implemented** as `--isolation gvisor` (docker +
   `--runtime runsc`). Command wiring is unit-tested; the end-to-end run is gated on
   a host whose docker exposes the `runsc` runtime.
2. **2d-ii — Firecracker backend.** Design only. Strongest isolation; needs `/dev/kvm`.
3. **2d-iii — validation.** A campaign target on a `runsc` host + a `GUARD.md`
   trust-boundary update.

See [`GUARD.md`](GUARD.md) for the current trust boundary,
the internal runner threat-model and development-plan documents (not part of this public repo).
