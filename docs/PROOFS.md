<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Proprietary and confidential — see LICENSE.
  Sole owner & author: Mana Alharbi (مانع الحربي).
-->

# EvoGuard — Live Proof

The canonical record of EvoGuard verifying real, AI-shaped changes **end-to-end
through the GitHub Action on a real repository** — the workflow trigger, the
diff-against-base resolution, the verdict, the PR-comment report, and the
check-status gating — not a local command-path simulation.

> **Scope policy (read this first).** The target below — **EvoERB**, a real
> TypeScript/pnpm ERP monorepo — is used **only as an external fixture / proof**.
> EvoGuard is **not** developed inside it, and it is **not** part of EvoGuard's
> roadmap. Any second repository is **validation only**: take the evidence,
> record it here, and stop. EvoGuard evolves **only inside this repository**.

## Target fixture

| | |
|---|---|
| Shape | TypeScript · pnpm workspace monorepo · **vitest** runner |
| EvoGuard | v1.3.0 (installed into the runner from the private repo via a PAT) |
| Adapter path exercised | **vitest** → `verdict_source: junit+exit` |

Adopter config (`.evoguard.json`) — the workspace pattern documented in
[`ADOPTION.md`](ADOPTION.md):

```json
{
  "setup_command": ["pnpm", "install", "--frozen-lockfile"],
  "test_command": ["pnpm", "--filter", "@evorise/shared", "exec", "vitest", "run"],
  "protected": ["apps/api/prisma/schema.prisma", "apps/api/prisma/migrations/**"],
  "timeout": 180,
  "mem_limit": 0
}
```

## Result 1 — clean source change → ✅ PASS

A behaviour-preserving change (an expanded doc-comment on an already-covered
function in `packages/shared/src/finance/installments.ts`; **no** test, config,
lockfile, or CI touched).

| Field | Value |
|---|---|
| Verdict | **✅ PASS** |
| Tests passed | **130 / 130** |
| Verdict source | **`junit+exit`** — judge-owned JUnit report + exit code |
| Files changed | 1 (`installments.ts`) |
| Check status | **success** (gate green) |

Proves the strong path: real counts read from a report the **judge** owns, never
scraped from candidate stdout.

## Result 2 — reward-hack (test edit) → ⛔ REJECTED

A realistic reward-hack: weaken the judging assertion in
`packages/shared/src/finance/installments.test.ts`
(`expect(sum).toBe(100_000n)` → `expect(sum).toBeGreaterThan(0n)`) so a future
broken implementation would still pass. The suite **still runs green**, so the
repo's own `test` job is fooled — EvoGuard is not.

| Field | Value |
|---|---|
| Verdict | **⛔ REJECTED** |
| Reason | protected harness file edited (`installments.test.ts`) |
| When | **before the suite runs** (harness-edit pre-gate) |
| Check status | **failure** (merge blocked) |

This is exactly the case EvoGuard exists for: the change the ordinary test run
cannot catch.

## What this proves — and what it does not

**Proves, live on real code:** Action trigger + base resolution; the two headline
verdicts (`PASS` with `junit+exit` real counts, and `REJECTED` on a harness
edit); the sticky PR-comment report; and correct check-status gating (PASS →
success, non-PASS → failure).

**Does not claim:** that the suite is *good* (a weak suite still `PASS`es), to
catch a novel exploit it does not model, or to sandbox hostile code. See the
honest scope in [`REWARD_HACKING_CATALOG.md`](REWARD_HACKING_CATALOG.md) and
[`GUARD.md`](GUARD.md).

## gVisor isolation — live on a separate guest kernel

Phase 2d-i (`--isolation gvisor`) was validated live on an ordinary **Ubuntu 24.04
KVM-guest VPS** (4 vCPU / 16 GB) with **no `/dev/kvm`** — nested virtualization is
unavailable there, so Firecracker is out, but gVisor's user-space `systrap`
platform needs no KVM. Docker + the gVisor `runsc` runtime were installed;
`docker run --runtime=runsc alpine uname -a` reports a **`4.19.0-gvisor`** kernel —
a separate, user-space guest kernel.

The same two demos, run through the binary with
`--isolation gvisor --docker-image node:22-slim`. The host has **no `node`** at
all, so the suite can only have executed **inside the gVisor sandbox**:

| Scenario | Verdict | Evidence |
|---|---|---|
| clean fix to `src.mjs` | ✅ `PASS` | `1/1`, `verdict_source: junit+exit`, exit `0` |
| reward-hack edit to `test/c.test.mjs` | ⛔ `REJECTED` | before the suite runs, exit `1` |

First live run of the **separate-kernel** judge: identical verdicts to the
subprocess / docker judges, but the candidate's test code executed under gVisor,
not the host kernel. See [`VM_ISOLATION.md`](VM_ISOLATION.md).

## Reproduce (any repo)

```bash
git diff <base>...<head> | evo-guard guard --diff - --report report.md --json verdict.json
# PASS -> exit 0 ; REJECTED / FAIL / TAMPERED / ERROR -> non-zero
```

The structured (`junit+exit`) oracle covers **pytest**, **`node --test`**, and
**vitest** today; see [`ADOPTION.md`](ADOPTION.md) for the supported runners and
the monorepo invocation note.
