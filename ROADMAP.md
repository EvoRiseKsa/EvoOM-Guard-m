<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Roadmap — from a patch gate to an agent-governance fabric

EvoOM Guard answers one question: *did this patch fix the code without gaming
the tests?* That question is one pillar of a larger problem — **governing what
AI agents do to production systems** — and this roadmap places Guard inside
that larger picture. The pillars are separate products by the same author that
compose along one principle: *no result is accepted without traceable
evidence — never trust a model's opinion of its own output.*

## Pillar 1 — the patch gate (this repo, shipping)

- ✅ v2.0.0: consolidated engine — `TAMPERED` verdict, deletion gating, eight
  structured-verdict runners, docker/gVisor isolation, JSON/SARIF contracts.
- ✅ v2.1.0: **signed verdicts** — Ed25519 detached signatures over the JSON
  verdict (`keygen` / `--sign-key` / `verify-verdict`), making the *record* as
  tamper-evident as the *run*. See [`docs/SIGNED_VERDICTS.md`](docs/SIGNED_VERDICTS.md).
- ✅ v2.2.0: **evidence beyond "the tests passed"** — changed-line coverage,
  Independent Verifier Packs, per-verdict attestation.
- ✅ v2.3.0: **assurance profile** — every verdict states its `report_integrity`
  honestly (see [`docs/ASSURANCE.md`](docs/ASSURANCE.md)).

### The headline next direction: an external black-box judge

The single most valuable thing Guard can build. Today the code under test runs
in the **same process** as the report writer, so a deliberate in-process patch
can forge the JUnit report and exit code (`report_integrity:
same_process_candidate_writable` — proven by an adversarial test). No in-process
change fixes this; the candidate has full authority over its own process.

The fix is architectural: run the candidate in one container reachable only
through an API / stdin / protocol, and a **separate judge** that owns the
verifier pack, drives inputs, observes outputs, and writes the report **without
ever importing the candidate's code**. That makes `report_integrity`
`external_isolated` and turns "checks the candidate can't game" from a
qualified claim into a real one. Natural fit for API/HTTP/CLI/DB targets;
library targets need a thin RPC wrapper.

- Other near-term candidates (driven by [user feedback](../../issues)):
  - a baseline scan mode (verdict for the repo as-is, no patch);
  - `mounts_ro` wired for read-only external evidence in the container modes;
  - `minimize_patch` surfaced as **extraneous-change detection** (which hunks
    the evidence does *not* require) — after the judge boundary is hardened, so
    it doesn't repeat a forgeable verdict.

## Pillar 2 — the evidence chain (integration: Sentinel AI)

**Sentinel AI** (the author's Agentic Trust Fabric) keeps an Ed25519-signed
Merkle audit log for AI decisions. Signed Guard verdicts are its natural feed:
each merge gated by Guard appends `verdict.json` + `.sig` to an append-only
log, giving compliance an offline-verifiable answer to *"which AI patches
entered this codebase, under which verdict, judged by whom?"* — from patch to
merge, cryptographically.

Status: the Guard side shipped in v2.1.0 (signing). The ingestion endpoint
lives on the Sentinel side.

## Pillar 3 — the capability ledger (integration: ToolLedger)

Guard governs what an agent **changes**; **ToolLedger** (same author) governs
what an agent **can reach** — which tools, which scopes, who approved them, and
what drifted after approval. Together they close the two agent-risk surfaces:
code that lies about being fixed, and capabilities that quietly widen.

Status: product-level composition; no code coupling planned — both emit/consume
signed, machine-readable records.

## Non-goals

- Guard will not become a general security scanner, a linter, or a code
  reviewer — one question, answered objectively, stays the contract.
- The subprocess judge will never be marketed as a sandbox; isolation levels
  stay explicit (`subprocess` < `docker` < `gvisor`).
