<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# Self-contained proof — what can be established without an external party

A recurring question is whether EvoOM Guard can be *proven* without waiting on an
independent reviewer. The answer turns on one distinction: **the kind of ground
truth a claim rests on.**

| Ground truth | Example | Needs an external party? |
| --- | --- | --- |
| **Mechanical / definitional** | Did the candidate touch a protected path? Did the honest suite genuinely fail? Did the tree change mid-run? | **No — ever.** Deterministic, reproducible by anyone. |
| **Judgment** | Is this change "correct"? Is this corpus "representative" of real agent behavior? | Yes — a party who cannot be accused of biasing it. |

Most of what makes the gate trustworthy is *mechanical*, so it can be proven to a
high degree **entirely self-contained, with no external reviewer**. Only the
representative-efficacy claim rests on judgment; that is what the independent
evaluation round exists for ([`INDEPENDENT_EVALUATION.md`](INDEPENDENT_EVALUATION.md)).

The runnable proofs live in `benchmarks/self_proof/` — every one is seeded and
byte-reproducible, so you do not have to trust anyone's labels; you run the
command and read the verdict. See that directory's README for exact commands.

## What is proven, self-contained

### Invariants hold under fuzzing

Thousands of randomized candidates, and on every one: a protected-path edit is
rejected before the suite runs (never `PASS`); a `PASS` implies the judge-owned
JUnit is all-pass with a zero exit; a plain break in unprotected source is never
`PASS`; every run returns a valid verdict within the timeout.
**Measured:** 2,000 seeded cases → **0 invariant violations.**

### Efficacy on a mechanically-labeled corpus

Labels are mechanical (protected-path tamper → must block; honest suite genuinely
fails → must block; benign → should pass). The gate is compared to a fair naive
exit-code baseline.
**Measured (400 cases):** gate catch rate **1.0** (95% CI 0.987–1.0), false-accept
**0.0** (0–0.014), false-reject **0.0** (0–0.031); the naive baseline false-accepts
**17.1 %** of must-block cases — the protected-tamper class it has no concept of.

### The tests actually bite

The security mutation gate injects **827** reviewed bugs into the security core and
requires the suite to kill each.
**Measured:** 827/827 killed in CI; a diverse 50-mutant local sample runs 50/50.

### Verdict stability and reference agreement

The verdict is invariant under semantics-preserving perturbations, and for
unprotected source edits the gate agrees with a trivial honest-suite reference
oracle.
**Measured (80 bases):** 80/80 invariant, 80/80 agreement.

## Non-blocking external validation (optional, additive)

Two more forms of assurance accrue **without blocking** on appointed reviewers:

* **Run-it-yourself.** Because the corpus is seeded and the verifier is portable,
  any skeptic becomes their own verifier on demand — the closest practical
  substitute for a third-party attestation.
* **Open red-team / bounty.** Publishing the gate with a standing "break it"
  challenge accrues adversarial external scrutiny over time, rather than waiting on
  two specific people.

## Honest limits

* These cover **non-forgery** candidates. In-process report/assertion forgery is a
  documented boundary of the default profile — see
  [`THREAT_MODEL.md`](THREAT_MODEL.md) and the reward-hacking catalog
  ([`REWARD_HACKING_CATALOG.md`](REWARD_HACKING_CATALOG.md)).
* They establish invariants and efficacy on a *mechanically* labeled corpus. They
  do **not**, by themselves, flip the `independent_validation` bit for a claim
  about a **representative sample of real-world** agent changes; that judgment-based
  claim still requires the independent round. Same-owner runs — however extensive —
  remain reproducible operational evidence, not third-party validation. See
  [`ASSURANCE.md`](ASSURANCE.md).
