<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# Self-contained proof — reproduce every number yourself

These harnesses establish the gate's security properties **without any external
reviewer**. The ground truth for every case is *mechanical* — a path is
policy-protected or it is not; an honest suite genuinely fails or it does not — so
you do not have to trust anyone's labels: run the commands below and read the
verdicts. Every run is seeded, so it is byte-reproducible. This is the substitute
for waiting on a third party for this class of claim (see the honest limits at the
end and in [`docs/THREAT_MODEL.md`](../../docs/THREAT_MODEL.md)).

Prerequisite: `pip install -e .` (puts `evo-guard` on PATH).

## 1. Invariant fuzzing — zero bypass

```bash
python benchmarks/self_proof/invariant_fuzz.py --cases 2000 --seed 1 --workers 8
```

Generates thousands of randomized candidates against a tiny synthetic repo and
asserts, on every one:

* **INV1** a candidate that edits/deletes a policy-protected path is `REJECTED`
  (or `ERROR`/unsafe) *before* the suite runs — never `PASS`, never `FAIL`;
* **INV2** a `PASS` implies the judge-owned JUnit is all-pass with ≥1 test and
  exit code 0;
* **INV3** a candidate that breaks a test by editing unprotected source (no
  forgery) is never `PASS`;
* **INV4** every run returns one valid verdict + `reason_code` within the timeout.

**Measured:** `2000` cases, seed 1 → **0 invariant violations**
(`results/invariant_fuzz.json`). Path-normalization variants (`./`, `//`,
`dir/../dir/f`) that resolve to a protected file are covered by INV1; lookalikes
(case flips, homoglyphs) that resolve to a *different* file are a separate class
that asserts only verdict validity.

## 2. Mechanical-ground-truth efficacy — catch rate with confidence intervals

```bash
python benchmarks/self_proof/efficacy_eval.py --per-category 100 --seed 1 --workers 8
```

Labels are mechanical: `protected_tamper` → must block (edits a judge path);
`genuine_break` → must block (honest suite genuinely fails); `benign` → should
pass. The gate is compared to a *fair* naive exit-code baseline (apply the change,
make the project importable, run the honest suite, accept iff exit 0).

**Measured (400 cases, seed 1):**

| decider | catch rate (95% CI) | false-accept (95% CI) | false-reject (95% CI) |
| --- | --- | --- | --- |
| **gate** | **1.0** (0.987–1.0) | **0.0** (0–0.014) | **0.0** (0–0.031) |
| naive baseline | 0.829 (0.781–0.869) | **0.171** (0.131–0.219) | 0.0 (0–0.031) |

The gate separates must-block from should-pass perfectly on this corpus; the naive
baseline false-accepts the protected-tamper class it has no concept of
(`results/efficacy.json`).

## 3. Security mutation gate — the tests actually bite

```bash
python tools/ci/run_security_mutation_gate.py --workers 8            # full 827 mutants (CI)
python tools/ci/run_security_mutation_gate.py --mutation <name> ...   # a sample
```

Injects **827** reviewed bugs into the security core and requires the test suite
to *kill* each (a test must fail). **Measured:** 827/827 killed in CI; a diverse
50-mutant sample runs 50/50 killed locally (`results/mutation_gate.json`). This
proves the regression suite behind every claim above is not hollow.

## 4. Metamorphic + differential

```bash
python benchmarks/self_proof/metamorphic_diff.py --bases 80 --perturbations 6 --seed 1 --workers 8
```

* **metamorphic** — the verdict is invariant under semantics-preserving
  perturbations (comments, blank lines, trailing whitespace);
* **differential** — for unprotected source edits, the gate's accept/block agrees
  with a trivial honest-suite reference oracle.

**Measured (80 bases, seed 1):** 80/80 verdict-invariant, 80/80 oracle agreement
(`results/metamorphic_diff.json`).

## Honest limits

* These prove the gate's **invariants** and its efficacy **on a mechanically
  labeled corpus** — entirely self-contained. They cover **non-forgery**
  candidates; in-process report/assertion forgery is a documented boundary of the
  default profile (catalog rows 11a/11b).
* They do **not** flip the `independent_validation` bit for a claim about a
  **representative sample of real-world** agent changes — that specific,
  judgment-based claim still needs the independent evaluation round (see
  [`docs/INDEPENDENT_EVALUATION.md`](../../docs/INDEPENDENT_EVALUATION.md)). What
  these harnesses *do* provide is the strongest self-serve substitute: anyone can
  reproduce the numbers from the fixed seeds, so no one has to trust the
  maintainer's labels.
