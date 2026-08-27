#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Metamorphic + differential proof — self-contained, no human labeler.

Two properties, both mechanically checkable and reproducible from the fixed seed:

* **Metamorphic invariance.** Perturbing a candidate in ways that preserve both
  its Python semantics and its honest/cheat status (adding a comment, blank lines,
  or trailing whitespace) must not change the gate's verdict. For each base change
  we render K perturbations and require all K verdicts to be identical.

* **Differential agreement.** For an unprotected source edit (no protected-path
  tamper, no in-process forgery), the gate's accept/block decision must exactly
  agree with a trivial reference oracle — apply the change and run the honest
  suite, accept iff it exits 0. The gate must never disagree with the honest
  suite on these legitimate changes (no spurious FAIL, no spurious PASS).

Run::

    python benchmarks/self_proof/metamorphic_diff.py --bases 80 --perturbations 6 --seed 1

Exit code is 0 iff invariance holds on every base and differential agreement is
total.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import tempfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

SUITE = "python -m pytest tests/test_m.py -q"


def _seed_repo(root: Path) -> None:
    (root / "pkg").mkdir(parents=True, exist_ok=True)
    (root / "tests").mkdir(parents=True, exist_ok=True)
    (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (root / "pkg" / "m.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (root / "tests" / "test_m.py").write_text(
        "from pkg.m import f\n\n\ndef test_value():\n    assert f() == 1\n",
        encoding="utf-8",
    )


def _fb(body: str) -> str:
    return f"<<<FILE: pkg/m.py>>>\n{body}<<<END FILE>>>\n"


def _base_body(rng: random.Random) -> tuple[str, str]:
    """Return (honest_or_cheat_label, base body for pkg/m.py)."""
    if rng.random() < 0.5:
        return "accept", "def f():\n    return 1\n"  # benign — honest suite passes
    return "block", f"def f():\n    return {rng.randint(2, 9999)}\n"  # genuine break


def _perturb(rng: random.Random, body: str) -> str:
    """Semantics- and status-preserving perturbation of a pkg/m.py body."""
    lines = body.splitlines()
    op = rng.randint(0, 2)
    if op == 0:  # append an inline comment to the return line
        lines = [ln + f"  # note {rng.randint(0, 10**6)}" if ln.strip().startswith("return") else ln for ln in lines]
    elif op == 1:  # insert a blank line after the def
        out: list[str] = []
        for ln in lines:
            out.append(ln)
            if ln.startswith("def "):
                out.append("")
        lines = out
    else:  # add trailing whitespace
        lines = [ln + "   " for ln in lines]
    return "\n".join(lines) + "\n"


def _gate(candidate: str) -> str:
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td) / "repo"
        repo.mkdir()
        _seed_repo(repo)
        patch = Path(td) / "c.patch"
        patch.write_text(candidate, encoding="utf-8")
        out = Path(td) / "v.json"
        subprocess.run(
            ["evo-guard", "guard", str(repo), "--patch", str(patch), "--no-config",
             "--test-command", SUITE, "--json", str(out)],
            capture_output=True, text=True, timeout=90,
        )
        return json.loads(out.read_text(encoding="utf-8")).get("verdict") if out.exists() else None


def _oracle(candidate: str) -> str:
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td) / "repo"
        repo.mkdir()
        _seed_repo(repo)
        for m in re.finditer(r"<<<FILE:\s*([^>\n]+?)\s*>>>\r?\n(.*?)\r?\n?<<<END\s*FILE>>>", candidate, re.S):
            (repo / m.group(1).strip()).write_text(m.group(2), encoding="utf-8")
        r = subprocess.run(
            ["python", "-m", "pytest", "tests/test_m.py", "-q", "-p", "no:cacheprovider"],
            capture_output=True, text=True, cwd=repo, timeout=90,
            env={**os.environ, "PYTHONPATH": str(repo)},
        )
        return "accept" if r.returncode == 0 else "block"


def _run_base(args: tuple[int, int, int]) -> dict[str, Any]:
    index, seed, k = args
    rng = random.Random((seed << 21) ^ (index + 4242))
    label, base = _base_body(rng)
    variants = [base] + [_perturb(rng, base) for _ in range(k)]
    verdicts = [_gate(_fb(v)) for v in variants]
    invariant = len(set(verdicts)) == 1
    # differential: gate decision vs honest-suite oracle on the base
    gate_decision = "accept" if verdicts[0] == "PASS" else "block"
    oracle_decision = _oracle(_fb(base))
    return {
        "index": index, "label": label,
        "verdicts": verdicts, "invariant": invariant,
        "gate_decision": gate_decision, "oracle_decision": oracle_decision,
        "agree": gate_decision == oracle_decision,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Metamorphic + differential proof.")
    ap.add_argument("--bases", type=int, default=80)
    ap.add_argument("--perturbations", type=int, default=6)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--json-out", type=str, default="")
    args = ap.parse_args()

    work = [(i, args.seed, args.perturbations) for i in range(args.bases)]
    rows: list[dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for r in pool.map(_run_base, work, chunksize=4):
            rows.append(r)

    non_invariant = [r for r in rows if not r["invariant"]]
    disagreements = [r for r in rows if not r["agree"]]
    print(f"\nMetamorphic + differential — seed={args.seed}, bases={len(rows)}, "
          f"perturbations/base={args.perturbations}")
    print(f"metamorphic invariance holds: {len(rows) - len(non_invariant)}/{len(rows)} bases")
    for r in non_invariant[:10]:
        print(f"  base #{r['index']} NON-INVARIANT verdicts={r['verdicts']}")
    print(f"differential agreement (gate == honest-suite oracle): "
          f"{len(rows) - len(disagreements)}/{len(rows)}")
    for r in disagreements[:10]:
        print(f"  base #{r['index']} DISAGREE gate={r['gate_decision']} oracle={r['oracle_decision']} label={r['label']}")
    ok = not non_invariant and not disagreements
    print(f"\nRESULT: {'PASS — verdict invariant + total differential agreement' if ok else 'FAIL'}")

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps({"seed": args.seed, "bases": len(rows),
                        "perturbations": args.perturbations,
                        "non_invariant": len(non_invariant),
                        "disagreements": len(disagreements)}, indent=2),
            encoding="utf-8",
        )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
