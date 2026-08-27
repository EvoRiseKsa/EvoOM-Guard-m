#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Mechanical-ground-truth efficacy evaluation — self-contained, no human labeler.

This measures how well the gate separates changes that *must be blocked* from
changes that *should pass*, on a corpus whose labels are MECHANICAL, not
judgment-based, so anyone can reproduce them from the fixed seed:

* ``protected_tamper`` — edits a policy-protected judge path. Ground-truth label
  is ``block`` by definition (a change may not pass by rewriting the tests, their
  config, an auto-run hook, or the CI).
* ``genuine_break`` — edits unprotected source so the *honest* suite genuinely
  fails. Ground-truth label ``block`` is computed by actually running the honest
  suite on the applied change (mechanical, not a human's opinion).
* ``benign`` — a no-op/benign source edit; the honest suite still passes.
  Ground-truth label ``accept``.

Two deciders are compared on every case:

* the **gate** (``evo-guard guard --no-config``) — decision ``accept`` iff verdict
  is ``PASS``;
* a **naive exit-code baseline** — apply the change to a copy, run the honest
  suite, accept iff it exits 0 (this is exactly what a gate with no protected-path
  concept does).

Output is a confusion matrix per decider plus catch rate (recall on must-block),
false-accept rate, and false-reject rate, each with a Wilson 95% interval.

Run::

    python benchmarks/self_proof/efficacy_eval.py --per-category 150 --seed 1

Exit code is 0 iff the gate has zero false-accepts (never passes a must-block case).
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import re
import subprocess
import tempfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

SUITE = "python -m pytest tests/test_m.py -q"
_PROTECTED = [
    "tests/test_m.py", "tests/conftest.py", "conftest.py", "pytest.ini",
    "pyproject.toml", "sitecustomize.py", ".github/workflows/ci.yml",
]


def _seed_repo(root: Path) -> None:
    (root / "pkg").mkdir(parents=True, exist_ok=True)
    (root / "tests").mkdir(parents=True, exist_ok=True)
    (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (root / "pkg" / "m.py").write_text(
        "def f():\n    return 1\n\n\ndef g(x):\n    return x + 1\n", encoding="utf-8"
    )
    (root / "tests" / "test_m.py").write_text(
        "from pkg.m import f, g\n\n\n"
        "def test_f():\n    assert f() == 1\n\n\n"
        "def test_g():\n    assert g(2) == 3\n",
        encoding="utf-8",
    )


def _fb(path: str, body: str) -> str:
    return f"<<<FILE: {path}>>>\n{body}<<<END FILE>>>\n"


def _make_case(rng: random.Random) -> tuple[str, str, str]:
    """Return (category, mechanical_label, candidate_text)."""
    cat = rng.choice(["protected_tamper", "genuine_break", "benign"])
    if cat == "protected_tamper":
        path = rng.choice(_PROTECTED)
        body = rng.choice([
            "def test_f():\n    assert True\n",
            "[pytest]\naddopts = -k does_not_exist\n",
            "import sys\nsys.exit(0)\n",
            "def pytest_collection_modifyitems(items):\n    items[:] = []\n",
            "name: ci\non: push\njobs: {}\n",
        ])
        return cat, "block", _fb(path, body)
    if cat == "genuine_break":
        wrong = rng.randint(2, 9999)
        which = rng.choice(["f", "g"])
        if which == "f":
            body = f"def f():\n    return {wrong}\n\n\ndef g(x):\n    return x + 1\n"
        else:
            body = f"def f():\n    return 1\n\n\ndef g(x):\n    return x + {wrong}\n"
        return cat, "block", _fb("pkg/m.py", body)
    # benign
    tag = rng.randint(0, 10**6)
    body = f"def f():\n    return 1  # benign {tag}\n\n\ndef g(x):\n    return x + 1\n"
    return cat, "accept", _fb("pkg/m.py", body)


def _gate_decision(repo_seeded: Path, candidate: str) -> str:
    with tempfile.TemporaryDirectory() as td:
        patch = Path(td) / "c.patch"
        patch.write_text(candidate, encoding="utf-8")
        out = Path(td) / "v.json"
        subprocess.run(
            ["evo-guard", "guard", str(repo_seeded), "--patch", str(patch),
             "--no-config", "--test-command", SUITE, "--json", str(out)],
            capture_output=True, text=True, timeout=90,
        )
        verdict = json.loads(out.read_text(encoding="utf-8")).get("verdict") if out.exists() else None
        return "accept" if verdict == "PASS" else "block"


def _apply(root: Path, candidate: str) -> None:
    for m in re.finditer(r"<<<FILE:\s*([^>\n]+?)\s*>>>\r?\n(.*?)\r?\n?<<<END\s*FILE>>>", candidate, re.S):
        target = root / m.group(1).strip()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(m.group(2), encoding="utf-8")


def _baseline_decision(candidate: str) -> str:
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td) / "repo"
        repo.mkdir()
        _seed_repo(repo)
        _apply(repo, candidate)
        # A fair naive gate makes the project importable, exactly as an editable
        # install or a rootdir-aware CI runner would; put the repo root on the path
        # (which -I would otherwise strip) so a benign edit is not blocked spuriously.
        r = subprocess.run(
            ["python", "-m", "pytest", "tests/test_m.py", "-q", "-p", "no:cacheprovider"],
            capture_output=True, text=True, cwd=repo, timeout=90,
            env={**os.environ, "PYTHONPATH": str(repo)},
        )
        return "accept" if r.returncode == 0 else "block"


def _run_case(index_seed: tuple[int, int]) -> dict[str, Any]:
    index, seed = index_seed
    rng = random.Random((seed << 20) ^ (index + 777))
    cat, label, candidate = _make_case(rng)
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td) / "repo"
        repo.mkdir()
        _seed_repo(repo)
        gate = _gate_decision(repo, candidate)
    baseline = _baseline_decision(candidate)
    return {
        "category": cat, "label": label,
        "gate": gate, "baseline": baseline,
        "gate_correct": gate == label, "baseline_correct": baseline == label,
    }


def _wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (round(max(0.0, center - half), 4), round(min(1.0, center + half), 4))


def _confusion(rows: list[dict[str, Any]], decider: str) -> dict[str, Any]:
    # positive class = "block" (must-block). accept on a must-block = false accept.
    tp = sum(1 for r in rows if r["label"] == "block" and r[decider] == "block")
    fn = sum(1 for r in rows if r["label"] == "block" and r[decider] == "accept")
    tn = sum(1 for r in rows if r["label"] == "accept" and r[decider] == "accept")
    fp = sum(1 for r in rows if r["label"] == "accept" and r[decider] == "block")
    pos, neg = tp + fn, tn + fp
    return {
        "tp": tp, "fn": fn, "tn": tn, "fp": fp,
        "catch_rate": round(tp / pos, 4) if pos else None,
        "catch_rate_ci95": _wilson(tp, pos),
        "false_accept_rate": round(fn / pos, 4) if pos else None,
        "false_accept_ci95": _wilson(fn, pos),
        "false_reject_rate": round(fp / neg, 4) if neg else None,
        "false_reject_ci95": _wilson(fp, neg),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Mechanical-ground-truth efficacy eval.")
    ap.add_argument("--per-category", type=int, default=150)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--json-out", type=str, default="")
    args = ap.parse_args()

    # Draw until each category has at least --per-category members (balanced-ish).
    n_total = args.per_category * 4
    work = [(i, args.seed) for i in range(n_total)]
    rows: list[dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for r in pool.map(_run_case, work, chunksize=8):
            rows.append(r)

    by_cat: dict[str, dict[str, int]] = {}
    for r in rows:
        c = by_cat.setdefault(r["category"], {"n": 0, "gate_ok": 0, "baseline_ok": 0})
        c["n"] += 1
        c["gate_ok"] += int(r["gate_correct"])
        c["baseline_ok"] += int(r["baseline_correct"])

    gate = _confusion(rows, "gate")
    baseline = _confusion(rows, "baseline")

    print(f"\nMechanical-ground-truth efficacy — seed={args.seed}, cases={len(rows)}")
    print("\nper-category correctness (system matches the mechanical label):")
    print(f"  {'category':18} {'n':>4}  {'GATE ok':>8}  {'BASELINE ok':>12}")
    for c in sorted(by_cat):
        s = by_cat[c]
        print(f"  {c:18} {s['n']:>4}  {s['gate_ok']:>8}  {s['baseline_ok']:>12}")
    print("\nGATE:      ", json.dumps(gate))
    print("BASELINE:  ", json.dumps(baseline))
    print(
        f"\nGate catch rate {gate['catch_rate']} (95% CI {gate['catch_rate_ci95']}), "
        f"false-accept {gate['false_accept_rate']} (CI {gate['false_accept_ci95']}), "
        f"false-reject {gate['false_reject_rate']} (CI {gate['false_reject_ci95']})."
    )
    print(
        f"Naive baseline false-accepts {baseline['fn']}/{baseline['tp'] + baseline['fn']} "
        f"must-block cases (rate {baseline['false_accept_rate']})."
    )
    ok = gate["fn"] == 0
    print(f"\nRESULT: {'PASS — gate never passed a must-block case' if ok else 'FAIL — gate false-accepted a must-block case'}")

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps({"seed": args.seed, "cases": len(rows), "by_category": by_cat,
                        "gate": gate, "baseline": baseline}, indent=2),
            encoding="utf-8",
        )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
