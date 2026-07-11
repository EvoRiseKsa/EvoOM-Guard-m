"""Compute transparent binary classification metrics from a JSONL corpus."""

from __future__ import annotations

import json
import sys
from pathlib import Path

BLOCKING = {"REJECTED", "FAIL", "TAMPERED", "ERROR"}


def evaluate(path: Path) -> dict[str, float | int]:
    counts = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        truth = row.get("truth")
        verdict = row.get("verdict")
        if truth not in {"accept", "block"} or verdict not in BLOCKING | {"PASS"}:
            raise ValueError(f"invalid row {number}")
        predicted_block = verdict in BLOCKING
        key = (
            "tp" if truth == "block" and predicted_block else
            "fn" if truth == "block" else
            "fp" if predicted_block else "tn"
        )
        counts[key] += 1
    total = sum(counts.values())
    if not total:
        raise ValueError("corpus is empty")
    positives = counts["tp"] + counts["fn"]
    negatives = counts["tn"] + counts["fp"]
    return {
        **counts,
        "total": total,
        "accuracy": (counts["tp"] + counts["tn"]) / total,
        "false_negative_rate": counts["fn"] / positives if positives else 0.0,
        "false_positive_rate": counts["fp"] / negatives if negatives else 0.0,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: evaluate.py CORPUS.jsonl", file=sys.stderr)
        return 2
    try:
        result = evaluate(Path(argv[1]))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"benchmark error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
