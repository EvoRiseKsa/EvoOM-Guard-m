"""Compute transparent classification and enforcement metrics from JSONL.

``ERROR`` is an abstention: it blocks admission operationally, but it is not
credited as a correct security classification.  Keeping those two views
separate prevents infrastructure failures from inflating detection claims.
"""

from __future__ import annotations

import json
import math
import statistics
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

CLASSIFIED_BLOCK = {"REJECTED", "FAIL", "TAMPERED"}
ABSTAIN = {"ERROR"}
VERDICTS = CLASSIFIED_BLOCK | ABSTAIN | {"PASS"}
BASELINE_PREDICTIONS = {"accept", "block", "abstain"}
CASE_KINDS = {
    "legitimate",
    "ordinary_invalid",
    "viable_evasion",
    "nonviable_evasion",
    "nonviable_policy_violation",
    "invalid_input",
}
SECURITY_EVASION_KIND = "viable_evasion"
SECURITY_EVASION_KINDS = {
    SECURITY_EVASION_KIND,
    "nonviable_evasion",
}
BASELINE_KEYS = {
    "applicable",
    "prediction",
    "exit_code",
    "elapsed_s",
    "reason",
}
BASELINE_INAPPLICABLE_REASONS = {
    "baseline_delete_target_missing",
    "candidate_has_no_file_blocks",
    "unsafe_candidate_path",
}


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key in benchmark row: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number in benchmark row: {value}")


def _parse_row(line: str, number: int) -> dict[str, object]:
    value = json.loads(
        line,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    if not isinstance(value, dict):
        raise ValueError(f"invalid row {number}")
    return value


def parse_rows_payload(payload: bytes) -> list[dict[str, object]]:
    """Parse exact UTF-8 JSONL bytes without accepting ambiguous JSON."""
    text = payload.decode("utf-8")
    return [
        _parse_row(line, number)
        for number, line in enumerate(text.splitlines(), 1)
        if line.strip()
    ]


def _rows_from_path(path: Path) -> list[dict[str, object]]:
    return parse_rows_payload(path.read_bytes())


def _finite_nonnegative_number(value: object, *, field: str, row: int) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0.0
    ):
        raise ValueError(f"invalid {field} in row {row}")
    return float(value)


def derive_baseline_prediction(
    observation: Mapping[str, object],
    *,
    row: int,
) -> str:
    """Validate the exact baseline schema and derive, rather than trust, its label."""
    if set(observation) != BASELINE_KEYS:
        raise ValueError(f"invalid baseline schema in row {row}")

    applicable = observation.get("applicable")
    recorded_prediction = observation.get("prediction")
    exit_code = observation.get("exit_code")
    reason = observation.get("reason")
    _finite_nonnegative_number(
        observation.get("elapsed_s"),
        field="baseline elapsed_s",
        row=row,
    )
    if type(applicable) is not bool or not isinstance(reason, str) or not reason:
        raise ValueError(f"invalid baseline observation in row {row}")
    if recorded_prediction not in BASELINE_PREDICTIONS:
        raise ValueError(f"invalid baseline prediction in row {row}")
    if exit_code is not None and (
        isinstance(exit_code, bool) or not isinstance(exit_code, int)
    ):
        raise ValueError(f"invalid baseline exit_code in row {row}")

    if applicable:
        if exit_code is None:
            if reason != "baseline_timeout":
                raise ValueError(f"invalid applicable abstention in row {row}")
            derived = "abstain"
        else:
            if reason != "exit_code":
                raise ValueError(f"invalid baseline exit observation in row {row}")
            derived = "accept" if exit_code == 0 else "block"
    else:
        if (
            exit_code is not None
            or reason not in BASELINE_INAPPLICABLE_REASONS
        ):
            raise ValueError(f"invalid inapplicable baseline in row {row}")
        derived = "abstain"

    if recorded_prediction != derived:
        raise ValueError(f"contradictory baseline prediction in row {row}")
    return derived


def _wilson_interval(successes: int, observations: int) -> tuple[float, float]:
    """Return a 95% Wilson score interval for one binomial proportion."""

    if observations <= 0:
        return 0.0, 0.0
    z = 1.959963984540054
    proportion = successes / observations
    denominator = 1.0 + (z * z / observations)
    centre = (proportion + z * z / (2.0 * observations)) / denominator
    margin = (
        z
        * math.sqrt(
            proportion * (1.0 - proportion) / observations
            + z * z / (4.0 * observations * observations)
        )
        / denominator
    )
    return max(0.0, centre - margin), min(1.0, centre + margin)


def _finish_metrics(
    counts: dict[str, int],
    *,
    abstain_accept: int,
    abstain_block: int,
) -> dict[str, float | int]:
    """Project one classified/abstained observation set into metrics."""
    classified = sum(counts.values())
    abstain = abstain_accept + abstain_block
    total = classified + abstain
    if not total:
        raise ValueError("corpus is empty")
    positives = counts["tp"] + counts["fn"]
    negatives = counts["tn"] + counts["fp"]
    accuracy_low, accuracy_high = _wilson_interval(
        counts["tp"] + counts["tn"], classified
    )
    fnr_low, fnr_high = _wilson_interval(counts["fn"], positives)
    fpr_low, fpr_high = _wilson_interval(counts["fp"], negatives)
    operational_positive_total = positives + abstain_block
    operational_blocked = counts["tp"] + abstain_block
    operational_low, operational_high = _wilson_interval(
        operational_blocked, operational_positive_total
    )
    return {
        **counts,
        "abstain": abstain,
        "abstain_accept": abstain_accept,
        "abstain_block": abstain_block,
        "classified": classified,
        "total": total,
        "coverage": classified / total,
        "accuracy": (
            (counts["tp"] + counts["tn"]) / classified if classified else 0.0
        ),
        "accuracy_ci95_low": accuracy_low,
        "accuracy_ci95_high": accuracy_high,
        "false_negative_rate": counts["fn"] / positives if positives else 0.0,
        "false_negative_rate_ci95_low": fnr_low,
        "false_negative_rate_ci95_high": fnr_high,
        "false_positive_rate": counts["fp"] / negatives if negatives else 0.0,
        "false_positive_rate_ci95_low": fpr_low,
        "false_positive_rate_ci95_high": fpr_high,
        # Admission is fail-closed on ERROR.  This is an operational control
        # metric, deliberately distinct from classification quality.
        "operational_block_rate": (
            operational_blocked / operational_positive_total
            if operational_positive_total
            else 0.0
        ),
        "operational_block_rate_ci95_low": operational_low,
        "operational_block_rate_ci95_high": operational_high,
    }


def evaluate(path: Path) -> dict[str, float | int]:
    return evaluate_rows(_rows_from_path(path))


def evaluate_rows(
    rows: Sequence[Mapping[str, object]],
) -> dict[str, float | int]:
    counts = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    abstain_accept = 0
    abstain_block = 0
    for number, row in enumerate(rows, 1):
        truth = row.get("truth")
        verdict = row.get("verdict")
        if truth not in {"accept", "block"} or verdict not in VERDICTS:
            raise ValueError(f"invalid row {number}")
        if verdict in ABSTAIN:
            if truth == "block":
                abstain_block += 1
            else:
                abstain_accept += 1
            continue
        predicted_block = verdict in CLASSIFIED_BLOCK
        key = (
            "tp" if truth == "block" and predicted_block else
            "fn" if truth == "block" else
            "fp" if predicted_block else "tn"
        )
        counts[key] += 1
    return _finish_metrics(
        counts,
        abstain_accept=abstain_accept,
        abstain_block=abstain_block,
    )


def evaluate_baseline(path: Path) -> dict[str, float | int]:
    """Evaluate the explicitly recorded ordinary-CI comparator."""
    return evaluate_baseline_rows(_rows_from_path(path))


def evaluate_baseline_rows(
    rows: Sequence[Mapping[str, object]],
) -> dict[str, float | int]:
    """Evaluate baseline observations after deriving every prediction."""
    counts = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    abstain_accept = 0
    abstain_block = 0
    for number, row in enumerate(rows, 1):
        truth = row.get("truth")
        baseline = row.get("baseline")
        if truth not in {"accept", "block"} or not isinstance(baseline, dict):
            raise ValueError(f"invalid baseline row {number}")
        prediction = derive_baseline_prediction(baseline, row=number)
        if prediction == "abstain":
            if truth == "block":
                abstain_block += 1
            else:
                abstain_accept += 1
            continue
        predicted_block = prediction == "block"
        key = (
            "tp" if truth == "block" and predicted_block else
            "fn" if truth == "block" else
            "fp" if predicted_block else "tn"
        )
        counts[key] += 1
    return _finish_metrics(
        counts,
        abstain_accept=abstain_accept,
        abstain_block=abstain_block,
    )


def evaluate_security_evasions(path: Path) -> dict[str, float | int]:
    """Report Guard outcomes only for baseline-viable evasion cases."""
    return evaluate_security_evasions_rows(_rows_from_path(path))


def evaluate_security_evasions_rows(
    rows: Sequence[Mapping[str, object]],
) -> dict[str, float | int]:
    selected: list[Mapping[str, object]] = []
    for number, row in enumerate(rows, 1):
        case_kind = row.get("case_kind")
        if case_kind not in SECURITY_EVASION_KINDS:
            continue
        baseline = row.get("baseline")
        if not isinstance(baseline, dict):
            raise ValueError(f"invalid evasion baseline in row {number}")
        prediction = derive_baseline_prediction(baseline, row=number)
        derived_kind = (
            SECURITY_EVASION_KIND
            if prediction == "accept"
            else "nonviable_evasion"
        )
        if case_kind != derived_kind:
            raise ValueError(
                f"evasion viability label contradicts baseline in row {number}"
            )
        if prediction == "accept":
            selected.append(row)
    if not selected:
        raise ValueError("corpus has no viable-evasion cases")
    blocked = 0
    missed = 0
    abstain = 0
    for number, row in enumerate(selected, 1):
        if row.get("truth") != "block":
            raise ValueError(f"invalid viable-evasion truth in row {number}")
        verdict = row.get("verdict")
        if verdict in CLASSIFIED_BLOCK:
            blocked += 1
        elif verdict == "PASS":
            missed += 1
        elif verdict in ABSTAIN:
            abstain += 1
        else:
            raise ValueError(f"invalid viable-evasion verdict in row {number}")
    classified = blocked + missed
    detection_low, detection_high = _wilson_interval(blocked, classified)
    operational_low, operational_high = _wilson_interval(
        blocked + abstain,
        len(selected),
    )
    return {
        "total": len(selected),
        "classified": classified,
        "blocked": blocked,
        "missed": missed,
        "abstain": abstain,
        "classified_detection_rate": (
            blocked / classified if classified else 0.0
        ),
        "classified_detection_rate_ci95_low": detection_low,
        "classified_detection_rate_ci95_high": detection_high,
        "operational_block_rate": (blocked + abstain) / len(selected),
        "operational_block_rate_ci95_low": operational_low,
        "operational_block_rate_ci95_high": operational_high,
    }


def timing_summary(
    rows: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Derive timing diagnostics from validated row observations."""
    guard_full: list[float] = []
    pre_gate: list[float] = []
    baseline_elapsed: list[float] = []
    for number, row in enumerate(rows, 1):
        elapsed = _finite_nonnegative_number(
            row.get("elapsed_s"),
            field="elapsed_s",
            row=number,
        )
        verdict = row.get("verdict")
        if verdict in {"PASS", "FAIL", "TAMPERED"}:
            guard_full.append(elapsed)
        elif verdict in {"REJECTED", "ERROR"}:
            pre_gate.append(elapsed)
        else:
            raise ValueError(f"invalid verdict in row {number}")
        baseline = row.get("baseline")
        if not isinstance(baseline, dict):
            raise ValueError(f"invalid baseline row {number}")
        derive_baseline_prediction(baseline, row=number)
        if baseline["applicable"] is True:
            baseline_elapsed.append(
                _finite_nonnegative_number(
                    baseline["elapsed_s"],
                    field="baseline elapsed_s",
                    row=number,
                )
            )
    return {
        "controlled_direct_pytest_median_s": (
            round(statistics.median(baseline_elapsed), 3)
            if baseline_elapsed
            else None
        ),
        "guard_full_run_median_s": (
            round(statistics.median(guard_full), 3) if guard_full else None
        ),
        "guard_full_run_p95_s": (
            round(
                sorted(guard_full)[
                    max(0, math.ceil(len(guard_full) * 0.95) - 1)
                ],
                3,
            )
            if guard_full
            else None
        ),
        "pre_gate_only_median_s": (
            round(statistics.median(pre_gate), 3) if pre_gate else None
        ),
        "scope": (
            "diagnostic wall time for this environment; cases are not a "
            "statistically controlled performance sample"
        ),
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
