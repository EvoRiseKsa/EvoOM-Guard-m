import json
from pathlib import Path

from benchmarks.evaluate import evaluate
from evoom_guard import __version__


def _load_rows(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _without_environmental_timing(
    rows: list[dict[str, object]],
) -> list[dict[str, object]]:
    return [
        {key: value for key, value in row.items() if key != "elapsed_s"}
        for row in rows
    ]


def test_sample_benchmark_has_no_classification_errors() -> None:
    result = evaluate(Path(__file__).parents[1] / "benchmarks" / "sample.jsonl")
    assert result["tp"] == 3
    assert result["tn"] == 1
    assert result["fp"] == 0
    assert result["fn"] == 0


def test_published_live_results_match_their_labels() -> None:
    # benchmarks/results.jsonl is the COMMITTED observed run (real guard()
    # verdicts, produced by benchmarks/run_live.py). Its published metrics must
    # stay true: zero missed hacks, and exactly two false positives — the
    # documented-by-design protected-policy trips.
    path = Path(__file__).parents[1] / "benchmarks" / "results.jsonl"
    result = evaluate(path)
    assert result["fn"] == 0, "a published hack case is no longer blocked"
    assert result["fp"] == 2, "the FP count changed — update benchmarks/README.md"
    assert result["total"] == 16
    rows = _load_rows(path)
    assert {row.get("engine_version") for row in rows} == {__version__}


def test_live_benchmark_reproduces_the_published_corpus(tmp_path) -> None:
    # Run the REAL harness end-to-end (16 live guard() runs, a few seconds) and
    # require every case to land on its expected verdict — so the published
    # numbers can never drift from what the engine actually does.
    from benchmarks.run_live import run_corpus

    out = tmp_path / "live.jsonl"
    assert run_corpus(str(out)) == 0
    fresh = evaluate(out)
    committed_path = Path(__file__).parents[1] / "benchmarks" / "results.jsonl"
    committed = evaluate(committed_path)
    assert fresh == committed
    # Per-case outcomes, reason codes and recorded engine identity are the
    # reproducible evidence. Wall-clock timings are environment-dependent.
    assert _without_environmental_timing(_load_rows(out)) == (
        _without_environmental_timing(_load_rows(committed_path))
    )
