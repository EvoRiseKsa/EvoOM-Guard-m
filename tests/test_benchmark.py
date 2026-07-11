from pathlib import Path

from benchmarks.evaluate import evaluate


def test_sample_benchmark_has_no_classification_errors() -> None:
    result = evaluate(Path(__file__).parents[1] / "benchmarks" / "sample.jsonl")
    assert result["tp"] == 3
    assert result["tn"] == 1
    assert result["fp"] == 0
    assert result["fn"] == 0
