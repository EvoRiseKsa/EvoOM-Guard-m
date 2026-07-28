"""Coverage-guided target for candidate-influenced JUnit XML."""

from __future__ import annotations

import sys

try:
    import atheris
except ModuleNotFoundError:  # Local deterministic smoke tests need no Atheris.
    atheris = None

if atheris is None:
    from evoom_guard.verifiers.junit_oracle import parse_junit_xml
else:
    with atheris.instrument_imports():
        from evoom_guard.verifiers.junit_oracle import parse_junit_xml

MAX_FUZZ_INPUT_BYTES = 1024 * 1024


def fuzz_one_input(data: bytes) -> None:
    """Require deterministic parsing and nonnegative, coherent accepted counts."""
    if len(data) > MAX_FUZZ_INPUT_BYTES:
        return
    text = data.decode("utf-8", errors="replace")
    first = parse_junit_xml(text)
    second = parse_junit_xml(text)
    if first != second:
        raise AssertionError("JUnit parsing is not deterministic")
    if first is None:
        return
    if min(first.passed, first.total, first.failures, first.errors) < 0:
        raise AssertionError("JUnit parser returned a negative count")
    if first.passed + first.failures + first.errors > first.total:
        raise AssertionError("JUnit parser returned incoherent counts")


def main() -> None:
    if atheris is None:
        raise SystemExit("Atheris is required for coverage-guided fuzzing")
    atheris.Setup(
        sys.argv,
        fuzz_one_input,
        enable_python_coverage=True,
    )
    atheris.Fuzz()


if __name__ == "__main__":
    main()
