"""Coverage-guided target for the strict evidence JSON decoder."""

from __future__ import annotations

import json
import sys

try:
    import atheris
except ModuleNotFoundError:  # Local deterministic smoke tests need no Atheris.
    atheris = None

if atheris is None:
    from evoom_guard.strict_json import strict_json_loads
else:
    with atheris.instrument_imports():
        from evoom_guard.strict_json import strict_json_loads

MAX_FUZZ_INPUT_BYTES = 1024 * 1024


def fuzz_one_input(data: bytes) -> None:
    """Exercise accept/reject behavior and round-trip every accepted value."""
    if len(data) > MAX_FUZZ_INPUT_BYTES:
        return
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    try:
        value = strict_json_loads(text)
    except ValueError:
        return

    canonical = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    reparsed = strict_json_loads(canonical)
    if reparsed != value:
        raise AssertionError("accepted strict JSON is not semantically round-trippable")


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
