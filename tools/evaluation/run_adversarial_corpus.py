#!/usr/bin/env python3
"""Run every pytest node registered in the executable adversarial corpus."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REGISTRY = ROOT / "adversarial" / "corpus.jsonl"
MAX_REGISTRY_BYTES = 2 * 1024 * 1024
MAX_CASES = 10_000
_SELECTOR_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_\-\[\].]*\Z")


class CorpusRegistryError(ValueError):
    """The registry cannot safely identify one complete pytest corpus."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CorpusRegistryError(f"duplicate JSON key in corpus row: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise CorpusRegistryError(f"non-finite JSON number in corpus row: {value}")


def _validated_nodeid(value: object, *, root: Path, row: int) -> str:
    if not isinstance(value, str) or not value:
        raise CorpusRegistryError(f"corpus row {row} has no test_nodeid")
    relative, *selectors = value.split("::")
    parsed = PurePosixPath(relative)
    if (
        not selectors
        or parsed.is_absolute()
        or parsed.suffix != ".py"
        or not parsed.parts
        or parsed.parts[0] != "tests"
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or "\\" in relative
        or any(not _SELECTOR_PATTERN.fullmatch(selector) for selector in selectors)
    ):
        raise CorpusRegistryError(f"corpus row {row} has an unsafe test_nodeid")
    test_path = root.joinpath(*parsed.parts)
    try:
        test_path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise CorpusRegistryError(
            f"corpus row {row} test_nodeid escapes the repository"
        ) from exc
    if not test_path.is_file() or test_path.is_symlink():
        raise CorpusRegistryError(
            f"corpus row {row} test_nodeid does not name a regular test file"
        )
    return value


def registered_nodeids(
    registry: Path = DEFAULT_REGISTRY,
    *,
    root: Path = ROOT,
) -> tuple[str, ...]:
    """Load the exact unique nodeids that constitute the executable corpus."""
    payload = registry.read_bytes()
    if len(payload) > MAX_REGISTRY_BYTES:
        raise CorpusRegistryError("adversarial corpus registry exceeds its size limit")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CorpusRegistryError(
            "adversarial corpus registry is not UTF-8"
        ) from exc
    nodeids: list[str] = []
    seen: set[str] = set()
    for row_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(
                line,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
        except json.JSONDecodeError as exc:
            raise CorpusRegistryError(
                f"adversarial corpus row {row_number} is invalid JSON"
            ) from exc
        if not isinstance(row, dict):
            raise CorpusRegistryError(
                f"adversarial corpus row {row_number} is not an object"
            )
        nodeid = _validated_nodeid(
            row.get("test_nodeid"),
            root=root,
            row=row_number,
        )
        if nodeid in seen:
            raise CorpusRegistryError(
                f"adversarial corpus row {row_number} duplicates a test_nodeid"
            )
        seen.add(nodeid)
        nodeids.append(nodeid)
        if len(nodeids) > MAX_CASES:
            raise CorpusRegistryError("adversarial corpus exceeds its case limit")
    if not nodeids:
        raise CorpusRegistryError("adversarial corpus registry is empty")
    return tuple(nodeids)


def run_registered_corpus(
    registry: Path = DEFAULT_REGISTRY,
    *,
    root: Path = ROOT,
) -> int:
    """Invoke pytest once with every exact nodeid from the registry."""
    nodeids = registered_nodeids(registry, root=root)
    environment = dict(os.environ)
    for key in (
        "PYTEST_ADDOPTS",
        "PYTEST_CURRENT_TEST",
        "PYTEST_DEBUG",
        "PYTEST_PLUGINS",
    ):
        environment.pop(key, None)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--color=no",
            "-p",
            "no:cacheprovider",
            "-o",
            "addopts=",
            *nodeids,
        ],
        cwd=root,
        env=environment,
        check=False,
    )
    return int(completed.returncode)


def main(_argv: Sequence[str] | None = None) -> int:
    try:
        return run_registered_corpus()
    except (CorpusRegistryError, OSError) as exc:
        print(f"adversarial corpus error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
