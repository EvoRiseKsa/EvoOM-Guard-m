# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Measure the current fidelity-snapshot cost on a synthetic repository tree.

This is an environment-labelled microbenchmark, not a universal performance
claim. Run it before and after filesystem hardening with identical arguments on
the same machine/toolchain, then compare the emitted JSON records.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard import __version__ as ENGINE_VERSION  # noqa: E402
from evoom_guard.verifiers.fidelity import _setup_fidelity_snapshot  # noqa: E402


def _populate_tree(root: Path, *, files: int, bytes_per_file: int) -> None:
    payload = b"E" * bytes_per_file
    for number in range(files):
        directory = root / "src" / f"shard-{number % 32:02d}"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"file-{number:06d}.bin").write_bytes(payload)


def run_baseline(
    root: Path,
    *,
    files: int = 1_000,
    bytes_per_file: int = 1_024,
    rounds: int = 5,
) -> dict[str, Any]:
    """Populate ``root`` and return an environment-labelled timing record."""
    if files < 1 or bytes_per_file < 1 or rounds < 1:
        raise ValueError("files, bytes_per_file, and rounds must all be positive")
    _populate_tree(root, files=files, bytes_per_file=bytes_per_file)

    started = time.perf_counter()
    snapshot = _setup_fidelity_snapshot(str(root))
    cold_seconds = time.perf_counter() - started

    samples: list[float] = []
    for _ in range(rounds):
        started = time.perf_counter()
        observed = _setup_fidelity_snapshot(str(root))
        samples.append(time.perf_counter() - started)
        if observed != snapshot:
            raise RuntimeError("synthetic tree changed during the security baseline")

    median_seconds = statistics.median(samples)
    payload_bytes = files * bytes_per_file
    return {
        "engine_version": ENGINE_VERSION,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "files": files,
        "bytes_per_file": bytes_per_file,
        "payload_bytes": payload_bytes,
        "snapshot_entries": len(snapshot),
        "rounds": rounds,
        "cold_seconds": round(cold_seconds, 6),
        "median_seconds": round(median_seconds, 6),
        "min_seconds": round(min(samples), 6),
        "max_seconds": round(max(samples), 6),
        "median_mib_per_second": round(
            (payload_bytes / (1024 * 1024)) / median_seconds
            if median_seconds
            else 0.0,
            3,
        ),
        "scope": "synthetic fidelity snapshot; compare only on equivalent environments",
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=1_000)
    parser.add_argument("--bytes-per-file", type=int, default=1_024)
    parser.add_argument("--rounds", type=int, default=5)
    args = parser.parse_args(argv)
    try:
        with tempfile.TemporaryDirectory(prefix="evoguard_security_baseline_") as tmp:
            result = run_baseline(
                Path(tmp),
                files=args.files,
                bytes_per_file=args.bytes_per_file,
                rounds=args.rounds,
            )
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"security baseline failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
