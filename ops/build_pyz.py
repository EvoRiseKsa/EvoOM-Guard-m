#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Build a single-file, zero-dependency ``evo-guard.pyz`` (a Python zipapp).

EvoGuard's core is stdlib-only, so the whole CLI ships as **one executable
archive** — no clone, no ``pip``, no third-party install, and crucially **no
access to the private source repo** needed to run the gate. Run it with
``python evo-guard.pyz …`` (or ``./evo-guard.pyz …`` via the shebang). The version baked
into the archive is read from the packaged ``evoom_guard/__init__.py``, so
``python evo-guard.pyz version`` matches the release it was built from.

    python ops/build_pyz.py                 # -> dist/evo-guard.pyz
    python ops/build_pyz.py -o /tmp/x.pyz   # custom output

This module is stdlib-only and importable (``build``) so the build is testable.
"""
from __future__ import annotations

import argparse
import os
import shutil
import tempfile
import zipfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_MAIN = b"import sys\nfrom evoom_guard.cli import main\n\nsys.exit(main())\n"


def _write_reproducible_archive(stage: str, out_path: str, interpreter: str) -> None:
    """Write a byte-reproducible zipapp from *stage*.

    ``zipapp.create_archive`` inherits source mtimes (including the freshly
    generated ``__main__.py``) and filesystem iteration order.  That makes two
    builds from identical source bytes produce different release checksums.
    Canonical entry order, timestamps, modes, and storage make the artifact
    reproducible while retaining the standard self-executing zip format.
    """
    if "\n" in interpreter or "\r" in interpreter:
        raise ValueError("interpreter must be a single line")

    entries: list[tuple[str, str]] = []
    for directory, dirnames, filenames in os.walk(stage):
        dirnames.sort()
        filenames.sort()
        for filename in filenames:
            source = os.path.join(directory, filename)
            archive_name = os.path.relpath(source, stage).replace(os.sep, "/")
            entries.append((archive_name, source))
    entries.sort(key=lambda item: item[0])

    with open(out_path, "wb") as raw:
        if interpreter:
            raw.write(b"#!" + interpreter.encode("utf-8") + b"\n")
        with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_STORED) as archive:
            for archive_name, source in entries:
                info = zipfile.ZipInfo(archive_name, date_time=_ZIP_TIMESTAMP)
                info.create_system = 3  # Unix; keep archive metadata cross-platform.
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_STORED
                with open(source, "rb") as file_handle:
                    archive.writestr(info, file_handle.read())


def build(
    out_path: str,
    *,
    root: str = _ROOT,
    interpreter: str = "/usr/bin/env python3",
) -> str:
    """Build ``evo-guard.pyz`` at ``out_path`` from the ``evoom_guard`` package under ``root``.

    Only the package's Python sources are archived (no ``__pycache__``); the entry
    point is ``evoom_guard.cli:main``. Returns the absolute output path.
    """
    pkg = os.path.join(root, "evoom_guard")
    if not os.path.isdir(pkg):
        raise FileNotFoundError(f"evoom_guard package not found under {root!r}")
    out_path = os.path.abspath(out_path)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="evoom_guard_pyz_") as stage:
        shutil.copytree(
            pkg, os.path.join(stage, "evoom_guard"),
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        # Hand-write __main__ so the CLI's return value becomes the process exit
        # code. zipapp's ``-m pkg:func`` entry only *calls* main() and discards its
        # return — which would make every verdict exit 0 (the gate would not block).
        with open(os.path.join(stage, "__main__.py"), "wb") as f:
            f.write(_MAIN)
        _write_reproducible_archive(stage, out_path, interpreter)
    os.chmod(out_path, 0o755)
    return out_path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Build the single-file evo-guard.pyz (zero-dependency zipapp)."
    )
    p.add_argument(
        "-o", "--output", default=os.path.join(_ROOT, "dist", "evo-guard.pyz"),
        help="output path (default: dist/evo-guard.pyz)",
    )
    p.add_argument(
        "--interpreter", default="/usr/bin/env python3",
        help="shebang interpreter line (default: /usr/bin/env python3)",
    )
    args = p.parse_args(argv)
    out = build(args.output, interpreter=args.interpreter)
    print(f"built {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
