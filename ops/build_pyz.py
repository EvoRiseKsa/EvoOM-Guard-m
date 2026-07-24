#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Build a single-file, zero-dependency ``evo-guard.pyz`` (a Python zipapp).

EvoGuard's core is stdlib-only, so the whole CLI ships as **one executable
archive** — no clone, no ``pip``, and no third-party install. Run it with
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
import stat
import tempfile
import zipfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_MAIN = b"import sys\nfrom evoom_guard.cli import main\n\nsys.exit(main())\n"


def _is_reparse_point(metadata: os.stat_result) -> bool:
    """Return whether *metadata* identifies a Windows reparse point."""
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _validate_component(name: str) -> None:
    """Reject names that cannot have one unambiguous portable ZIP spelling."""
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise ValueError(f"unsafe source entry name: {name!r}")


def _validate_directory(path: str) -> None:
    metadata = os.lstat(path)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise ValueError(f"source directory must be a real directory: {path!r}")


def _regular_file_metadata(path: str) -> os.stat_result:
    metadata = os.lstat(path)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(metadata)
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise ValueError(f"source entry must be a regular file: {path!r}")
    return metadata


def _same_file(
    left: os.stat_result,
    right: os.stat_result,
    *,
    include_ctime: bool = True,
) -> bool:
    stable_identity = (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_size,
        left.st_mtime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_size,
        right.st_mtime_ns,
    )
    return stable_identity and (
        not include_ctime or left.st_ctime_ns == right.st_ctime_ns
    )


def _read_stable_regular_file(path: str) -> bytes:
    """Read one regular file without silently following a substituted link."""
    before = _regular_file_metadata(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        # Windows path-stat and handle-stat can expose different ctime
        # precision for the same file. Compare ctime only within like-for-like
        # path/path or handle/handle probes below.
        if not stat.S_ISREG(opened.st_mode) or not _same_file(
            before, opened, include_ctime=False
        ):
            raise ValueError(f"source entry changed while opening: {path!r}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after_read = os.fstat(descriptor)
        if not _same_file(opened, after_read):
            raise ValueError(f"source entry changed while reading: {path!r}")
    finally:
        os.close(descriptor)
    after_close = _regular_file_metadata(path)
    if not _same_file(before, after_close):
        raise ValueError(f"source entry changed during the build: {path!r}")
    return b"".join(chunks)


def _copy_regular_file(source: str, destination: str) -> None:
    data = _read_stable_regular_file(source)
    with open(destination, "xb") as destination_handle:
        destination_handle.write(data)


def _copy_source_tree(source: str, destination: str | None) -> None:
    """Validate one source tree and copy its included files without link traversal."""
    _validate_directory(source)
    if destination is not None:
        os.mkdir(destination)
    with os.scandir(source) as scanner:
        entries = sorted(scanner, key=lambda entry: entry.name)
    for entry in entries:
        _validate_component(entry.name)
        metadata = entry.stat(follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
            raise ValueError(f"source tree contains a link or reparse point: {entry.path!r}")
        if stat.S_ISDIR(metadata.st_mode):
            child_destination = (
                None
                if destination is None or entry.name == "__pycache__"
                else os.path.join(destination, entry.name)
            )
            _copy_source_tree(entry.path, child_destination)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"source tree contains a special file: {entry.path!r}")
        if destination is not None and not entry.name.endswith(".pyc"):
            _copy_regular_file(entry.path, os.path.join(destination, entry.name))


def _stage_entries(stage: str) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []

    def visit(directory: str, relative: tuple[str, ...]) -> None:
        _validate_directory(directory)
        with os.scandir(directory) as scanner:
            children = sorted(scanner, key=lambda entry: entry.name)
        for child in children:
            _validate_component(child.name)
            metadata = child.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
                raise ValueError(
                    f"archive staging contains a link or reparse point: {child.path!r}"
                )
            child_relative = (*relative, child.name)
            if stat.S_ISDIR(metadata.st_mode):
                visit(child.path, child_relative)
            elif stat.S_ISREG(metadata.st_mode):
                entries.append(("/".join(child_relative), child.path))
            else:
                raise ValueError(f"archive staging contains a special file: {child.path!r}")

    visit(stage, ())
    entries.sort(key=lambda item: item[0])
    return entries


def _archive_bytes(archive_name: str, source: str) -> bytes:
    """Return canonical bytes for one archive entry.

    Git may materialize text with LF or CRLF depending on the checkout platform
    and ``core.autocrlf``. Python source semantics and JSON Schema semantics do
    not depend on that representation, so preserving it would break release
    reproducibility without adding meaning. Other package data remains exact.
    """
    data = _read_stable_regular_file(source)
    if archive_name == "LICENSE" or archive_name.endswith(".py") or (
        archive_name.startswith("evoom_guard/schemas/")
        and archive_name.endswith(".json")
    ):
        return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return data


def _write_reproducible_archive(stage: str, out_path: str, interpreter: str) -> None:
    """Write a reproducible zipapp from *stage*.

    ``zipapp.create_archive`` inherits source mtimes (including the freshly
    generated ``__main__.py``) and filesystem iteration order.  That makes two
    builds from identical source bytes produce different release checksums.
    Canonical entry order, timestamps, modes, storage, and Python-source LF
    newlines remove those sources of variance. Repeated builds are
    byte-identical across LF and CRLF checkouts when canonical source contents,
    the interpreter line, and the Python ZIP implementation are equivalent.
    Release publication separately refuses to replace an existing tag asset
    with different bytes.
    """
    if "\n" in interpreter or "\r" in interpreter:
        raise ValueError("interpreter must be a single line")

    entries = _stage_entries(stage)

    with open(out_path, "wb") as raw:
        if interpreter:
            raw.write(b"#!" + interpreter.encode("utf-8") + b"\n")
        with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_STORED) as archive:
            for archive_name, source in entries:
                info = zipfile.ZipInfo(archive_name, date_time=_ZIP_TIMESTAMP)
                info.create_system = 3  # Unix; keep archive metadata cross-platform.
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_STORED
                archive.writestr(info, _archive_bytes(archive_name, source))


def build(
    out_path: str,
    *,
    root: str = _ROOT,
    interpreter: str = "/usr/bin/env python3",
) -> str:
    """Build ``evo-guard.pyz`` at ``out_path`` from the ``evoom_guard`` package under ``root``.

    The package's sources and declared data are archived (no ``__pycache__``);
    the entry point is ``evoom_guard.cli:main``. Returns the absolute output path.
    """
    root = os.path.abspath(root)
    try:
        _validate_directory(root)
    except FileNotFoundError as error:
        raise FileNotFoundError(f"source root is not a real directory: {root!r}") from error
    pkg = os.path.join(root, "evoom_guard")
    if not os.path.lexists(pkg):
        raise FileNotFoundError(f"evoom_guard package not found under {root!r}")
    _validate_directory(pkg)
    license_path = os.path.join(root, "LICENSE")
    if not os.path.lexists(license_path):
        raise FileNotFoundError(f"LICENSE not found under {root!r}")
    _regular_file_metadata(license_path)
    out_path = os.path.abspath(out_path)
    try:
        output_is_in_package = os.path.commonpath((pkg, out_path)) == pkg
    except ValueError:  # Different Windows drives cannot overlap.
        output_is_in_package = False
    if output_is_in_package or out_path == license_path:
        raise ValueError("output must not replace or be nested inside packaged source")
    if os.path.lexists(out_path):
        _regular_file_metadata(out_path)
    output_directory = os.path.dirname(out_path) or "."
    os.makedirs(output_directory, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="evoom_guard_pyz_") as stage:
        _copy_source_tree(pkg, os.path.join(stage, "evoom_guard"))
        # The standalone archive is a distribution in its own right. Keep its
        # governing terms inside the exact bytes users download and verify.
        _copy_regular_file(license_path, os.path.join(stage, "LICENSE"))
        # Hand-write __main__ so the CLI's return value becomes the process exit
        # code. zipapp's ``-m pkg:func`` entry only *calls* main() and discards its
        # return — which would make every verdict exit 0 (the gate would not block).
        with open(os.path.join(stage, "__main__.py"), "wb") as f:
            f.write(_MAIN)
        descriptor, temporary_output = tempfile.mkstemp(
            prefix=".evo-guard.pyz.", suffix=".tmp", dir=output_directory
        )
        os.close(descriptor)
        try:
            _write_reproducible_archive(stage, temporary_output, interpreter)
            os.chmod(temporary_output, 0o755)
            os.replace(temporary_output, out_path)
        finally:
            try:
                os.unlink(temporary_output)
            except FileNotFoundError:
                pass
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
