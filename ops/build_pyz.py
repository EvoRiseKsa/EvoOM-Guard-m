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
import io
import os
import stat
import tempfile
import zipfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_MAX_ARCHIVE_OVERHEAD_BYTES = 8 * 1024 * 1024
_MAIN = b"import sys\nfrom evoom_guard.cli import main\n\nsys.exit(main())\n"
# Governing terms that must travel inside the standalone archive. LICENSE is the
# source-available umbrella (always required); LICENSE-APACHE carries the
# Apache-2.0 grant text the core paths are licensed under (Apache-2.0 §4(a)),
# LICENSING.md the authoritative path->license map that conveys that grant, and
# NOTICE the attribution notices (Apache-2.0 §4(d)). All are canonical text.
_GOVERNING_DOCUMENTS = ("LICENSE", "LICENSE-APACHE", "LICENSING.md", "NOTICE")


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


def _validate_output_directory_chain(source_root: str, output_directory: str) -> None:
    """Reject an existing link-like hop between source and output parents."""
    try:
        common = os.path.commonpath((source_root, output_directory))
    except ValueError:  # Different Windows drives have no lexical common root.
        drive, tail = os.path.splitdrive(output_directory)
        common = drive + os.sep if tail.startswith(os.sep) else drive
    current = common
    relative = os.path.relpath(output_directory, common)
    components = () if relative == os.curdir else tuple(relative.split(os.sep))
    for component in (os.curdir, *components):
        if component != os.curdir:
            current = os.path.join(current, component)
        if not os.path.lexists(current):
            break
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
            raise ValueError(
                f"output directory chain contains a link or reparse point: {current!r}"
            )
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(
                f"output directory chain contains a non-directory: {current!r}"
            )


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


def _read_stable_regular_file_snapshot(path: str) -> tuple[bytes, os.stat_result]:
    """Read one file and return bytes plus its stable same-path identity."""
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
    return b"".join(chunks), before


def _read_stable_regular_file(path: str) -> bytes:
    """Read one regular file without silently following a substituted link."""
    return _read_stable_regular_file_snapshot(path)[0]


def _confirm_stable_archive_snapshot(
    path: str,
    expected_bytes: bytes,
    expected_identity: os.stat_result,
) -> None:
    """Require *path* to retain the exact audited identity and bytes."""
    actual_bytes, actual_identity = _read_stable_regular_file_snapshot(path)
    if not _same_file(expected_identity, actual_identity) or actual_bytes != expected_bytes:
        raise ValueError(f"archive path changed after the audited snapshot: {path!r}")


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
    if archive_name in _GOVERNING_DOCUMENTS or archive_name.endswith(".py") or (
        archive_name.startswith("evoom_guard/schemas/")
        and archive_name.endswith(".json")
    ):
        return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return data


def _snapshot_stage(stage: str) -> tuple[tuple[str, bytes], ...]:
    """Read one immutable logical snapshot of the staged archive payload."""
    return tuple(
        (archive_name, _archive_bytes(archive_name, source))
        for archive_name, source in _stage_entries(stage)
    )


def _audit_reproducible_archive(
    archive_path: str,
    payload: tuple[tuple[str, bytes], ...],
    interpreter: str,
) -> None:
    """Require *archive_path* to be the canonical encoding of *payload*.

    The check is deliberately byte-oriented.  It proves that every staged byte
    snapshot reached exactly one archive member and that no unreviewed member,
    timestamp, mode, compression choice, ZIP comment, or trailing payload was
    introduced while writing the distribution.
    """
    expected_names = [name for name, _data in payload]
    if expected_names != sorted(expected_names) or len(expected_names) != len(
        set(expected_names)
    ):
        raise ValueError("archive payload names must be sorted and unique")
    expected = dict(payload)
    prefix = b"#!" + interpreter.encode("utf-8") + b"\n" if interpreter else b""
    maximum_archive_bytes = (
        len(prefix)
        + sum(len(data) for _name, data in payload)
        + _MAX_ARCHIVE_OVERHEAD_BYTES
    )
    raw, archive_metadata = _read_stable_regular_file_snapshot(archive_path)
    if archive_metadata.st_size > maximum_archive_bytes:
        raise ValueError(
            "archive exceeds the staged payload plus the ZIP metadata budget"
        )
    if not raw.startswith(prefix) or raw[len(prefix) : len(prefix) + 4] != b"PK\x03\x04":
        raise ValueError("archive prefix or first ZIP record is not canonical")
    # This distribution is intentionally small enough to use an ordinary EOCD.
    # Requiring it to terminate the file rejects appended, non-ZIP payloads.
    end = raw.rfind(b"PK\x05\x06")
    if end < 0 or end + 22 > len(raw):
        raise ValueError("archive end-of-central-directory record is missing")
    comment_length = int.from_bytes(raw[end + 20 : end + 22], "little")
    if end + 22 + comment_length != len(raw):
        raise ValueError("archive contains trailing bytes after its ZIP records")

    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if names != expected_names:
            raise ValueError("archive member set or canonical order differs from staging")
        if archive.comment:
            raise ValueError("archive comment must be empty")
        for info in infos:
            if info.date_time != _ZIP_TIMESTAMP:
                raise ValueError(f"archive timestamp is not canonical: {info.filename}")
            if info.create_system != 3:
                raise ValueError(f"archive creator is not canonical: {info.filename}")
            if (info.external_attr >> 16) & 0xFFFF != 0o100644:
                raise ValueError(f"archive mode is not canonical: {info.filename}")
            if info.compress_type != zipfile.ZIP_STORED:
                raise ValueError(f"archive compression is not canonical: {info.filename}")
            if info.extra or info.comment:
                raise ValueError(f"archive member metadata is not empty: {info.filename}")
            expected_bytes = expected[info.filename]
            if info.file_size != len(expected_bytes):
                raise ValueError(f"archive member size differs from staging: {info.filename}")
        # Do not read any member body until all declared sizes and canonical
        # storage modes have been checked against the trusted staging snapshot.
        if archive.testzip() is not None:
            raise ValueError("archive member CRC validation failed")
        for info in infos:
            if archive.read(info) != expected[info.filename]:
                raise ValueError(f"archive member bytes differ from staging: {info.filename}")
    canonical_raw = _canonical_archive_bytes(payload, interpreter)
    if raw != canonical_raw:
        raise ValueError("archive raw ZIP bytes are not the canonical encoding")
    _confirm_stable_archive_snapshot(archive_path, raw, archive_metadata)


def _canonical_archive_bytes(
    payload: tuple[tuple[str, bytes], ...], interpreter: str
) -> bytes:
    """Encode the only accepted raw zipapp representation of *payload*."""
    raw = io.BytesIO()
    if interpreter:
        raw.write(b"#!" + interpreter.encode("utf-8") + b"\n")
    with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_STORED) as archive:
        for archive_name, data in payload:
            info = zipfile.ZipInfo(archive_name, date_time=_ZIP_TIMESTAMP)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, data)
    return raw.getvalue()


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

    # Snapshot each staged file once.  The writer never re-reads staging, and
    # the post-write audit binds the archive back to this exact byte snapshot.
    payload = _snapshot_stage(stage)

    with open(out_path, "wb") as raw:
        raw.write(_canonical_archive_bytes(payload, interpreter))
    _audit_reproducible_archive(out_path, payload, interpreter)


def _prepare_stage(root: str, stage: str) -> tuple[str, str]:
    """Populate *stage* from one validated distribution source root."""
    try:
        _validate_directory(root)
    except FileNotFoundError as error:
        raise FileNotFoundError(f"source root is not a real directory: {root!r}") from error
    pkg = os.path.join(root, "evoom_guard")
    if not os.path.lexists(pkg):
        raise FileNotFoundError(f"evoom_guard package not found under {root!r}")
    _validate_directory(pkg)
    _copy_source_tree(pkg, os.path.join(stage, "evoom_guard"))
    for governing in _GOVERNING_DOCUMENTS:
        governing_path = os.path.join(root, governing)
        if not os.path.lexists(governing_path):
            raise FileNotFoundError(f"{governing} not found under {root!r}")
        _regular_file_metadata(governing_path)
        _copy_regular_file(governing_path, os.path.join(stage, governing))
    with open(os.path.join(stage, "__main__.py"), "xb") as entrypoint:
        entrypoint.write(_MAIN)
    return pkg, os.path.join(root, "LICENSE")


def audit(
    archive_path: str,
    *,
    root: str = _ROOT,
    interpreter: str = "/usr/bin/env python3",
) -> None:
    """Audit an existing zipapp against the exact current distribution source."""
    root = os.path.abspath(root)
    archive_path = os.path.abspath(archive_path)
    _regular_file_metadata(archive_path)
    with tempfile.TemporaryDirectory(prefix="evoom_guard_pyz_audit_") as stage:
        _prepare_stage(root, stage)
        _audit_reproducible_archive(archive_path, _snapshot_stage(stage), interpreter)


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
    # Validate the source boundary before using its paths to validate output.
    try:
        _validate_directory(root)
    except FileNotFoundError as error:
        raise FileNotFoundError(f"source root is not a real directory: {root!r}") from error
    pkg = os.path.join(root, "evoom_guard")
    out_path = os.path.abspath(out_path)
    output_directory = os.path.dirname(out_path) or "."
    _validate_output_directory_chain(root, output_directory)
    resolved_output = os.path.realpath(out_path)
    package_identity = os.path.normcase(os.path.realpath(pkg))
    output_identity = os.path.normcase(resolved_output)
    governing_document_identities = {
        os.path.normcase(os.path.realpath(os.path.join(root, document)))
        for document in _GOVERNING_DOCUMENTS
    }
    try:
        output_is_in_package = (
            os.path.commonpath((package_identity, output_identity)) == package_identity
        )
    except ValueError:  # Different Windows drives cannot overlap.
        output_is_in_package = False
    if output_is_in_package or output_identity in governing_document_identities:
        raise ValueError("output must not replace or be nested inside packaged source")
    if os.path.lexists(out_path):
        _regular_file_metadata(out_path)
    os.makedirs(output_directory, exist_ok=True)
    _validate_output_directory_chain(root, output_directory)
    if os.path.normcase(os.path.realpath(out_path)) != output_identity:
        raise ValueError("output path changed while preparing its directory")
    with tempfile.TemporaryDirectory(prefix="evoom_guard_pyz_") as stage:
        _prepare_stage(root, stage)
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
    p.add_argument(
        "--audit",
        metavar="ARCHIVE",
        help="audit an existing archive against the current source instead of building",
    )
    args = p.parse_args(argv)
    if args.audit:
        audit(args.audit, interpreter=args.interpreter)
        print(f"audited {os.path.abspath(args.audit)}")
        return 0
    out = build(args.output, interpreter=args.interpreter)
    print(f"built {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
