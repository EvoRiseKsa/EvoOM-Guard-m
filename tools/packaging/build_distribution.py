#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Build and audit the one existing ``evoom-guard`` Python distribution.

This is release-readiness tooling, not a second package or a publication path.
It stages the complete, dual-licensed-by-path distribution, builds it with the
hash-locked setuptools version already installed by CI, canonicalizes the wheel,
and proves that package members are byte-exact copies of staging.  It also
verifies the wheel's exact member allowlist, METADATA, WHEEL, entry point,
license documents, and every RECORD digest/size.

The build and clean-install smoke disable pip index/config resolution.  That is
not an operating-system egress boundary; the procedure never claims otherwise
and never installs pytest or another unpinned verification dependency.
"""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import hashlib
import importlib.metadata
import io
import os
import stat
import subprocess
import sys
import tempfile
import venv
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import NoReturn

try:  # Python 3.11+
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # Python 3.10 remains a supported CI target.
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "requirements" / "ci.lock"
PACKAGE = "evoom_guard"
DISTRIBUTION = "evoom-guard"
WHEEL_DISTRIBUTION = "evoom_guard"
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
SOURCE_DATE_EPOCH = "315532800"  # 1980-01-01T00:00:00Z
MAX_MEMBERS = 4096
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_BYTES = 160 * 1024 * 1024
GOVERNING_DOCUMENTS = ("LICENSE", "LICENSE-APACHE", "LICENSING.md", "NOTICE")
SYSTEM_ENVIRONMENT_ALLOWLIST = frozenset(
    {
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
    }
)
DIST_INFO_FILES = frozenset(
    {
        "METADATA",
        "WHEEL",
        "entry_points.txt",
        "top_level.txt",
        "RECORD",
        "licenses/LICENSE",
        "licenses/LICENSE-APACHE",
        "licenses/LICENSING.md",
        "licenses/NOTICE",
    }
)
EXPECTED_SUMMARY = (
    "Policy- and evidence-bound change admission, with AI-generated patches as the "
    "primary use case."
)
EXPECTED_CLASSIFIERS = (
    "License :: Other/Proprietary License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Software Development :: Testing",
    "Topic :: Software Development :: Quality Assurance",
)
EXPECTED_REQUIRES_DIST = (
    'cryptography>=41; extra == "sign"',
    'coverage>=7; extra == "cov"',
    'pytest>=8; extra == "dev"',
    'ruff>=0.6; extra == "dev"',
    'mypy>=1.10; extra == "dev"',
    'coverage>=7; extra == "dev"',
    'cryptography>=41; extra == "dev"',
    'jsonschema>=4.23; extra == "dev"',
)


class DistributionBuildError(RuntimeError):
    """The single distribution cannot be built or audited as specified."""


def _fail(message: str) -> NoReturn:
    raise DistributionBuildError(message)


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _validate_component(name: str) -> None:
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        _fail(f"unsafe source entry name: {name!r}")


def _validate_directory(path: Path) -> None:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        _fail(f"source directory must be a real directory: {path}")


def _regular_file_metadata(path: Path) -> os.stat_result:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(metadata)
        or not stat.S_ISREG(metadata.st_mode)
    ):
        _fail(f"source entry must be a regular file: {path}")
    return metadata


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
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


def _read_stable_snapshot(path: Path) -> tuple[bytes, os.stat_result]:
    """Read *path* once and return its bytes plus the bound path identity."""
    before = _regular_file_metadata(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_file(before, opened):
            _fail(f"source entry changed while opening: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after_read = os.fstat(descriptor)
        if not _same_file(opened, after_read):
            _fail(f"source entry changed while reading: {path}")
    finally:
        os.close(descriptor)
    if not _same_file(before, _regular_file_metadata(path)):
        _fail(f"source entry changed during staging: {path}")
    return b"".join(chunks), before


def _read_stable(path: Path) -> bytes:
    return _read_stable_snapshot(path)[0]


def _confirm_stable_snapshot(
    path: Path,
    expected_bytes: bytes,
    expected_identity: os.stat_result,
) -> None:
    """Require the audited path to still name the exact snapshotted file."""
    actual_bytes, actual_identity = _read_stable_snapshot(path)
    if not _same_file(expected_identity, actual_identity) or actual_bytes != expected_bytes:
        _fail(f"archive path changed after the audited snapshot: {path}")


def _copy_file(source: Path, destination: Path) -> None:
    data = _read_stable(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(data)


def _copy_tree(source: Path, destination: Path) -> None:
    _validate_directory(source)
    destination.mkdir()
    children = sorted(os.scandir(source), key=lambda entry: entry.name)
    for child in children:
        _validate_component(child.name)
        metadata = child.stat(follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
            _fail(f"source tree contains a link or reparse point: {child.path}")
        child_destination = destination / child.name
        if stat.S_ISDIR(metadata.st_mode):
            if child.name == "__pycache__":
                # Validate ignored contents too; an ignored directory must not
                # hide a link or special file at the trusted build boundary.
                _validate_ignored_tree(Path(child.path))
            else:
                _copy_tree(Path(child.path), child_destination)
        elif stat.S_ISREG(metadata.st_mode):
            if child.name.endswith(".pyc"):
                continue
            _copy_file(Path(child.path), child_destination)
        else:
            _fail(f"source tree contains a special file: {child.path}")


def _validate_ignored_tree(source: Path) -> None:
    _validate_directory(source)
    children = sorted(os.scandir(source), key=lambda entry: entry.name)
    for child in children:
        _validate_component(child.name)
        metadata = child.stat(follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
            _fail(f"ignored source tree contains a link or reparse point: {child.path}")
        if stat.S_ISDIR(metadata.st_mode):
            _validate_ignored_tree(Path(child.path))
        elif not stat.S_ISREG(metadata.st_mode):
            _fail(f"ignored source tree contains a special file: {child.path}")


def _source_version(package_root: Path) -> str:
    tree = ast.parse(_read_stable(package_root / "__init__.py"), filename="__init__.py")
    versions: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if (
            isinstance(target, ast.Name)
            and target.id == "__version__"
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            versions.append(node.value.value)
    if len(versions) != 1 or not versions[0]:
        _fail("source must contain exactly one literal __version__ assignment")
    return versions[0]


def _locked_setuptools_version(root: Path) -> str:
    text = _read_stable(root / "requirements" / "ci.lock").decode("utf-8")
    versions = [
        line.removeprefix("setuptools==").split()[0]
        for line in text.splitlines()
        if line.startswith("setuptools==")
    ]
    if len(versions) != 1:
        _fail("ci.lock must contain exactly one pinned setuptools version")
    return versions[0]


def _require_locked_backend(root: Path) -> str:
    locked = _locked_setuptools_version(root)
    try:
        installed = importlib.metadata.version("setuptools")
    except importlib.metadata.PackageNotFoundError:
        _fail("the hash-locked setuptools build backend is not installed")
    if installed != locked:
        _fail(f"setuptools version is not the locked build backend: {installed} != {locked}")
    return locked


def _validate_staged_build_system(pyproject_path: Path, locked_setuptools: str) -> None:
    """Bind the staged PEP 517 backend to the one hash-locked requirement."""
    try:
        project = tomllib.loads(_read_stable(pyproject_path).decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        _fail(f"staged pyproject.toml is not canonical UTF-8 TOML: {error}")
    build_system = project.get("build-system")
    if not isinstance(build_system, dict):
        _fail("staged pyproject.toml must contain one build-system table")
    if "backend-path" in build_system:
        _fail("staged pyproject.toml build-system must not define backend-path")
    if set(build_system) != {"requires", "build-backend"}:
        _fail("staged pyproject.toml build-system fields differ from the closed contract")
    if build_system.get("build-backend") != "setuptools.build_meta":
        _fail("staged pyproject.toml build-backend must be exactly setuptools.build_meta")
    expected_requirements = [f"setuptools=={locked_setuptools}"]
    if build_system.get("requires") != expected_requirements:
        _fail(
            "staged pyproject.toml build-system.requires must equal the exact locked "
            f"requirement: {expected_requirements!r}"
        )


def _stage(root: Path, staging: Path) -> tuple[str, str]:
    _validate_directory(root)
    staging.mkdir()
    _copy_tree(root / PACKAGE, staging / PACKAGE)
    for name in ("pyproject.toml", "README.md", *GOVERNING_DOCUMENTS):
        _copy_file(root / name, staging / name)
    locked = _locked_setuptools_version(root)
    _validate_staged_build_system(staging / "pyproject.toml", locked)
    return _source_version(staging / PACKAGE), locked


def _payload_snapshot(staging: Path) -> dict[str, bytes]:
    package_root = staging / PACKAGE
    payload: dict[str, bytes] = {}

    def visit(directory: Path, relative: tuple[str, ...]) -> None:
        _validate_directory(directory)
        children = sorted(os.scandir(directory), key=lambda entry: entry.name)
        for child in children:
            _validate_component(child.name)
            metadata = child.stat(follow_symlinks=False)
            child_relative = (*relative, child.name)
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
                _fail(f"staging contains a link or reparse point: {child.path}")
            if stat.S_ISDIR(metadata.st_mode):
                visit(Path(child.path), child_relative)
            elif stat.S_ISREG(metadata.st_mode):
                name = "/".join((PACKAGE, *child_relative))
                payload[name] = _read_stable(Path(child.path))
            else:
                _fail(f"staging contains a special file: {child.path}")

    visit(package_root, ())
    if len(payload) < 150:
        _fail(f"implausibly small staged distribution payload: {len(payload)} files")
    return payload


def _safe_wheel_name(name: str) -> None:
    path = PurePosixPath(name)
    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        _fail(f"unsafe wheel member name: {name!r}")


def _require_zip_eof(
    path: Path, *, prefix: bytes = b""
) -> tuple[bytes, os.stat_result]:
    raw, metadata = _read_stable_snapshot(path)
    if metadata.st_size > MAX_ARCHIVE_BYTES:
        _fail(f"wheel archive is too large: {metadata.st_size}")
    if not raw.startswith(prefix) or raw[len(prefix) : len(prefix) + 4] != b"PK\x03\x04":
        _fail("wheel prefix or first ZIP record is invalid")
    end = raw.rfind(b"PK\x05\x06")
    if end < 0 or end + 22 > len(raw):
        _fail("wheel end-of-central-directory record is missing")
    comment_length = int.from_bytes(raw[end + 20 : end + 22], "little")
    if end + 22 + comment_length != len(raw):
        _fail("wheel contains trailing bytes after its ZIP records")
    return raw, metadata


def _canonical_zip_bytes(contents: dict[str, bytes], *, prefix: bytes = b"") -> bytes:
    """Encode the only accepted raw ZIP representation of *contents*."""
    raw = io.BytesIO()
    raw.write(prefix)
    with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(contents):
            info = zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, contents[name])
    return raw.getvalue()


def _sha256_record_value(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "sha256=" + digest.decode("ascii")


def _canonical_record(contents: dict[str, bytes], record_name: str) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name in sorted((*contents.keys(), record_name)):
        if name == record_name:
            writer.writerow((name, "", ""))
        else:
            data = contents[name]
            writer.writerow((name, _sha256_record_value(data), str(len(data))))
    return output.getvalue().encode("utf-8")


def _verify_record(contents: dict[str, bytes], record_name: str, *, canonical: bool) -> None:
    record = contents.get(record_name)
    if record is None:
        _fail("wheel RECORD is missing")
    try:
        rows = list(csv.reader(io.StringIO(record.decode("utf-8"), newline="")))
    except (UnicodeDecodeError, csv.Error) as error:
        _fail(f"wheel RECORD is not valid UTF-8 CSV: {error}")
    if any(len(row) != 3 for row in rows):
        _fail("wheel RECORD rows must each contain exactly three fields")
    names = [row[0] for row in rows]
    if len(names) != len(set(names)):
        _fail("wheel RECORD contains duplicate paths")
    if set(names) != set(contents):
        _fail("wheel RECORD path set does not match the archive")
    for name, digest, size in rows:
        if name == record_name:
            if digest or size:
                _fail("wheel RECORD must not hash itself")
            continue
        data = contents[name]
        if digest != _sha256_record_value(data):
            _fail(f"wheel RECORD digest mismatch: {name}")
        if size != str(len(data)):
            _fail(f"wheel RECORD size mismatch: {name}")
    expected = _canonical_record(
        {name: data for name, data in contents.items() if name != record_name},
        record_name,
    )
    if canonical and record != expected:
        _fail("wheel RECORD is valid but not canonically ordered/encoded")


def _expected_wheel_metadata(locked_setuptools: str) -> bytes:
    return (
        "Wheel-Version: 1.0\n"
        f"Generator: setuptools ({locked_setuptools})\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
        "\n"
    ).encode("ascii")


def _canonical_text(data: bytes, *, where: str) -> str:
    try:
        return data.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeDecodeError as error:
        _fail(f"{where} is not UTF-8: {error}")


def _expected_core_metadata(staging: Path, version: str) -> bytes:
    """Return the one closed, cross-platform Core Metadata representation."""
    license_text = _canonical_text(
        _read_stable(staging / "LICENSE"), where="staged LICENSE"
    )
    license_header = license_text.replace("\n", "\n        ")
    headers = [
        "Metadata-Version: 2.4",
        f"Name: {DISTRIBUTION}",
        f"Version: {version}",
        f"Summary: {EXPECTED_SUMMARY}",
        "Author: Mana Alharbi (مانع الحربي)",
        "Maintainer: Mana Alharbi (مانع الحربي)",
        f"License: {license_header}",
        "Project-URL: Repository, https://github.com/EvoRiseKsa/EvoOM-Guard-m",
        "Project-URL: Issues, https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues",
        "Keywords: ai,agents,ci,testing,reward-hacking,patch,verification",
        *(f"Classifier: {classifier}" for classifier in EXPECTED_CLASSIFIERS),
        "Requires-Python: >=3.10",
        "Description-Content-Type: text/markdown",
        *(f"License-File: {document}" for document in GOVERNING_DOCUMENTS),
        "Provides-Extra: sign",
        f"Requires-Dist: {EXPECTED_REQUIRES_DIST[0]}",
        "Provides-Extra: cov",
        f"Requires-Dist: {EXPECTED_REQUIRES_DIST[1]}",
        "Provides-Extra: dev",
        *(f"Requires-Dist: {requirement}" for requirement in EXPECTED_REQUIRES_DIST[2:]),
        "Dynamic: license-file",
    ]
    readme = _canonical_text(_read_stable(staging / "README.md"), where="staged README")
    return ("\n".join(headers) + "\n\n" + readme).encode("utf-8")


def _audit_metadata(
    contents: dict[str, bytes],
    staging: Path,
    dist_info: str,
    version: str,
    locked_setuptools: str,
    *,
    canonical: bool,
) -> None:
    metadata_name = f"{dist_info}/METADATA"
    try:
        metadata = BytesParser(policy=policy.default).parsebytes(contents[metadata_name])
    except Exception as error:  # email defects vary by Python maintenance release.
        _fail(f"wheel METADATA cannot be parsed: {error}")
    exact_headers = {
        "Metadata-Version": "2.4",
        "Name": DISTRIBUTION,
        "Version": version,
        "Summary": EXPECTED_SUMMARY,
        "Requires-Python": ">=3.10",
        "Keywords": "ai,agents,ci,testing,reward-hacking,patch,verification",
    }
    for field, expected in exact_headers.items():
        values = [str(value) for value in metadata.get_all(field, [])]
        if values != [expected]:
            _fail(f"wheel METADATA {field} differs: {values!r} != {[expected]!r}")
    if {str(value) for value in metadata.get_all("License-File", [])} != set(
        GOVERNING_DOCUMENTS
    ):
        _fail("wheel METADATA license-file set differs from governing documents")
    if {str(value) for value in metadata.get_all("Provides-Extra", [])} != {
        "sign",
        "cov",
        "dev",
    }:
        _fail("wheel METADATA optional-extra set differs from pyproject contract")
    if [str(value) for value in metadata.get_all("Dynamic", [])] != ["license-file"]:
        _fail("wheel METADATA dynamic-field declaration differs from the reviewed contract")
    if {str(value) for value in metadata.get_all("Requires-Dist", [])} != set(
        EXPECTED_REQUIRES_DIST
    ):
        _fail("wheel METADATA dependency set differs from pyproject contract")
    if [str(value) for value in metadata.get_all("Classifier", [])] != list(
        EXPECTED_CLASSIFIERS
    ):
        _fail("wheel METADATA classifier list differs from the reviewed contract")
    exact_multi_headers = {
        "Author": {"Mana Alharbi (مانع الحربي)"},
        "Maintainer": {"Mana Alharbi (مانع الحربي)"},
        "Project-URL": {
            "Repository, https://github.com/EvoRiseKsa/EvoOM-Guard-m",
            "Issues, https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues",
        },
        "Description-Content-Type": {"text/markdown"},
    }
    for field, expected_values in exact_multi_headers.items():
        if {str(value) for value in metadata.get_all(field, [])} != expected_values:
            _fail(f"wheel METADATA {field} differs from the reviewed contract")
    license_header = metadata.get("License")
    if license_header is None or " ".join(str(license_header).split()) != " ".join(
        _read_stable(staging / "LICENSE").decode("utf-8").split()
    ):
        _fail("wheel METADATA embedded license differs from staged LICENSE")
    readme = _canonical_text(_read_stable(staging / "README.md"), where="staged README")
    # ``email``'s compatibility parser replaces non-ASCII payload characters
    # when the message has no MIME charset.  Core metadata is UTF-8, so compare
    # its raw body bytes instead of accepting that lossy decoding.
    raw_metadata = contents[metadata_name]
    expected_metadata = _expected_core_metadata(staging, version)
    backend_metadata_variants = {
        expected_metadata,
        expected_metadata.replace(b"\n", b"\r\n"),
    }
    if raw_metadata not in backend_metadata_variants:
        _fail("wheel METADATA bytes or closed header fields differ from the reviewed contract")
    normalized_metadata = raw_metadata.replace(b"\r\n", b"\n")
    separator = b"\n\n"
    if normalized_metadata.count(separator) < 1:
        _fail("wheel METADATA has no canonical header/body separator")
    description = normalized_metadata.split(separator, 1)[1].decode("utf-8")
    if description != readme:
        _fail("wheel METADATA long description is not the exact staged README")
    if canonical and raw_metadata != expected_metadata:
        _fail("wheel METADATA is valid but not canonically LF-encoded")
    if contents[f"{dist_info}/WHEEL"] != _expected_wheel_metadata(locked_setuptools):
        _fail("wheel WHEEL metadata does not bind the locked setuptools backend")
    if contents[f"{dist_info}/entry_points.txt"] != (
        b"[console_scripts]\nevo-guard = evoom_guard.cli:main\n"
    ):
        _fail("wheel console entry point differs from the reviewed contract")
    if contents[f"{dist_info}/top_level.txt"] != b"evoom_guard\n":
        _fail("wheel top-level package declaration differs from the reviewed contract")


def audit_wheel(
    wheel: Path,
    staging: Path,
    locked_setuptools: str,
    *,
    canonical: bool,
) -> dict[str, bytes]:
    """Audit *wheel* against exact staged source and package metadata."""
    raw_wheel, wheel_identity = _require_zip_eof(wheel)
    version = _source_version(staging / PACKAGE)
    dist_info = f"{WHEEL_DISTRIBUTION}-{version}.dist-info"
    record_name = f"{dist_info}/RECORD"
    expected_payload = _payload_snapshot(staging)
    expected_names = set(expected_payload)
    expected_names.update(f"{dist_info}/{relative}" for relative in DIST_INFO_FILES)

    with zipfile.ZipFile(io.BytesIO(raw_wheel)) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_MEMBERS:
            _fail(f"wheel contains too many members: {len(infos)}")
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            _fail("wheel contains duplicate member names")
        for name in names:
            _safe_wheel_name(name)
        if set(names) != expected_names:
            missing = sorted(expected_names - set(names))
            extra = sorted(set(names) - expected_names)
            _fail(f"wheel member set differs from staging: missing={missing}, extra={extra}")
        if archive.comment:
            _fail("wheel ZIP comment must be empty")
        total = 0
        for info in infos:
            if info.is_dir() or info.file_size > MAX_MEMBER_BYTES:
                _fail(f"wheel member is a directory or too large: {info.filename}")
            total += info.file_size
            mode = (info.external_attr >> 16) & 0xFFFF
            if mode and not stat.S_ISREG(mode):
                _fail(f"wheel member is not a regular file: {info.filename}")
            if canonical:
                if info.date_time != ZIP_TIMESTAMP:
                    _fail(f"wheel timestamp is not canonical: {info.filename}")
                if info.create_system != 3 or mode != 0o100644:
                    _fail(f"wheel creator/mode is not canonical: {info.filename}")
                if info.compress_type != zipfile.ZIP_STORED:
                    _fail(f"wheel compression is not canonical: {info.filename}")
                if info.extra or info.comment:
                    _fail(f"wheel member metadata is not empty: {info.filename}")
        if total > MAX_TOTAL_BYTES:
            _fail(f"wheel uncompressed payload is too large: {total}")
        # Only read or inflate member bodies after their declared sizes and the
        # aggregate archive budget have been bounded.
        if archive.testzip() is not None:
            _fail("wheel member CRC validation failed")
        contents = {name: archive.read(name) for name in names}

    # Authenticate the archive's own integrity index before comparing it with
    # trusted staging.  This makes stale-RECORD corruption an explicit failure
    # instead of merely reporting the later source-binding mismatch.
    _verify_record(contents, record_name, canonical=canonical)
    for name, expected_bytes in expected_payload.items():
        if contents[name] != expected_bytes:
            _fail(f"wheel package member differs from staged source: {name}")
    for document in GOVERNING_DOCUMENTS:
        name = f"{dist_info}/licenses/{document}"
        if contents[name] != _read_stable(staging / document):
            _fail(f"wheel governing document differs from staging: {document}")
    _audit_metadata(
        contents,
        staging,
        dist_info,
        version,
        locked_setuptools,
        canonical=canonical,
    )
    if canonical and names != sorted(names):
        _fail("wheel members are not in canonical order")
    if canonical and raw_wheel != _canonical_zip_bytes(contents):
        _fail("wheel raw ZIP bytes are not the canonical encoding")
    _confirm_stable_snapshot(wheel, raw_wheel, wheel_identity)
    return contents


def _resolver_disabled_environment() -> dict[str, str]:
    # Start from a portable allowlist instead of attempting to enumerate every
    # Python, pip, setuptools, home-directory, and PEP 517 injection variable.
    # HOME/USERPROFILE/APPDATA/LOCALAPPDATA are deliberately absent: an
    # otherwise isolated pip parent launches a fresh backend child, and that
    # child must not discover a caller-controlled user-site ``sitecustomize``.
    environment = {
        name: value
        for name, value in os.environ.items()
        if name.upper() in SYSTEM_ENVIRONMENT_ALLOWLIST
    }
    environment.update(
        {
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_CACHE_DIR": "1",
            "PIP_NO_INDEX": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "PYTHONUTF8": "1",
            "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
        }
    )
    return environment


def _run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=_resolver_disabled_environment(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
        check=False,
    )


def _build_raw_wheel(staging: Path, destination: Path) -> Path:
    destination.mkdir()
    completed = _run(
        [
            sys.executable,
            "-I",
            "-m",
            "pip",
            "--isolated",
            "wheel",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "--no-deps",
            "--no-build-isolation",
            "--no-index",
            "--wheel-dir",
            str(destination),
            str(staging),
        ],
        cwd=staging,
    )
    if completed.returncode != 0:
        _fail(
            "index-disabled wheel build failed\n"
            f"stdout={completed.stdout}\nstderr={completed.stderr}"
        )
    wheels = list(destination.glob("*.whl"))
    if len(wheels) != 1:
        _fail(f"index-disabled build produced {len(wheels)} wheels instead of one")
    return wheels[0]


def _canonicalize(
    raw_wheel: Path,
    output: Path,
    staging: Path,
    locked_setuptools: str,
) -> None:
    # Reject a backend-produced stale RECORD or unexpected payload before any
    # canonical rewrite could accidentally legitimize it.
    contents = audit_wheel(raw_wheel, staging, locked_setuptools, canonical=False)
    version = _source_version(staging / PACKAGE)
    metadata_name = f"{WHEEL_DISTRIBUTION}-{version}.dist-info/METADATA"
    record_name = f"{WHEEL_DISTRIBUTION}-{version}.dist-info/RECORD"
    # setuptools 83 serializes Core Metadata with the host platform's email
    # line separator.  Preserve the strict closed-field audit above, then emit
    # one LF-only representation so Linux and Windows builds are byte-identical.
    contents[metadata_name] = _expected_core_metadata(staging, version)
    without_record = {name: data for name, data in contents.items() if name != record_name}
    contents[record_name] = _canonical_record(without_record, record_name)

    with output.open("xb") as raw:
        raw.write(_canonical_zip_bytes(contents))
    audit_wheel(output, staging, locked_setuptools, canonical=True)


def _build_once(root: Path, work: Path) -> Path:
    work.mkdir()
    staging = work / "staging"
    version, locked = _stage(root, staging)
    raw_wheel = _build_raw_wheel(staging, work / "raw")
    output = work / f"{WHEEL_DISTRIBUTION}-{version}-py3-none-any.whl"
    _canonicalize(raw_wheel, output, staging, locked)
    return output


def build(
    output_dir: Path,
    *,
    root: Path = ROOT,
    reproducibility_check: bool = False,
) -> Path:
    """Build the complete distribution wheel and return its final path."""
    root = root.resolve()
    _require_locked_backend(root)
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="evoguard-distribution-build-") as temporary:
        temporary_root = Path(temporary)
        first = _build_once(root, temporary_root / "first")
        if reproducibility_check:
            second = _build_once(root, temporary_root / "second")
            if _read_stable(first) != _read_stable(second):
                _fail("independent canonical wheel builds are not byte-identical")
        final = output_dir / first.name
        if final.exists() or final.is_symlink():
            _regular_file_metadata(final)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{first.name}.", suffix=".tmp", dir=output_dir
        )
        os.close(descriptor)
        temporary_output = Path(temporary_name)
        try:
            temporary_output.write_bytes(_read_stable(first))
            os.replace(temporary_output, final)
        finally:
            try:
                temporary_output.unlink()
            except FileNotFoundError:
                pass
    audit(final, root=root)
    return final


def audit(wheel: Path, *, root: Path = ROOT) -> None:
    """Audit an existing canonical wheel against current complete source."""
    root = root.resolve()
    wheel = wheel.absolute()
    _regular_file_metadata(wheel)
    with tempfile.TemporaryDirectory(prefix="evoguard-distribution-audit-") as temporary:
        staging = Path(temporary) / "staging"
        _version, locked = _stage(root, staging)
        audit_wheel(wheel, staging, locked, canonical=True)


def verify(wheel: Path, *, root: Path = ROOT) -> None:
    """Install *wheel* with pip index resolution disabled and smoke the real CLI."""
    wheel = wheel.absolute()
    _regular_file_metadata(wheel)
    version = _source_version(root / PACKAGE)
    with tempfile.TemporaryDirectory(prefix="evoguard-distribution-verify-") as temporary:
        work = Path(temporary)
        environment = work / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        binaries = environment / ("Scripts" if os.name == "nt" else "bin")
        python = binaries / ("python.exe" if os.name == "nt" else "python")
        neutral = work / "neutral"
        neutral.mkdir()
        installed = _run(
            [
                str(python),
                "-I",
                "-m",
                "pip",
                "--isolated",
                "install",
                "--disable-pip-version-check",
                "--no-cache-dir",
                "--no-deps",
                "--no-index",
                str(wheel),
            ],
            cwd=neutral,
        )
        if installed.returncode != 0:
            _fail(
                "index-disabled clean-wheel install failed\n"
                f"stdout={installed.stdout}\nstderr={installed.stderr}"
            )
        imported = _run(
            [
                str(python),
                "-I",
                "-c",
                (
                    "import importlib.util, evoom_guard, evoom_guard.cli, "
                    "evoom_guard.guard; import importlib.metadata as metadata; "
                    f"assert evoom_guard.__version__ == {version!r}; "
                    f"assert metadata.version('evoom-guard') == {version!r}; "
                    "assert importlib.util.find_spec('pytest') is None; "
                    "assert not any(d.metadata['Name'] == 'evoom-guard-core' "
                    "for d in metadata.distributions())"
                ),
            ],
            cwd=neutral,
        )
        if imported.returncode != 0:
            _fail(
                "clean-wheel import smoke failed or acquired pytest\n"
                f"stdout={imported.stdout}\nstderr={imported.stderr}"
            )
        for subcommand, expected in (
            ("version", f"evo-guard {version}"),
            ("doctor", None),
        ):
            # Exercise the installed console target through its supported
            # module entry point.  Some Windows application-control policies
            # reject launchers generated inside a temporary venv even though
            # the installed Python code is trusted; the wheel audit above
            # separately binds the console-script declaration itself.
            command = [str(python), "-I", "-m", "evoom_guard.cli", subcommand]
            completed = _run(command, cwd=neutral)
            if completed.returncode != 0 or (
                expected is not None and expected not in completed.stdout
            ):
                _fail(
                    f"clean-wheel CLI smoke failed: {command[-1]}\n"
                    f"stdout={completed.stdout}\nstderr={completed.stderr}"
                )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "dist" / "distribution",
        help="wheel output directory (default: dist/distribution)",
    )
    parser.add_argument(
        "--audit",
        type=Path,
        metavar="WHEEL",
        help="audit an existing canonical wheel instead of building",
    )
    parser.add_argument(
        "--reproducibility-check",
        action="store_true",
        help="build twice from separate staging trees and require byte identity",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="install with pip index resolution disabled and run clean smoke checks",
    )
    args = parser.parse_args(argv)

    if args.audit is not None:
        audit(args.audit)
        if args.verify:
            verify(args.audit)
        print(f"single distribution audited: {args.audit.resolve()}")
        return 0
    wheel = build(args.output_dir, reproducibility_check=args.reproducibility_check)
    if args.verify:
        verify(wheel)
    print(f"single distribution built and audited: {wheel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
