#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Generate the deterministic external SPDX 2.3 inventory for a release zipapp.

The generator is deliberately stdlib-only.  It inventories the exact regular
files contained in one already-built ``evo-guard.pyz``; it does not inspect a
source checkout, resolve dependencies, scan vulnerabilities, or claim that
license conclusions have been reviewed.

Example::

    python -I ops/generate_spdx_sbom.py dist/evo-guard.pyz \
      --version 4.4.0 \
      --created 2026-07-24T12:34:56+00:00 \
      --output dist/evo-guard.spdx.json

``--created`` is normally the release commit time.  It is normalized to whole
UTC seconds so the same artifact, version, and commit time produce identical
bytes.  Output is written through a same-directory temporary regular file and
atomically replaced only after serialization and ``fsync`` complete.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
import re
import stat
import struct
import tempfile
import unicodedata
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

_DOCUMENT_ID = "SPDXRef-DOCUMENT"
_PACKAGE_ID = "SPDXRef-Package-evoom-guard"
_LICENSE_ID = "LicenseRef-EvoRise-Source-Available-1.0"
_REPOSITORY = "https://github.com/EvoRiseKsa/EvoOM-Guard-m"
_ZIPAPP_SHEBANG = b"#!/usr/bin/env python3\n"
_VERSION_RE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
_MAX_MEMBER_BYTES = 32 * 1024 * 1024
_MAX_TOTAL_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
_MAX_MEMBERS = 10_000
_LOCAL_FILE_HEADER = struct.Struct("<4s5H3L2H")
_LOCAL_FILE_MAGIC = b"PK\x03\x04"
_END_OF_CENTRAL_DIRECTORY = struct.Struct("<4s4H2LH")
_END_OF_CENTRAL_DIRECTORY_MAGIC = b"PK\x05\x06"
_ALLOWED_COMPRESSIONS = frozenset({zipfile.ZIP_STORED})


class SbomGenerationError(ValueError):
    """The input cannot produce one unambiguous release SBOM."""


@dataclass(frozen=True)
class _Member:
    name: str
    spdx_id: str
    sha1: str
    sha256: str
    content: bytes


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _regular_file_metadata(path: str) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise SbomGenerationError(f"cannot inspect regular file: {path!r}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(metadata)
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise SbomGenerationError(f"path must be a real regular file: {path!r}")
    return metadata


def _real_directory_metadata(path: str) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise SbomGenerationError(f"cannot inspect output directory: {path!r}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise SbomGenerationError(f"output parent must be a real directory: {path!r}")
    return metadata


def _same_file(
    left: os.stat_result,
    right: os.stat_result,
    *,
    include_ctime: bool = True,
) -> bool:
    identity = (
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
    return identity and (
        not include_ctime or left.st_ctime_ns == right.st_ctime_ns
    )


def _read_stable_archive(path: str) -> bytes:
    before = _regular_file_metadata(path)
    if before.st_size > _MAX_ARCHIVE_BYTES:
        raise SbomGenerationError("zipapp exceeds the bounded archive size")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SbomGenerationError(f"cannot open zipapp: {path!r}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_file(
            before, opened, include_ctime=False
        ):
            raise SbomGenerationError("zipapp changed while opening")
        chunks: list[bytes] = []
        remaining = _MAX_ARCHIVE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > _MAX_ARCHIVE_BYTES:
            raise SbomGenerationError("zipapp exceeds the bounded archive size")
        after_read = os.fstat(descriptor)
        if not _same_file(opened, after_read):
            raise SbomGenerationError("zipapp changed while reading")
    finally:
        os.close(descriptor)
    after_close = _regular_file_metadata(path)
    if not _same_file(before, after_close):
        raise SbomGenerationError("zipapp changed during inventory")
    return content


def _validate_member_name(name: str) -> None:
    if (
        not name
        or name.startswith(("/", "\\"))
        or "\\" in name
        or unicodedata.normalize("NFC", name) != name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise SbomGenerationError(f"unsafe ZIP member name: {name!r}")
    parts = name.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise SbomGenerationError(f"unsafe ZIP member path: {name!r}")
    first = PurePosixPath(name).parts[0]
    if ":" in first:
        raise SbomGenerationError(f"drive-qualified ZIP member path: {name!r}")
    try:
        name.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise SbomGenerationError(f"non-UTF-8 ZIP member name: {name!r}") from exc


def _validate_local_record(
    archive: bytes,
    info: zipfile.ZipInfo,
    *,
    central_directory_offset: int,
) -> tuple[int, int]:
    offset = info.header_offset
    header_end = offset + _LOCAL_FILE_HEADER.size
    if offset < len(_ZIPAPP_SHEBANG) or header_end > central_directory_offset:
        raise SbomGenerationError(f"invalid local header offset: {info.filename!r}")
    fields = _LOCAL_FILE_HEADER.unpack(archive[offset:header_end])
    (
        magic,
        _version,
        flags,
        compression,
        _time,
        _date,
        crc,
        compressed_size,
        uncompressed_size,
        name_size,
        extra_size,
    ) = fields
    if magic != _LOCAL_FILE_MAGIC:
        raise SbomGenerationError(f"invalid local ZIP header: {info.filename!r}")
    if flags != info.flag_bits or compression != info.compress_type:
        raise SbomGenerationError(f"local/central ZIP metadata mismatch: {info.filename!r}")
    if (
        crc != info.CRC
        or compressed_size != info.compress_size
        or uncompressed_size != info.file_size
    ):
        raise SbomGenerationError(
            f"local/central ZIP content metadata mismatch: {info.filename!r}"
        )
    name_start = header_end
    name_end = name_start + name_size
    data_start = name_end + extra_size
    data_end = data_start + info.compress_size
    if data_end > central_directory_offset:
        raise SbomGenerationError(f"ZIP member overlaps central directory: {info.filename!r}")
    if extra_size != 0:
        raise SbomGenerationError(f"local ZIP extras are not allowed: {info.filename!r}")
    if archive[name_start:name_end] != info.filename.encode("utf-8"):
        raise SbomGenerationError(f"local ZIP name mismatch: {info.filename!r}")
    return offset, data_end


def _file_spdx_id(name: str) -> str:
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()
    return f"SPDXRef-File-{digest}"


def _validate_end_of_central_directory(
    archive: bytes,
    zipped: zipfile.ZipFile,
    *,
    member_count: int,
) -> None:
    record_size = _END_OF_CENTRAL_DIRECTORY.size
    if len(archive) < record_size:
        raise SbomGenerationError("ZIP end-of-central-directory record is missing")
    record = archive[-record_size:]
    (
        magic,
        disk_number,
        central_directory_disk,
        entries_on_disk,
        total_entries,
        central_directory_size,
        central_directory_offset,
        comment_size,
    ) = _END_OF_CENTRAL_DIRECTORY.unpack(record)
    if magic != _END_OF_CENTRAL_DIRECTORY_MAGIC or comment_size != 0:
        raise SbomGenerationError("ZIP must end at one comment-free central directory")
    if disk_number != 0 or central_directory_disk != 0:
        raise SbomGenerationError("multi-disk ZIP archives are not allowed")
    if entries_on_disk != member_count or total_entries != member_count:
        raise SbomGenerationError("ZIP central-directory member count mismatch")
    end_record_offset = len(archive) - record_size
    if zipped.start_dir + central_directory_size != end_record_offset:
        raise SbomGenerationError("ZIP central-directory size/offset mismatch")
    if central_directory_offset != zipped.start_dir:
        raise SbomGenerationError("ZIP prepended-data boundary is not canonical")


def _inventory(archive: bytes) -> tuple[list[_Member], str]:
    if not archive.startswith(_ZIPAPP_SHEBANG):
        raise SbomGenerationError("input is not the canonical EvoOM Guard zipapp")
    try:
        zipped = zipfile.ZipFile(io.BytesIO(archive), mode="r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise SbomGenerationError("input is not a valid ZIP archive") from exc
    with zipped:
        if zipped.comment:
            raise SbomGenerationError("ZIP archive comments are not allowed")
        infos = zipped.infolist()
        if not infos or len(infos) > _MAX_MEMBERS:
            raise SbomGenerationError("ZIP member count is outside the allowed bounds")
        if getattr(zipped, "start_dir", len(archive)) >= len(archive):
            raise SbomGenerationError("ZIP central directory offset is invalid")
        _validate_end_of_central_directory(
            archive,
            zipped,
            member_count=len(infos),
        )

        members: list[_Member] = []
        exact_names: set[str] = set()
        portable_names: set[str] = set()
        ranges: list[tuple[int, int, str]] = []
        total_uncompressed = 0
        spdx_ids: set[str] = set()
        for info in infos:
            name = info.filename
            _validate_member_name(name)
            portable_name = name.casefold()
            if name in exact_names or portable_name in portable_names:
                raise SbomGenerationError(f"duplicate portable ZIP member: {name!r}")
            exact_names.add(name)
            portable_names.add(portable_name)
            if info.is_dir():
                raise SbomGenerationError(f"directory ZIP entries are not allowed: {name!r}")
            if info.create_system != 3:
                raise SbomGenerationError(f"ZIP entry has no Unix file type: {name!r}")
            mode = info.external_attr >> 16
            if not stat.S_ISREG(mode) or stat.S_IMODE(mode) != 0o644:
                raise SbomGenerationError(
                    f"ZIP entry is not a canonical regular file: {name!r}"
                )
            if info.volume != 0:
                raise SbomGenerationError(f"multi-disk ZIP entry is not allowed: {name!r}")
            if info.flag_bits & 0x1 or info.flag_bits not in {0, 0x800}:
                raise SbomGenerationError(f"unsupported ZIP flags: {name!r}")
            if info.compress_type not in _ALLOWED_COMPRESSIONS:
                raise SbomGenerationError(f"unsupported ZIP compression: {name!r}")
            if info.compress_size != info.file_size:
                raise SbomGenerationError(
                    f"stored ZIP member size mismatch: {name!r}"
                )
            if info.extra or info.comment:
                raise SbomGenerationError(f"ZIP extras/comments are not allowed: {name!r}")
            if info.file_size > _MAX_MEMBER_BYTES:
                raise SbomGenerationError(f"ZIP member exceeds size bound: {name!r}")
            total_uncompressed += info.file_size
            if total_uncompressed > _MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise SbomGenerationError("ZIP uncompressed content exceeds size bound")
            ranges.append(
                (*_validate_local_record(
                    archive,
                    info,
                    central_directory_offset=zipped.start_dir,
                ), name)
            )
            try:
                content = zipped.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                raise SbomGenerationError(f"cannot verify ZIP member: {name!r}") from exc
            if len(content) != info.file_size:
                raise SbomGenerationError(f"ZIP member length mismatch: {name!r}")
            spdx_id = _file_spdx_id(name)
            if spdx_id in spdx_ids:
                raise SbomGenerationError("SPDX file identifier collision")
            spdx_ids.add(spdx_id)
            members.append(
                _Member(
                    name=name,
                    spdx_id=spdx_id,
                    sha1=hashlib.sha1(content).hexdigest(),
                    sha256=hashlib.sha256(content).hexdigest(),
                    content=content,
                )
            )

        previous_end = len(_ZIPAPP_SHEBANG)
        for start, end, name in sorted(ranges):
            if start != previous_end:
                raise SbomGenerationError(f"non-contiguous ZIP member records: {name!r}")
            previous_end = end
        if previous_end != zipped.start_dir:
            raise SbomGenerationError("ZIP content/central-directory boundary mismatch")
        if "__main__.py" not in exact_names:
            raise SbomGenerationError("zipapp is missing __main__.py")
        license_members = [member for member in members if member.name == "LICENSE"]
        if len(license_members) != 1:
            raise SbomGenerationError("zipapp must contain exactly one LICENSE member")
        try:
            license_text = license_members[0].content.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise SbomGenerationError("embedded LICENSE is not UTF-8") from exc
        if not license_text.strip():
            raise SbomGenerationError("embedded LICENSE is empty")
        return sorted(members, key=lambda member: member.name), license_text


def _normalize_created(value: str) -> str:
    candidate = value.strip()
    if candidate.endswith(("Z", "z")):
        candidate = f"{candidate[:-1]}+00:00"
    try:
        parsed = dt.datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise SbomGenerationError("--created must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SbomGenerationError("--created must include an explicit UTC offset")
    normalized = parsed.astimezone(dt.timezone.utc).replace(microsecond=0)
    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def _checksums(*, sha1: str, sha256: str) -> list[dict[str, str]]:
    return [
        {"algorithm": "SHA1", "checksumValue": sha1},
        {"algorithm": "SHA256", "checksumValue": sha256},
    ]


def _document(
    *,
    archive: bytes,
    members: Sequence[_Member],
    license_text: str,
    version: str,
    created: str,
) -> dict[str, Any]:
    artifact_sha1 = hashlib.sha1(archive).hexdigest()
    artifact_sha256 = hashlib.sha256(archive).hexdigest()
    document_identity = hashlib.sha256(
        "\0".join((version, artifact_sha256, created)).encode("utf-8")
    ).hexdigest()
    verification_code = hashlib.sha1(
        "".join(sorted(member.sha1 for member in members)).encode("ascii")
    ).hexdigest()
    file_entries = [
        {
            "SPDXID": member.spdx_id,
            "checksums": _checksums(sha1=member.sha1, sha256=member.sha256),
            "copyrightText": "NOASSERTION",
            "fileName": f"./{member.name}",
            "licenseConcluded": "NOASSERTION",
            "licenseInfoInFiles": ["NOASSERTION"],
        }
        for member in members
    ]
    relationships = [
        {
            "spdxElementId": _DOCUMENT_ID,
            "relatedSpdxElement": _PACKAGE_ID,
            "relationshipType": "DESCRIBES",
        },
        *[
            {
                "spdxElementId": _PACKAGE_ID,
                "relatedSpdxElement": member.spdx_id,
                "relationshipType": "CONTAINS",
            }
            for member in members
        ],
    ]
    return {
        "SPDXID": _DOCUMENT_ID,
        "creationInfo": {
            "created": created,
            "creators": [
                "Organization: EvoRise Tech",
                "Tool: EvoOM Guard deterministic SPDX generator",
            ],
        },
        "dataLicense": "CC0-1.0",
        "documentDescribes": [_PACKAGE_ID],
        "documentNamespace": (
            f"{_REPOSITORY}/spdx/evo-guard/{version}/{document_identity}"
        ),
        "files": file_entries,
        "hasExtractedLicensingInfos": [
            {
                "extractedText": license_text,
                "licenseId": _LICENSE_ID,
                "name": "EvoRise Source-Available License 1.0",
            }
        ],
        "name": f"evo-guard-{version}-release-sbom",
        "packages": [
            {
                "SPDXID": _PACKAGE_ID,
                "checksums": _checksums(sha1=artifact_sha1, sha256=artifact_sha256),
                "copyrightText": "Copyright © 2026 EvoRise Tech. All rights reserved.",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": _LICENSE_ID,
                "name": "evo-guard",
                "packageFileName": "evo-guard.pyz",
                "packageVerificationCode": {
                    "packageVerificationCodeValue": verification_code
                },
                "primaryPackagePurpose": "APPLICATION",
                "supplier": "Organization: EvoRise Tech",
                "versionInfo": version,
            }
        ],
        "relationships": relationships,
        "spdxVersion": "SPDX-2.3",
    }


def _serialize(document: dict[str, Any]) -> bytes:
    try:
        rendered = json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise SbomGenerationError("SBOM is not strict JSON") from exc
    return f"{rendered}\n".encode()


def _atomic_write(path: str, content: bytes, *, input_path: str) -> None:
    output = os.path.abspath(path)
    source = os.path.abspath(input_path)
    if os.path.normcase(output) == os.path.normcase(source):
        raise SbomGenerationError("output must not alias the input zipapp")
    parent = os.path.dirname(output) or os.curdir
    _real_directory_metadata(parent)
    if os.path.lexists(output):
        output_metadata = _regular_file_metadata(output)
        source_metadata = _regular_file_metadata(source)
        if os.path.samestat(output_metadata, source_metadata):
            raise SbomGenerationError("output must not alias the input zipapp")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{os.path.basename(output)}.",
        suffix=".tmp",
        dir=parent,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary_metadata = _regular_file_metadata(temporary)
        if temporary_metadata.st_size != len(content):
            raise SbomGenerationError("temporary SBOM length mismatch")
        os.replace(temporary, output)
        temporary = ""
        if os.name != "nt":
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory = os.open(parent, directory_flags)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except OSError as exc:
        raise SbomGenerationError(f"cannot publish SBOM atomically: {output!r}") from exc
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def generate(
    pyz_path: str,
    *,
    output_path: str,
    version: str,
    created: str,
) -> str:
    """Generate an SPDX document and return the absolute output path."""
    if _VERSION_RE.fullmatch(version) is None:
        raise SbomGenerationError("--version must be canonical MAJOR.MINOR.PATCH")
    archive = _read_stable_archive(os.path.abspath(pyz_path))
    members, license_text = _inventory(archive)
    normalized_created = _normalize_created(created)
    document = _document(
        archive=archive,
        members=members,
        license_text=license_text,
        version=version,
        created=normalized_created,
    )
    serialized = _serialize(document)
    _atomic_write(output_path, serialized, input_path=pyz_path)
    return os.path.abspath(output_path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate the deterministic SPDX 2.3 inventory for evo-guard.pyz."
    )
    parser.add_argument("pyz", help="already-built evo-guard.pyz")
    parser.add_argument(
        "--output",
        "-o",
        default="dist/evo-guard.spdx.json",
        help="external SPDX JSON output",
    )
    parser.add_argument(
        "--version",
        required=True,
        help="canonical release version without the leading v",
    )
    parser.add_argument(
        "--created",
        required=True,
        help="release commit time as an offset-aware ISO 8601 timestamp",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        output = generate(
            args.pyz,
            output_path=args.output,
            version=args.version,
            created=args.created,
        )
    except SbomGenerationError as exc:
        raise SystemExit(f"error: {exc}") from exc
    print(f"built {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
