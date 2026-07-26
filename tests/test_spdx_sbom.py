"""Deterministic SPDX 2.3 release-inventory and input-hardening tests."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import struct
import subprocess
import sys
import zipfile
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import jsonschema
import pytest

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "tests" / "schema" / "spdx-2.3.schema.json"
SCHEMA_LICENSE = ROOT / "tests" / "schema" / "SPDX-2.3-SCHEMA-LICENSE.txt"
SCHEMA_NOTICE = ROOT / "tests" / "schema" / "SPDX-2.3-SCHEMA-NOTICE.md"
GENERATOR = ROOT / "ops" / "generate_spdx_sbom.py"
BUILDER = ROOT / "ops" / "build_pyz.py"
CREATED = "2026-07-24T12:34:56+03:00"
NORMALIZED_CREATED = "2026-07-24T09:34:56Z"


def _git_blob_sha1(content: bytes) -> str:
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content).hexdigest()


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate_spdx_sbom", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generator() -> ModuleType:
    return _load_generator()


@pytest.fixture()
def release_pyz(tmp_path: Path) -> Path:
    output = tmp_path / "evo-guard.pyz"
    subprocess.run(
        [sys.executable, "-I", str(BUILDER), "-o", str(output)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return output


def _generate(
    generator: ModuleType,
    pyz: Path,
    output: Path,
    *,
    version: str = "4.4.0",
    created: str = CREATED,
) -> Path:
    generated = generator.generate(
        str(pyz),
        output_path=str(output),
        version=version,
        created=created,
    )
    assert generated == str(output.resolve())
    return output


def _write_zip(
    path: Path,
    entries: list[tuple[zipfile.ZipInfo | str, bytes]],
    *,
    compression: int = zipfile.ZIP_STORED,
) -> None:
    path.write_bytes(b"#!/usr/bin/env python3\n")
    with zipfile.ZipFile(path, mode="a", compression=compression) as archive:
        for entry, content in entries:
            if isinstance(entry, str):
                info = zipfile.ZipInfo(entry, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.compress_type = compression
            else:
                info = entry
            archive.writestr(info, content)


def _canonical_entries() -> list[tuple[str, bytes]]:
    return [
        ("LICENSE", b"test license\n"),
        ("__main__.py", b"raise SystemExit(0)\n"),
        ("evoom_guard/__init__.py", b'__version__ = "test"\n'),
    ]


def test_vendored_official_schema_has_exact_upstream_identity() -> None:
    schema = SCHEMA.read_bytes()
    license_text = SCHEMA_LICENSE.read_bytes()
    notice = SCHEMA_NOTICE.read_text(encoding="utf-8")
    assert len(schema) == 45_312
    assert _git_blob_sha1(schema) == "ee61e6686e885f8139c132647fd0b4f483b8fb81"
    assert len(license_text) == 18_508
    assert _git_blob_sha1(license_text) == "44a22d370bba8d13c7dd7449d71b40ea8842788e"
    assert "aadf3b0b8dbbabdb4d880b0fc714255fea436ff7" in notice
    assert "f7f7bce5511a23fe3c9d8a1edca0d870a7d0bea5" in notice
    assert json.loads(schema)["title"] == "SPDX 2.3"


def test_generated_sbom_is_schema_valid_deterministic_and_complete(
    generator: ModuleType,
    release_pyz: Path,
    tmp_path: Path,
) -> None:
    first = _generate(generator, release_pyz, tmp_path / "first.spdx.json")
    second = _generate(generator, release_pyz, tmp_path / "second.spdx.json")
    assert first.read_bytes() == second.read_bytes()
    later = _generate(
        generator,
        release_pyz,
        tmp_path / "later.spdx.json",
        created="2026-07-24T09:34:57Z",
    )
    assert later.read_bytes() != first.read_bytes()

    document = json.loads(first.read_bytes())
    later_document = json.loads(later.read_bytes())
    assert first.read_bytes() == (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    assert later_document["documentNamespace"] != document["documentNamespace"]
    jsonschema.Draft7Validator(
        json.loads(SCHEMA.read_text(encoding="utf-8"))
    ).validate(document)
    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["creationInfo"]["created"] == NORMALIZED_CREATED
    assert document["documentDescribes"] == ["SPDXRef-Package-evoom-guard"]
    assert len(document["packages"]) == 1
    package = document["packages"][0]
    assert package["name"] == "evo-guard"
    assert package["versionInfo"] == "4.4.0"
    assert package["filesAnalyzed"] is True

    with zipfile.ZipFile(release_pyz) as archive:
        infos = sorted(archive.infolist(), key=lambda info: info.filename)
        contents = {info.filename: archive.read(info) for info in infos}
    assert [entry["fileName"] for entry in document["files"]] == [
        f"./{info.filename}" for info in infos
    ]
    assert document["hasExtractedLicensingInfos"] == [
        {
            "extractedText": contents["LICENSE"].decode("utf-8"),
            "licenseId": "LicenseRef-EvoRise-Source-Available-1.0",
            "name": "EvoRise Source-Available License 1.0",
        }
    ]

    file_sha1: list[str] = []
    file_ids: list[str] = []
    for entry in document["files"]:
        name = entry["fileName"][2:]
        checksums = {
            checksum["algorithm"]: checksum["checksumValue"]
            for checksum in entry["checksums"]
        }
        assert checksums == {
            "SHA1": hashlib.sha1(contents[name]).hexdigest(),
            "SHA256": hashlib.sha256(contents[name]).hexdigest(),
        }
        file_sha1.append(checksums["SHA1"])
        file_ids.append(entry["SPDXID"])
    expected_verification_code = hashlib.sha1(
        "".join(sorted(file_sha1)).encode("ascii")
    ).hexdigest()
    assert package["packageVerificationCode"] == {
        "packageVerificationCodeValue": expected_verification_code
    }

    relationships = document["relationships"]
    assert relationships[0] == {
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relatedSpdxElement": "SPDXRef-Package-evoom-guard",
        "relationshipType": "DESCRIBES",
    }
    assert relationships[1:] == [
        {
            "spdxElementId": "SPDXRef-Package-evoom-guard",
            "relatedSpdxElement": spdx_id,
            "relationshipType": "CONTAINS",
        }
        for spdx_id in file_ids
    ]


def test_cli_generates_strict_json(generator: ModuleType, release_pyz: Path, tmp_path: Path) -> None:
    del generator
    output = tmp_path / "evo-guard.spdx.json"
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(GENERATOR),
            str(release_pyz),
            "--version",
            "4.4.0",
            "--created",
            "2026-07-24T09:34:56Z",
            "--output",
            str(output),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.stdout.strip() == f"built {output.resolve()}"
    assert b"NaN" not in output.read_bytes()


def test_rejects_noncanonical_version_and_naive_timestamp(
    generator: ModuleType,
    release_pyz: Path,
    tmp_path: Path,
) -> None:
    with pytest.raises(generator.SbomGenerationError, match="canonical"):
        _generate(
            generator,
            release_pyz,
            tmp_path / "version.json",
            version="v4.4.0",
        )
    with pytest.raises(generator.SbomGenerationError, match="explicit UTC offset"):
        _generate(
            generator,
            release_pyz,
            tmp_path / "time.json",
            created="2026-07-24T09:34:56",
        )


def _unsafe_entry(
    name: str,
    *,
    mode: int = stat.S_IFREG | 0o644,
    compression: int = zipfile.ZIP_STORED,
    extra: bytes = b"",
) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = mode << 16
    info.compress_type = compression
    info.extra = extra
    return info


def _backslash_entry() -> zipfile.ZipInfo:
    # ZipInfo normalizes the host separator in its constructor on Windows.
    # Set the stored name afterwards to exercise the parser's portable-name
    # rejection rather than the test helper's normalization.
    info = _unsafe_entry("placeholder")
    info.filename = "evoom_guard\\escape.py"
    return info


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda entries: [*entries, ("../escape.py", b"x")],
            "unsafe ZIP member path",
        ),
        (
            lambda entries: [*entries, (_backslash_entry(), b"x")],
            "unsafe ZIP member name|local ZIP name mismatch",
        ),
        (
            lambda entries: [
                *entries,
                (_unsafe_entry("link", mode=stat.S_IFLNK | 0o777), b"LICENSE"),
            ],
            "not a canonical regular file",
        ),
        (
            lambda entries: [
                *entries,
                (_unsafe_entry("pipe", mode=stat.S_IFIFO | 0o644), b""),
            ],
            "not a canonical regular file",
        ),
        (
            lambda entries: [
                *entries,
                (_unsafe_entry("executable", mode=stat.S_IFREG | 0o755), b"x"),
            ],
            "not a canonical regular file",
        ),
        (
            lambda entries: [
                *entries,
                (_unsafe_entry("extra", extra=b"\x01\x00\x00\x00"), b"x"),
            ],
            "extras/comments",
        ),
        (
            lambda entries: [
                *entries,
                (
                    _unsafe_entry(
                        "deflated",
                        compression=zipfile.ZIP_DEFLATED,
                    ),
                    b"x" * 1024,
                ),
            ],
            "unsupported ZIP compression",
        ),
        (
            lambda entries: [
                *entries,
                (
                    _unsafe_entry(
                        "compressed",
                        compression=zipfile.ZIP_BZIP2,
                    ),
                    b"x",
                ),
            ],
            "unsupported ZIP compression",
        ),
        (
            lambda entries: [*entries, ("Case.py", b"x"), ("case.py", b"y")],
            "duplicate portable ZIP member",
        ),
    ],
)
def test_unsafe_zip_entries_fail_before_output_replacement(
    generator: ModuleType,
    tmp_path: Path,
    mutate: Callable[
        [list[tuple[str | zipfile.ZipInfo, bytes]]],
        list[tuple[str | zipfile.ZipInfo, bytes]],
    ],
    message: str,
) -> None:
    archive = tmp_path / "unsafe.pyz"
    _write_zip(archive, mutate(list(_canonical_entries())))
    output = tmp_path / "evo-guard.spdx.json"
    output.write_bytes(b"keep-existing-output")
    with pytest.raises(generator.SbomGenerationError, match=message):
        _generate(generator, archive, output)
    assert output.read_bytes() == b"keep-existing-output"
    assert not list(tmp_path.glob(".evo-guard.spdx.json.*.tmp"))


def test_duplicate_exact_zip_member_is_rejected(
    generator: ModuleType,
    tmp_path: Path,
) -> None:
    archive = tmp_path / "duplicate.pyz"
    with pytest.warns(UserWarning, match="Duplicate name"):
        _write_zip(
            archive,
            [*_canonical_entries(), ("LICENSE", b"different")],
        )
    with pytest.raises(generator.SbomGenerationError, match="duplicate portable"):
        _generate(generator, archive, tmp_path / "sbom.json")


def test_stored_member_size_mismatch_is_rejected_before_read(
    generator: ModuleType,
    tmp_path: Path,
) -> None:
    archive = tmp_path / "stored-size-mismatch.pyz"
    _write_zip(archive, list(_canonical_entries()))
    forged = bytearray(archive.read_bytes())
    local_header = forged.index(b"PK\x03\x04")
    central_header = forged.index(b"PK\x01\x02")
    struct.pack_into("<L", forged, local_header + 22, 1)
    struct.pack_into("<L", forged, central_header + 24, 1)
    archive.write_bytes(forged)

    output = tmp_path / "evo-guard.spdx.json"
    output.write_bytes(b"keep-existing-output")
    with pytest.raises(
        generator.SbomGenerationError,
        match="stored ZIP member size mismatch",
    ):
        _generate(generator, archive, output)
    assert output.read_bytes() == b"keep-existing-output"
    assert not list(tmp_path.glob(".evo-guard.spdx.json.*.tmp"))


def test_trailing_bytes_and_archive_comment_are_rejected(
    generator: ModuleType,
    tmp_path: Path,
) -> None:
    trailing = tmp_path / "trailing.pyz"
    _write_zip(trailing, list(_canonical_entries()))
    trailing.write_bytes(trailing.read_bytes() + b"unbound-trailer")
    with pytest.raises(generator.SbomGenerationError, match="must end"):
        _generate(generator, trailing, tmp_path / "trailing.json")

    commented = tmp_path / "commented.pyz"
    _write_zip(commented, list(_canonical_entries()))
    with zipfile.ZipFile(commented, "a") as archive:
        archive.comment = b"ambiguous-comment"
    with pytest.raises(generator.SbomGenerationError, match="comments|must end"):
        _generate(generator, commented, tmp_path / "commented.json")


def test_non_finite_internal_value_cannot_replace_existing_output(
    generator: ModuleType,
    release_pyz: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "evo-guard.spdx.json"
    output.write_bytes(b"previous")
    monkeypatch.setattr(generator, "_document", lambda **_kwargs: {"value": float("nan")})
    with pytest.raises(generator.SbomGenerationError, match="strict JSON"):
        _generate(generator, release_pyz, output)
    assert output.read_bytes() == b"previous"
    assert not list(tmp_path.glob(".evo-guard.spdx.json.*.tmp"))


def test_input_and_output_must_not_alias(
    generator: ModuleType,
    release_pyz: Path,
) -> None:
    original = release_pyz.read_bytes()
    with pytest.raises(generator.SbomGenerationError, match="alias"):
        _generate(generator, release_pyz, release_pyz)
    assert release_pyz.read_bytes() == original


def test_input_symlink_is_rejected(
    generator: ModuleType,
    release_pyz: Path,
    tmp_path: Path,
) -> None:
    link = tmp_path / "linked.pyz"
    try:
        link.symlink_to(release_pyz)
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation is not available")
    with pytest.raises(generator.SbomGenerationError, match="real regular file"):
        _generate(generator, link, tmp_path / "sbom.json")
