"""External release protocol; this judge never imports candidate modules."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from typing import cast

import pytest

LAUNCHER = cast(str, os.environ.get("EVOGUARD_EXEC"))
if not LAUNCHER:
    pytest.skip("runs only through the EvoOM Guard candidate launcher", allow_module_level=True)

PYTHON = os.environ.get("EVOGUARD_PYTHON") or sys.executable


def _candidate_shell(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            LAUNCHER,
            "/bin/sh",
            "-ceu",
            textwrap.dedent(script),
            "evoguard-release-judge",
            PYTHON,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=240,
    )


def test_release_zipapp_public_protocol() -> None:
    completed = _candidate_shell(
        """
        work="$(mktemp -d)"
        trap 'rm -rf -- "$work"' EXIT
        "$1" -I ops/build_pyz.py -o "$work/evo-guard.pyz" >/dev/null
        test -s "$work/evo-guard.pyz"
        version="$("$1" -I "$work/evo-guard.pyz" version)"
        printf '%s\\n' "$version"
        doctor_out="$work/doctor.json"
        doctor_err="$work/doctor.err"
        if "$1" -I "$work/evo-guard.pyz" doctor --json \
            >"$doctor_out" 2>"$doctor_err"; then
          exit 1
        else
          doctor_status="$?"
        fi
        test "$doctor_status" -eq 1
        test ! -s "$doctor_err"
        "$1" -I - "$doctor_out" "${version#evo-guard }" <<'PY'
        import json
        import pathlib
        import sys

        def reject_duplicate_keys(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError(f"duplicate JSON key: {key}")
                value[key] = item
            return value

        report = json.loads(
            pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
        release_version = sys.argv[2]
        assert all(
            type(report[key]) is bool for key in ("git", "patch", "supported")
        )
        assert report == {
            "tool": "evoguard",
            "version": release_version,
            "platform": "linux-x86_64",
            "python": "3.12.13",
            "git": False,
            "patch": False,
            "supported": False,
        }
        PY
        """,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.startswith("evo-guard ")


def test_release_assets_are_deterministic_and_bound() -> None:
    completed = _candidate_shell(
        """
        work="$(mktemp -d)"
        trap 'rm -rf -- "$work"' EXIT
        for n in 1 2; do
          "$1" -I ops/build_pyz.py -o "$work/evo-guard-$n.pyz"
        done
        cmp "$work/evo-guard-1.pyz" "$work/evo-guard-2.pyz"
        version="$("$1" -I "$work/evo-guard-1.pyz" version | awk '{print $2}')"
        test -n "$version"
        for n in 1 2; do
          "$1" -I ops/generate_spdx_sbom.py "$work/evo-guard-$n.pyz" \
            --version "$version" --created 2026-01-01T00:00:00Z \
            --output "$work/evo-guard-$n.spdx.json"
        done
        cmp "$work/evo-guard-1.spdx.json" "$work/evo-guard-2.spdx.json"
        VERSION="$version" PYZ="$work/evo-guard-1.pyz" SBOM="$work/evo-guard-1.spdx.json" "$1" -I - <<'PY'
        import ast
        import copy
        import hashlib
        import json
        import os
        import pathlib
        import stat
        import tempfile
        import unicodedata
        import warnings
        import zipfile

        MAX_PYZ_BYTES = 64 * 1024 * 1024
        MAX_SBOM_BYTES = 16 * 1024 * 1024
        MAX_MEMBERS = 4096
        MAX_MEMBER_BYTES = 16 * 1024 * 1024
        MAX_TOTAL_MEMBER_BYTES = 64 * 1024 * 1024
        PACKAGE_ID = "SPDXRef-Package-evoom-guard"
        LICENSE_ID = "LicenseRef-EvoRise-Source-Available-1.0"
        SHEBANG = b"#!/usr/bin/env python3\\n"

        def require(condition, message):
            if not condition:
                raise ValueError(message)

        def reject_duplicate_keys(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError(f"duplicate JSON key: {key}")
                value[key] = item
            return value

        def checksums(items):
            require(isinstance(items, list) and len(items) == 2, "checksum set is not exact")
            value = {}
            for item in items:
                require(isinstance(item, dict), "checksum entry is not an object")
                algorithm = item.get("algorithm")
                require(algorithm in {"SHA1", "SHA256"}, "checksum algorithm is not allowed")
                require(algorithm not in value, "checksum algorithm is duplicated")
                digest = item.get("checksumValue")
                require(isinstance(digest, str), "checksum digest is not text")
                value[algorithm] = digest
            require(set(value) == {"SHA1", "SHA256"}, "checksum algorithms are incomplete")
            return value

        def writes_version(node):
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                targets = [node.target]
            else:
                return False
            return any(
                isinstance(part, ast.Name) and part.id == "__version__"
                for target in targets
                for part in ast.walk(target)
            )

        def verify(pyz_path, sbom_path, expected_version):
            pyz_path = pathlib.Path(pyz_path)
            sbom_path = pathlib.Path(sbom_path)
            require(0 < pyz_path.stat().st_size <= MAX_PYZ_BYTES, "PYZ size is outside bounds")
            require(0 < sbom_path.stat().st_size <= MAX_SBOM_BYTES, "SBOM size is outside bounds")
            sbom = json.loads(
                sbom_path.read_text(encoding="utf-8"),
                object_pairs_hook=reject_duplicate_keys,
            )
            require(isinstance(sbom, dict), "SBOM root is not an object")
            require(set(sbom) == {
                "SPDXID", "creationInfo", "dataLicense", "documentDescribes",
                "documentNamespace", "files", "hasExtractedLicensingInfos",
                "name", "packages", "relationships", "spdxVersion",
            }, "SPDX document fields are not exact")
            require(sbom.get("SPDXID") == "SPDXRef-DOCUMENT", "document SPDXID is wrong")
            require(sbom.get("spdxVersion") == "SPDX-2.3", "SPDX version is wrong")
            require(sbom.get("dataLicense") == "CC0-1.0", "SPDX dataLicense is wrong")
            require(sbom.get("name") == f"evo-guard-{expected_version}-release-sbom", "document name is wrong")
            created = "2026-01-01T00:00:00Z"
            require(sbom.get("creationInfo") == {
                "created": created,
                "creators": [
                    "Organization: EvoRise Tech",
                    "Tool: EvoOM Guard deterministic SPDX generator",
                ],
            }, "SPDX creationInfo is not exact")
            require(sbom.get("documentDescribes") == [PACKAGE_ID], "documentDescribes is wrong")
            packages = sbom.get("packages")
            require(isinstance(packages, list) and len(packages) == 1, "package set is not exact")
            package = packages[0]
            require(isinstance(package, dict), "package is not an object")
            require(set(package) == {
                "SPDXID", "checksums", "copyrightText", "downloadLocation",
                "filesAnalyzed", "licenseConcluded", "licenseDeclared", "name",
                "packageFileName", "packageVerificationCode",
                "primaryPackagePurpose", "supplier", "versionInfo",
            }, "SPDX package fields are not exact")
            require(package.get("SPDXID") == PACKAGE_ID, "package SPDXID is wrong")
            require(package.get("name") == "evo-guard", "package name is wrong")
            require(package.get("versionInfo") == expected_version, "package version is wrong")
            require(package.get("filesAnalyzed") is True, "package files are not analyzed")
            require(package.get("licenseDeclared") == LICENSE_ID, "declared license is wrong")
            require(package.get("licenseConcluded") == "NOASSERTION", "concluded license is wrong")
            require(package.get("packageFileName") == "evo-guard.pyz", "package file name is wrong")
            require(package.get("copyrightText") == "Copyright © 2026 EvoRise Tech. All rights reserved.", "package copyright is wrong")
            require(package.get("downloadLocation") == "NOASSERTION", "package download location is wrong")
            require(package.get("primaryPackagePurpose") == "APPLICATION", "package purpose is wrong")
            require(package.get("supplier") == "Organization: EvoRise Tech", "package supplier is wrong")

            archive_bytes = pyz_path.read_bytes()
            artifact_sha256 = hashlib.sha256(archive_bytes).hexdigest()
            identity = hashlib.sha256(
                "\\0".join((expected_version, artifact_sha256, created)).encode("utf-8")
            ).hexdigest()
            require(
                sbom.get("documentNamespace")
                == f"https://github.com/EvoRiseKsa/EvoOM-Guard-m/spdx/evo-guard/{expected_version}/{identity}",
                "document namespace is wrong",
            )
            require(archive_bytes.startswith(SHEBANG + b"PK\\x03\\x04"), "PYZ preamble is not canonical")
            eocd = archive_bytes.rfind(b"PK\\x05\\x06")
            require(eocd >= 0 and eocd + 22 <= len(archive_bytes), "ZIP EOCD is missing")
            comment_length = int.from_bytes(archive_bytes[eocd + 20:eocd + 22], "little")
            require(eocd + 22 + comment_length == len(archive_bytes), "ZIP has ambiguous trailing bytes")
            require(comment_length == 0, "ZIP comment is not canonical")
            with zipfile.ZipFile(pyz_path) as archive:
                require(archive.comment == b"", "ZIP archive comment is not empty")
                infos = archive.infolist()
                require(0 < len(infos) <= MAX_MEMBERS, "ZIP member count is outside bounds")
                names = [info.filename for info in infos]
                require(names == sorted(names), "ZIP member order is not canonical")
                require(len(names) == len(set(names)), "ZIP member names are duplicated")
                require(all(unicodedata.normalize("NFC", name) == name for name in names), "ZIP member is not NFC")
                require(len({name.casefold() for name in names}) == len(names), "ZIP names are not portable-case unique")
                contents = {}
                total = 0
                for info in infos:
                    name = info.filename
                    path = pathlib.PurePosixPath(name)
                    require(
                        name
                        and not info.is_dir()
                        and "\\\\" not in name
                        and "\\x00" not in name
                        and not name.endswith("/")
                        and not (
                            len(name) >= 2
                            and name[0].isascii()
                            and name[0].isalpha()
                            and name[1] == ":"
                        )
                        and all(
                            ord(character) >= 32
                            and ord(character) != 127
                            and not 0xD800 <= ord(character) <= 0xDFFF
                            for character in name
                        )
                        and not path.is_absolute()
                        and path.as_posix() == name
                        and all(part not in {"", ".", ".."} for part in path.parts),
                        f"unsafe ZIP member name: {name!r}",
                    )
                    require(info.compress_type == zipfile.ZIP_STORED, f"compressed ZIP member: {name}")
                    require(info.compress_size == info.file_size, f"ZIP size ambiguity: {name}")
                    require(info.date_time == (1980, 1, 1, 0, 0, 0), f"ZIP timestamp is not canonical: {name}")
                    require(info.create_system == 3, f"ZIP creator is not canonical: {name}")
                    require(info.external_attr == 0o100644 << 16, f"ZIP mode is not canonical: {name}")
                    require(info.extra == b"" and info.comment == b"", f"ZIP metadata is not empty: {name}")
                    require(0 <= info.file_size <= MAX_MEMBER_BYTES, f"ZIP member too large: {name}")
                    total += info.file_size
                    require(total <= MAX_TOTAL_MEMBER_BYTES, "ZIP expanded size is outside bounds")
                    data = archive.read(info)
                    require(len(data) == info.file_size, f"ZIP member length mismatch: {name}")
                    contents[name] = data

            expected_contents = {
                "__main__.py": b"import sys\\nfrom evoom_guard.cli import main\\n\\nsys.exit(main())\\n",
            }
            for current, directories, files_in_directory in os.walk(
                "evoom_guard", topdown=True, followlinks=False
            ):
                kept_directories = []
                for directory in directories:
                    path = pathlib.Path(current, directory)
                    metadata = path.lstat()
                    require(
                        not stat.S_ISLNK(metadata.st_mode) and stat.S_ISDIR(metadata.st_mode),
                        f"unsafe source directory: {path}",
                    )
                    if directory != "__pycache__":
                        kept_directories.append(directory)
                directories[:] = kept_directories
                for filename in files_in_directory:
                    path = pathlib.Path(current, filename)
                    metadata = path.lstat()
                    require(
                        not stat.S_ISLNK(metadata.st_mode) and stat.S_ISREG(metadata.st_mode),
                        f"unsafe source file: {path}",
                    )
                    if filename.endswith(".pyc"):
                        continue
                    name = path.as_posix()
                    data = path.read_bytes()
                    if name.endswith(".py") or (
                        name.startswith("evoom_guard/schemas/") and name.endswith(".json")
                    ):
                        data = data.replace(b"\\r\\n", b"\\n").replace(b"\\r", b"\\n")
                    expected_contents[name] = data
            license_path = pathlib.Path("LICENSE")
            license_metadata = license_path.lstat()
            require(
                not stat.S_ISLNK(license_metadata.st_mode)
                and stat.S_ISREG(license_metadata.st_mode),
                "LICENSE is not a regular source file",
            )
            expected_contents["LICENSE"] = (
                license_path.read_bytes().replace(b"\\r\\n", b"\\n").replace(b"\\r", b"\\n")
            )
            require(set(contents) == set(expected_contents), "PYZ members do not equal source")
            for name, data in expected_contents.items():
                require(contents[name] == data, f"PYZ member differs from source: {name}")

            files = sbom.get("files")
            require(isinstance(files, list) and len(files) == len(names), "SPDX file set is not exact")
            file_ids = []
            file_sha1 = []
            for entry, name in zip(files, names, strict=True):
                require(isinstance(entry, dict), "SPDX file entry is not an object")
                require(set(entry) == {
                    "SPDXID", "checksums", "copyrightText", "fileName",
                    "licenseConcluded", "licenseInfoInFiles",
                }, f"SPDX file fields are not exact: {name}")
                require(entry.get("fileName") == f"./{name}", f"SPDX fileName is wrong: {name}")
                spdx_id = entry.get("SPDXID")
                require(
                    spdx_id == f"SPDXRef-File-{hashlib.sha256(name.encode('utf-8')).hexdigest()}"
                    and spdx_id not in file_ids,
                    f"SPDX file identifier is invalid: {name}",
                )
                file_ids.append(spdx_id)
                expected = checksums(entry.get("checksums"))
                data = contents[name]
                sha1 = hashlib.sha1(data).hexdigest()
                require(expected["SHA1"] == sha1, f"SHA1 mismatch: {name}")
                require(expected["SHA256"] == hashlib.sha256(data).hexdigest(), f"SHA256 mismatch: {name}")
                require(entry.get("copyrightText") == "NOASSERTION", f"file copyright is wrong: {name}")
                require(entry.get("licenseConcluded") == "NOASSERTION", f"file license is wrong: {name}")
                require(entry.get("licenseInfoInFiles") == ["NOASSERTION"], f"file license info is wrong: {name}")
                file_sha1.append(sha1)

            package_checksums = checksums(package.get("checksums"))
            require(
                package_checksums["SHA1"] == hashlib.sha1(archive_bytes).hexdigest(),
                "package SHA1 does not bind the PYZ",
            )
            require(
                package_checksums["SHA256"] == hashlib.sha256(archive_bytes).hexdigest(),
                "package SHA256 does not bind the PYZ",
            )
            verification_code = hashlib.sha1(
                "".join(sorted(file_sha1)).encode("ascii")
            ).hexdigest()
            require(
                package.get("packageVerificationCode")
                == {"packageVerificationCodeValue": verification_code},
                "package verification code is wrong",
            )
            expected_relationships = [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relatedSpdxElement": PACKAGE_ID,
                    "relationshipType": "DESCRIBES",
                },
                *[
                    {
                        "spdxElementId": PACKAGE_ID,
                        "relatedSpdxElement": spdx_id,
                        "relationshipType": "CONTAINS",
                    }
                    for spdx_id in file_ids
                ],
            ]
            require(sbom.get("relationships") == expected_relationships, "SPDX relationships are not exact")
            extracted = sbom.get("hasExtractedLicensingInfos")
            require(isinstance(extracted, list) and len(extracted) == 1, "extracted license set is not exact")
            require(
                isinstance(extracted[0], dict)
                and set(extracted[0]) == {"extractedText", "licenseId", "name"},
                "extracted license fields are not exact",
            )
            require(extracted[0].get("licenseId") == LICENSE_ID, "extracted license ID is wrong")
            require(
                extracted[0].get("name") == "EvoRise Source-Available License 1.0",
                "extracted license name is wrong",
            )
            require(
                extracted[0].get("extractedText") == contents["LICENSE"].decode("utf-8"),
                "extracted license text does not bind LICENSE",
            )

            version_source = contents["evoom_guard/__init__.py"]
            version_tree = ast.parse(version_source.decode("utf-8"), filename="evoom_guard/__init__.py")
            version_writes = [node for node in ast.walk(version_tree) if writes_version(node)]
            require(len(version_writes) == 1, "release version write is not unique")
            assignment = version_writes[0]
            require(
                isinstance(assignment, ast.Assign)
                and len(assignment.targets) == 1
                and isinstance(assignment.targets[0], ast.Name)
                and isinstance(assignment.value, ast.Constant)
                and isinstance(assignment.value.value, str)
                and assignment.value.value == expected_version,
                "static release version does not match CLI/SPDX",
            )

        def write_json(path, value):
            pathlib.Path(path).write_text(
                json.dumps(value, sort_keys=True, separators=(",", ":")) + "\\n",
                encoding="utf-8",
                newline="\\n",
            )

        def must_reject(label, pyz_path, sbom_path, version):
            try:
                verify(pyz_path, sbom_path, version)
            except (AssertionError, KeyError, TypeError, UnicodeError, ValueError, zipfile.BadZipFile):
                return
            raise AssertionError(f"mutation was accepted: {label}")

        pyz = pathlib.Path(os.environ["PYZ"])
        sbom_path = pathlib.Path(os.environ["SBOM"])
        version = os.environ["VERSION"]
        verify(pyz, sbom_path, version)
        original_sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            bad_version = copy.deepcopy(original_sbom)
            bad_version["packages"][0]["versionInfo"] = "9.9.9"
            write_json(root / "bad-version.json", bad_version)
            must_reject("version", pyz, root / "bad-version.json", version)

            bad_relationship = copy.deepcopy(original_sbom)
            bad_relationship["relationships"].pop()
            write_json(root / "bad-relationship.json", bad_relationship)
            must_reject("relationship", pyz, root / "bad-relationship.json", version)

            bad_verification = copy.deepcopy(original_sbom)
            bad_verification["packages"][0]["packageVerificationCode"] = {
                "packageVerificationCodeValue": "0" * 40
            }
            write_json(root / "bad-verification.json", bad_verification)
            must_reject("verification-code", pyz, root / "bad-verification.json", version)

            with zipfile.ZipFile(pyz) as source:
                source_infos = source.infolist()
                source_contents = [(info.filename, source.read(info)) for info in source_infos]
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with (root / "duplicate.pyz").open("wb") as raw:
                    raw.write(SHEBANG)
                    with zipfile.ZipFile(raw, "w", allowZip64=False) as output:
                        for name, data in source_contents:
                            output.writestr(name, data, compress_type=zipfile.ZIP_STORED)
                        output.writestr(
                            source_contents[0][0],
                            source_contents[0][1],
                            compress_type=zipfile.ZIP_STORED,
                        )
            must_reject("duplicate-member", root / "duplicate.pyz", sbom_path, version)

            with (root / "compressed.pyz").open("wb") as raw:
                raw.write(SHEBANG)
                with zipfile.ZipFile(raw, "w", allowZip64=False) as output:
                    for index, (name, data) in enumerate(source_contents):
                        output.writestr(
                            name,
                            data,
                            compress_type=zipfile.ZIP_DEFLATED if index == 0 else zipfile.ZIP_STORED,
                        )
            must_reject("compressed-member", root / "compressed.pyz", sbom_path, version)

            with (root / "unsafe.pyz").open("wb") as raw:
                raw.write(SHEBANG)
                with zipfile.ZipFile(raw, "w", allowZip64=False) as output:
                    output.writestr("../escape", b"x", compress_type=zipfile.ZIP_STORED)
            must_reject("unsafe-member", root / "unsafe.pyz", sbom_path, version)

            with (root / "drive.pyz").open("wb") as raw:
                raw.write(SHEBANG)
                with zipfile.ZipFile(raw, "w", allowZip64=False) as output:
                    output.writestr("C:/escape", b"x", compress_type=zipfile.ZIP_STORED)
            must_reject("drive-member", root / "drive.pyz", sbom_path, version)

            with (root / "control.pyz").open("wb") as raw:
                raw.write(SHEBANG)
                with zipfile.ZipFile(raw, "w", allowZip64=False) as output:
                    output.writestr("bad\\nname", b"x", compress_type=zipfile.ZIP_STORED)
            must_reject("control-member", root / "control.pyz", sbom_path, version)

            (root / "bad-preamble.pyz").write_bytes(
                b"#!/bin/sh\\n" + pyz.read_bytes()[len(SHEBANG):]
            )
            must_reject("preamble", root / "bad-preamble.pyz", sbom_path, version)

            (root / "trailing.pyz").write_bytes(pyz.read_bytes() + b"x")
            must_reject("trailing-bytes", root / "trailing.pyz", sbom_path, version)
        PY
        """,
    )
    assert completed.returncode == 0, completed.stderr
