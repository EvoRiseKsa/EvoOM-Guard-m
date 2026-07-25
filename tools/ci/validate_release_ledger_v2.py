# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Validate and canonicalize protected release-ledger v2 evidence.

The JSON Schema closes structural ambiguity.  This tool additionally enforces
cross-field bindings that JSON Schema cannot express, verifies every retained
byte, authenticates the RSAE/RAAE envelopes and the detached ledger signature,
and rejects unlisted files or link-like paths.

It deliberately does not collect evidence from GitHub or generate facts.  A
ledger is assembled only after publication from reviewed, retained A-H
evidence.  The ``canonicalize`` command merely serializes an already complete
draft deterministically and refuses to overwrite its output.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import importlib
import importlib.machinery
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import urllib.parse
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = (
    ROOT / "tests" / "baseline" / "schema" / "release-ledger-v2.schema.json"
)
OFFICIAL_SCHEMA_ID = "urn:evoguard:release-ledger:2"
OFFICIAL_SCHEMA_REPOSITORY_PATH = (
    "tests/baseline/schema/release-ledger-v2.schema.json"
)
VALIDATOR_REPOSITORY_PATH = "tools/ci/validate_release_ledger_v2.py"
TRUSTED_BUILD_INPUT_PATHS = {
    "build_pyz_blob_sha": "ops/build_pyz.py",
    "spdx_generator_blob_sha": "ops/generate_spdx_sbom.py",
    "spdx_attestation_verifier_blob_sha": "tools/ci/verify_spdx_attestation.py",
}
LEDGER_NAME = "RELEASE_LEDGER.json"
SIGNATURE_NAME = "RELEASE_LEDGER.json.sig"
README_NAME = "README.md"
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_README_BYTES = 1024 * 1024
MAX_PUBLIC_KEY_BYTES = 64 * 1024
CANONICAL_SIGNATURE_BYTES = 89
MAX_RETAINED_FILES = 64
MAX_RETAINED_FILE_BYTES = 72 * 1024 * 1024
MAX_RETAINED_TOTAL_BYTES = 256 * 1024 * 1024
_READ_CHUNK_BYTES = 1024 * 1024
MAX_TRUSTED_FIRST_PARTY_FILES = 512
MAX_TRUSTED_FIRST_PARTY_FILE_BYTES = 4 * 1024 * 1024
MAX_TRUSTED_FIRST_PARTY_TOTAL_BYTES = 32 * 1024 * 1024
MAX_TRUSTED_FIRST_PARTY_TREE_BYTES = 2 * 1024 * 1024
MAX_TRUSTED_FIRST_PARTY_PATH_BYTES = 1024
MAX_TRUSTED_FIRST_PARTY_PATH_DEPTH = 16
MAX_TRUSTED_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_TRUSTED_DEPENDENCY_FILE_BYTES = 64 * 1024 * 1024
MAX_TRUSTED_DEPENDENCY_TOTAL_BYTES = 256 * 1024 * 1024
_TRUSTED_FIRST_PARTY_PREFIX = "evoom_guard"
_TRUSTED_FIRST_PARTY_MODULES = (
    "evoom_guard.github_attestation",
    "evoom_guard.admission.release_artifact",
    "evoom_guard.admission.release_source",
    "evoom_guard.signing",
)
_TRUSTED_DEPENDENCY_PREFIXES = (
    "cryptography",
    "cffi",
    "_cffi_backend",
    "pycparser",
)
_TRUSTED_SCHEMA_PREFIXES = (
    "jsonschema",
    "jsonschema_specifications",
    "referencing",
    "rpds",
    "attrs",
    "attr",
    "typing_extensions",
)
_TRUSTED_RUNTIME_PREFIXES = (
    *_TRUSTED_DEPENDENCY_PREFIXES,
    *_TRUSTED_SCHEMA_PREFIXES,
)
_TRUSTED_DEPENDENCY_MODULES = (
    "cryptography",
    "cryptography.exceptions",
    "cryptography.hazmat.primitives.serialization",
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    "jsonschema",
    "pycparser",
    "typing_extensions",
)
_FIRST_PARTY_IMPORT_LOCK = threading.RLock()
_TRUSTED_IMPORT_DEPTH = 0
_WINDOWS_RESERVED_PATH_NAMES = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
_CANONICAL_UTC = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z"
)

EXPECTED_REPOSITORY = "EvoRiseKsa/EvoOM-Guard-m"
PHASES = ("A", "B", "C", "D", "E", "F", "G", "H")
ROOT_DOMAINS = (
    "release-source-admission-v2",
    "trusted-finalizer",
    "artifact-admission-v1",
    "artifact-digest-admission-v2",
    "release-source-finalizer-v1",
    "release-artifact-admission-v1",
)
REQUIRED_MAIN_CHECKS = {
    "test (3.10)",
    "test (3.11)",
    "test (3.12)",
    "e2e-runners",
    "blackbox-docker-e2e",
    "smoke",
    "analyze",
    "CodeQL",
    "project-status",
}
EXPECTED_TAG_JOBS = (
    "blackbox-docker-e2e",
    "e2e-runners",
    "project-status",
    "publish-pyz",
    "release-tag-guard",
    "test (3.10)",
    "test (3.11)",
    "test (3.12)",
)
SOURCE_CONTROL_MATERIALS = {
    "source.json",
    "context.json",
    "verdict.json",
    "handoff.json",
    "producer.json",
    "producer-receipt.json",
    "signing-requirements.lock",
    "admitter.json",
    "github-policy.json",
}
ARTIFACT_CONTROL_MATERIALS = {
    "evo-guard.pyz",
    "evo-guard.spdx.json",
    "SHA256SUMS",
    "builder-controls.json",
    "source-allow.rsae",
    "source.json",
    "context.json",
    "producer.json",
    "source-admitter.json",
    "source-github-policy.json",
    "signing-requirements.lock",
    "builder.json",
    "admitter.json",
    "verify_spdx_attestation.py",
    "build-provenance-verification.json",
    "build-provenance-verification-output.json",
    "spdx-provenance-verification.json",
    "spdx-provenance-verification-output.json",
    "sbom-attestation-output.json",
    "sbom-attestation-receipt.json",
}
PUBLICATION_CONTROL_MATERIALS = {
    "evo-guard.pyz.detached-verification.json",
    "evo-guard.spdx.json.detached-verification.json",
    "raae-negative-results.txt",
}
PUBLICATION_READY_MATERIALS = {
    "evo-guard.pyz",
    "evo-guard.spdx.json",
    "SHA256SUMS",
}
SOURCE_NEGATIVE_RESULT = {
    "format": "EVOGUARD_RELEASE_SOURCE_V2_DETACHED_NEGATIVE_V1",
    "mutated_context": "REJECTED",
    "mutated_policy": "REJECTED",
    "mutated_producer": "REJECTED",
    "mutated_source": "REJECTED",
    "tampered_bundle": "REJECTED",
    "wrong_bootstrap_pin": "REJECTED",
    "wrong_gh_pin": "REJECTED",
    "wrong_git_pin": "REJECTED",
    "wrong_provider_gid": "REJECTED",
    "wrong_provider_uid": "REJECTED",
    "wrong_v2_root": "REJECTED",
}
ARTIFACT_NEGATIVE_LINES = (
    "tampered-pyz=REJECTED",
    "tampered-sbom=REJECTED",
    "tampered-bundle=REJECTED",
    "cross-artifact-substitution=REJECTED",
    "wrong-raae-root=REJECTED",
    "wrong-outer-git-pin=REJECTED",
    "wrong-source-gh-pin=REJECTED",
)


class LedgerValidationError(ValueError):
    """A release ledger failed a structural, semantic, or byte-level check."""


@dataclass(frozen=True)
class _TrustedLedgerKey:
    path: Path
    pem: bytes
    key_id: str
    key: Any
    identity: tuple[int, int, int, int, int]


@dataclass(frozen=True)
class _TrustedParentContracts:
    repository: Path
    commit_sha: str
    tree_sha: str
    repository_object: tuple[int, int]
    git: _TrustedExecutable


@dataclass(frozen=True)
class _TrustedExecutable:
    path: Path
    data: bytes
    identity: tuple[int, int, int, int, int]
    search_path: str
    parent_chain: Mapping[Path, tuple[int, int]]


@dataclass(frozen=True)
class _TrustedDependencyFile:
    path: Path
    data: bytes
    identity: tuple[int, int, int, int, int]


@dataclass(frozen=True)
class _TrustedFirstPartyFile:
    blob_sha: str
    sha256: str
    size_bytes: int


def _fail(message: str) -> NoReturn:
    raise LedgerValidationError(message)


def _reject_constant(value: str) -> NoReturn:
    _fail(f"non-finite JSON number is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _is_link_like(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        reparse_flag and attributes & reparse_flag
    )


def _require_plain_directory(path: Path, *, label: str) -> Path:
    """Return an absolute directory path only when no component is link-like."""

    absolute = Path(os.path.abspath(path))
    chain = (absolute, *absolute.parents)
    for current in chain:
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise LedgerValidationError(
                f"cannot inspect {label} component: {current}"
            ) from exc
        if _is_link_like(metadata):
            _fail(f"{label} contains a link-like component: {current}")
        if current == absolute and not stat.S_ISDIR(metadata.st_mode):
            _fail(f"{label} is not a directory: {absolute}")
    return absolute


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _inventory_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int]:
    """Capture path metadata, including change time, for final inventory checks."""

    return (*_identity(metadata), metadata.st_ctime_ns)


def _directory_chain(path: Path, *, label: str) -> dict[Path, tuple[int, int]]:
    """Snapshot every existing directory from ``path`` through the volume root."""

    values: dict[Path, tuple[int, int]] = {}
    for current in (path, *path.parents):
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise LedgerValidationError(
                f"cannot inspect {label} component: {current}"
            ) from exc
        if _is_link_like(metadata) or not stat.S_ISDIR(metadata.st_mode):
            _fail(f"{label} contains a non-directory or link-like component: {current}")
        values[current] = (metadata.st_dev, metadata.st_ino)
    return values


def _require_same_directory_chain(
    expected: Mapping[Path, tuple[int, int]],
    *,
    label: str,
) -> None:
    for path, identity in expected.items():
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise LedgerValidationError(
                f"cannot re-inspect {label} component: {path}"
            ) from exc
        observed = (metadata.st_dev, metadata.st_ino)
        if (
            _is_link_like(metadata)
            or not stat.S_ISDIR(metadata.st_mode)
            or observed != identity
        ):
            _fail(f"{label} changed while evidence was accessed: {path}")


def _read_regular(path: Path, *, limit: int, label: str) -> bytes:
    parent_snapshot = _directory_chain(path.parent, label=f"{label} parent")
    try:
        before = path.lstat()
    except OSError as exc:
        raise LedgerValidationError(f"cannot inspect {label}: {path}") from exc
    if _is_link_like(before) or not stat.S_ISREG(before.st_mode):
        _fail(f"{label} must be a regular non-link file: {path}")
    if before.st_nlink != 1:
        _fail(f"{label} must not be a hard-linked file: {path}")
    if before.st_size < 1 or before.st_size > limit:
        _fail(f"{label} size is outside 1..{limit} bytes: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LedgerValidationError(f"cannot open {label}: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            _is_link_like(opened)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _identity(opened) != _identity(before)
        ):
            _fail(f"{label} changed while it was opened: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                _fail(f"{label} exceeded its read limit: {path}")
        after = os.fstat(descriptor)
    except OSError as exc:
        raise LedgerValidationError(f"cannot read {label}: {path}") from exc
    finally:
        os.close(descriptor)
    try:
        final_path = path.lstat()
    except OSError as exc:
        raise LedgerValidationError(f"cannot re-inspect {label}: {path}") from exc
    if (
        _is_link_like(after)
        or _is_link_like(final_path)
        or after.st_nlink != 1
        or final_path.st_nlink != 1
        or _identity(opened) != _identity(after)
        or _identity(opened) != _identity(final_path)
    ):
        _fail(f"{label} changed while it was read: {path}")
    _require_same_directory_chain(parent_snapshot, label=f"{label} parent")
    data = b"".join(chunks)
    if len(data) != before.st_size:
        _fail(f"{label} returned a short or extended read: {path}")
    return data


def _path_is_within(path: Path, root: Path) -> bool:
    path_text = os.path.normcase(os.path.abspath(path))
    root_text = os.path.normcase(os.path.abspath(root))
    try:
        return os.path.commonpath((path_text, root_text)) == root_text
    except ValueError:
        return False


def _load_trusted_ledger_key(root: Path, path: Path) -> _TrustedLedgerKey:
    """Load one caller-supplied key that is independent of the evidence root."""

    absolute = Path(os.path.abspath(path))
    if _path_is_within(absolute, root):
        _fail("trusted ledger public key must be outside the ledger root")
    pem = _read_regular(
        absolute,
        limit=MAX_PUBLIC_KEY_BYTES,
        label="external trusted ledger public key",
    )
    try:
        metadata = absolute.lstat()
    except OSError as exc:
        raise LedgerValidationError(
            f"cannot re-inspect external trusted ledger public key: {absolute}"
        ) from exc

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        key = serialization.load_pem_public_key(pem)
    except (ImportError, TypeError, ValueError) as exc:
        raise LedgerValidationError(
            "external trusted ledger public key is not a usable PEM key"
        ) from exc
    if not isinstance(key, ed25519.Ed25519PublicKey):
        _fail("external trusted ledger public key is not Ed25519")
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return _TrustedLedgerKey(
        path=absolute,
        pem=pem,
        key_id=f"sha256:{_sha256(der)}",
        key=key,
        identity=_inventory_identity(metadata),
    )


def _decode_canonical_signature(data: bytes) -> bytes:
    if len(data) != CANONICAL_SIGNATURE_BYTES or not data.endswith(b"\n"):
        _fail(
            "RELEASE_LEDGER.json.sig must be exact canonical base64 "
            "for one 64-byte Ed25519 signature plus LF"
        )
    encoded = data[:-1]
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise LedgerValidationError(
            "RELEASE_LEDGER.json.sig is not strict base64"
        ) from exc
    if len(signature) != 64 or base64.b64encode(signature) != encoded:
        _fail("RELEASE_LEDGER.json.sig is not canonical Ed25519 base64")
    return signature


def _verify_external_ledger_signature(
    ledger_bytes: bytes,
    signature_bytes: bytes,
    trusted_key: _TrustedLedgerKey,
) -> None:
    from cryptography.exceptions import InvalidSignature

    signature = _decode_canonical_signature(signature_bytes)
    try:
        trusted_key.key.verify(signature, ledger_bytes)
    except InvalidSignature as exc:
        raise LedgerValidationError(
            "detached ledger signature is invalid under the external trusted key"
        ) from exc


def _require_trusted_key_unchanged(trusted_key: _TrustedLedgerKey) -> None:
    current = _read_regular(
        trusted_key.path,
        limit=MAX_PUBLIC_KEY_BYTES,
        label="external trusted ledger public key",
    )
    try:
        metadata = trusted_key.path.lstat()
    except OSError as exc:
        raise LedgerValidationError(
            "cannot re-inspect external trusted ledger public key"
        ) from exc
    if (
        current != trusted_key.pem
        or _inventory_identity(metadata) != trusted_key.identity
    ):
        _fail("external trusted ledger public key changed during validation")


def _load_json_value_bytes(data: bytes, *, label: str) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LedgerValidationError(f"{label} is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise LedgerValidationError(f"{label} is not valid JSON: {exc}") from exc
    return value


def _load_json_bytes(data: bytes, *, label: str) -> dict[str, Any]:
    value = _load_json_value_bytes(data, label=label)
    if not isinstance(value, dict):
        _fail(f"{label} root must be an object")
    return value


def _load_json_file(path: Path, *, label: str, limit: int = MAX_JSON_BYTES) -> dict[str, Any]:
    return _load_json_bytes(_read_regular(path, limit=limit, label=label), label=label)


def _load_official_schema() -> tuple[dict[str, Any], str]:
    data = _read_regular(
        DEFAULT_SCHEMA,
        limit=MAX_JSON_BYTES,
        label="official release ledger schema",
    )
    schema = _load_json_bytes(data, label="official release ledger schema")
    if schema.get("$id") != OFFICIAL_SCHEMA_ID:
        _fail("official release ledger schema has the wrong $id")
    return schema, _sha256(data)


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the one v2 ledger serialization accepted for signing."""

    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _trusted_process_environment(*, search_path: str | None = None) -> dict[str, str]:
    environment = {
        key: os.environ[key]
        for key in (
            "PATHEXT",
            "SystemRoot",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "TEMP",
            "TMP",
        )
        if key in os.environ
    }
    if search_path is not None:
        environment["PATH"] = search_path
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "LC_ALL": "C",
        }
    )
    return environment


def _trusted_path_roots(*blocked_roots: Path) -> list[Path]:
    """Return the absolute, non-candidate-controlled PATH search directories."""

    blocked = [
        Path(os.path.abspath(path))
        for path in (
            Path.cwd(),
            ROOT,
            Path(tempfile.gettempdir()),
            *blocked_roots,
        )
    ]
    roots: list[Path] = []
    seen: set[str] = set()
    for raw in os.environ.get("PATH", "").split(os.pathsep):
        value = raw.strip()
        if not value or value != raw or value.startswith('"') or value.endswith('"'):
            continue
        candidate = Path(value)
        if not candidate.is_absolute():
            continue
        absolute = Path(os.path.abspath(candidate))
        portable = os.path.normcase(str(absolute))
        if portable in seen or any(
            _path_is_within(absolute, root) or _path_is_within(root, absolute)
            for root in blocked
        ):
            continue
        try:
            metadata = absolute.lstat()
        except OSError:
            continue
        if _is_link_like(metadata) or not stat.S_ISDIR(metadata.st_mode):
            continue
        seen.add(portable)
        roots.append(absolute)
    return roots


def _read_trusted_executable(path: Path) -> tuple[bytes, tuple[int, int, int, int, int]]:
    """Read a host executable while allowing legitimate hard-linked installs."""

    parent_snapshot = _directory_chain(
        path.parent,
        label="trusted Git executable parent",
    )
    try:
        before = path.lstat()
    except OSError as exc:
        raise LedgerValidationError("cannot inspect trusted Git executable") from exc
    if (
        _is_link_like(before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size < 1
        or before.st_size > MAX_TRUSTED_EXECUTABLE_BYTES
    ):
        _fail("trusted Git executable is not one bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LedgerValidationError("cannot open trusted Git executable") from exc
    try:
        opened = os.fstat(descriptor)
        if _is_link_like(opened) or not stat.S_ISREG(opened.st_mode) or _identity(
            opened
        ) != _identity(before):
            _fail("trusted Git executable changed while opening")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(_READ_CHUNK_BYTES, MAX_TRUSTED_EXECUTABLE_BYTES + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_TRUSTED_EXECUTABLE_BYTES:
                _fail("trusted Git executable exceeded its read limit")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        final = path.lstat()
    except OSError as exc:
        raise LedgerValidationError(
            "cannot re-inspect trusted Git executable"
        ) from exc
    if (
        _is_link_like(after)
        or _is_link_like(final)
        or _identity(opened) != _identity(after)
        or _identity(opened) != _identity(final)
    ):
        _fail("trusted Git executable changed while reading")
    _require_same_directory_chain(
        parent_snapshot,
        label="trusted Git executable parent",
    )
    data = b"".join(chunks)
    if len(data) != before.st_size:
        _fail("trusted Git executable returned a short or extended read")
    return data, _inventory_identity(before)


def _resolve_trusted_git(*blocked_roots: Path) -> _TrustedExecutable:
    """Resolve Git without consulting cwd, relative PATH entries, or repo roots."""

    roots = _trusted_path_roots(*blocked_roots)
    executable_name = "git.exe" if os.name == "nt" else "git"
    for root in roots:
        path = root / executable_name
        try:
            data, identity = _read_trusted_executable(path)
        except LedgerValidationError:
            continue
        if os.name != "nt" and not os.access(path, os.X_OK):
            continue
        return _TrustedExecutable(
            path=path,
            data=data,
            identity=identity,
            search_path=str(root),
            parent_chain=_directory_chain(
                path.parent,
                label="trusted Git executable parent",
            ),
        )
    _fail("no trusted Git executable exists in an absolute host PATH directory")


def _require_trusted_executable_unchanged(
    executable: _TrustedExecutable,
) -> None:
    data, identity = _read_trusted_executable(executable.path)
    if data != executable.data or identity != executable.identity:
        _fail("trusted Git executable changed during validation")
    _require_same_directory_chain(
        executable.parent_chain,
        label="trusted Git executable parent",
    )


def _git_blob_sha(
    data: bytes,
    *,
    repository: Path = ROOT,
    executable: _TrustedExecutable | None = None,
) -> str:
    """Return Git's protocol-mandated blob identity through frozen host Git."""

    if len(data) > MAX_JSON_BYTES:
        _fail("trusted Git blob input exceeds its bounded size limit")
    trusted = executable or _resolve_trusted_git(repository)
    output = _trusted_git(
        trusted.path.parent,
        "hash-object",
        "--stdin",
        label="blob identity",
        output_limit=65,
        input_data=data,
        executable=trusted,
    )
    if re.fullmatch(b"[0-9a-f]{40}\n", output) is None:
        _fail("trusted Git returned a non-canonical SHA-1 blob identity")
    return output[:-1].decode("ascii", "strict")


def _trusted_git(
    repository: Path,
    *arguments: str,
    label: str,
    output_limit: int,
    input_data: bytes | None = None,
    executable: _TrustedExecutable | None = None,
) -> bytes:
    trusted = executable or _resolve_trusted_git(repository)
    _require_trusted_executable_unchanged(trusted)
    try:
        returncode, stdout, _stderr = _run_bounded_subprocess(
            [str(trusted.path), "-C", str(repository), *arguments],
            environment=_trusted_process_environment(
                search_path=trusted.search_path,
            ),
            output_limit=output_limit,
            timeout=15,
            label=f"trusted parent {label}",
            input_data=input_data,
        )
    except (OSError, subprocess.SubprocessError) as primary:
        try:
            _require_trusted_executable_unchanged(trusted)
        except BaseException as integrity:
            raise integrity from primary
        raise LedgerValidationError(f"cannot inspect trusted parent {label}") from primary
    _require_trusted_executable_unchanged(trusted)
    if returncode != 0:
        _fail(f"trusted parent {label} is unavailable or invalid")
    return stdout


def _run_bounded_subprocess(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    output_limit: int,
    timeout: int,
    label: str,
    input_data: bytes | None = None,
) -> tuple[int, bytes, bytes]:
    """Run one fixed command while bounding combined stdout and stderr bytes."""

    if output_limit < 1:
        _fail(f"{label} output limit must be positive")
    started = time.monotonic()
    popen_options: dict[str, Any] = {}
    if os.name == "nt":
        popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_options["start_new_session"] = True
    input_stream: Any = subprocess.DEVNULL
    temporary_input = None
    if input_data is not None:
        temporary_input = tempfile.TemporaryFile()
        temporary_input.write(input_data)
        temporary_input.seek(0)
        input_stream = temporary_input
    try:
        process = subprocess.Popen(  # noqa: S603 - caller supplies a fixed argv
            list(command),
            stdin=input_stream,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(environment),
            **popen_options,
        )
    finally:
        if temporary_input is not None:
            temporary_input.close()
    if process.stdout is None or process.stderr is None:
        with suppress(OSError):
            process.kill()
        _fail(f"{label} did not expose bounded output pipes")
    output_fds = (process.stdout.fileno(), process.stderr.fileno())
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    total = [0]
    exceeded = threading.Event()
    lock = threading.Lock()

    def kill_process_tree() -> None:
        if os.name == "nt":
            break_signal = getattr(signal, "CTRL_BREAK_EVENT", None)
            if break_signal is not None:
                with suppress(OSError):
                    os.kill(process.pid, break_signal)
            with suppress(OSError):
                process.kill()
        else:
            kill_process_group = getattr(os, "killpg", None)
            kill_signal = getattr(signal, "SIGKILL", None)
            if kill_process_group is None or kill_signal is None:
                with suppress(OSError):
                    process.kill()
                return
            with suppress(OSError, ProcessLookupError):
                kill_process_group(process.pid, kill_signal)

    def close_output_pipes() -> None:
        for file_descriptor in output_fds:
            with suppress(OSError, ValueError):
                os.close(file_descriptor)

    def close_output_pipes_bounded() -> None:
        closer = threading.Thread(target=close_output_pipes, daemon=True)
        closer.start()
        closer.join(timeout=0.25)

    def drain(stream: Any, chunks: list[bytes]) -> None:
        while True:
            try:
                chunk = stream.read(64 * 1024)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            with lock:
                remaining = max(0, output_limit - total[0])
                if remaining:
                    chunks.append(chunk[:remaining])
                total[0] += len(chunk)
                if total[0] > output_limit:
                    exceeded.set()
            if exceeded.is_set():
                kill_process_tree()
                return

    readers = (
        threading.Thread(
            target=drain,
            args=(process.stdout, stdout_chunks),
            daemon=True,
        ),
        threading.Thread(
            target=drain,
            args=(process.stderr, stderr_chunks),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        kill_process_tree()
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=1)
        for reader in readers:
            reader.join(timeout=0.25)
        if any(reader.is_alive() for reader in readers):
            close_output_pipes_bounded()
            for reader in readers:
                reader.join(timeout=0.25)
        raise LedgerValidationError(f"{label} timed out") from exc
    for reader in readers:
        remaining = max(0.0, started + timeout - time.monotonic())
        reader.join(timeout=remaining)
    if any(reader.is_alive() for reader in readers):
        kill_process_tree()
        for reader in readers:
            reader.join(timeout=0.25)
        if any(reader.is_alive() for reader in readers):
            close_output_pipes_bounded()
            for reader in readers:
                reader.join(timeout=0.25)
        _fail(f"{label} left bounded output pipes open after process exit")
    if exceeded.is_set():
        _fail(f"{label} exceeded its bounded combined output limit")
    return returncode, b"".join(stdout_chunks), b"".join(stderr_chunks)


def _validate_trusted_parent_contracts(
    ledger_root: Path,
    ledger: Mapping[str, Any],
    trusted_parent_repo: Path | None,
    trusted_key: _TrustedLedgerKey,
) -> _TrustedParentContracts:
    if trusted_parent_repo is None:
        _fail("an external trusted parent repository is required")
    repository = _require_plain_directory(
        trusted_parent_repo,
        label="external trusted parent repository",
    )
    try:
        repository_metadata = repository.lstat()
    except OSError as exc:
        raise LedgerValidationError(
            "cannot inspect external trusted parent repository"
        ) from exc
    repository_object = (repository_metadata.st_dev, repository_metadata.st_ino)
    if _path_is_within(repository, ledger_root) or _path_is_within(
        ledger_root, repository
    ):
        _fail("trusted parent repository and ledger root must be disjoint")
    trusted_git = _resolve_trusted_git(repository, ledger_root)
    parent = ledger["source"]["parent_commit_sha"]
    parent_tree = ledger["source"]["parent_tree_sha"]
    resolved_commit = _trusted_git(
        repository,
        "rev-parse",
        "--verify",
        f"{parent}^{{commit}}",
        label="commit",
        output_limit=128,
        executable=trusted_git,
    ).decode("ascii", "strict").strip()
    resolved_tree = _trusted_git(
        repository,
        "rev-parse",
        "--verify",
        f"{parent}^{{tree}}",
        label="tree",
        output_limit=128,
        executable=trusted_git,
    ).decode("ascii", "strict").strip()
    if resolved_commit != parent or resolved_tree != parent_tree:
        _fail("trusted parent commit/tree identity is not exact")
    contracts = (
        (
            ledger["schema_contracts"]["release_ledger"],
            DEFAULT_SCHEMA.read_bytes(),
            "schema",
        ),
        (
            ledger["schema_contracts"]["validator"],
            Path(__file__).read_bytes(),
            "validator",
        ),
        (
            ledger["ledger_signature"]["trusted_parent_anchor"],
            trusted_key.pem,
            "ledger signing anchor",
        ),
    )
    for contract, current_bytes, label in contracts:
        path = contract["path"]
        entry = _trusted_git(
            repository,
            "ls-tree",
            "-z",
            parent,
            "--",
            path,
            label=f"{label} tree entry",
            output_limit=4096,
            executable=trusted_git,
        )
        expected_prefix = f"100644 blob {contract['git_blob_sha']}\t{path}\0".encode()
        if entry != expected_prefix:
            _fail(f"trusted parent {label} tree entry is not exact")
        blob_size_text = _trusted_git(
            repository,
            "cat-file",
            "-s",
            contract["git_blob_sha"],
            label=f"{label} blob size",
            output_limit=128,
            executable=trusted_git,
        ).decode("ascii", "strict").strip()
        if not blob_size_text.isdigit() or int(blob_size_text) != len(current_bytes):
            _fail(f"trusted parent {label} blob size is not exact")
        parent_bytes = _trusted_git(
            repository,
            "cat-file",
            "blob",
            contract["git_blob_sha"],
            label=f"{label} blob",
            output_limit=len(current_bytes) + 1,
            executable=trusted_git,
        )
        if (
            parent_bytes != current_bytes
            or _sha256(parent_bytes) != contract["sha256"]
            or (
                _git_blob_sha(
                    parent_bytes,
                    repository=repository,
                    executable=trusted_git,
                )
                != contract["git_blob_sha"]
            )
            or contract["trusted_parent_commit_sha"] != parent
            or contract["trusted_parent_tree_sha"] != parent_tree
        ):
            _fail(f"trusted parent {label} bytes do not equal the executing contract")
    trusted_inputs = ledger["toolchain"]["trusted_build_inputs"]
    for field, path in TRUSTED_BUILD_INPUT_PATHS.items():
        expected_blob = trusted_inputs[field]
        current_path = ROOT.joinpath(*PurePosixPath(path).parts)
        current_bytes = _read_regular(
            current_path,
            limit=MAX_JSON_BYTES,
            label=f"trusted build input {path}",
        )
        entry = _trusted_git(
            repository,
            "ls-tree",
            "-z",
            parent,
            "--",
            path,
            label=f"trusted build input {path} tree entry",
            output_limit=4096,
            executable=trusted_git,
        )
        expected_entry = f"100644 blob {expected_blob}\t{path}\0".encode()
        if entry != expected_entry:
            _fail(f"trusted parent build input {path} tree entry is not exact")
        parent_bytes = _trusted_git(
            repository,
            "cat-file",
            "blob",
            expected_blob,
            label=f"trusted build input {path} blob",
            output_limit=len(current_bytes) + 1,
            executable=trusted_git,
        )
        if (
            parent_bytes != current_bytes
            or (
                _git_blob_sha(
                    parent_bytes,
                    repository=repository,
                    executable=trusted_git,
                )
                != expected_blob
            )
        ):
            _fail(f"trusted parent build input {path} bytes are not exact")
    return _TrustedParentContracts(
        repository=repository,
        commit_sha=parent,
        tree_sha=parent_tree,
        repository_object=repository_object,
        git=trusted_git,
    )


def _require_trusted_parent_repository_unchanged(
    contracts: _TrustedParentContracts,
) -> None:
    repository = _require_plain_directory(
        contracts.repository,
        label="external trusted parent repository",
    )
    try:
        metadata = repository.lstat()
    except OSError as exc:
        raise LedgerValidationError(
            "cannot re-inspect external trusted parent repository"
        ) from exc
    if (metadata.st_dev, metadata.st_ino) != contracts.repository_object:
        _fail("external trusted parent repository changed during validation")
    resolved_commit = _trusted_git(
        repository,
        "rev-parse",
        "--verify",
        f"{contracts.commit_sha}^{{commit}}",
        label="first-party parent commit",
        output_limit=128,
        executable=contracts.git,
    ).decode("ascii", "strict").strip()
    resolved_tree = _trusted_git(
        repository,
        "rev-parse",
        "--verify",
        f"{contracts.commit_sha}^{{tree}}",
        label="first-party parent tree",
        output_limit=128,
        executable=contracts.git,
    ).decode("ascii", "strict").strip()
    if (
        resolved_commit != contracts.commit_sha
        or resolved_tree != contracts.tree_sha
    ):
        _fail("trusted first-party parent commit/tree changed during validation")


def _trusted_parent_contract_reference(
    repository: Path,
    commit_sha: str,
    tree_sha: str,
    *,
    executable: _TrustedExecutable | None = None,
) -> _TrustedParentContracts:
    trusted_repository = _require_plain_directory(
        repository,
        label="external trusted parent repository",
    )
    try:
        metadata = trusted_repository.lstat()
    except OSError as exc:
        raise LedgerValidationError(
            "cannot inspect external trusted parent repository"
        ) from exc
    contracts = _TrustedParentContracts(
        repository=trusted_repository,
        commit_sha=commit_sha,
        tree_sha=tree_sha,
        repository_object=(metadata.st_dev, metadata.st_ino),
        git=executable or _resolve_trusted_git(trusted_repository),
    )
    _require_trusted_parent_repository_unchanged(contracts)
    return contracts


def _trusted_first_party_relative_path(raw: bytes) -> str:
    try:
        relative = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise LedgerValidationError(
            "trusted first-party path is not UTF-8"
        ) from exc
    pure = PurePosixPath(relative)
    if (
        not relative
        or "\\" in relative
        or pure.is_absolute()
        or pure.as_posix() != relative
        or not pure.parts
        or pure.parts[0] != _TRUSTED_FIRST_PARTY_PREFIX
        or len(raw) > MAX_TRUSTED_FIRST_PARTY_PATH_BYTES
        or len(pure.parts) > MAX_TRUSTED_FIRST_PARTY_PATH_DEPTH
        or any(part in {"", ".", ".."} for part in pure.parts)
        or any(
            len(part.encode("utf-8")) > 255
            or part.endswith((" ", "."))
            or any(character in '<>:"|?*' for character in part)
            or part.casefold().split(".", 1)[0]
            in _WINDOWS_RESERVED_PATH_NAMES
            for part in pure.parts
        )
        or unicodedata.normalize("NFC", relative) != relative
        or any(
            ord(character) < 32
            or ord(character) == 127
            or 0xD800 <= ord(character) <= 0xDFFF
            for character in relative
        )
    ):
        _fail(f"trusted first-party path is unsafe: {relative!r}")
    return relative


def _matches_git_blob_object_id(
    data: bytes,
    object_id: str,
    *,
    repository: Path = ROOT,
    executable: _TrustedExecutable | None = None,
) -> bool:
    framed = f"blob {len(data)}\0".encode("ascii") + data
    if len(object_id) == 40:
        observed = _git_blob_sha(
            data,
            repository=repository,
            executable=executable,
        )
    elif len(object_id) == 64:
        observed = hashlib.sha256(framed).hexdigest()
    else:
        return False
    return observed == object_id


def _read_trusted_first_party_tree(
    contracts: _TrustedParentContracts,
) -> tuple[dict[str, bytes], dict[str, _TrustedFirstPartyFile]]:
    _require_trusted_parent_repository_unchanged(contracts)
    listing = _trusted_git(
        contracts.repository,
        "ls-tree",
        "-r",
        "-l",
        "-z",
        "--full-tree",
        contracts.commit_sha,
        "--",
        _TRUSTED_FIRST_PARTY_PREFIX,
        label="first-party tree",
        output_limit=MAX_TRUSTED_FIRST_PARTY_TREE_BYTES,
        executable=contracts.git,
    )
    records = listing.split(b"\0")
    if not records or records[-1] != b"":
        _fail("trusted first-party tree listing is not NUL-terminated")
    records.pop()
    if not records or len(records) > MAX_TRUSTED_FIRST_PARTY_FILES:
        _fail(
            "trusted first-party file count is outside "
            f"1..{MAX_TRUSTED_FIRST_PARTY_FILES}"
        )

    entries: list[tuple[str, str, int]] = []
    portable_paths: dict[str, str] = {}
    blob_sizes: dict[str, int] = {}
    total = 0
    for record in records:
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id_bytes, size_bytes = header.split()
        except ValueError as exc:
            raise LedgerValidationError(
                "trusted first-party tree entry is malformed"
            ) from exc
        if (
            mode != b"100644"
            or object_type != b"blob"
            or re.fullmatch(b"(?:[0-9a-f]{40}|[0-9a-f]{64})", object_id_bytes)
            is None
            or not size_bytes.isdigit()
        ):
            _fail("trusted first-party tree contains a non-regular blob")
        relative = _trusted_first_party_relative_path(raw_path)
        portable = relative.casefold()
        prior = portable_paths.get(portable)
        if prior is not None:
            _fail(
                "trusted first-party tree contains duplicate or "
                f"portable-case-colliding paths: {prior!r}, {relative!r}"
            )
        portable_paths[portable] = relative
        object_id = object_id_bytes.decode("ascii", "strict")
        size_text = size_bytes.decode("ascii", "strict")
        if str(int(size_text)) != size_text:
            _fail(f"trusted first-party blob size is not canonical: {relative}")
        size = int(size_text)
        if size > MAX_TRUSTED_FIRST_PARTY_FILE_BYTES:
            _fail(f"trusted first-party blob is too large: {relative}")
        total += size
        if total > MAX_TRUSTED_FIRST_PARTY_TOTAL_BYTES:
            _fail("trusted first-party tree exceeds the total byte budget")
        prior_size = blob_sizes.setdefault(object_id, size)
        if prior_size != size:
            _fail("trusted first-party tree reports inconsistent blob sizes")
        entries.append((relative, object_id, size))

    query = b"".join(
        f"{object_id}\n".encode("ascii") for object_id in blob_sizes
    )
    batch = _trusted_git(
        contracts.repository,
        "cat-file",
        "--batch",
        label="first-party blob batch",
        output_limit=max(
            1,
            sum(blob_sizes.values()) + (len(blob_sizes) * 128) + 1,
        ),
        input_data=query,
        executable=contracts.git,
    )
    blobs: dict[str, bytes] = {}
    offset = 0
    for object_id, size in blob_sizes.items():
        header_end = batch.find(b"\n", offset, min(len(batch), offset + 128))
        expected_header = f"{object_id} blob {size}".encode("ascii")
        if header_end < 0 or batch[offset:header_end] != expected_header:
            _fail("trusted first-party blob batch header is not exact")
        data_start = header_end + 1
        data_end = data_start + size
        if data_end >= len(batch) or batch[data_end : data_end + 1] != b"\n":
            _fail("trusted first-party blob batch framing is not exact")
        data = batch[data_start:data_end]
        if not _matches_git_blob_object_id(
            data,
            object_id,
            repository=contracts.repository,
            executable=contracts.git,
        ):
            _fail("trusted first-party blob batch bytes are not exact")
        blobs[object_id] = data
        offset = data_end + 1
    if offset != len(batch):
        _fail("trusted first-party blob batch has trailing output")

    files: dict[str, bytes] = {}
    manifest: dict[str, _TrustedFirstPartyFile] = {}
    for relative, object_id, size in entries:
        data = blobs[object_id]
        files[relative] = data
        manifest[relative] = _TrustedFirstPartyFile(
            blob_sha=object_id,
            sha256=_sha256(data),
            size_bytes=size,
        )
    if f"{_TRUSTED_FIRST_PARTY_PREFIX}/__init__.py" not in files:
        _fail("trusted first-party tree is not an importable package")
    _require_trusted_parent_repository_unchanged(contracts)
    return files, manifest


def _verify_loaded_first_party_modules(
    import_root: Path,
    manifest: Mapping[str, _TrustedFirstPartyFile],
    contracts: _TrustedParentContracts,
) -> None:
    loaded = {
        name: module
        for name, module in sys.modules.items()
        if name == _TRUSTED_FIRST_PARTY_PREFIX
        or name.startswith(f"{_TRUSTED_FIRST_PARTY_PREFIX}.")
    }
    missing = set(_TRUSTED_FIRST_PARTY_MODULES) - set(loaded)
    if missing:
        _fail(f"trusted first-party modules were not loaded: {sorted(missing)}")
    origins: dict[str, str] = {}
    for name, module in sorted(loaded.items()):
        file_value = getattr(module, "__file__", None)
        spec = getattr(module, "__spec__", None)
        origin_value = getattr(spec, "origin", None)
        if not isinstance(file_value, str) or not isinstance(origin_value, str):
            _fail(f"trusted first-party module has no file origin: {name}")
        file_path = Path(os.path.abspath(file_value))
        origin_path = Path(os.path.abspath(origin_value))
        if file_path != origin_path or not _path_is_within(file_path, import_root):
            _fail(f"trusted first-party module escaped the parent snapshot: {name}")
        try:
            relative = file_path.relative_to(import_root).as_posix()
        except ValueError as exc:
            raise LedgerValidationError(
                f"trusted first-party module origin is outside the snapshot: {name}"
            ) from exc
        descriptor = manifest.get(relative)
        if descriptor is None:
            _fail(f"trusted first-party module is not in the parent manifest: {name}")
        data = _read_regular(
            file_path,
            limit=max(descriptor.size_bytes, 1),
            label=f"loaded trusted first-party module {name}",
        )
        if (
            len(data) != descriptor.size_bytes
            or _sha256(data) != descriptor.sha256
            or not _matches_git_blob_object_id(
                data,
                descriptor.blob_sha,
                repository=contracts.repository,
                executable=contracts.git,
            )
        ):
            _fail(f"loaded trusted first-party module bytes changed: {name}")
        prior = origins.get(relative)
        if prior is not None and prior != name:
            _fail(
                "multiple trusted first-party modules share one origin: "
                f"{prior}, {name}"
            )
        origins[relative] = name


def _require_trusted_first_party_unchanged(
    import_root: Path,
    manifest: Mapping[str, _TrustedFirstPartyFile],
    contracts: _TrustedParentContracts,
    snapshot_files: set[str],
    snapshot_directories: set[str],
    snapshot_identities: Mapping[str, tuple[int, int, int, int, int]],
) -> None:
    _verify_loaded_first_party_modules(import_root, manifest, contracts)
    _require_inventory_unchanged(
        import_root,
        files=snapshot_files,
        directories=snapshot_directories,
        identities=snapshot_identities,
        max_files=MAX_TRUSTED_FIRST_PARTY_FILES,
        max_directories=(
            MAX_TRUSTED_FIRST_PARTY_FILES * MAX_TRUSTED_FIRST_PARTY_PATH_DEPTH
        )
        + 1,
        max_total_bytes=MAX_TRUSTED_FIRST_PARTY_TOTAL_BYTES,
    )
    _require_trusted_parent_repository_unchanged(contracts)


def _module_matches_prefix(name: str, prefixes: Sequence[str]) -> bool:
    return any(name == prefix or name.startswith(f"{prefix}.") for prefix in prefixes)


def _safe_python_roots(*blocked_roots: Path) -> tuple[Path, ...]:
    prefixes = {
        Path(os.path.abspath(sys.prefix)),
        Path(os.path.abspath(sys.base_prefix)),
    }
    blocked = tuple(Path(os.path.abspath(path)) for path in blocked_roots)
    candidates = [
        *prefixes,
        *(Path(value) for value in sys.path if value and Path(value).is_absolute()),
    ]
    roots: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        absolute = Path(os.path.abspath(candidate))
        if (
            not any(_path_is_within(absolute, prefix) for prefix in prefixes)
            or any(
                _path_is_within(absolute, root) or _path_is_within(root, absolute)
                for root in blocked
            )
        ):
            continue
        portable = os.path.normcase(str(absolute))
        if portable in seen:
            continue
        try:
            metadata = absolute.lstat()
        except OSError:
            continue
        if _is_link_like(metadata) or not stat.S_ISDIR(metadata.st_mode):
            continue
        seen.add(portable)
        roots.append(absolute)
    if not roots:
        _fail("no safe Python runtime roots are available")
    roots.sort(key=lambda path: (len(path.parts), os.path.normcase(str(path))))
    return tuple(roots)


def _module_origin_paths(module: Any) -> tuple[Path, ...]:
    values: list[Path] = []
    spec = getattr(module, "__spec__", None)
    origin = getattr(spec, "origin", None)
    file_value = getattr(module, "__file__", None)
    for value in (file_value, origin):
        if not isinstance(value, str) or value in {"built-in", "frozen"}:
            continue
        path = Path(value)
        if not path.is_absolute():
            return (Path(""),)
        values.append(Path(os.path.abspath(path)))
    locations = getattr(spec, "submodule_search_locations", None)
    if locations is not None:
        for value in locations:
            path = Path(value)
            if not path.is_absolute():
                return (Path(""),)
            values.append(Path(os.path.abspath(path)))
    return tuple(dict.fromkeys(values))


def _module_is_outside_roots(module: Any, roots: Sequence[Path]) -> bool:
    paths = _module_origin_paths(module)
    if not paths:
        spec = getattr(module, "__spec__", None)
        origin = getattr(spec, "origin", None)
        loader = getattr(spec, "loader", None)
        return not (
            origin == "built-in"
            and loader is importlib.machinery.BuiltinImporter
            or origin == "frozen"
            and loader is importlib.machinery.FrozenImporter
        )
    return any(not any(_path_is_within(path, root) for root in roots) for path in paths)


def _loaded_dependency_files(
    safe_roots: Sequence[Path],
) -> dict[Path, _TrustedDependencyFile]:
    snapshots: dict[Path, _TrustedDependencyFile] = {}
    total = 0
    for name, module in sorted(sys.modules.items()):
        if not _module_matches_prefix(name, _TRUSTED_RUNTIME_PREFIXES):
            continue
        file_value = getattr(module, "__file__", None)
        spec = getattr(module, "__spec__", None)
        origin_value = getattr(spec, "origin", None)
        if not isinstance(file_value, str):
            _fail(f"trusted dependency module has no file origin: {name}")
        path = Path(os.path.abspath(file_value))
        if (
            (
                isinstance(origin_value, str)
                and origin_value not in {"built-in", "frozen"}
                and path != Path(os.path.abspath(origin_value))
            )
            or not any(_path_is_within(path, root) for root in safe_roots)
        ):
            _fail(f"trusted dependency module escaped safe Python roots: {name}")
        if path in snapshots:
            continue
        data = _read_regular(
            path,
            limit=MAX_TRUSTED_DEPENDENCY_FILE_BYTES,
            label=f"trusted dependency module {name}",
        )
        total += len(data)
        if total > MAX_TRUSTED_DEPENDENCY_TOTAL_BYTES:
            _fail("trusted dependency modules exceed the total byte budget")
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise LedgerValidationError(
                f"cannot re-inspect trusted dependency module: {name}"
            ) from exc
        snapshots[path] = _TrustedDependencyFile(
            path=path,
            data=data,
            identity=_inventory_identity(metadata),
        )
    return snapshots


def _require_dependency_files_unchanged(
    expected: Mapping[Path, _TrustedDependencyFile],
    safe_roots: Sequence[Path],
) -> None:
    observed = _loaded_dependency_files(safe_roots)
    if set(observed) != set(expected):
        _fail("trusted dependency module set changed during validation")
    for path, descriptor in expected.items():
        current = observed[path]
        if (
            current.data != descriptor.data
            or current.identity != descriptor.identity
        ):
            _fail(f"trusted dependency module changed during validation: {path}")


def _bind_cryptography_extension_exceptions() -> None:
    """Bind reloaded Python wrappers to the process-resident extension class."""

    from cryptography import exceptions
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate().public_key()
    try:
        key.verify(b"\0" * 64, b"evoguard-import-integrity-probe")
    except Exception as exc:
        observed = type(exc)
    else:
        _fail("cryptography accepted the invalid import-integrity probe")
    if (
        observed.__name__ != "InvalidSignature"
        or observed.__module__ != "cryptography.exceptions"
    ):
        _fail("cryptography returned an unexpected signature exception")
    exceptions.InvalidSignature = observed


@contextmanager
def _trusted_python_imports(
    *,
    import_root: Path | None,
    blocked_roots: Sequence[Path],
) -> Iterator[None]:
    """Isolate imports for one single-threaded trusted-operator CLI operation.

    This rejects candidate filesystem/module origins.  It does not attempt to
    recover from an already-compromised Python interpreter or standard library.
    """

    global _TRUSTED_IMPORT_DEPTH
    safe_roots = _safe_python_roots(
        Path.cwd(),
        ROOT,
        Path(tempfile.gettempdir()),
        *blocked_roots,
    )
    allowed_roots = (*safe_roots, *((import_root,) if import_root else ()))
    saved_names = set(sys.modules)
    removed_modules = {
        name: module
        for name, module in sys.modules.items()
        if _module_matches_prefix(
            name,
            (*_TRUSTED_RUNTIME_PREFIXES, _TRUSTED_FIRST_PARTY_PREFIX),
        )
        or _module_is_outside_roots(module, safe_roots)
    }
    saved_path = list(sys.path)
    saved_meta_path = list(sys.meta_path)
    saved_path_hooks = list(sys.path_hooks)
    saved_importer_cache = dict(sys.path_importer_cache)
    saved_dont_write_bytecode = sys.dont_write_bytecode
    entered = False
    try:
        for name in removed_modules:
            sys.modules.pop(name, None)
        sys.path[:] = [
            *((str(import_root),) if import_root else ()),
            *(str(path) for path in safe_roots),
        ]
        sys.meta_path[:] = [
            importlib.machinery.BuiltinImporter,
            importlib.machinery.FrozenImporter,
            importlib.machinery.PathFinder,
        ]
        sys.path_hooks[:] = [
            importlib.machinery.FileFinder.path_hook(
                (
                    importlib.machinery.SourceFileLoader,
                    importlib.machinery.SOURCE_SUFFIXES,
                ),
                (
                    importlib.machinery.SourcelessFileLoader,
                    importlib.machinery.BYTECODE_SUFFIXES,
                ),
                (
                    importlib.machinery.ExtensionFileLoader,
                    importlib.machinery.EXTENSION_SUFFIXES,
                ),
            )
        ]
        sys.path_importer_cache.clear()
        sys.dont_write_bytecode = True
        importlib.invalidate_caches()
        try:
            for name in _TRUSTED_DEPENDENCY_MODULES:
                importlib.import_module(name)
            _bind_cryptography_extension_exceptions()
        except Exception as exc:
            raise LedgerValidationError(
                "cannot import validation dependencies from safe Python roots"
            ) from exc
        dependency_files = _loaded_dependency_files(safe_roots)
        trusted_originless = {
            name: module
            for name, module in sys.modules.items()
            if not _module_origin_paths(module)
            and _module_is_outside_roots(module, safe_roots)
        }

        def require_module_roots() -> None:
            for name, module in sys.modules.items():
                if not _module_is_outside_roots(module, allowed_roots):
                    continue
                if trusted_originless.get(name) is module:
                    continue
                _fail(f"module escaped trusted import roots: {name}")

        _TRUSTED_IMPORT_DEPTH += 1
        entered = True
        try:
            yield
        except BaseException as primary:
            try:
                _require_dependency_files_unchanged(dependency_files, safe_roots)
                require_module_roots()
            except BaseException as integrity:
                raise integrity from primary
            raise
        else:
            _require_dependency_files_unchanged(dependency_files, safe_roots)
            require_module_roots()
    finally:
        if entered:
            _TRUSTED_IMPORT_DEPTH -= 1
        for name in list(sys.modules):
            if name not in saved_names or name in removed_modules:
                sys.modules.pop(name, None)
        sys.modules.update(removed_modules)
        sys.path[:] = saved_path
        sys.meta_path[:] = saved_meta_path
        sys.path_hooks[:] = saved_path_hooks
        sys.path_importer_cache.clear()
        sys.path_importer_cache.update(saved_importer_cache)
        sys.dont_write_bytecode = saved_dont_write_bytecode
        importlib.invalidate_caches()


@contextmanager
def _trusted_parent_first_party(
    contracts: _TrustedParentContracts,
) -> Iterator[None]:
    """Import every first-party verifier dependency from one literal parent tree."""

    with _FIRST_PARTY_IMPORT_LOCK:
        files, manifest = _read_trusted_first_party_tree(contracts)
        with tempfile.TemporaryDirectory(
            prefix="evoguard-ledger-v2-parent-"
        ) as temporary:
            import_root = _require_plain_directory(
                Path(temporary),
                label="trusted first-party import snapshot",
            )
            snapshot_files, snapshot_directories, snapshot_identities = (
                _materialize_snapshot(
                    import_root,
                    files,
                    max_files=MAX_TRUSTED_FIRST_PARTY_FILES,
                    max_directories=(
                        MAX_TRUSTED_FIRST_PARTY_FILES
                        * MAX_TRUSTED_FIRST_PARTY_PATH_DEPTH
                    )
                    + 1,
                    max_total_bytes=MAX_TRUSTED_FIRST_PARTY_TOTAL_BYTES,
                )
            )
            with _trusted_python_imports(
                import_root=import_root,
                blocked_roots=(contracts.repository,),
            ):
                try:
                    for name in _TRUSTED_FIRST_PARTY_MODULES:
                        importlib.import_module(name)
                except Exception as exc:
                    raise LedgerValidationError(
                        "cannot import first-party verification code from "
                        "the trusted parent snapshot"
                    ) from exc
                _verify_loaded_first_party_modules(
                    import_root,
                    manifest,
                    contracts,
                )
                try:
                    yield
                except BaseException as primary:
                    try:
                        _require_trusted_first_party_unchanged(
                            import_root,
                            manifest,
                            contracts,
                            snapshot_files,
                            snapshot_directories,
                            snapshot_identities,
                        )
                    except BaseException as integrity:
                        raise integrity from primary
                    raise
                else:
                    _require_trusted_first_party_unchanged(
                        import_root,
                        manifest,
                        contracts,
                        snapshot_files,
                        snapshot_directories,
                        snapshot_identities,
                    )


def _is_valid_schema_date_time(value: object) -> bool:
    if not isinstance(value, str):
        return True
    if _CANONICAL_UTC.fullmatch(value) is None:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _is_valid_absolute_uri(value: object) -> bool:
    if not isinstance(value, str):
        return True
    if (
        not value
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value)
        or re.search(r"%(?![0-9A-Fa-f]{2})", value) is not None
    ):
        return False
    try:
        parsed = urllib.parse.urlsplit(value)
        _ = parsed.port
    except ValueError:
        return False
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*", parsed.scheme) is None:
        return False
    if parsed.scheme.lower() in {"http", "https"}:
        return parsed.netloc != "" and parsed.hostname is not None
    return True


def _schema_errors(
    ledger: Mapping[str, Any], schema: Mapping[str, Any]
) -> list[str]:
    def collect() -> tuple[Any, ...]:
        try:
            from jsonschema import Draft202012Validator, FormatChecker
        except ImportError as exc:
            raise LedgerValidationError(
                "jsonschema is unavailable from safe Python runtime roots"
            ) from exc
        format_checker = FormatChecker()
        format_checker.checkers["date-time"] = (
            _is_valid_schema_date_time,
            (),
        )
        format_checker.checkers["uri"] = (_is_valid_absolute_uri, ())
        if not {"date-time", "uri"}.issubset(format_checker.checkers):
            raise LedgerValidationError(
                "required release-ledger schema format checkers are unavailable"
            )
        Draft202012Validator.check_schema(schema)
        schema_validator = Draft202012Validator(
            schema,
            format_checker=format_checker,
        )
        return tuple(schema_validator.iter_errors(ledger))

    if _TRUSTED_IMPORT_DEPTH:
        errors = collect()
    else:
        with _FIRST_PARTY_IMPORT_LOCK, _trusted_python_imports(
            import_root=None,
            blocked_roots=(ROOT,),
        ):
            errors = collect()
    messages: list[str] = []
    for error in sorted(
        errors,
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    ):
        location = "/".join(str(part) for part in error.absolute_path) or "<root>"
        messages.append(f"{location}: {error.message}")
    return messages


def _parse_time(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or _CANONICAL_UTC.fullmatch(value) is None:
        _fail(f"{label} must be canonical whole-second UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise LedgerValidationError(f"{label} is not an ISO date-time") from exc
    return parsed


def _require_exact_keys(
    value: Mapping[str, Any],
    expected: set[str],
    *,
    label: str,
) -> None:
    actual = set(value)
    if actual != expected:
        _fail(
            f"{label} keys are not exact; "
            f"missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}"
        )


def _require_required_keys(
    value: Mapping[str, Any],
    required: set[str],
    *,
    label: str,
) -> None:
    missing = required - set(value)
    if missing:
        _fail(f"{label} is missing required keys: {sorted(missing)}")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _descriptor(value: Mapping[str, Any]) -> tuple[str, int, str]:
    path = value.get("path")
    size = value.get("size_bytes")
    digest = value.get("sha256")
    if not isinstance(path, str) or not isinstance(size, int) or isinstance(size, bool):
        _fail("file descriptor has invalid path or size")
    if not isinstance(digest, str):
        _fail(f"file descriptor has invalid digest: {path}")
    return path, size, digest


def _add_descriptor(
    inventory: dict[str, tuple[int, str]],
    value: Mapping[str, Any],
    *,
    label: str,
    allowed_reserved_path: str | None = None,
) -> None:
    path, size, digest = _descriptor(value)
    if (
        path in {LEDGER_NAME, SIGNATURE_NAME, README_NAME}
        and path != allowed_reserved_path
    ):
        _fail(f"{label} illegally reuses reserved metadata path: {path}")
    prior = inventory.get(path)
    descriptor = (size, digest)
    if prior is not None and prior != descriptor:
        _fail(f"conflicting descriptors for retained path: {path}")
    inventory[path] = descriptor


def _collect_descriptors(ledger: Mapping[str, Any]) -> dict[str, tuple[int, str]]:
    inventory: dict[str, tuple[int, str]] = {}
    _add_descriptor(
        inventory,
        ledger["ledger_scope"]["readme"],
        label="ledger README",
        allowed_reserved_path=README_NAME,
    )
    for artifact in ledger["artifacts"]:
        _add_descriptor(inventory, artifact, label="release artifact")

    for bundle in ledger["control_evidence"].values():
        _add_descriptor(inventory, bundle["manifest"], label="control manifest")
        for material in bundle["materials"]:
            _add_descriptor(inventory, material, label="control material")

    source = ledger["source_admission"]
    for key in (
        "rsae",
        "protected_seal_result",
        "detached_verification_result",
        "negative_results",
    ):
        _add_descriptor(inventory, source[key], label=f"source admission {key}")

    artifact_admission = ledger["artifact_admission"]
    for subject in artifact_admission["subjects"]:
        for key in ("raae", "protected_seal_result", "detached_verification_result"):
            _add_descriptor(
                inventory,
                subject[key],
                label=f"artifact admission {subject['name']} {key}",
            )
    _add_descriptor(
        inventory,
        artifact_admission["negative_results"],
        label="artifact admission negative results",
    )

    for name in (
        "source_producer",
        "build_provenance",
        "spdx_provenance",
        "sbom_provenance",
    ):
        for evidence_name in ("verification_receipt", "verification_output"):
            _add_descriptor(
                inventory,
                ledger["attestations"][name][evidence_name],
                label=f"{name} {evidence_name}",
            )

    _add_descriptor(
        inventory,
        ledger["repository_controls"]["observation_evidence"],
        label="repository-control observation evidence",
    )

    for root in ledger["trust_roots"]:
        _add_descriptor(
            inventory,
            root["public_key"],
            label=f"{root['domain']} public key",
        )
    _add_descriptor(
        inventory,
        ledger["ledger_signature"]["public_key"],
        label="ledger signing public key",
    )
    return inventory


def _phase_map(ledger: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    chain = ledger["workflow_chain"]
    return {str(item["phase"]): item for item in chain}


def _validate_workflow_chain(ledger: Mapping[str, Any]) -> None:
    release = ledger["release"]
    source = ledger["source"]
    repository = release["repository"]
    phases = _phase_map(ledger)
    if tuple(phases) != PHASES:
        _fail("workflow chain must contain A through H exactly once and in order")

    candidate = source["candidate_commit_sha"]
    for phase, item in phases.items():
        if item["head_sha"] != candidate:
            _fail(f"phase {phase} head does not equal the admitted candidate")
        base_url = f"https://github.com/{repository}/actions/runs/{item['run_id']}"
        accepted_urls = {
            base_url,
            f"{base_url}/attempts/{item['run_attempt']}",
        }
        if item["run_url"] not in accepted_urls:
            _fail(f"phase {phase} run URL is not bound to its run and attempt")

    for phase, upstream in (
        ("B", "A"),
        ("C", "B"),
        ("D", "C"),
        ("F", "E"),
        ("G", "F"),
        ("H", "G"),
    ):
        reference = phases[phase]["upstream"]
        expected = {
            "phase": upstream,
            "run_id": phases[upstream]["run_id"],
            "run_attempt": phases[upstream]["run_attempt"],
        }
        if reference != expected:
            _fail(f"phase {phase} is not bound to the exact {upstream} attempt")

    c = phases["C"]
    d = phases["D"]
    for key in (
        "workflow_id",
        "workflow_path",
        "workflow_blob_sha",
        "run_id",
        "run_attempt",
        "head_sha",
        "run_url",
    ):
        if c[key] != d[key]:
            _fail(f"phase D does not share C's workflow run binding: {key}")

    unique_runs = [phases[name]["run_id"] for name in ("A", "B", "C", "E", "F", "G", "H")]
    if len(set(unique_runs)) != len(unique_runs):
        _fail("the seven A-H workflow runs must have distinct run IDs")
    unique_workflows = [
        (phases[name]["workflow_id"], phases[name]["workflow_blob_sha"])
        for name in ("A", "B", "C", "E", "F", "G", "H")
    ]
    if len(set(unique_workflows)) != len(unique_workflows):
        _fail("the seven protected workflow ID/blob pairs must be distinct")

    expected_version = str(ledger["project"]["version"])
    expected_e_inputs = {
        "source_admission_run_id": c["run_id"],
        "source_admission_run_attempt": c["run_attempt"],
        "expected_version": expected_version,
    }
    if phases["E"]["dispatch_inputs"] != expected_e_inputs:
        _fail("phase E inputs do not bind the exact C attempt and release version")


def _validate_timeline(ledger: Mapping[str, Any]) -> None:
    """Prove the recorded A-H and post-publication chronology is coherent."""

    phases = _phase_map(ledger)
    windows: dict[str, tuple[datetime, datetime]] = {}
    prior_end: datetime | None = None
    for phase in PHASES:
        started = _parse_time(
            phases[phase]["started_utc"],
            label=f"workflow_chain.{phase}.started_utc",
        )
        completed = _parse_time(
            phases[phase]["completed_utc"],
            label=f"workflow_chain.{phase}.completed_utc",
        )
        if completed < started:
            _fail(f"phase {phase} completes before it starts")
        if prior_end is not None and started < prior_end:
            _fail(f"phase {phase} starts before the preceding phase completed")
        windows[phase] = (started, completed)
        prior_end = completed

    created = _parse_time(
        ledger["release"]["created_utc"], label="release.created_utc"
    )
    published = _parse_time(
        ledger["release"]["published_utc"], label="release.published_utc"
    )
    ledger_created = _parse_time(
        ledger["ledger_scope"]["created_utc"], label="ledger_scope.created_utc"
    )
    if not (windows["H"][0] <= created <= published <= windows["H"][1]):
        _fail("release creation/publication must occur inside phase H")

    attestation_times = {
        name: _parse_time(
            value["verified_utc"],
            label=f"attestations.{name}.verified_utc",
        )
        for name, value in ledger["attestations"].items()
    }
    source_verified = attestation_times["source_producer"]
    if not (windows["B"][1] <= source_verified <= windows["C"][1]):
        _fail("source-producer attestation verification is outside B/C")
    for name in ("build_provenance", "spdx_provenance", "sbom_provenance"):
        if not (windows["E"][1] <= attestation_times[name] <= windows["F"][1]):
            _fail(f"{name} verification is outside E/F")
    if not (published <= attestation_times["release"] <= ledger_created):
        _fail("release attestation verification is outside publication/ledger time")

    observations: list[tuple[str, datetime]] = [
        (
            "repository_controls.observed_utc",
            _parse_time(
                ledger["repository_controls"]["observed_utc"],
                label="repository_controls.observed_utc",
            ),
        ),
        (
            "tag_ci.completed_utc",
            _parse_time(
                ledger["tag_ci"]["completed_utc"],
                label="tag_ci.completed_utc",
            ),
        ),
        (
            "tag_ci.observed_utc",
            _parse_time(
                ledger["tag_ci"]["observed_utc"],
                label="tag_ci.observed_utc",
            ),
        ),
        (
            "marketplace.observed_utc",
            _parse_time(
                ledger["marketplace"]["observed_utc"],
                label="marketplace.observed_utc",
            ),
        ),
    ]
    observations.extend(
        (
            f"control_evidence.{name}.observed_utc",
            _parse_time(
                value["observed_utc"],
                label=f"control_evidence.{name}.observed_utc",
            ),
        )
        for name, value in ledger["control_evidence"].items()
    )
    observations.extend(
        (
            f"repository_controls.admission_secret_absence_after_publication[{index}]"
            ".observed_utc",
            _parse_time(
                value["observed_utc"],
                label=(
                    "repository_controls."
                    f"admission_secret_absence_after_publication[{index}].observed_utc"
                ),
            ),
        )
        for index, value in enumerate(
            ledger["repository_controls"][
                "admission_secret_absence_after_publication"
            ]
        )
    )
    for label, observed in observations:
        if not (published <= observed <= ledger_created):
            _fail(f"{label} is outside publication/ledger time")
    tag_completed = dict(observations)["tag_ci.completed_utc"]
    tag_observed = dict(observations)["tag_ci.observed_utc"]
    if tag_observed < tag_completed:
        _fail("tag CI was observed before it completed")
    for label, observed in observations:
        if label.startswith(
            "repository_controls.admission_secret_absence_after_publication"
        ) and observed < windows["H"][1]:
            _fail(f"{label} predates phase H completion")


def _validate_controls(ledger: Mapping[str, Any]) -> None:
    phases = _phase_map(ledger)
    controls = ledger["control_evidence"]
    expected = {
        "source_external_controls": (
            "C",
            f"evoguard-release-source-v2-controls-{phases['C']['run_attempt']}",
            30,
            "control-manifest.json",
        ),
        "artifact_external_controls": (
            "F",
            (
                "evoguard-release-artifact-v1-complete-controls-"
                f"{phases['F']['run_attempt']}"
            ),
            30,
            "f-control-manifest.json",
        ),
        "publication_controls": (
            "G",
            f"evoguard-release-artifact-admission-v1-verified-{phases['G']['run_attempt']}",
            30,
            "publication-controls.json",
        ),
        "publication_ready": (
            "H",
            (
                f"evoguard-release-publication-ready-{phases['G']['run_id']}-"
                f"{phases['G']['run_attempt']}"
            ),
            1,
            "publication-ready.json",
        ),
    }
    artifact_ids: list[int] = []
    artifact_digests: list[str] = []
    repository = ledger["release"]["repository"]
    for name, (phase, artifact_name, retention, manifest_name) in expected.items():
        bundle = controls[name]
        run = phases[phase]
        if (
            bundle["workflow_run_id"] != run["run_id"]
            or bundle["workflow_run_attempt"] != run["run_attempt"]
        ):
            _fail(f"{name} is not bound to phase {phase}")
        github_artifact = bundle["github_artifact"]
        if github_artifact["name"] != artifact_name:
            _fail(f"{name} has the wrong GitHub artifact name")
        if github_artifact["retention_days"] != retention:
            _fail(f"{name} has the wrong retention window")
        artifact_ids.append(github_artifact["id"])
        artifact_digests.append(github_artifact["digest"])
        expected_url = (
            f"https://github.com/{repository}/actions/runs/{run['run_id']}/"
            f"artifacts/{github_artifact['id']}"
        )
        if github_artifact["url"] != expected_url:
            _fail(f"{name} GitHub artifact URL is not exact")
        if PurePosixPath(bundle["manifest"]["path"]).name != manifest_name:
            _fail(f"{name} has the wrong manifest path")
        material_paths = [item["path"] for item in bundle["materials"]]
        if len(set(material_paths)) != len(material_paths):
            _fail(f"{name} contains duplicate material paths")
        if bundle["manifest"]["path"] in material_paths:
            _fail(f"{name} repeats its manifest as a material")
        material_names = {PurePosixPath(path).name for path in material_paths}
        expected_material_names = {
            "source_external_controls": SOURCE_CONTROL_MATERIALS,
            "artifact_external_controls": ARTIFACT_CONTROL_MATERIALS,
            "publication_controls": PUBLICATION_CONTROL_MATERIALS,
            "publication_ready": PUBLICATION_READY_MATERIALS,
        }[name]
        if len(material_names) != len(material_paths) or (
            material_names != expected_material_names
        ):
            _fail(
                f"{name} material set is not exact; "
                f"expected={sorted(expected_material_names)}, "
                f"actual={sorted(material_names)}"
            )
    if len(set(artifact_ids)) != len(artifact_ids):
        _fail("control evidence GitHub artifact IDs must be distinct")
    if len(set(artifact_digests)) != len(artifact_digests):
        _fail("control evidence GitHub artifact digests must be distinct")

    assets = {item["name"]: item for item in ledger["artifacts"]}
    artifact_materials = {
        PurePosixPath(item["path"]).name: item
        for item in controls["artifact_external_controls"]["materials"]
    }
    if len(artifact_materials) != len(
        controls["artifact_external_controls"]["materials"]
    ):
        _fail("artifact controls repeat a retained filename")
    expected_artifact_materials = {
        name: {
            "size_bytes": assets[name]["size_bytes"],
            "sha256": assets[name]["sha256"],
        }
        for name in ("evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS")
    }
    expected_artifact_materials["source-allow.rsae"] = {
        "size_bytes": ledger["source_admission"]["rsae"]["size_bytes"],
        "sha256": ledger["source_admission"]["rsae"]["sha256"],
    }
    for name, expected_descriptor in expected_artifact_materials.items():
        material = artifact_materials.get(name)
        if material is None or any(
            material.get(field) != expected
            for field, expected in expected_descriptor.items()
        ):
            _fail(f"artifact controls do not retain the exact {name} bytes")

    publication_materials = {
        PurePosixPath(item["path"]).name
        for item in controls["publication_ready"]["materials"]
    }
    if len(publication_materials) != len(
        controls["publication_ready"]["materials"]
    ) or publication_materials != {
        "evo-guard.pyz",
        "evo-guard.spdx.json",
        "SHA256SUMS",
    }:
        _fail("publication-ready materials must be exactly the three release assets")
    for material in controls["publication_ready"]["materials"]:
        asset = assets[PurePosixPath(material["path"]).name]
        if (
            material["size_bytes"] != asset["size_bytes"]
            or material["sha256"] != asset["sha256"]
        ):
            _fail("publication-ready materials do not equal the release assets")


def _validate_admissions(ledger: Mapping[str, Any]) -> None:
    source = ledger["source"]
    roots = {item["domain"]: item["key_id"] for item in ledger["trust_roots"]}
    source_admission = ledger["source_admission"]
    if (
        source_admission["target_commit_sha"] != source["candidate_commit_sha"]
        or source_admission["target_tree_sha"] != source["candidate_tree_sha"]
    ):
        _fail("RSAE target does not match the release source")
    if source_admission["rsae"]["key_id"] != roots["release-source-admission-v2"]:
        _fail("RSAE key does not match its recorded public root")

    artifact_admission = ledger["artifact_admission"]
    if artifact_admission["source_rsae_sha256"] != source_admission["rsae"]["sha256"]:
        _fail("RAAE evidence does not bind the retained RSAE bytes")
    assets = {item["name"]: item for item in ledger["artifacts"]}
    for subject in artifact_admission["subjects"]:
        asset = assets[subject["name"]]
        if (
            subject["artifact_sha256"] != asset["sha256"]
            or subject["artifact_size_bytes"] != asset["size_bytes"]
        ):
            _fail(f"RAAE subject does not match release asset: {subject['name']}")
        if subject["raae"]["key_id"] != roots["release-artifact-admission-v1"]:
            _fail(f"RAAE key does not match its public root: {subject['name']}")
    raae_paths = [item["raae"]["path"] for item in artifact_admission["subjects"]]
    if len(set(raae_paths)) != 2:
        _fail("the two admitted assets must use separate RAAE envelopes")


def _validate_attestations(ledger: Mapping[str, Any]) -> None:
    phases = _phase_map(ledger)
    source = ledger["source"]
    attestations = ledger["attestations"]
    assets = {item["name"]: item for item in ledger["artifacts"]}

    expected = {
        "source_producer": ("B", "producer-receipt.json"),
        "build_provenance": ("E", "evo-guard.pyz"),
        "spdx_provenance": ("E", "evo-guard.spdx.json"),
        # An SPDX predicate describes the pyz subject; the SPDX document is the
        # predicate payload, not a second GitHub attestation subject.
        "sbom_provenance": ("E", "evo-guard.pyz"),
    }
    expected_predicates = {
        "source_producer": "https://slsa.dev/provenance/v1",
        "build_provenance": "https://slsa.dev/provenance/v1",
        "spdx_provenance": "https://slsa.dev/provenance/v1",
        "sbom_provenance": "https://spdx.dev/Document/v2.3",
    }
    descriptors = _collect_descriptors(ledger)
    for name, (phase, subject_name) in expected.items():
        attestation = attestations[name]
        run = phases[phase]
        if (
            attestation["signer_workflow"] != run["workflow_path"]
            or attestation["signer_workflow_blob_sha"] != run["workflow_blob_sha"]
            or attestation["run_id"] != run["run_id"]
            or attestation["run_attempt"] != run["run_attempt"]
            or attestation["source_digest"] != source["candidate_commit_sha"]
            or attestation["subject_name"] != subject_name
            or attestation["predicate_type"] != expected_predicates[name]
        ):
            _fail(f"{name} is not bound to the exact phase {phase} identity")

    producer_candidates = [
        (path, descriptor)
        for path, descriptor in descriptors.items()
        if PurePosixPath(path).name == "producer-receipt.json"
    ]
    if len(producer_candidates) != 1:
        _fail("retained evidence must contain exactly one producer-receipt.json")
    if attestations["source_producer"]["subject_sha256"] != producer_candidates[0][1][1]:
        _fail("source producer attestation does not bind the retained receipt")
    expected_subject_digests = {
        "build_provenance": assets["evo-guard.pyz"]["sha256"],
        "spdx_provenance": assets["evo-guard.spdx.json"]["sha256"],
        "sbom_provenance": assets["evo-guard.pyz"]["sha256"],
    }
    for name, digest in expected_subject_digests.items():
        if attestations[name]["subject_sha256"] != digest:
            _fail(f"{name} does not bind its exact subject")

    release_attestation = attestations["release"]
    release = ledger["release"]
    if (
        release_attestation["tag"] != release["tag"]
        or release_attestation["commit_sha"] != release["commit_sha"]
        or release_attestation["purl"]
        != f"pkg:github/{release['repository']}@{release['tag']}"
    ):
        _fail("release attestation identity does not match the immutable release")
    observed_subjects = {
        item["name"]: item["sha256"]
        for item in release_attestation["asset_subjects"]
    }
    expected_subjects = {name: item["sha256"] for name, item in assets.items()}
    if observed_subjects != expected_subjects:
        _fail("release attestation does not bind all three immutable assets")


def _validate_repository_controls(ledger: Mapping[str, Any]) -> None:
    controls = ledger["repository_controls"]
    source = ledger["source"]
    main = controls["main_branch"]
    if main["head_sha"] != source["candidate_commit_sha"]:
        _fail("recorded protected-main head does not equal the admitted candidate")
    missing = REQUIRED_MAIN_CHECKS - set(main["required_checks"])
    if missing:
        _fail(f"protected main is missing required checks: {sorted(missing)}")

    environments = controls["environments"]
    ids = [item["id"] for item in environments]
    if len(set(ids)) != len(ids):
        _fail("protected Environment IDs must be distinct")
    if any(item["reviewer"] != "MANA-awam" for item in environments):
        _fail("protected release Environments must record reviewer MANA-awam")

    deploy_key = controls["release_deploy_key"]
    ruleset = controls["tag_ruleset"]
    if ruleset["bypass_actor_classes"] != [
        {
            "actor_type": "DeployKey",
            "actor_id": None,
            "bypass_mode": "always",
        }
    ]:
        _fail("tag ruleset bypass must remain the generic DeployKey actor class")
    if deploy_key["sole_write_enabled"] is not True:
        _fail("the release deploy key must be the sole write-enabled deploy key")
    expected_absence = [
        {
            "environment": "evoguard-release-source-v2",
            "secret_name": (
                "EVOGUARD_RELEASE_SOURCE_ADMISSION_V2_PRIVATE_KEY_B64"
            ),
            "present": False,
            "observed_utc": controls[
                "admission_secret_absence_after_publication"
            ][0]["observed_utc"],
            "observation_scope": "github-environment-secret-name-list",
        },
        {
            "environment": "evoguard-release-artifact-v1",
            "secret_name": (
                "EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1_PRIVATE_KEY_B64"
            ),
            "present": False,
            "observed_utc": controls[
                "admission_secret_absence_after_publication"
            ][1]["observed_utc"],
            "observation_scope": "github-environment-secret-name-list",
        },
    ]
    if controls["admission_secret_absence_after_publication"] != expected_absence:
        _fail("admission signing-secret absence observations are not exact")
    if controls["observation_evidence"]["path"] != (
        "controls/repository/repository-controls-observation.json"
    ):
        _fail("repository-control observation evidence path is not exact")
    retirement = controls["publication_authority_retirement"]
    if (
        retirement["deploy_key_id"] != deploy_key["id"]
        or retirement["status"] != "pending-post-ledger"
        or retirement["proof_boundary"] != "not-claimed-by-release-ledger"
    ):
        _fail("publication authority retirement must remain pending after the ledger")


def _validate_repository_control_observation_bytes(
    root: Path,
    ledger: Mapping[str, Any],
) -> None:
    controls = ledger["repository_controls"]
    descriptor = controls["observation_evidence"]
    data = _read_regular(
        _safe_retained_path(root, descriptor["path"]),
        limit=1024 * 1024,
        label="repository-control observation evidence",
    )
    value = _load_json_bytes(data, label="repository-control observation evidence")
    if canonical_json_bytes(value) != data:
        _fail("repository-control observation evidence is not canonical JSON")
    _require_exact_keys(
        value,
        {
            "format",
            "repository",
            "repository_id",
            "repository_owner_id",
            "collector",
            "github_api_version",
            "observations",
            "evidence_boundary",
        },
        label="repository-control observation evidence",
    )
    if (
        value["format"] != "EVOGUARD_REPOSITORY_CONTROL_OBSERVATION_V1"
        or value["repository"] != ledger["release"]["repository"]
        or value["repository_id"] != ledger["release"]["repository_id"]
        or value["repository_owner_id"]
        != ledger["release"]["repository_owner_id"]
        or value["collector"]
        != {
            "name": "evoguard-release-ledger",
            "version": "2",
        }
        or value["github_api_version"] != "2022-11-28"
        or value["evidence_boundary"]
        != "owner-collected-point-in-time-github-api-observation"
    ):
        _fail("repository-control observation identity is not exact")
    observations = value["observations"]
    if not isinstance(observations, list) or len(observations) != 2:
        _fail("repository-control observation must contain exactly two API results")
    environments = {
        item["name"]: item["id"] for item in controls["environments"]
    }
    for index, (observed, expected) in enumerate(
        zip(
            observations,
            controls["admission_secret_absence_after_publication"],
            strict=True,
        )
    ):
        if not isinstance(observed, dict):
            _fail(f"repository-control observation {index} must be an object")
        _require_exact_keys(
            observed,
            {
                "environment_id",
                "environment",
                "api_action",
                "request_method",
                "endpoint",
                "http_status",
                "pagination_complete",
                "per_page",
                "page_count",
                "total_count",
                "queried_secret_name",
                "present",
                "observed_utc",
            },
            label=f"repository-control observation {index}",
        )
        expected_endpoint = (
            f"/repos/{ledger['release']['repository']}/environments/"
            f"{expected['environment']}/secrets"
        )
        if (
            observed["environment_id"] != environments[expected["environment"]]
            or observed["environment"] != expected["environment"]
            or observed["api_action"] != "list-environment-secrets"
            or observed["request_method"] != "GET"
            or observed["endpoint"] != expected_endpoint
            or observed["http_status"] != 200
            or observed["pagination_complete"] is not True
            or observed["per_page"] != 100
            or not isinstance(observed["page_count"], int)
            or isinstance(observed["page_count"], bool)
            or observed["page_count"] < 1
            or not isinstance(observed["total_count"], int)
            or isinstance(observed["total_count"], bool)
            or observed["total_count"] < 0
            or observed["page_count"]
            != max(1, (observed["total_count"] + 99) // 100)
            or observed["queried_secret_name"] != expected["secret_name"]
            or observed["present"] is not False
            or observed["observed_utc"] != expected["observed_utc"]
        ):
            _fail(f"repository-control observation {index} is not exact")


def _validate_semantics(
    ledger: Mapping[str, Any],
    *,
    schema_sha256: str,
) -> None:
    release = ledger["release"]
    project = ledger["project"]
    source = ledger["source"]
    expected_schema = {
        "id": OFFICIAL_SCHEMA_ID,
        "path": OFFICIAL_SCHEMA_REPOSITORY_PATH,
        "sha256": schema_sha256,
        "git_blob_sha": _git_blob_sha(DEFAULT_SCHEMA.read_bytes()),
        "trusted_parent_commit_sha": source["parent_commit_sha"],
        "trusted_parent_tree_sha": source["parent_tree_sha"],
    }
    if ledger["schema_contracts"]["release_ledger"] != expected_schema:
        _fail("signed ledger does not bind the exact official v2 schema bytes")
    validator_bytes = Path(__file__).read_bytes()
    expected_validator = {
        "path": VALIDATOR_REPOSITORY_PATH,
        "sha256": _sha256(validator_bytes),
        "git_blob_sha": _git_blob_sha(validator_bytes),
        "trusted_parent_commit_sha": source["parent_commit_sha"],
        "trusted_parent_tree_sha": source["parent_tree_sha"],
    }
    if ledger["schema_contracts"]["validator"] != expected_validator:
        _fail("signed ledger does not bind the exact trusted-parent validator bytes")
    parent_anchor = ledger["ledger_signature"]["trusted_parent_anchor"]
    if (
        parent_anchor["path"]
        != f"security/release-ledger-roots/{release['tag']}.pub.pem"
        or parent_anchor["trusted_parent_commit_sha"] != source["parent_commit_sha"]
        or parent_anchor["trusted_parent_tree_sha"] != source["parent_tree_sha"]
    ):
        _fail("ledger signing anchor is not bound to the exact trusted parent")
    if release["repository"] != EXPECTED_REPOSITORY:
        _fail(f"ledger repository must be {EXPECTED_REPOSITORY}")
    if release["tag"] != f"v{project['version']}":
        _fail("project version and release tag differ")
    if (
        release["commit_sha"] != source["candidate_commit_sha"]
        or release["tree_sha"] != source["candidate_tree_sha"]
    ):
        _fail("immutable release does not bind the admitted source")
    expected_release_url = (
        f"https://github.com/{release['repository']}/releases/tag/{release['tag']}"
    )
    if release["release_url"] != expected_release_url:
        _fail("release URL does not bind the recorded repository and tag")

    created = _parse_time(release["created_utc"], label="release.created_utc")
    published = _parse_time(release["published_utc"], label="release.published_utc")
    ledger_created = _parse_time(
        ledger["ledger_scope"]["created_utc"], label="ledger_scope.created_utc"
    )
    if published < created:
        _fail("release publication precedes draft creation")
    if ledger_created < published:
        _fail("a post-publication ledger cannot predate publication")

    assets = ledger["artifacts"]
    names = [item["name"] for item in assets]
    paths = [item["path"] for item in assets]
    ids = [item["release_asset_id"] for item in assets]
    digests = [item["sha256"] for item in assets]
    if len(set(names)) != 3 or len(set(paths)) != 3 or len(set(ids)) != 3:
        _fail("release asset names, paths, and IDs must each be unique")
    if len(set(digests)) != 3:
        _fail("the three release assets must not share a digest")
    for artifact in assets:
        if PurePosixPath(artifact["path"]).name != artifact["name"]:
            _fail(f"release artifact path changes its filename: {artifact['name']}")
        if artifact["github_digest"] != f"sha256:{artifact['sha256']}":
            _fail(f"GitHub digest does not match retained bytes: {artifact['name']}")
        expected_url = (
            f"https://github.com/{release['repository']}/releases/download/"
            f"{release['tag']}/{artifact['name']}"
        )
        if artifact["download_url"] != expected_url:
            _fail(f"release download URL is not exact: {artifact['name']}")

    artifact_map = {item["name"]: item for item in assets}
    checksum = ledger["checksum_manifest"]
    if (
        checksum["path"] != artifact_map["SHA256SUMS"]["path"]
        or checksum["manifest_sha256"] != artifact_map["SHA256SUMS"]["sha256"]
    ):
        _fail("checksum manifest descriptor does not match the release asset")
    expected_checksum_entries = [
        {
            "target": name,
            "sha256": artifact_map[name]["sha256"],
        }
        for name in ("evo-guard.pyz", "evo-guard.spdx.json")
    ]
    if checksum["entries"] != expected_checksum_entries:
        _fail("checksum entries do not bind the runtime and SPDX bytes")

    _validate_workflow_chain(ledger)
    _validate_timeline(ledger)
    _validate_controls(ledger)
    _validate_admissions(ledger)
    _validate_attestations(ledger)
    _validate_repository_controls(ledger)

    roots = ledger["trust_roots"]
    if tuple(item["domain"] for item in roots) != ROOT_DOMAINS:
        _fail("the six public roots are not in the canonical domain order")
    root_ids = [item["key_id"] for item in roots]
    root_paths = [item["public_key"]["path"] for item in roots]
    if len(set(root_ids)) != 6 or len(set(root_paths)) != 6:
        _fail("the six public roots must have distinct key IDs and paths")
    if ledger["ledger_signature"]["key_id"] in set(root_ids):
        _fail("ledger signing key must be distinct from all six admission roots")

    toolchain = ledger["toolchain"]
    bootstrap = toolchain["bootstrap_guard"]
    expected_bootstrap_url = (
        f"https://github.com/{release['repository']}/releases/download/"
        f"v{bootstrap['version']}/evo-guard.pyz"
    )
    if bootstrap["url"] != expected_bootstrap_url:
        _fail(
            "bootstrap Guard URL does not bind its repository, version, "
            "and runtime asset"
        )
    image_digest = toolchain["runner_image"]["sha256"]
    if not toolchain["runner_image"]["reference"].endswith(f"@sha256:{image_digest}"):
        _fail("runner image reference does not bind its recorded digest")
    if toolchain["trusted_build_inputs"]["source_parent_sha"] != source["parent_commit_sha"]:
        _fail("trusted build tools are not bound to the candidate's sole parent")
    if (
        toolchain["trusted_build_inputs"]["source_parent_tree_sha"]
        != source["parent_tree_sha"]
    ):
        _fail("trusted build tools are not bound to the sole parent tree")
    if toolchain["runner_image"]["network"] != "none":
        _fail("trusted build container must run without a network")
    source_identity = toolchain["provider_identities"]["source_admission"]
    artifact_identity = toolchain["provider_identities"]["artifact_admission"]
    if source_identity == artifact_identity:
        _fail("source and artifact provider identities must be distinct")
    expected_provider_identities = {
        "source_admission": {"platform": "posix", "uid": 60001, "gid": 60001},
        "artifact_admission": {"platform": "posix", "uid": 60002, "gid": 60002},
    }
    if toolchain["provider_identities"] != expected_provider_identities:
        _fail("provider identities do not equal the protected workflow identities")

    tag_ci = ledger["tag_ci"]
    expected_tag_ref = f"refs/tags/{release['tag']}"
    if (
        tag_ci["tag_ref"] != expected_tag_ref
        or tag_ci["head_sha"] != source["candidate_commit_sha"]
        or tuple(tag_ci["successful_jobs"]) != EXPECTED_TAG_JOBS
    ):
        _fail("tag CI does not bind the release tag, source, and exact job set")
    expected_tag_run_url = (
        f"https://github.com/{release['repository']}/actions/runs/{tag_ci['run_id']}"
    )
    if tag_ci["run_url"] not in {
        expected_tag_run_url,
        f"{expected_tag_run_url}/attempts/{tag_ci['attempt']}",
    }:
        _fail("tag CI URL does not bind its run and attempt")

    marketplace = ledger["marketplace"]
    if marketplace["version"] != release["tag"]:
        _fail("Marketplace observation does not name the release tag")
    if _parse_time(
        marketplace["observed_utc"], label="marketplace.observed_utc"
    ) < published:
        _fail("Marketplace observation predates release publication")


def _validate_structure_with_official_schema(
    ledger: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    schema_sha256: str,
) -> None:
    errors = _schema_errors(ledger, schema)
    if errors:
        preview = "\n".join(f"- {message}" for message in errors[:20])
        suffix = "" if len(errors) <= 20 else f"\n- ... {len(errors) - 20} more"
        _fail(f"release-ledger-v2 schema validation failed:\n{preview}{suffix}")
    _validate_semantics(ledger, schema_sha256=schema_sha256)


def validate_structure(ledger: Mapping[str, Any]) -> None:
    """Validate only against the repository's exact official v2 schema bytes."""

    schema, schema_sha256 = _load_official_schema()
    _validate_structure_with_official_schema(
        ledger,
        schema,
        schema_sha256=schema_sha256,
    )


def _safe_retained_path(root: Path, relative: str) -> Path:
    if "\\" in relative:
        _fail(f"backslash is forbidden in retained path: {relative}")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts:
        _fail(f"retained path is not relative: {relative}")
    if any(part in {"", ".", ".."} for part in pure.parts):
        _fail(f"unsafe retained path component: {relative}")
    target = root.joinpath(*pure.parts)
    resolved_root = root.resolve()
    try:
        resolved_target = target.resolve(strict=False)
    except OSError as exc:
        raise LedgerValidationError(f"cannot resolve retained path: {relative}") from exc
    if not resolved_target.is_relative_to(resolved_root):
        _fail(f"retained path escapes ledger root: {relative}")
    current = target
    while current != root:
        if current.exists() or current.is_symlink():
            metadata = current.lstat()
            if _is_link_like(metadata):
                _fail(f"link-like component in retained path: {relative}")
        current = current.parent
    return target


def _actual_inventory(
    root: Path,
    *,
    expected_files: set[str],
    expected_directories: set[str],
    max_files: int = MAX_RETAINED_FILES + 2,
    max_directories: int = (MAX_RETAINED_FILES * 8) + 1,
    max_total_bytes: int = (
        MAX_RETAINED_TOTAL_BYTES + MAX_JSON_BYTES + CANONICAL_SIGNATURE_BYTES
    ),
) -> tuple[
    set[str],
    set[str],
    dict[str, tuple[int, int, int, int, int]],
]:
    files: set[str] = set()
    directories_found: set[str] = {"."}
    identities: dict[str, tuple[int, int, int, int, int]] = {}
    file_objects: dict[tuple[int, int], str] = {}
    if (
        max_files < 1
        or max_directories < 1
        or max_total_bytes < 1
        or len(expected_files) > max_files
        or len(expected_directories) > max_directories
    ):
        _fail("expected ledger inventory exceeds its bounded scan budget")
    pending: list[tuple[Path, str]] = [(root, ".")]
    total_bytes = 0
    while pending:
        current_path, current_relative = pending.pop()
        if current_relative not in expected_directories:
            _fail(
                "ledger directory set is not exact; unexpected directory: "
                f"{current_relative}"
            )
        current_metadata = current_path.lstat()
        if _is_link_like(current_metadata) or not stat.S_ISDIR(
            current_metadata.st_mode
        ):
            _fail(f"ledger directory contains an unsafe directory: {current_path}")
        directories_found.add(current_relative)
        identities[f"d:{current_relative}"] = _inventory_identity(current_metadata)
        try:
            entries = os.scandir(current_path)
        except OSError as exc:
            raise LedgerValidationError(
                f"cannot scan ledger directory: {current_path}"
            ) from exc
        with entries:
            for entry in entries:
                path = current_path / entry.name
                relative = (
                    entry.name
                    if current_relative == "."
                    else f"{current_relative}/{entry.name}"
                )
                try:
                    metadata = path.lstat()
                except OSError as exc:
                    raise LedgerValidationError(
                        f"cannot inspect ledger inventory entry: {path}"
                    ) from exc
                if _is_link_like(metadata):
                    _fail(f"ledger directory contains a link-like entry: {path}")
                if stat.S_ISDIR(metadata.st_mode):
                    if relative not in expected_directories:
                        _fail(
                            "ledger directory set is not exact; unexpected directory: "
                            f"{relative}"
                        )
                    if len(directories_found) + len(pending) >= len(
                        expected_directories
                    ):
                        _fail("ledger directory count exceeds its expected budget")
                    pending.append((path, relative))
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    _fail(f"ledger directory contains an unsafe file: {path}")
                if metadata.st_nlink != 1:
                    _fail(f"ledger directory contains a hard-linked file: {path}")
                if relative not in expected_files:
                    _fail(f"ledger file set is not exact; unexpected file: {relative}")
                if len(files) >= len(expected_files):
                    _fail("ledger file count exceeds its expected budget")
                total_bytes += metadata.st_size
                if total_bytes > max_total_bytes:
                    _fail("ledger inventory exceeds its total byte scan budget")
                object_id = (metadata.st_dev, metadata.st_ino)
                prior = file_objects.get(object_id)
                if prior is not None:
                    _fail(
                        f"ledger files share one filesystem object: {prior}, {relative}"
                    )
                file_objects[object_id] = relative
                files.add(relative)
                identities[f"f:{relative}"] = _inventory_identity(metadata)
    return files, directories_found, identities


def _expected_directories(files: set[str]) -> set[str]:
    expected = {"."}
    for relative in files:
        parent = PurePosixPath(relative).parent
        while parent != PurePosixPath("."):
            expected.add(parent.as_posix())
            parent = parent.parent
    return expected


def _require_retained_budget(
    inventory: Mapping[str, tuple[int, str]],
) -> None:
    if len(inventory) > MAX_RETAINED_FILES:
        _fail(
            f"retained evidence file count exceeds {MAX_RETAINED_FILES}: "
            f"{len(inventory)}"
        )
    total = 0
    for relative, (size, _digest) in inventory.items():
        if size > MAX_RETAINED_FILE_BYTES:
            _fail(
                f"retained evidence file exceeds {MAX_RETAINED_FILE_BYTES} bytes: "
                f"{relative}"
            )
        total += size
        if total > MAX_RETAINED_TOTAL_BYTES:
            _fail(
                f"retained evidence total exceeds {MAX_RETAINED_TOTAL_BYTES} bytes"
            )


def _write_snapshot_file(path: Path, data: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise LedgerValidationError(
            f"cannot create protected evidence snapshot file: {path}"
        ) from exc
    try:
        remaining = memoryview(data)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                _fail(f"short write while creating protected evidence snapshot: {path}")
            remaining = remaining[written:]
        os.fsync(descriptor)
    except OSError as exc:
        raise LedgerValidationError(
            f"cannot write protected evidence snapshot file: {path}"
        ) from exc
    finally:
        os.close(descriptor)


def _materialize_snapshot(
    root: Path,
    files: Mapping[str, bytes],
    *,
    max_files: int = MAX_RETAINED_FILES + 2,
    max_directories: int = (MAX_RETAINED_FILES * 8) + 1,
    max_total_bytes: int = (
        MAX_RETAINED_TOTAL_BYTES + MAX_JSON_BYTES + CANONICAL_SIGNATURE_BYTES
    ),
) -> tuple[
    set[str],
    set[str],
    dict[str, tuple[int, int, int, int, int]],
]:
    expected_files = set(files)
    expected_directories = _expected_directories(expected_files)
    for relative in sorted(
        expected_directories - {"."},
        key=lambda value: (value.count("/"), value),
    ):
        target = root.joinpath(*PurePosixPath(relative).parts)
        try:
            target.mkdir(mode=0o700)
        except OSError as exc:
            raise LedgerValidationError(
                f"cannot create protected evidence snapshot directory: {relative}"
            ) from exc
    for relative, data in sorted(files.items()):
        target = _safe_retained_path(root, relative)
        _write_snapshot_file(target, data)

    actual_files, actual_directories, identities = _actual_inventory(
        root,
        expected_files=expected_files,
        expected_directories=expected_directories,
        max_files=max_files,
        max_directories=max_directories,
        max_total_bytes=max_total_bytes,
    )
    if actual_files != expected_files or actual_directories != expected_directories:
        _fail("protected evidence snapshot inventory is not exact")
    return actual_files, actual_directories, identities


def _require_original_bytes_unchanged(
    root: Path,
    *,
    ledger_bytes: bytes,
    signature_bytes: bytes,
    retained_bytes: Mapping[str, bytes],
) -> None:
    try:
        current_ledger = _read_regular(
            root / LEDGER_NAME,
            limit=MAX_JSON_BYTES,
            label="release ledger",
        )
    except LedgerValidationError as exc:
        raise LedgerValidationError(
            "RELEASE_LEDGER.json changed during validation"
        ) from exc
    if current_ledger != ledger_bytes:
        _fail("RELEASE_LEDGER.json changed during validation")
    try:
        current_signature = _read_regular(
            root / SIGNATURE_NAME,
            limit=CANONICAL_SIGNATURE_BYTES,
            label="release ledger signature",
        )
    except LedgerValidationError as exc:
        raise LedgerValidationError(
            "RELEASE_LEDGER.json.sig changed during validation"
        ) from exc
    if current_signature != signature_bytes:
        _fail("RELEASE_LEDGER.json.sig changed during validation")
    for relative, expected in retained_bytes.items():
        try:
            current = _read_regular(
                _safe_retained_path(root, relative),
                limit=max(len(expected), 1),
                label=f"retained evidence {relative}",
            )
        except LedgerValidationError as exc:
            raise LedgerValidationError(
                f"retained evidence changed during validation: {relative}"
            ) from exc
        if current != expected:
            _fail(f"retained evidence changed during validation: {relative}")


def _require_inventory_unchanged(
    root: Path,
    *,
    files: set[str],
    directories: set[str],
    identities: Mapping[str, tuple[int, int, int, int, int]],
    max_files: int = MAX_RETAINED_FILES + 2,
    max_directories: int = (MAX_RETAINED_FILES * 8) + 1,
    max_total_bytes: int = (
        MAX_RETAINED_TOTAL_BYTES + MAX_JSON_BYTES + CANONICAL_SIGNATURE_BYTES
    ),
) -> None:
    current_files, current_directories, current_identities = _actual_inventory(
        root,
        expected_files=files,
        expected_directories=directories,
        max_files=max_files,
        max_directories=max_directories,
        max_total_bytes=max_total_bytes,
    )
    if (
        current_files != files
        or current_directories != directories
        or current_identities != identities
    ):
        _fail("ledger inventory changed while validation was in progress")


def _validate_control_bytes(
    root: Path,
    ledger: Mapping[str, Any],
) -> None:
    release = ledger["release"]
    source = ledger["source"]
    phases = _phase_map(ledger)
    roots = {item["domain"]: item["key_id"] for item in ledger["trust_roots"]}
    toolchain = ledger["toolchain"]

    def retained_materials(bundle: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        values: dict[str, dict[str, Any]] = {}
        for descriptor in bundle["materials"]:
            name = PurePosixPath(descriptor["path"]).name
            if name in values:
                _fail(f"control bundle repeats a retained filename: {name}")
            values[name] = {
                "sha256": descriptor["sha256"],
                "size": descriptor["size_bytes"],
            }
        return values

    def material_descriptors(
        bundle: Mapping[str, Any],
    ) -> dict[str, Mapping[str, Any]]:
        values: dict[str, Mapping[str, Any]] = {}
        for descriptor in bundle["materials"]:
            filename = PurePosixPath(descriptor["path"]).name
            if filename in values:
                _fail(f"control bundle repeats a retained filename: {filename}")
            values[filename] = descriptor
        return values

    manifest_keys = {
        "source_external_controls": {
            "format",
            "repository",
            "repository_id",
            "target_sha",
            "workflows",
            "toolchain",
            "public_key_ids",
            "materials",
        },
        "artifact_external_controls": {
            "format",
            "artifacts",
            "checksums",
            "release_source_admission",
            "release_version",
            "repository",
            "repository_id",
            "target_sha",
            "external_settings",
            "trusted_tools",
            "attestation_evidence",
            "workflows",
        },
        "publication_controls": {
            "format",
            "repository",
            "target_sha",
            "release_version",
            "f",
            "g",
            "f_control_manifest",
            "f_external_settings",
            "f_trusted_tools",
            "f_workflows",
            "release_assets",
            "admissions",
            "attestation_evidence",
        },
        "publication_ready": {
            "format",
            "repository",
            "target_sha",
            "tag",
            "g_run_id",
            "g_run_attempt",
            "tag_deploy_key_fingerprint",
            "host_tools",
            "assets",
        },
    }

    for name, bundle in ledger["control_evidence"].items():
        manifest_path = _safe_retained_path(root, bundle["manifest"]["path"])
        manifest_bytes = _read_regular(
            manifest_path,
            limit=MAX_JSON_BYTES,
            label=f"{name} manifest",
        )
        manifest = _load_json_bytes(manifest_bytes, label=f"{name} manifest")
        if canonical_json_bytes(manifest) != manifest_bytes:
            _fail(f"{name} manifest is not canonical JSON")
        _require_exact_keys(
            manifest,
            manifest_keys[name],
            label=f"{name} manifest",
        )
        if manifest.get("format") != bundle["format"]:
            _fail(f"{name} retained format differs from the ledger")
        if manifest.get("repository") != release["repository"]:
            _fail(f"{name} retained repository differs from the ledger")
        if manifest.get("target_sha") != source["candidate_commit_sha"]:
            _fail(f"{name} retained target differs from the candidate")

        if name == "source_external_controls":
            workflows = manifest.get("workflows")
            expected_workflows = {
                "A": {
                    "id": str(phases["A"]["workflow_id"]),
                    "blob": phases["A"]["workflow_blob_sha"],
                },
                "B": {
                    "id": str(phases["B"]["workflow_id"]),
                    "blob": phases["B"]["workflow_blob_sha"],
                    "run_id": str(phases["B"]["run_id"]),
                    "run_attempt": phases["B"]["run_attempt"],
                },
                "C": {
                    "id": str(phases["C"]["workflow_id"]),
                    "blob": phases["C"]["workflow_blob_sha"],
                    "run_id": str(phases["C"]["run_id"]),
                    "run_attempt": phases["C"]["run_attempt"],
                },
            }
            if workflows != expected_workflows:
                _fail("source controls do not bind the exact A/B/C identities")
            if manifest.get("materials") != retained_materials(bundle):
                _fail("source controls do not inventory their retained material bytes")
            expected_toolchain = {
                "git_sha256": toolchain["git"]["sha256"],
                "gh_sha256": toolchain["github_cli"]["sha256"],
                "provider_uid": toolchain["provider_identities"]["source_admission"][
                    "uid"
                ],
                "provider_gid": toolchain["provider_identities"]["source_admission"][
                    "gid"
                ],
            }
            expected_roots = {
                "release_source_admission_v2": roots[
                    "release-source-admission-v2"
                ],
                "trusted_finalizer": roots["trusted-finalizer"],
                "artifact_admission_v1": roots["artifact-admission-v1"],
                "artifact_digest_admission_v2": roots[
                    "artifact-digest-admission-v2"
                ],
                "release_source_finalizer_v1": roots[
                    "release-source-finalizer-v1"
                ],
            }
            if (
                manifest.get("repository_id") != release["repository_id"]
                or manifest.get("toolchain") != expected_toolchain
                or manifest.get("public_key_ids") != expected_roots
            ):
                _fail("source controls differ from the recorded tool and root pins")
        elif name == "artifact_external_controls":
            workflows = manifest.get("workflows")
            if not isinstance(workflows, dict):
                _fail("artifact controls have no E/F identities")
            for phase in ("E", "F"):
                value = workflows.get(phase)
                if not isinstance(value, dict):
                    _fail(f"artifact controls have no phase {phase} identity")
                expected_run = phases[phase]
                expected_identity = {
                    "workflow_repository": release["repository"],
                    "workflow_repository_id": release["repository_id"],
                    "workflow_id": str(expected_run["workflow_id"]),
                    "workflow_path": expected_run["workflow_path"],
                    "workflow_blob_sha": expected_run["workflow_blob_sha"],
                    "workflow_run_id": str(expected_run["run_id"]),
                    "workflow_run_attempt": expected_run["run_attempt"],
                    "workflow_event": expected_run["event"],
                    "workflow_ref": "refs/heads/main",
                    "workflow_commit_sha": source["candidate_commit_sha"],
                    "runner_class": "github-hosted",
                }
                if value != expected_identity:
                    _fail(f"artifact controls do not bind the exact phase {phase}")
            material_map = retained_materials(bundle)
            descriptor_map = material_descriptors(bundle)
            required_materials = {
                "evo-guard.pyz",
                "evo-guard.spdx.json",
                "SHA256SUMS",
                "source-allow.rsae",
            }
            missing_materials = required_materials - set(material_map)
            if missing_materials:
                _fail(
                    "artifact controls omit retained materials: "
                    f"{sorted(missing_materials)}"
                )
            expected_artifacts = {
                filename: material_map[filename]
                for filename in ("evo-guard.pyz", "evo-guard.spdx.json")
            }
            expected_roots = {
                "release_artifact_admission_v1": roots[
                    "release-artifact-admission-v1"
                ],
                "release_source_admission_v2": roots[
                    "release-source-admission-v2"
                ],
                "trusted_finalizer": roots["trusted-finalizer"],
                "artifact_admission_v1": roots["artifact-admission-v1"],
                "artifact_digest_admission_v2": roots[
                    "artifact-digest-admission-v2"
                ],
                "release_source_finalizer_v1": roots[
                    "release-source-finalizer-v1"
                ],
            }
            expected_settings = {
                "runtime": {
                    "url": toolchain["bootstrap_guard"]["url"],
                    "version": toolchain["bootstrap_guard"]["version"],
                    "sha256": toolchain["bootstrap_guard"]["sha256"],
                },
                "toolchain": {
                    "git_sha256": toolchain["git"]["sha256"],
                    "gh_sha256": toolchain["github_cli"]["sha256"],
                    "provider_uid": toolchain["provider_identities"][
                        "artifact_admission"
                    ]["uid"],
                    "provider_gid": toolchain["provider_identities"][
                        "artifact_admission"
                    ]["gid"],
                },
                "source_admission": {
                    "bootstrap_sha256": toolchain["bootstrap_guard"]["sha256"],
                    "git_sha256": toolchain["git"]["sha256"],
                    "gh_sha256": toolchain["github_cli"]["sha256"],
                    "provider_uid": toolchain["provider_identities"][
                        "source_admission"
                    ]["uid"],
                    "provider_gid": toolchain["provider_identities"][
                        "source_admission"
                    ]["gid"],
                },
                "publication": {
                    "tag_deploy_key_fingerprint": ledger["repository_controls"][
                        "release_deploy_key"
                    ]["fingerprint"],
                },
                "public_key_ids": expected_roots,
            }
            expected_trusted_tools = {
                "tools/ci/verify_spdx_attestation.py": toolchain[
                    "trusted_build_inputs"
                ]["spdx_attestation_verifier_blob_sha"]
            }
            evidence_names = (
                "build-provenance-verification.json",
                "build-provenance-verification-output.json",
                "spdx-provenance-verification.json",
                "spdx-provenance-verification-output.json",
                "sbom-attestation-receipt.json",
                "sbom-attestation-output.json",
            )
            expected_attestation_evidence = {
                filename: material_map[filename]
                for filename in evidence_names
            }
            if (
                manifest.get("repository_id") != release["repository_id"]
                or manifest.get("release_version") != ledger["project"]["version"]
                or manifest.get("artifacts") != expected_artifacts
                or manifest.get("checksums") != material_map["SHA256SUMS"]
                or manifest.get("release_source_admission")
                != material_map["source-allow.rsae"]
                or manifest.get("external_settings") != expected_settings
                or manifest.get("trusted_tools") != expected_trusted_tools
                or manifest.get("attestation_evidence")
                != expected_attestation_evidence
            ):
                _fail("artifact controls differ from retained assets, tools, or roots")
            verifier_descriptor = descriptor_map["verify_spdx_attestation.py"]
            verifier_bytes = _read_regular(
                _safe_retained_path(root, verifier_descriptor["path"]),
                limit=1024 * 1024,
                label="trusted SPDX attestation verifier",
            )
            if _git_blob_sha(verifier_bytes) != toolchain["trusted_build_inputs"][
                "spdx_attestation_verifier_blob_sha"
            ]:
                _fail("trusted SPDX attestation verifier blob is not exact")
            builder_descriptor = descriptor_map["builder-controls.json"]
            builder_path = _safe_retained_path(root, builder_descriptor["path"])
            builder_bytes = _read_regular(
                builder_path,
                limit=MAX_JSON_BYTES,
                label="E builder controls",
            )
            builder_controls = _load_json_bytes(
                builder_bytes,
                label="E builder controls",
            )
            if canonical_json_bytes(builder_controls) != builder_bytes:
                _fail("E builder controls are not canonical JSON")
            _require_exact_keys(
                builder_controls,
                {
                    "format",
                    "artifacts",
                    "checksums",
                    "release_source_admission",
                    "release_version",
                    "repository",
                    "source_created",
                    "source_admission_run_attempt",
                    "source_admission_run_id",
                    "target_sha",
                    "trusted_build_parent_sha",
                    "trusted_build_parent_tree_sha",
                    "trusted_build_tool_blobs",
                    "build_container",
                },
                label="E builder controls",
            )
            expected_builder_controls = {
                "format": "EVOGUARD_RELEASE_ASSET_BUILDER_CONTROLS_V1",
                "artifacts": expected_artifacts,
                "checksums": material_map["SHA256SUMS"],
                "release_source_admission": material_map["source-allow.rsae"],
                "release_version": ledger["project"]["version"],
                "repository": release["repository"],
                "source_created": builder_controls.get("source_created"),
                "source_admission_run_attempt": phases["C"]["run_attempt"],
                "source_admission_run_id": str(phases["C"]["run_id"]),
                "target_sha": source["candidate_commit_sha"],
                "trusted_build_parent_sha": source["parent_commit_sha"],
                "trusted_build_parent_tree_sha": source["parent_tree_sha"],
                "trusted_build_tool_blobs": {
                    "ops/build_pyz.py": toolchain["trusted_build_inputs"][
                        "build_pyz_blob_sha"
                    ],
                    "ops/generate_spdx_sbom.py": toolchain[
                        "trusted_build_inputs"
                    ]["spdx_generator_blob_sha"],
                },
                "build_container": {
                    "reference": toolchain["runner_image"]["reference"],
                    "sha256": toolchain["runner_image"]["sha256"],
                    "network": toolchain["runner_image"]["network"],
                },
            }
            _parse_time(
                builder_controls.get("source_created"),
                label="E builder controls source_created",
            )
            if builder_controls != expected_builder_controls:
                _fail(
                    "E builder controls do not bind the exact parent tree, "
                    "container, assets, source, and trusted tools"
                )
        elif name == "publication_controls":
            artifact_bundle = ledger["control_evidence"]["artifact_external_controls"]
            f_manifest_descriptor = artifact_bundle["manifest"]
            f_manifest_bytes = _read_regular(
                _safe_retained_path(root, f_manifest_descriptor["path"]),
                limit=MAX_JSON_BYTES,
                label="F control manifest cross-binding",
            )
            f_manifest = _load_json_bytes(
                f_manifest_bytes,
                label="F control manifest cross-binding",
            )
            for phase in ("F", "G"):
                value = manifest.get(phase.lower())
                run = phases[phase]
                expected_identity = {
                    "workflow_id": str(run["workflow_id"]),
                    "workflow_blob_sha": run["workflow_blob_sha"],
                    "workflow_run_id": str(run["run_id"]),
                    "workflow_run_attempt": run["run_attempt"],
                }
                if value != expected_identity:
                    _fail(f"publication controls do not bind the exact phase {phase}")
            expected_assets = {
                item["name"]: {
                    "sha256": item["sha256"],
                    "size": item["size_bytes"],
                }
                for item in ledger["artifacts"]
            }
            expected_admissions = {
                PurePosixPath(subject["raae"]["path"]).name: {
                    "sha256": subject["raae"]["sha256"],
                    "size": subject["raae"]["size_bytes"],
                }
                for subject in ledger["artifact_admission"]["subjects"]
            }
            publication_attestation_evidence: dict[str, dict[str, Any]] = {}
            for attestation_name in (
                "build_provenance",
                "spdx_provenance",
                "sbom_provenance",
            ):
                attestation = ledger["attestations"][attestation_name]
                for evidence_name in (
                    "verification_receipt",
                    "verification_output",
                ):
                    descriptor = attestation[evidence_name]
                    publication_attestation_evidence[
                        PurePosixPath(descriptor["path"]).name
                    ] = {
                        "sha256": descriptor["sha256"],
                        "size": descriptor["size_bytes"],
                    }
            if (
                manifest.get("release_version") != ledger["project"]["version"]
                or manifest.get("f_control_manifest")
                != {
                    "sha256": f_manifest_descriptor["sha256"],
                    "size": f_manifest_descriptor["size_bytes"],
                }
                or manifest.get("f_external_settings")
                != f_manifest.get("external_settings")
                or manifest.get("f_trusted_tools")
                != f_manifest.get("trusted_tools")
                or manifest.get("f_workflows") != f_manifest.get("workflows")
                or manifest.get("release_assets") != expected_assets
                or manifest.get("admissions") != expected_admissions
                or manifest.get("attestation_evidence")
                != publication_attestation_evidence
            ):
                _fail(
                    "publication controls do not bind the release assets "
                    "and both RAAE envelopes"
                )
        elif name == "publication_ready":
            if (
                manifest.get("repository") != release["repository"]
                or manifest.get("target_sha") != source["candidate_commit_sha"]
                or manifest.get("tag") != release["tag"]
                or manifest.get("g_run_id") != str(phases["G"]["run_id"])
                or manifest.get("g_run_attempt") != phases["G"]["run_attempt"]
                or manifest.get("tag_deploy_key_fingerprint")
                != ledger["repository_controls"]["release_deploy_key"]["fingerprint"]
            ):
                _fail("publication-ready record does not bind the reviewed G attempt")
            host_tools = manifest.get("host_tools")
            if not isinstance(host_tools, dict) or set(host_tools) != {
                "git",
                "gh",
                "ssh",
                "ssh_keygen",
            }:
                _fail("publication-ready host tool set is not exact")
            for tool_name, descriptor in host_tools.items():
                if not isinstance(descriptor, dict):
                    _fail(f"publication-ready host tool is not an object: {tool_name}")
                _require_exact_keys(
                    descriptor,
                    {"path", "sha256", "size"},
                    label=f"publication-ready host tool {tool_name}",
                )
                if (
                    not isinstance(descriptor.get("path"), str)
                    or not descriptor["path"].startswith("/")
                    or not re.fullmatch(r"[0-9a-f]{64}", str(descriptor.get("sha256")))
                    or not isinstance(descriptor.get("size"), int)
                    or isinstance(descriptor.get("size"), bool)
                    or not 1 <= descriptor["size"] <= 64 * 1024 * 1024
                ):
                    _fail(
                        f"publication-ready host tool descriptor is invalid: {tool_name}"
                    )
            if (
                host_tools["git"]["sha256"] != toolchain["git"]["sha256"]
                or host_tools["gh"]["sha256"]
                != toolchain["github_cli"]["sha256"]
            ):
                _fail("publication-ready host tools differ from the reviewed pins")
            expected_assets = {
                item["name"]: {
                    "sha256": item["sha256"],
                    "size": item["size_bytes"],
                }
                for item in ledger["artifacts"]
            }
            if manifest.get("assets") != expected_assets:
                _fail("publication-ready record does not bind the three release assets")


def _load_canonical_json_descriptor(
    root: Path,
    descriptor: Mapping[str, Any],
    *,
    label: str,
) -> dict[str, Any]:
    data = _read_regular(
        _safe_retained_path(root, descriptor["path"]),
        limit=MAX_JSON_BYTES,
        label=label,
    )
    value = _load_json_bytes(data, label=label)
    if canonical_json_bytes(value) != data:
        _fail(f"{label} is not canonical JSON")
    return value


def _validate_source_result(
    root: Path,
    descriptor: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    sealed: bool,
    bundle_name: str,
    label: str,
) -> None:
    value = _load_canonical_json_descriptor(root, descriptor, label=label)
    common = {
        "format": "EVOGUARD_RELEASE_SOURCE_ADMISSION_V2",
        "ok": True,
        "verified": True,
        "status": "SEALED" if sealed else "VERIFIED",
        "key_id": manifest["authentication"]["key_id"],
        "record_sha256": manifest["record"]["sha256"],
        "producer_receipt_sha256": manifest["producer_receipt"]["sha256"],
        "decision": "ALLOW",
        "admission": True,
    }
    if sealed:
        _require_exact_keys(
            value,
            set(common) | {"sealed", "bundle", "provider_verified"},
            label=label,
        )
        bundle = value.get("bundle")
        if (
            not isinstance(bundle, str)
            or PurePosixPath(bundle.replace("\\", "/")).name != bundle_name
        ):
            _fail(f"{label} names the wrong sealed bundle")
        expected = {
            **common,
            "sealed": True,
            "bundle": bundle,
            "provider_verified": True,
        }
    else:
        _require_exact_keys(value, set(common), label=label)
        expected = common
    if value != expected:
        _fail(f"{label} does not equal the actual C/D success report contract")


def _validate_artifact_result(
    root: Path,
    descriptor: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    sealed: bool,
    bundle_name: str,
    label: str,
) -> None:
    value = _load_canonical_json_descriptor(root, descriptor, label=label)
    common = {
        "format": "EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1",
        "ok": True,
        "verified": True,
        "status": "SEALED" if sealed else "VERIFIED",
        "artifact": manifest["artifact"],
        "release_source": manifest["release_source"],
        "builder": manifest["builder"],
        "admitter": manifest["admitter"],
        "key_id": manifest["authentication"]["key_id"],
        "decision": "ALLOW",
        "admission": True,
        "live_provider_reverification": sealed,
    }
    if sealed:
        _require_exact_keys(
            value,
            set(common) | {"sealed", "bundle", "provider_verified"},
            label=label,
        )
        bundle = value.get("bundle")
        if (
            not isinstance(bundle, str)
            or PurePosixPath(bundle.replace("\\", "/")).name != bundle_name
        ):
            _fail(f"{label} names the wrong sealed bundle")
        expected = {
            **common,
            "sealed": True,
            "bundle": bundle,
            "provider_verified": True,
        }
    else:
        _require_exact_keys(
            value,
            set(common) | {"verification_scope"},
            label=label,
        )
        expected = {
            **common,
            "verification_scope": "detached-offline-retained-provider-evidence",
        }
    if value != expected:
        _fail(f"{label} does not equal the actual F/G success report contract")


def _strict_attestation_parts(
    data: bytes,
    *,
    repository: str,
    repository_id: str,
    repository_owner_id: str,
    workflow_path: str,
    source_digest: str,
    run_id: int,
    run_attempt: int,
    expected_event: str,
    subject_name: str,
    subject_sha256: str,
    predicate_type: str,
    label: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    decoded = _load_json_value_bytes(data, label=label)
    if (
        not isinstance(decoded, list)
        or len(decoded) != 1
        or not isinstance(decoded[0], dict)
    ):
        _fail(f"{label} must contain exactly one attestation object")
    entry = decoded[0]
    _require_exact_keys(
        entry,
        {"attestation", "verificationResult"},
        label=f"{label} entry",
    )
    if not isinstance(entry["attestation"], dict):
        _fail(f"{label} opaque attestation must be an object")
    result = entry["verificationResult"]
    if not isinstance(result, dict):
        _fail(f"{label} verificationResult must be an object")
    _require_required_keys(
        result,
        {"signature", "verifiedIdentity", "statement"},
        label=f"{label} verificationResult",
    )
    signature = result["signature"]
    identity = result["verifiedIdentity"]
    statement = result["statement"]
    if not all(isinstance(value, dict) for value in (signature, identity, statement)):
        _fail(f"{label} signature, identity, and statement must be objects")
    _require_required_keys(
        signature,
        {"certificate"},
        label=f"{label} signature",
    )
    certificate = signature["certificate"]
    if not isinstance(certificate, dict):
        _fail(f"{label} certificate must be an object")
    _require_required_keys(
        identity,
        {"subjectAlternativeName", "issuer", "runnerEnvironment"},
        label=f"{label} verifiedIdentity",
    )
    identity_san = identity["subjectAlternativeName"]
    identity_issuer = identity["issuer"]
    if not isinstance(identity_san, dict) or not isinstance(identity_issuer, dict):
        _fail(f"{label} verified identity constraints must be objects")
    _require_exact_keys(
        identity_san,
        {"subjectAlternativeName", "regexp"},
        label=f"{label} verified identity subject alternative name",
    )
    _require_exact_keys(
        identity_issuer,
        {"issuer", "regexp"},
        label=f"{label} verified identity issuer",
    )
    if (
        not all(isinstance(value, str) for value in identity_san.values())
        or not all(isinstance(value, str) for value in identity_issuer.values())
    ):
        _fail(f"{label} verified identity constraints must be strings")
    if expected_event not in {"workflow_run", "workflow_dispatch"}:
        _fail(f"{label} expected GitHub event is not supported")
    if not repository_id.isdigit() or (
        repository_id != "0" and repository_id.startswith("0")
    ):
        _fail(f"{label} repository ID is not canonical decimal")
    if not repository_owner_id.isdigit() or (
        repository_owner_id != "0" and repository_owner_id.startswith("0")
    ):
        _fail(f"{label} repository owner ID is not canonical decimal")
    workflow = f"{repository}/{workflow_path}"
    signer_base = f"https://github.com/{workflow}@"
    signer_uri = certificate.get("buildSignerURI")
    if signer_uri not in {
        signer_base + source_digest,
        signer_base + "refs/heads/main",
    }:
        _fail(f"{label} signer workflow URI is not exact")
    run_uri = (
        f"https://github.com/{repository}/actions/runs/{run_id}/"
        f"attempts/{run_attempt}"
    )
    expected_certificate = {
        "subjectAlternativeName": signer_uri,
        "issuer": "https://token.actions.githubusercontent.com",
        "githubWorkflowTrigger": expected_event,
        "githubWorkflowRepository": repository,
        "githubWorkflowSHA": source_digest,
        "githubWorkflowRef": "refs/heads/main",
        "buildSignerURI": signer_uri,
        "buildSignerDigest": source_digest,
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": f"https://github.com/{repository}",
        "sourceRepositoryDigest": source_digest,
        "sourceRepositoryRef": "refs/heads/main",
        "sourceRepositoryIdentifier": repository_id,
        "sourceRepositoryOwnerURI": (
            f"https://github.com/{repository.split('/', 1)[0]}"
        ),
        "sourceRepositoryVisibilityAtSigning": "public",
        "buildConfigURI": signer_uri,
        "buildConfigDigest": source_digest,
        "buildTrigger": expected_event,
        "runInvocationURI": run_uri,
    }
    _require_required_keys(
        certificate,
        set(expected_certificate),
        label=f"{label} certificate",
    )
    if any(certificate.get(key) != value for key, value in expected_certificate.items()):
        _fail(f"{label} certificate does not bind the exact workflow run")
    certificate_issuer = certificate.get("certificateIssuer")
    if certificate_issuer is not None and not isinstance(certificate_issuer, str):
        _fail(f"{label} certificate issuer metadata must be a string")
    if certificate.get("sourceRepositoryOwnerIdentifier") != repository_owner_id:
        _fail(f"{label} certificate repository owner ID is not exact")
    expected_san_pattern = f"^https://github.com/{workflow}"
    san_matches = identity_san == {
        "subjectAlternativeName": "",
        "regexp": expected_san_pattern,
    }
    issuer_matches = identity_issuer == {
        "issuer": "",
        "regexp": ".*",
    }
    if (
        identity.get("runnerEnvironment") != "github-hosted"
        or not san_matches
        or not issuer_matches
    ):
        _fail(f"{label} verified identity is not GitHub-hosted")
    _require_exact_keys(
        statement,
        {"_type", "subject", "predicateType", "predicate"},
        label=f"{label} statement",
    )
    subjects = statement["subject"]
    if (
        not isinstance(subjects, list)
        or len(subjects) != 1
        or not isinstance(subjects[0], dict)
    ):
        _fail(f"{label} must have exactly one subject")
    subject = subjects[0]
    _require_exact_keys(
        subject,
        {"name", "digest"},
        label=f"{label} subject",
    )
    digest = subject["digest"]
    if not isinstance(digest, dict):
        _fail(f"{label} subject digest must be an object")
    _require_exact_keys(
        digest,
        {"sha256"},
        label=f"{label} subject digest",
    )
    if subject != {"name": subject_name, "digest": {"sha256": subject_sha256}}:
        _fail(f"{label} subject does not bind the exact retained file")
    if (
        statement["_type"] != "https://in-toto.io/Statement/v1"
        or statement["predicateType"] != predicate_type
        or not isinstance(statement["predicate"], dict)
    ):
        _fail(f"{label} statement type or predicate type is not exact")
    return statement, certificate


def _validate_slsa_raw_output(
    data: bytes,
    *,
    repository: str,
    repository_id: str,
    repository_owner_id: str,
    workflow_path: str,
    source_digest: str,
    run_id: int,
    run_attempt: int,
    expected_event: str,
    subject_name: str,
    subject_sha256: str,
    subject_size: int,
    label: str,
) -> None:
    from evoom_guard.github_attestation import (
        GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
        GitHubAttestationArtifact,
        GitHubAttestationError,
        github_attestation_policy,
        validate_github_attestation_verifier_output,
    )

    artifact = GitHubAttestationArtifact(
        sha256=subject_sha256,
        size=subject_size,
    )
    policy = github_attestation_policy(
        repository,
        f"{repository}/{workflow_path}",
        source_digest,
        signer_digest=source_digest,
        source_ref="refs/heads/main",
        cert_oidc_issuer=GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
    )
    try:
        validate_github_attestation_verifier_output(
            data,
            artifact=artifact,
            policy=policy,
            expected_workflow_run_id=str(run_id),
            expected_workflow_run_attempt=run_attempt,
        )
    except GitHubAttestationError as exc:
        raise LedgerValidationError(f"{label} semantic verification failed: {exc}") from exc
    statement, certificate = _strict_attestation_parts(
        data,
        repository=repository,
        repository_id=repository_id,
        repository_owner_id=repository_owner_id,
        workflow_path=workflow_path,
        source_digest=source_digest,
        run_id=run_id,
        run_attempt=run_attempt,
        expected_event=expected_event,
        subject_name=subject_name,
        subject_sha256=subject_sha256,
        predicate_type="https://slsa.dev/provenance/v1",
        label=label,
    )
    predicate = statement["predicate"]
    _require_required_keys(
        predicate,
        {"buildDefinition", "runDetails"},
        label=f"{label} SLSA predicate",
    )
    definition = predicate["buildDefinition"]
    details = predicate["runDetails"]
    if not isinstance(definition, dict) or not isinstance(details, dict):
        _fail(f"{label} SLSA build definition and run details must be objects")
    _require_required_keys(
        definition,
        {
            "buildType",
            "externalParameters",
            "internalParameters",
            "resolvedDependencies",
        },
        label=f"{label} SLSA buildDefinition",
    )
    if definition["buildType"] != "https://actions.github.io/buildtypes/workflow/v1":
        _fail(f"{label} SLSA build type is not the GitHub workflow build type")
    external = definition["externalParameters"]
    internal = definition["internalParameters"]
    if not isinstance(external, dict) or not isinstance(internal, dict):
        _fail(f"{label} SLSA parameters must be objects")
    _require_required_keys(
        external,
        {"workflow"},
        label=f"{label} SLSA externalParameters",
    )
    workflow = external["workflow"]
    if not isinstance(workflow, dict):
        _fail(f"{label} SLSA workflow parameter must be an object")
    _require_exact_keys(
        workflow,
        {"repository", "ref", "path"},
        label=f"{label} SLSA workflow",
    )
    expected_workflow = {
        "repository": f"https://github.com/{repository}",
        "ref": "refs/heads/main",
        "path": workflow_path,
    }
    if workflow != expected_workflow:
        _fail(f"{label} SLSA workflow parameters are not exact")
    _require_required_keys(
        internal,
        {"github"},
        label=f"{label} SLSA internalParameters",
    )
    github = internal["github"]
    if not isinstance(github, dict):
        _fail(f"{label} SLSA GitHub parameters must be an object")
    _require_required_keys(
        github,
        {
            "event_name",
            "repository_id",
            "repository_owner_id",
            "runner_environment",
        },
        label=f"{label} SLSA GitHub parameters",
    )
    if (
        github.get("runner_environment") != "github-hosted"
        or github.get("event_name") != expected_event
        or str(github.get("repository_id", "")) != repository_id
        or str(github.get("repository_owner_id", ""))
        != repository_owner_id
    ):
        _fail(f"{label} SLSA GitHub identity is not exact")
    expected_dependency = {
        "uri": f"git+https://github.com/{repository}@refs/heads/main",
        "digest": {"gitCommit": source_digest},
    }
    if definition["resolvedDependencies"] != [expected_dependency]:
        _fail(f"{label} SLSA resolved dependency set is not exact")
    _require_required_keys(
        details,
        {"builder", "metadata"},
        label=f"{label} SLSA runDetails",
    )
    builder = details["builder"]
    metadata = details["metadata"]
    if not isinstance(builder, dict) or not isinstance(metadata, dict):
        _fail(f"{label} SLSA builder and metadata must be objects")
    _require_required_keys(builder, {"id"}, label=f"{label} SLSA builder")
    _require_required_keys(
        metadata,
        {"invocationId"},
        label=f"{label} SLSA metadata",
    )
    if (
        builder.get("id") != certificate["buildSignerURI"]
        or metadata.get("invocationId") != certificate["runInvocationURI"]
    ):
        _fail(f"{label} SLSA builder/run identity is not exact")


def _validate_spdx_raw_output(
    data: bytes,
    *,
    repository: str,
    repository_id: str,
    repository_owner_id: str,
    workflow_path: str,
    source_digest: str,
    run_id: int,
    run_attempt: int,
    expected_event: str,
    subject_name: str,
    subject_sha256: str,
    spdx_predicate: Mapping[str, Any],
    label: str,
) -> None:
    statement, _certificate = _strict_attestation_parts(
        data,
        repository=repository,
        repository_id=repository_id,
        repository_owner_id=repository_owner_id,
        workflow_path=workflow_path,
        source_digest=source_digest,
        run_id=run_id,
        run_attempt=run_attempt,
        expected_event=expected_event,
        subject_name=subject_name,
        subject_sha256=subject_sha256,
        predicate_type="https://spdx.dev/Document/v2.3",
        label=label,
    )
    if statement["predicate"] != spdx_predicate:
        _fail(f"{label} SPDX predicate does not equal the retained SPDX bytes")


def _validate_attestation_bytes(
    root: Path,
    ledger: Mapping[str, Any],
) -> None:
    repository = ledger["release"]["repository"]
    repository_id = ledger["release"]["repository_id"]
    repository_owner_id = ledger["release"]["repository_owner_id"]
    candidate = ledger["source"]["candidate_commit_sha"]
    descriptors = _collect_descriptors(ledger)
    producer_matches = [
        descriptor
        for path, descriptor in descriptors.items()
        if PurePosixPath(path).name == "producer-receipt.json"
    ]
    if len(producer_matches) != 1:
        _fail("cannot identify one retained producer receipt for attestation checking")
    pyz = next(
        item for item in ledger["artifacts"] if item["name"] == "evo-guard.pyz"
    )
    spdx = next(
        item
        for item in ledger["artifacts"]
        if item["name"] == "evo-guard.spdx.json"
    )
    subjects = {
        "source_producer": {
            "sha256": producer_matches[0][1],
            "size": producer_matches[0][0],
        },
        "build_provenance": {
            "sha256": pyz["sha256"],
            "size": pyz["size_bytes"],
        },
        "spdx_provenance": {
            "sha256": spdx["sha256"],
            "size": spdx["size_bytes"],
        },
        "sbom_provenance": {
            "sha256": pyz["sha256"],
            "size": pyz["size_bytes"],
        },
    }
    spdx_bytes = _read_regular(
        _safe_retained_path(root, spdx["path"]),
        limit=MAX_JSON_BYTES,
        label="retained SPDX predicate",
    )
    spdx_predicate = _load_json_bytes(
        spdx_bytes,
        label="retained SPDX predicate",
    )
    if canonical_json_bytes(spdx_predicate) != spdx_bytes:
        _fail("retained SPDX predicate is not canonical JSON")
    for name, expected_subject in subjects.items():
        attestation = ledger["attestations"][name]
        receipt_descriptor = attestation["verification_receipt"]
        receipt_path = _safe_retained_path(root, receipt_descriptor["path"])
        receipt_bytes = _read_regular(
            receipt_path,
            limit=1024 * 1024,
            label=f"{name} attestation receipt",
        )
        receipt = _load_json_bytes(
            receipt_bytes,
            label=f"{name} attestation receipt",
        )
        if canonical_json_bytes(receipt) != receipt_bytes:
            _fail(f"{name} attestation receipt is not canonical JSON")
        output = attestation["verification_output"]
        output_bytes = _read_regular(
            _safe_retained_path(root, output["path"]),
            limit=MAX_JSON_BYTES,
            label=f"{name} raw attestation output",
        )
        expected_output = {
            "sha256": _sha256(output_bytes),
            "size": len(output_bytes),
            "verified_attestation_count": 1,
        }
        expected_policy = {
            "repository": repository,
            "signer_workflow": f"{repository}/{attestation['signer_workflow']}",
            "signer_digest": candidate,
            "source_ref": "refs/heads/main",
            "source_digest": candidate,
            "cert_oidc_issuer": "https://token.actions.githubusercontent.com",
            "predicate_type": attestation["predicate_type"],
            "deny_self_hosted_runners": True,
            "attestation_limit": 1,
        }
        if name == "sbom_provenance":
            expected_receipt = {
                "format": "EVOGUARD_GITHUB_SPDX_ATTESTATION_RECEIPT_V1",
                "artifact": {
                    "name": attestation["subject_name"],
                    **expected_subject,
                },
                "predicate": {
                    "name": spdx["name"],
                    "sha256": spdx["sha256"],
                    "size": spdx["size_bytes"],
                    "type": "https://spdx.dev/Document/v2.3",
                },
                "verification_policy": {
                    **expected_policy,
                    "repository_id": repository_id,
                    "repository_owner_id": repository_owner_id,
                },
                "workflow_run": {
                    "id": attestation["run_id"],
                    "attempt": attestation["run_attempt"],
                    "event": "workflow_dispatch",
                },
                "verification_output": expected_output,
            }
            if receipt != expected_receipt:
                _fail(
                    "sbom_provenance receipt does not bind its predicate, "
                    "subject, policy, and E run"
                )
        else:
            _require_exact_keys(
                receipt,
                {
                    "format",
                    "artifact",
                    "verification_policy",
                    "verification_output",
                },
                label=f"{name} attestation receipt",
            )
            artifact_value = receipt.get("artifact")
            policy_value = receipt.get("verification_policy")
            output_value = receipt.get("verification_output")
            if not isinstance(artifact_value, dict):
                _fail(f"{name} attestation receipt artifact must be an object")
            if not isinstance(policy_value, dict):
                _fail(f"{name} attestation receipt policy must be an object")
            if not isinstance(output_value, dict):
                _fail(f"{name} attestation receipt children must be objects")
            _require_exact_keys(
                artifact_value,
                {"sha256", "size"},
                label=f"{name} receipt artifact",
            )
            _require_exact_keys(
                policy_value,
                {
                    "repository",
                    "signer_workflow",
                    "signer_digest",
                    "source_ref",
                    "source_digest",
                    "cert_oidc_issuer",
                    "predicate_type",
                    "deny_self_hosted_runners",
                    "attestation_limit",
                },
                label=f"{name} receipt policy",
            )
            _require_exact_keys(
                output_value,
                {"sha256", "size", "verified_attestation_count"},
                label=f"{name} receipt output",
            )
            if (
                receipt["format"] != "EVOGUARD_GITHUB_ATTESTATION_RECEIPT_V1"
                or artifact_value != expected_subject
                or policy_value != expected_policy
                or output_value != expected_output
            ):
                _fail(
                    f"{name} attestation receipt does not bind its subject and policy"
                )
        if (
            output["sha256"] != expected_output["sha256"]
            or output["size_bytes"] != expected_output["size"]
        ):
            _fail(f"{name} raw output descriptor does not bind retained bytes")
        validation_args: dict[str, Any] = {
            "data": output_bytes,
            "repository": repository,
            "repository_id": repository_id,
            "repository_owner_id": repository_owner_id,
            "workflow_path": attestation["signer_workflow"],
            "source_digest": candidate,
            "run_id": attestation["run_id"],
            "run_attempt": attestation["run_attempt"],
            "expected_event": (
                "workflow_run" if name == "source_producer" else "workflow_dispatch"
            ),
            "subject_name": attestation["subject_name"],
            "subject_sha256": expected_subject["sha256"],
            "label": f"{name} raw attestation output",
        }
        if name == "sbom_provenance":
            _validate_spdx_raw_output(
                **validation_args,
                spdx_predicate=spdx_predicate,
            )
        else:
            _validate_slsa_raw_output(
                **validation_args,
                subject_size=expected_subject["size"],
            )


def _validate_source_negative_file(
    root: Path,
    descriptor: Mapping[str, Any],
    *,
    label: str,
) -> None:
    data = _read_regular(
        _safe_retained_path(root, descriptor["path"]),
        limit=1024 * 1024,
        label=label,
    )
    expected = canonical_json_bytes(SOURCE_NEGATIVE_RESULT)
    if data != expected:
        _fail(f"{label} does not equal the actual eleven-case C/D negative record")


def _validate_artifact_negative_file(
    root: Path,
    descriptor: Mapping[str, Any],
    *,
    label: str,
) -> None:
    data = _read_regular(
        _safe_retained_path(root, descriptor["path"]),
        limit=1024 * 1024,
        label=label,
    )
    expected = ("\n".join(ARTIFACT_NEGATIVE_LINES) + "\n").encode("ascii")
    if data != expected:
        _fail(f"{label} does not equal the ordered seven-case G negative record")


def _require_embedded_attestation_evidence(
    root: Path,
    ledger: Mapping[str, Any],
    *,
    attestation_name: str,
    embedded_receipt: bytes,
    embedded_output: bytes,
    envelope_label: str,
) -> None:
    attestation = ledger["attestations"][attestation_name]
    retained_receipt = _read_regular(
        _safe_retained_path(
            root,
            attestation["verification_receipt"]["path"],
        ),
        limit=MAX_JSON_BYTES,
        label=f"{attestation_name} receipt cross-binding",
    )
    retained_output = _read_regular(
        _safe_retained_path(
            root,
            attestation["verification_output"]["path"],
        ),
        limit=MAX_JSON_BYTES,
        label=f"{attestation_name} raw-output cross-binding",
    )
    if (
        retained_receipt != embedded_receipt
        or retained_output != embedded_output
    ):
        _fail(
            f"{attestation_name} evidence is not the exact provider evidence "
            f"embedded in {envelope_label}"
        )


def _validate_envelopes(root: Path, ledger: Mapping[str, Any]) -> None:
    # Imported lazily so schema-only validation remains useful without the
    # optional signing extra.
    from evoom_guard.admission.release_artifact import (
        RELEASE_ARTIFACT_ADMISSION_SIGNATURE_DOMAIN,
        inspect_release_artifact_admission,
    )
    from evoom_guard.admission.release_source import (
        RELEASE_SOURCE_ADMISSION_SIGNATURE_DOMAIN,
        inspect_release_source_admission,
    )
    from evoom_guard.signing import verify_bytes_with_key_id

    roots = {item["domain"]: item for item in ledger["trust_roots"]}
    root_ids = {domain: item["key_id"] for domain, item in roots.items()}
    release = ledger["release"]
    source = ledger["source"]
    phases = _phase_map(ledger)
    toolchain = ledger["toolchain"]

    def workflow_identity(phase: str, *, event: str) -> dict[str, Any]:
        run = phases[phase]
        return {
            "workflow_repository": release["repository"],
            "workflow_repository_id": release["repository_id"],
            "workflow_id": str(run["workflow_id"]),
            "workflow_path": run["workflow_path"],
            "workflow_blob_sha": run["workflow_blob_sha"],
            "workflow_run_id": str(run["run_id"]),
            "workflow_run_attempt": run["run_attempt"],
            "workflow_event": event,
            "workflow_ref": "refs/heads/main",
            "workflow_commit_sha": source["candidate_commit_sha"],
            "runner_class": "github-hosted",
        }

    def source_actor(phase: str, trigger: str) -> dict[str, Any]:
        value = workflow_identity(phase, event="workflow_run")
        upstream = phases[trigger]
        value.update(
            {
                "trigger_workflow_id": str(upstream["workflow_id"]),
                "trigger_workflow_path": upstream["workflow_path"],
                "trigger_workflow_blob_sha": upstream["workflow_blob_sha"],
                "trigger_workflow_run_id": str(upstream["run_id"]),
                "trigger_workflow_run_attempt": upstream["run_attempt"],
            }
        )
        return value

    expected_provider_policy = {
        "repository": release["repository"],
        "signer_digest": source["candidate_commit_sha"],
        "source_ref": "refs/heads/main",
        "source_digest": source["candidate_commit_sha"],
        "cert_oidc_issuer": "https://token.actions.githubusercontent.com",
        "predicate_type": "https://slsa.dev/provenance/v1",
        "deny_self_hosted_runners": True,
        "attestation_limit": 1,
    }

    source_admission = ledger["source_admission"]
    rsae_path = _safe_retained_path(root, source_admission["rsae"]["path"])
    rsae = inspect_release_source_admission(str(rsae_path))
    rsae_public = _safe_retained_path(
        root,
        roots["release-source-admission-v2"]["public_key"]["path"],
    )
    valid, key_id = verify_bytes_with_key_id(
        RELEASE_SOURCE_ADMISSION_SIGNATURE_DOMAIN + rsae.manifest_bytes,
        rsae.signature,
        str(rsae_public),
    )
    if not valid or key_id != source_admission["rsae"]["key_id"]:
        _fail("retained RSAE signature or key identity is invalid")
    expected_rsae_source = {
        "repository": release["repository"],
        "repository_id": release["repository_id"],
        "default_branch": "main",
        "workflow_run_id": str(phases["A"]["run_id"]),
        "workflow_run_attempt": phases["A"]["run_attempt"],
        "protected_ref": "refs/heads/main",
        "target_commit_sha": source["candidate_commit_sha"],
        "target_tree_sha": source["candidate_tree_sha"],
    }
    expected_replay = {
        "evaluation": {
            "run_id": str(phases["A"]["run_id"]),
            "run_attempt": phases["A"]["run_attempt"],
        },
        "producer": {
            "run_id": str(phases["B"]["run_id"]),
            "run_attempt": phases["B"]["run_attempt"],
        },
        "trigger": {
            "run_id": str(phases["A"]["run_id"]),
            "run_attempt": phases["A"]["run_attempt"],
        },
        "admitter": {
            "run_id": str(phases["C"]["run_id"]),
            "run_attempt": phases["C"]["run_attempt"],
        },
    }
    expected_source_toolchain = {
        "git": {"sha256": toolchain["git"]["sha256"]},
        "github_cli": {"sha256": toolchain["github_cli"]["sha256"]},
        "provider_isolation": toolchain["provider_identities"]["source_admission"],
    }
    expected_source_separation = {
        "trusted_finalizer": root_ids["trusted-finalizer"],
        "artifact_admission_v1": root_ids["artifact-admission-v1"],
        "artifact_digest_admission_v2": root_ids["artifact-digest-admission-v2"],
        "release_source_finalizer_v1": root_ids["release-source-finalizer-v1"],
    }
    rsae_policy = {
        **expected_provider_policy,
        "signer_workflow": (
            f"{release['repository']}/{phases['B']['workflow_path']}"
        ),
    }
    rsae_context = rsae.manifest["context"]
    expected_context_fields = {
        "repository": release["repository"],
        "repository_id": release["repository_id"],
        "run_id": str(phases["A"]["run_id"]),
        "run_attempt": phases["A"]["run_attempt"],
        "protected_ref": "refs/heads/main",
        "target_commit_sha": source["candidate_commit_sha"],
        "target_tree_sha": source["candidate_tree_sha"],
        "parent_commit_sha": source["parent_commit_sha"],
        "parent_tree_sha": source["parent_tree_sha"],
    }
    if (
        rsae.manifest["decision"] != "ALLOW"
        or rsae.manifest["source"] != expected_rsae_source
        or any(
            rsae_context.get(field) != expected
            for field, expected in expected_context_fields.items()
        )
        or rsae.manifest["producer"] != source_actor("B", "A")
        or rsae.manifest["admitter"] != source_actor("C", "B")
        or rsae.manifest["replay"] != expected_replay
        or rsae.manifest["bootstrap"]["guard_artifact_sha256"]
        != toolchain["bootstrap_guard"]["sha256"]
        or rsae.manifest["toolchain"] != expected_source_toolchain
        or rsae.manifest["key_separation"] != expected_source_separation
        or rsae.manifest["provider"]["policy"] != rsae_policy
    ):
        _fail("retained RSAE manifest does not bind the admitted source")
    _require_embedded_attestation_evidence(
        root,
        ledger,
        attestation_name="source_producer",
        embedded_receipt=rsae.github_receipt_bytes,
        embedded_output=rsae.github_raw_output_bytes,
        envelope_label="RSAE",
    )

    _validate_source_result(
        root,
        source_admission["protected_seal_result"],
        manifest=rsae.manifest,
        sealed=True,
        bundle_name=PurePosixPath(source_admission["rsae"]["path"]).name,
        label="RSAE protected seal result",
    )
    _validate_source_result(
        root,
        source_admission["detached_verification_result"],
        manifest=rsae.manifest,
        sealed=False,
        bundle_name=PurePosixPath(source_admission["rsae"]["path"]).name,
        label="RSAE detached verification result",
    )
    _validate_source_negative_file(
        root,
        source_admission["negative_results"],
        label="RSAE negative matrix",
    )

    artifacts = {item["name"]: item for item in ledger["artifacts"]}
    raae_public = _safe_retained_path(
        root,
        roots["release-artifact-admission-v1"]["public_key"]["path"],
    )
    for subject in ledger["artifact_admission"]["subjects"]:
        raae_path = _safe_retained_path(root, subject["raae"]["path"])
        raae = inspect_release_artifact_admission(str(raae_path))
        valid, key_id = verify_bytes_with_key_id(
            RELEASE_ARTIFACT_ADMISSION_SIGNATURE_DOMAIN + raae.manifest_bytes,
            raae.signature,
            str(raae_public),
        )
        if not valid or key_id != subject["raae"]["key_id"]:
            _fail(f"retained RAAE signature or key is invalid: {subject['name']}")
        asset = artifacts[subject["name"]]
        manifest = raae.manifest
        expected_release_source = {
            "format": "EVOGUARD_RELEASE_SOURCE_ADMISSION_V2",
            "decision": "ALLOW",
            "bundle": {
                "path": "materials/release-source-admission.rsae",
                "sha256": source_admission["rsae"]["sha256"],
                "size": source_admission["rsae"]["size_bytes"],
            },
            "key_id": root_ids["release-source-admission-v2"],
            "repository": release["repository"],
            "repository_id": release["repository_id"],
            "target_commit_sha": source["candidate_commit_sha"],
            "target_tree_sha": source["candidate_tree_sha"],
            "bootstrap_guard_sha256": toolchain["bootstrap_guard"]["sha256"],
        }
        expected_artifact_toolchain = {
            "git": {"sha256": toolchain["git"]["sha256"]},
            "github_cli": {"sha256": toolchain["github_cli"]["sha256"]},
            "provider_isolation": toolchain["provider_identities"][
                "artifact_admission"
            ],
        }
        expected_artifact_separation = {
            "trusted_finalizer": root_ids["trusted-finalizer"],
            "artifact_admission_v1": root_ids["artifact-admission-v1"],
            "artifact_digest_admission_v2": root_ids[
                "artifact-digest-admission-v2"
            ],
            "release_source_finalizer_v1": root_ids[
                "release-source-finalizer-v1"
            ],
            "release_source_admission_v2": root_ids[
                "release-source-admission-v2"
            ],
        }
        raae_policy = {
            **expected_provider_policy,
            "signer_workflow": (
                f"{release['repository']}/{phases['E']['workflow_path']}"
            ),
        }
        if (
            manifest["decision"] != "ALLOW"
            or manifest["artifact"]
            != {
                "kind": "file",
                "sha256": asset["sha256"],
                "size": asset["size_bytes"],
            }
            or manifest["release_source"] != expected_release_source
            or manifest["builder"]
            != workflow_identity("E", event="workflow_dispatch")
            or manifest["admitter"] != workflow_identity("F", event="workflow_run")
            or manifest["provider"]["artifact"]
            != {"sha256": asset["sha256"], "size": asset["size_bytes"]}
            or manifest["provider"]["policy"] != raae_policy
            or manifest["toolchain"] != expected_artifact_toolchain
            or manifest["key_separation"] != expected_artifact_separation
        ):
            _fail(f"retained RAAE does not bind its asset and RSAE: {subject['name']}")
        attestation_name = {
            "evo-guard.pyz": "build_provenance",
            "evo-guard.spdx.json": "spdx_provenance",
        }[subject["name"]]
        _require_embedded_attestation_evidence(
            root,
            ledger,
            attestation_name=attestation_name,
            embedded_receipt=raae.github_receipt_bytes,
            embedded_output=raae.github_raw_output_bytes,
            envelope_label=f"{subject['name']} RAAE",
        )
        _validate_artifact_result(
            root,
            subject["protected_seal_result"],
            manifest=manifest,
            sealed=True,
            bundle_name=PurePosixPath(subject["raae"]["path"]).name,
            label=f"{subject['name']} RAAE protected seal result",
        )
        _validate_artifact_result(
            root,
            subject["detached_verification_result"],
            manifest=manifest,
            sealed=False,
            bundle_name=PurePosixPath(subject["raae"]["path"]).name,
            label=f"{subject['name']} RAAE detached verification result",
        )
    _validate_artifact_negative_file(
        root,
        ledger["artifact_admission"]["negative_results"],
        label="RAAE negative matrix",
    )


def _validate_keys_and_anchor(
    root: Path,
    ledger: Mapping[str, Any],
    trusted_key: _TrustedLedgerKey,
) -> None:
    from evoom_guard.signing import public_key_id

    for entry in ledger["trust_roots"]:
        path = _safe_retained_path(root, entry["public_key"]["path"])
        if public_key_id(str(path)) != entry["key_id"]:
            _fail(f"public root key ID does not match retained PEM: {entry['domain']}")

    seal = ledger["ledger_signature"]
    public_path = _safe_retained_path(root, seal["public_key"]["path"])
    retained = _read_regular(
        public_path,
        limit=MAX_PUBLIC_KEY_BYTES,
        label="retained ledger signing public key",
    )
    try:
        retained_id = public_key_id(str(public_path))
    except (OSError, ValueError) as exc:
        raise LedgerValidationError(
            "retained ledger signing public key is unusable"
        ) from exc
    if retained != trusted_key.pem:
        _fail("retained ledger signing public key differs from external trusted key")
    if retained_id != trusted_key.key_id or seal["key_id"] != trusted_key.key_id:
        _fail("ledger signing key ID differs from external trusted key identity")


def _validate_directory_with_trusted_imports(
    root: Path,
    trusted_ledger_pub: Path,
    trusted_parent_repo: Path | None = None,
) -> Mapping[str, Any]:
    """Validate one v2 ledger under an independently supplied trust anchor."""

    root = _require_plain_directory(root, label="ledger root")
    trusted_key = _load_trusted_ledger_key(root, trusted_ledger_pub)
    ledger_path = root / LEDGER_NAME
    ledger_bytes = _read_regular(
        ledger_path,
        limit=MAX_JSON_BYTES,
        label="release ledger",
    )
    ledger = _load_json_bytes(ledger_bytes, label="release ledger")
    if canonical_json_bytes(ledger) != ledger_bytes:
        _fail("RELEASE_LEDGER.json is not canonical JSON")
    signature_path = root / SIGNATURE_NAME
    signature_bytes = _read_regular(
        signature_path,
        limit=CANONICAL_SIGNATURE_BYTES,
        label="release ledger signature",
    )
    _verify_external_ledger_signature(ledger_bytes, signature_bytes, trusted_key)

    schema, schema_sha256 = _load_official_schema()
    _validate_structure_with_official_schema(
        ledger,
        schema,
        schema_sha256=schema_sha256,
    )
    trusted_parent_contracts = _validate_trusted_parent_contracts(
        root,
        ledger,
        trusted_parent_repo,
        trusted_key,
    )

    inventory = _collect_descriptors(ledger)
    _require_retained_budget(inventory)
    expected_files = set(inventory) | {LEDGER_NAME, SIGNATURE_NAME}
    expected_directories = _expected_directories(expected_files)
    actual_files, actual_directories, inventory_identities = _actual_inventory(
        root,
        expected_files=expected_files,
        expected_directories=expected_directories,
    )
    if actual_files != expected_files:
        missing = sorted(expected_files - actual_files)
        unexpected = sorted(actual_files - expected_files)
        _fail(f"ledger file set is not exact; missing={missing}, unexpected={unexpected}")
    if actual_directories != expected_directories:
        missing = sorted(expected_directories - actual_directories)
        unexpected = sorted(actual_directories - expected_directories)
        _fail(
            f"ledger directory set is not exact; "
            f"missing={missing}, unexpected={unexpected}"
        )

    trusted_object = trusted_key.identity[:2]
    if any(
        identity[:2] == trusted_object
        for label, identity in inventory_identities.items()
        if label.startswith("f:")
    ):
        _fail("external trusted ledger public key shares a filesystem object with ledger")

    retained_bytes: dict[str, bytes] = {}
    for relative, (size, digest) in inventory.items():
        path = _safe_retained_path(root, relative)
        data = _read_regular(
            path,
            limit=max(size, 1),
            label=f"retained evidence {relative}",
        )
        if len(data) != size or _sha256(data) != digest:
            _fail(f"retained evidence bytes do not match descriptor: {relative}")
        retained_bytes[relative] = data

    snapshot_files = dict(retained_bytes)
    snapshot_files[LEDGER_NAME] = ledger_bytes
    snapshot_files[SIGNATURE_NAME] = signature_bytes
    with tempfile.TemporaryDirectory(prefix="evoguard-ledger-v2-") as temporary:
        snapshot_root = _require_plain_directory(
            Path(temporary),
            label="protected evidence snapshot",
        )
        (
            snapshot_actual_files,
            snapshot_actual_directories,
            snapshot_identities,
        ) = _materialize_snapshot(snapshot_root, snapshot_files)

        assets = {item["name"]: item for item in ledger["artifacts"]}
        checksum_bytes = _read_regular(
            _safe_retained_path(snapshot_root, ledger["checksum_manifest"]["path"]),
            limit=1024 * 1024,
            label="release checksum manifest",
        )
        expected_checksum = "".join(
            f"{assets[name]['sha256']}  {name}\n"
            for name in ("evo-guard.pyz", "evo-guard.spdx.json")
        ).encode("ascii")
        if checksum_bytes != expected_checksum:
            _fail("SHA256SUMS is not the exact two-line filename-ordered manifest")

        _validate_repository_control_observation_bytes(snapshot_root, ledger)
        _validate_control_bytes(snapshot_root, ledger)

        def validate_first_party_material() -> None:
            _validate_attestation_bytes(snapshot_root, ledger)
            _validate_envelopes(snapshot_root, ledger)
            _validate_keys_and_anchor(snapshot_root, ledger, trusted_key)

        # Characterization fixtures replace both this owner and all dependent
        # byte validators. The production path always receives the contract.
        if trusted_parent_contracts is None:
            validate_first_party_material()
        else:
            with _trusted_parent_first_party(trusted_parent_contracts):
                validate_first_party_material()
        _require_inventory_unchanged(
            snapshot_root,
            files=snapshot_actual_files,
            directories=snapshot_actual_directories,
            identities=snapshot_identities,
        )

    _require_original_bytes_unchanged(
        root,
        ledger_bytes=ledger_bytes,
        signature_bytes=signature_bytes,
        retained_bytes=retained_bytes,
    )
    _require_inventory_unchanged(
        root,
        files=actual_files,
        directories=actual_directories,
        identities=inventory_identities,
    )
    _require_trusted_key_unchanged(trusted_key)
    return ledger


def validate_directory(
    root: Path,
    trusted_ledger_pub: Path,
    trusted_parent_repo: Path | None = None,
) -> Mapping[str, Any]:
    """Validate one ledger with host dependencies isolated from candidate paths.

    The validator is a single-threaded CLI.  This context temporarily owns the
    interpreter import tables and is intentionally not an embeddable concurrent
    API.
    """

    absolute_root = _require_plain_directory(root, label="ledger root")
    blocked = [absolute_root]
    if trusted_parent_repo is not None:
        blocked.append(Path(os.path.abspath(trusted_parent_repo)))
    with _FIRST_PARTY_IMPORT_LOCK, _trusted_python_imports(
        import_root=None,
        blocked_roots=tuple(blocked),
    ):
        return _validate_directory_with_trusted_imports(
            absolute_root,
            trusted_ledger_pub,
            trusted_parent_repo,
        )


def _validate_retirement_observation(
    value: Any,
    *,
    expected: Mapping[str, Any],
    label: str,
) -> datetime:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    _require_exact_keys(
        value,
        set(expected)
        | {
            "http_status",
            "pagination_complete",
            "per_page",
            "page_count",
            "total_count",
            "present",
            "observed_utc",
        },
        label=label,
    )
    if any(value.get(key) != item for key, item in expected.items()):
        _fail(f"{label} identity is not exact")
    total = value.get("total_count")
    pages = value.get("page_count")
    if (
        value.get("http_status") != 200
        or value.get("pagination_complete") is not True
        or value.get("per_page") != 100
        or not isinstance(total, int)
        or isinstance(total, bool)
        or total < 0
        or not isinstance(pages, int)
        or isinstance(pages, bool)
        or pages != max(1, (total + 99) // 100)
        or value.get("present") is not False
    ):
        _fail(f"{label} does not prove a successful complete absence observation")
    return _parse_time(value["observed_utc"], label=f"{label}.observed_utc")


def _validate_key_retirement_value(
    value: Mapping[str, Any],
    *,
    ledger: Mapping[str, Any],
    ledger_bytes: bytes,
    ledger_signature_bytes: bytes,
    trusted_key: _TrustedLedgerKey,
) -> None:
    _require_exact_keys(
        value,
        {
            "format",
            "created_utc",
            "repository",
            "release",
            "ledger",
            "publication_authority",
            "github_api_version",
            "proof_boundary",
        },
        label="key-retirement receipt",
    )
    release = ledger["release"]
    controls = ledger["repository_controls"]
    if value.get("format") != "EVOGUARD_RELEASE_KEY_RETIREMENT_V1":
        _fail("key-retirement receipt format is not exact")
    if value.get("github_api_version") != "2022-11-28":
        _fail("key-retirement GitHub API version is not exact")
    if value.get("repository") != {
        "name": release["repository"],
        "id": release["repository_id"],
        "owner_id": release["repository_owner_id"],
    }:
        _fail("key-retirement repository identity is not exact")
    if value.get("release") != {
        "tag": release["tag"],
        "commit_sha": release["commit_sha"],
    }:
        _fail("key-retirement release identity is not exact")
    if value.get("ledger") != {
        "sha256": _sha256(ledger_bytes),
        "signature_sha256": _sha256(ledger_signature_bytes),
        "key_id": trusted_key.key_id,
        "created_utc": ledger["ledger_scope"]["created_utc"],
    }:
        _fail("key-retirement receipt does not bind the validated ledger")
    if value.get("proof_boundary") != (
        "owner-collected-point-in-time-github-api-observation"
    ):
        _fail("key-retirement proof boundary is not exact")
    authority = value.get("publication_authority")
    if not isinstance(authority, dict):
        _fail("key-retirement publication authority must be an object")
    _require_exact_keys(
        authority,
        {"deploy_key", "environment_secret"},
        label="key-retirement publication authority",
    )
    deploy_key = controls["release_deploy_key"]
    deploy_observed = _validate_retirement_observation(
        authority["deploy_key"],
        expected={
            "kind": "repository-deploy-key",
            "id": deploy_key["id"],
            "title": deploy_key["title"],
            "fingerprint": deploy_key["fingerprint"],
            "api_action": "list-repository-deploy-keys",
            "request_method": "GET",
            "endpoint": f"/repos/{release['repository']}/keys",
        },
        label="key-retirement deploy-key observation",
    )
    publication_environment = next(
        item
        for item in controls["environments"]
        if item["name"] == "evoguard-release-publication"
    )
    secret_observed = _validate_retirement_observation(
        authority["environment_secret"],
        expected={
            "kind": "environment-secret-name",
            "environment_id": publication_environment["id"],
            "environment": publication_environment["name"],
            "secret_name": "EVOGUARD_RELEASE_TAG_DEPLOY_KEY",
            "api_action": "list-environment-secrets",
            "request_method": "GET",
            "endpoint": (
                f"/repos/{release['repository']}/environments/"
                "evoguard-release-publication/secrets"
            ),
        },
        label="key-retirement publication-secret observation",
    )
    ledger_created = _parse_time(
        ledger["ledger_scope"]["created_utc"],
        label="ledger_scope.created_utc",
    )
    receipt_created = _parse_time(
        value["created_utc"],
        label="key-retirement created_utc",
    )
    if not (
        ledger_created < deploy_observed <= receipt_created
        and ledger_created < secret_observed <= receipt_created
    ):
        _fail("key-retirement observations are outside the post-ledger window")
    if controls["publication_authority_retirement"] != {
        "status": "pending-post-ledger",
        "deploy_key_id": deploy_key["id"],
        "environment": "evoguard-release-publication",
        "secret_name": "EVOGUARD_RELEASE_TAG_DEPLOY_KEY",
        "proof_boundary": "not-claimed-by-release-ledger",
    }:
        _fail("validated ledger did not leave publication authority pending")


def _validate_key_retirement_with_trusted_imports(
    ledger_root: Path,
    receipt_path: Path,
    signature_path: Path,
    trusted_ledger_pub: Path,
    trusted_parent_repo: Path,
) -> Mapping[str, Any]:
    ledger = validate_directory(
        ledger_root,
        trusted_ledger_pub,
        trusted_parent_repo,
    )
    trusted_key = _load_trusted_ledger_key(ledger_root, trusted_ledger_pub)
    ledger_bytes = _read_regular(
        ledger_root / LEDGER_NAME,
        limit=MAX_JSON_BYTES,
        label="release ledger",
    )
    ledger_signature_bytes = _read_regular(
        ledger_root / SIGNATURE_NAME,
        limit=CANONICAL_SIGNATURE_BYTES,
        label="release ledger signature",
    )
    if canonical_json_bytes(ledger) != ledger_bytes:
        _fail("release ledger changed after directory validation")
    _verify_external_ledger_signature(
        ledger_bytes,
        ledger_signature_bytes,
        trusted_key,
    )
    receipt_bytes = _read_regular(
        receipt_path,
        limit=1024 * 1024,
        label="key-retirement receipt",
    )
    receipt = _load_json_bytes(receipt_bytes, label="key-retirement receipt")
    if canonical_json_bytes(receipt) != receipt_bytes:
        _fail("KEY_RETIREMENT.json is not canonical JSON")
    signature_bytes = _read_regular(
        signature_path,
        limit=CANONICAL_SIGNATURE_BYTES,
        label="key-retirement signature",
    )
    _verify_external_ledger_signature(receipt_bytes, signature_bytes, trusted_key)
    _validate_key_retirement_value(
        receipt,
        ledger=ledger,
        ledger_bytes=ledger_bytes,
        ledger_signature_bytes=ledger_signature_bytes,
        trusted_key=trusted_key,
    )
    current_ledger = _read_regular(
        ledger_root / LEDGER_NAME,
        limit=MAX_JSON_BYTES,
        label="release ledger",
    )
    current_ledger_signature = _read_regular(
        ledger_root / SIGNATURE_NAME,
        limit=CANONICAL_SIGNATURE_BYTES,
        label="release ledger signature",
    )
    current_receipt = _read_regular(
        receipt_path,
        limit=1024 * 1024,
        label="key-retirement receipt",
    )
    current_receipt_signature = _read_regular(
        signature_path,
        limit=CANONICAL_SIGNATURE_BYTES,
        label="key-retirement signature",
    )
    if (
        current_ledger != ledger_bytes
        or current_ledger_signature != ledger_signature_bytes
        or current_receipt != receipt_bytes
        or current_receipt_signature != signature_bytes
    ):
        _fail("key-retirement inputs changed during validation")
    _verify_external_ledger_signature(
        current_ledger,
        current_ledger_signature,
        trusted_key,
    )
    _verify_external_ledger_signature(
        current_receipt,
        current_receipt_signature,
        trusted_key,
    )
    _require_trusted_key_unchanged(trusted_key)
    return receipt


def validate_key_retirement(
    ledger_root: Path,
    receipt_path: Path,
    signature_path: Path,
    trusted_ledger_pub: Path,
    trusted_parent_repo: Path,
) -> Mapping[str, Any]:
    with _FIRST_PARTY_IMPORT_LOCK, _trusted_python_imports(
        import_root=None,
        blocked_roots=(
            Path(os.path.abspath(ledger_root)),
            Path(os.path.abspath(receipt_path.parent)),
            Path(os.path.abspath(signature_path.parent)),
            Path(os.path.abspath(trusted_parent_repo)),
        ),
    ):
        return _validate_key_retirement_with_trusted_imports(
            ledger_root,
            receipt_path,
            signature_path,
            trusted_ledger_pub,
            trusted_parent_repo,
        )


def _canonicalize_with_trusted_imports(
    input_path: Path,
    output_path: Path,
) -> None:
    draft = _load_json_file(input_path, label="release ledger draft")
    schema, schema_sha256 = _load_official_schema()
    _validate_structure_with_official_schema(
        draft,
        schema,
        schema_sha256=schema_sha256,
    )
    if output_path.exists() or output_path.is_symlink():
        _fail(f"refusing to overwrite canonical output: {output_path}")
    parent = _require_plain_directory(
        output_path.parent,
        label="canonical output parent",
    )
    absolute_output = parent / output_path.name
    parent_snapshot = _directory_chain(parent, label="canonical output parent")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    created_identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(absolute_output, flags, 0o600)
        opened = os.fstat(descriptor)
        if _is_link_like(opened) or not stat.S_ISREG(opened.st_mode):
            _fail("canonical output did not create a regular file")
        created_identity = (opened.st_dev, opened.st_ino)
        data = canonical_json_bytes(draft)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written < 1:
                _fail("canonical output write made no progress")
            offset += written
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        if (
            _identity(final)[:2] != created_identity
            or final.st_nlink != 1
            or final.st_size != len(data)
        ):
            _fail("canonical output changed while it was written")
        os.close(descriptor)
        descriptor = -1
        _require_same_directory_chain(
            parent_snapshot,
            label="canonical output parent",
        )
        path_metadata = absolute_output.lstat()
        if (
            _is_link_like(path_metadata)
            or not stat.S_ISREG(path_metadata.st_mode)
            or (path_metadata.st_dev, path_metadata.st_ino) != created_identity
        ):
            _fail("canonical output pathname changed after writing")
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        if created_identity is not None:
            try:
                current = absolute_output.lstat()
                if (
                    not _is_link_like(current)
                    and stat.S_ISREG(current.st_mode)
                    and (current.st_dev, current.st_ino) == created_identity
                ):
                    absolute_output.unlink()
            except OSError:
                pass
        raise LedgerValidationError(
            f"cannot write canonical output: {output_path}"
        ) from exc
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        if created_identity is not None:
            try:
                current = absolute_output.lstat()
                if (
                    not _is_link_like(current)
                    and stat.S_ISREG(current.st_mode)
                    and (current.st_dev, current.st_ino) == created_identity
                ):
                    absolute_output.unlink()
            except OSError:
                pass
        raise


def _canonicalize(input_path: Path, output_path: Path) -> None:
    with _FIRST_PARTY_IMPORT_LOCK, _trusted_python_imports(
        import_root=None,
        blocked_roots=(
            Path(os.path.abspath(input_path.parent)),
            Path(os.path.abspath(output_path.parent)),
        ),
    ):
        _canonicalize_with_trusted_imports(input_path, output_path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser(
        "validate",
        help=(
            "validate a complete signed ledger directory under an external "
            "ledger-key trust anchor"
        ),
    )
    validate.add_argument("root", type=Path)
    validate.add_argument(
        "--trusted-ledger-pub",
        type=Path,
        required=True,
        help=(
            "caller-supplied Ed25519 public key outside ROOT, obtained from a "
            "previously trusted channel"
        ),
    )
    validate.add_argument(
        "--trusted-parent-repo",
        type=Path,
        required=True,
        help=(
            "caller-supplied disjoint Git repository containing the admitted "
            "trusted parent commit and exact schema/validator blobs"
        ),
    )

    canonicalize = subparsers.add_parser(
        "canonicalize",
        help="serialize one already-complete draft deterministically; no evidence is collected",
    )
    canonicalize.add_argument("input", type=Path)
    canonicalize.add_argument("output", type=Path)

    retirement = subparsers.add_parser(
        "validate-retirement",
        help="validate a post-ledger publication-authority retirement receipt",
    )
    retirement.add_argument("ledger_root", type=Path)
    retirement.add_argument("receipt", type=Path)
    retirement.add_argument("signature", type=Path)
    retirement.add_argument(
        "--trusted-ledger-pub",
        type=Path,
        required=True,
        help="the same external per-release ledger public key",
    )
    retirement.add_argument(
        "--trusted-parent-repo",
        type=Path,
        required=True,
        help="the same external trusted-parent Git repository used for the ledger",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate":
            validate_directory(
                args.root,
                args.trusted_ledger_pub,
                args.trusted_parent_repo,
            )
            print("release-ledger-v2: VALID")
        elif args.command == "canonicalize":
            _canonicalize(args.input, args.output)
            print(f"release-ledger-v2: canonical bytes written to {args.output}")
        else:
            validate_key_retirement(
                args.ledger_root,
                args.receipt,
                args.signature,
                args.trusted_ledger_pub,
                args.trusted_parent_repo,
            )
            print("release-key-retirement-v1: VALID")
    except LedgerValidationError as exc:
        print(f"release-ledger-v2: INVALID: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
