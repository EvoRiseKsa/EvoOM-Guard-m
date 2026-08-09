# --------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# --------------------------------------------------------------------------------
"""Single source of truth for the optional verifier-pack contract."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from typing import Any

PACK_REQUIRED = ("id", "version")
PACK_OPTIONAL = ("description", "target_type", "protocol")
PACK_KEYS = (*PACK_REQUIRED, *PACK_OPTIONAL)
PACK_DIGEST_FORMAT = "EVOGUARD_PACK_V2"
# These ceilings are part of the verifier-pack intake boundary.  They match the
# raw-Git Trusted Finalizer so a pack accepted by the runner cannot later become
# unfinalizable solely because the two components apply different resource
# limits.
MAX_PACK_FILE_BYTES = 8 * 1024 * 1024
MAX_PACK_BYTES = 32 * 1024 * 1024
MAX_PACK_MANIFEST_BYTES = 64 * 1024
MAX_PACK_ENTRIES = 10_000


class PackManifestError(ValueError):
    """An invalid or unstable verifier pack; missing manifests remain valid."""


def manifest_problems(manifest: Any) -> list[str]:
    """Return every contract problem so ``pack-doctor`` can report them all."""
    if not isinstance(manifest, dict):
        return ["pack.json must be a JSON object"]
    problems: list[str] = []
    for key in PACK_REQUIRED:
        if not isinstance(manifest.get(key), str) or not manifest[key].strip():
            problems.append(f"pack.json missing required string field {key!r}")
    for key in PACK_OPTIONAL:
        if key in manifest and not isinstance(manifest[key], str):
            problems.append(f"pack.json field {key!r} must be a string")
    unknown = sorted(set(manifest) - set(PACK_KEYS))
    if unknown:
        problems.append(
            "pack.json has unknown field(s): "
            + ", ".join(unknown)
            + f" (accepted: {', '.join(PACK_KEYS)})"
        )
    return problems


def extract_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return the canonical record every judge places in its attestation."""
    return {key: manifest[key] for key in PACK_KEYS if key in manifest}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    duplicates: list[str] = []
    for key, value in pairs:
        if key in decoded:
            duplicates.append(key)
        decoded[key] = value
    if duplicates:
        raise ValueError("duplicate JSON key(s): " + ", ".join(sorted(set(duplicates))))
    return decoded


def load_pack_manifest(pack_dir: str) -> dict[str, Any] | None:
    """Load ``pack.json`` fail-closed; return ``None`` when it is absent."""
    path = os.path.join(pack_dir, "pack.json")
    if not os.path.lexists(path):
        return None
    if os.path.islink(path) or not os.path.isfile(path):
        raise PackManifestError("pack.json exists but is not a regular file")
    try:
        size = os.path.getsize(path)
        if size > MAX_PACK_MANIFEST_BYTES:
            raise PackManifestError(
                f"pack.json exceeds the {MAX_PACK_MANIFEST_BYTES}-byte limit"
            )
        with open(path, "rb") as stream:
            data = stream.read(MAX_PACK_MANIFEST_BYTES + 1)
        if len(data) > MAX_PACK_MANIFEST_BYTES:
            raise PackManifestError(
                f"pack.json exceeds the {MAX_PACK_MANIFEST_BYTES}-byte limit"
            )
        if len(data) != size:
            raise PackManifestError("pack.json changed while it was being read")
        decoded = json.loads(
            data.decode("utf-8", "strict"),
            object_pairs_hook=_unique_object,
        )
    except PackManifestError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise PackManifestError(
            f"pack.json in {pack_dir!r} is not readable JSON ({exc}) — fix it "
            "or remove it (a plain folder of tests is a valid pack); check with "
            "`evo-guard pack-doctor`"
        ) from exc
    problems = manifest_problems(decoded)
    if problems:
        raise PackManifestError(
            f"pack.json in {pack_dir!r} is invalid: "
            + "; ".join(problems)
            + " — a manifest names a versioned behaviour contract; check with "
            "`evo-guard pack-doctor`"
        )
    return extract_manifest(decoded)


def _require_pack_root(pack_dir: str) -> None:
    if (
        not os.path.lexists(pack_dir)
        or os.path.islink(pack_dir)
        or not os.path.isdir(pack_dir)
    ):
        raise PackManifestError("verifier pack root must be a real directory")


def _relative_pack_path(path: str, pack_dir: str) -> str:
    return os.path.relpath(path, pack_dir).replace(os.sep, "/")


def _inspect_pack_directory(path: str, rel: str) -> None:
    try:
        mode = os.lstat(path).st_mode
    except OSError as exc:
        raise PackManifestError(
            f"verifier pack directory is not readable: {rel!r} ({exc})"
        ) from exc
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise PackManifestError(
            f"verifier pack contains a symlinked or special directory: {rel!r}"
        )


def _inspect_pack_file(path: str, rel: str) -> int:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise PackManifestError(
            f"verifier pack file is not readable: {rel!r} ({exc})"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise PackManifestError(
            f"verifier pack contains a symlink or special file: {rel!r}"
        )
    _require_pack_file_size(metadata.st_size, rel)
    return metadata.st_size


def _require_pack_file_size(size: int, rel: str) -> None:
    if size > MAX_PACK_FILE_BYTES:
        raise PackManifestError(
            f"verifier pack file exceeds the {MAX_PACK_FILE_BYTES}-byte "
            f"limit: {rel!r}"
        )


def _require_pack_total(total: int) -> None:
    if total > MAX_PACK_BYTES:
        raise PackManifestError(
            f"verifier pack exceeds the {MAX_PACK_BYTES}-byte total limit"
        )


def _require_pack_entry_count(count: int) -> None:
    if count > MAX_PACK_ENTRIES:
        raise PackManifestError(
            f"verifier pack exceeds the {MAX_PACK_ENTRIES}-entry limit"
        )


def _pack_inventory(pack_dir: str) -> tuple[list[str], list[tuple[str, str]]]:
    """Return sorted directories and regular files, refusing unbound content."""
    _require_pack_root(pack_dir)
    directories: list[str] = []
    files: list[tuple[str, str]] = []
    total_bytes = 0

    def walk_error(exc: OSError) -> None:
        raise PackManifestError(f"verifier pack tree is not readable: {exc}") from exc

    for dirpath, dirnames, filenames in os.walk(pack_dir, onerror=walk_error):
        dirnames.sort()
        for dirname in dirnames:
            path = os.path.join(dirpath, dirname)
            rel = _relative_pack_path(path, pack_dir)
            _inspect_pack_directory(path, rel)
            directories.append(rel)
            _require_pack_entry_count(len(directories) + len(files))
        for filename in sorted(filenames):
            path = os.path.join(dirpath, filename)
            rel = _relative_pack_path(path, pack_dir)
            total_bytes += _inspect_pack_file(path, rel)
            _require_pack_total(total_bytes)
            files.append((rel, path))
            _require_pack_entry_count(len(directories) + len(files))
    return directories, files


def _framed_path(digest: Any, kind: bytes, rel: str) -> None:
    try:
        rel_bytes = rel.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise PackManifestError(
            f"verifier pack path is not UTF-8 encodable: {rel!r}"
        ) from exc
    digest.update(kind)
    digest.update(len(rel_bytes).to_bytes(8, "big"))
    digest.update(rel_bytes)


def _hash_pack_file(digest: Any, rel: str, path: str, total: int) -> int:
    _framed_path(digest, b"F", rel)
    try:
        size = os.path.getsize(path)
        _require_pack_file_size(size, rel)
        _require_pack_total(total + size)
        digest.update(size.to_bytes(8, "big"))
        observed = 0
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                observed += len(chunk)
                total += len(chunk)
                _require_pack_file_size(observed, rel)
                _require_pack_total(total)
                digest.update(chunk)
        if observed != size:
            raise PackManifestError(f"verifier pack changed while hashing: {rel!r}")
    except PackManifestError:
        raise
    except OSError as exc:
        raise PackManifestError(
            f"verifier pack file is not readable: {rel!r} ({exc})"
        ) from exc
    return total


def _digest_inventory(
    directories: list[str], files: list[tuple[str, str]]
) -> str:
    """Hash one validated inventory using unambiguous, typed records."""
    digest = hashlib.sha256()
    digest.update(PACK_DIGEST_FORMAT.encode("ascii") + b"\0")
    for rel in directories:
        _framed_path(digest, b"D", rel)
    total_observed = 0
    for rel, path in files:
        total_observed = _hash_pack_file(digest, rel, path, total_observed)
    return digest.hexdigest()


def pack_digest(pack_dir: str) -> str:
    """Framed SHA-256 over a regular-file-only pack tree.

    Typed path records and length prefixes prevent ambiguous concatenation.
    Directory records bind empty namespace-package directories too. Symlinks and
    special files are refused because their runtime-dependent targets cannot be
    bound by a portable content digest.
    """
    directories, files = _pack_inventory(pack_dir)
    return _digest_inventory(directories, files)


def pack_test_files(pack_dir: str) -> list[str]:
    """Canonical list of pytest files a verifier pack can contribute."""
    _directories, files = _pack_inventory(pack_dir)
    return [
        rel
        for rel, _path in files
        if os.path.basename(rel).startswith("test_") and rel.endswith(".py")
    ]


def digest_and_manifest(pack_dir: str) -> tuple[str, dict[str, Any] | None]:
    """Return the canonical identity pair recorded by every judge."""
    directories, files = _pack_inventory(pack_dir)
    if not any(
        os.path.basename(rel).startswith("test_") and rel.endswith(".py")
        for rel, _path in files
    ):
        raise PackManifestError(
            "verifier pack contains no pytest test files (test_*.py)"
        )
    return _digest_inventory(directories, files), load_pack_manifest(pack_dir)


def snapshot_pack(
    source: str, destination: str
) -> tuple[str, dict[str, Any] | None]:
    """Copy, verify, and identify the exact snapshot a judge will execute."""
    source_identity = digest_and_manifest(source)
    try:
        shutil.copytree(source, destination, symlinks=True)
    except OSError as exc:
        raise PackManifestError(f"verifier pack could not be snapshotted: {exc}") from exc
    snapshot_identity = digest_and_manifest(destination)
    if source_identity != snapshot_identity:
        raise PackManifestError("verifier pack changed while it was being snapshotted")
    return snapshot_identity


def verify_pack_snapshot(
    snapshot: str,
    expected: tuple[str, dict[str, Any] | None],
) -> None:
    """Fail when a post-snapshot actor changed the pack before/while it ran."""
    observed = digest_and_manifest(snapshot)
    if observed != expected:
        raise PackManifestError(
            "verifier pack snapshot changed after it was accepted; refusing unbound results"
        )
