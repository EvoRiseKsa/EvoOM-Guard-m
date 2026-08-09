#!/usr/bin/env python3
"""Render reviewable project-status prose from one machine-readable source.

``PROJECT_STATUS.json`` contains only maintained state and explicit authority
paths. Ledger-recorded release identity and assets are read from the newest
immutable release ledger, while source identity is read from
``evoom_guard.__version__``. A separately referenced, unsigned
``published_unledgered`` exception may preserve bounded publication facts while
development advances. It never supplies release identity, assets, attestations,
or pipeline evidence in place of a valid signed ledger, and it does not imply
that one can be issued later.
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import cast

_ROOT = Path(__file__).resolve().parents[1]
_STATUS_PATH = Path("PROJECT_STATUS.json")
_FROZEN_V1_TREES = {
    "tests/baseline/v4.0.2": "26dfd2cad8c3deb936673569b0a82a141327e565",
    "tests/baseline/v4.1.0": "37e77848ed7a882ce17a86aecaec54c92e5ecd40",
    "tests/baseline/v4.2.0": "5bdd80810478b2b668e965841e50cfe4769f6643",
    "tests/baseline/v4.3.0": "f41640668f3dc76c5032c87d6bfe41694fb36e8f",
}
_STABLE_VERSION_RE = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z"
)
_DEV_VERSION_RE = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"\.dev(0|[1-9][0-9]*)\Z"
)
_V1_LEDGER_PATH_RE = re.compile(
    r"tests/baseline/v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"\.(?:0|[1-9][0-9]*))/RELEASE_LEDGER\.json\Z"
)
_V2_LEDGER_PATH_RE = re.compile(
    r"evidence/release-ledgers/v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"\.(?:0|[1-9][0-9]*))/RELEASE_LEDGER\.json\Z"
)
_UNSEALED_RECORD_PATH_RE = re.compile(
    r"evidence/release-operations/v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"\.(?:0|[1-9][0-9]*))/UNSEALED_STATUS\.json\Z"
)
_LEDGER_ERRATUM_PATH_RE = re.compile(
    r"docs/errata/V((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"\.(?:0|[1-9][0-9]*))-LEDGER\.md\Z"
)
_KEY_DISPOSITION_PATH_RE = re.compile(
    r"evidence/release-operations/v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"\.(?:0|[1-9][0-9]*))/LEDGER_KEY_DISPOSITION\.json\Z"
)
_LEDGER_DIRECTORY_RE = re.compile(
    r"v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"\.(?:0|[1-9][0-9]*))\Z"
)
_LAST_V1_LEDGER_VERSION = (4, 3, 0)
_PIPELINE_ASSETS = ("evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS")
_MAX_LEDGER_DIRECTORIES = 128
_MAX_PUBLISHED_UNLEDGERED_EXCEPTIONS = 128
_MAX_UNSEALED_DEFECTS = 16
_MAX_UNSEALED_AFFECTED_MATERIAL = 128
_BEGIN_RE = re.compile(r"<!-- BEGIN EVOGUARD_PROJECT_STATUS:([A-Z0-9_]+) -->")
_END_RE = re.compile(r"<!-- END EVOGUARD_PROJECT_STATUS:([A-Z0-9_]+) -->")
_MARKER_LINE_RE = re.compile(
    r"<!-- (BEGIN|END) EVOGUARD_PROJECT_STATUS:([A-Z0-9_]+) -->\Z"
)
_RAW_HTML_RE = re.compile(
    r"<(?:/?[A-Za-z][A-Za-z0-9-]*(?:\s|/?>|\Z)|!--|!DOCTYPE\b|\?|!\[CDATA\[)",
    re.IGNORECASE,
)
_MARKER_FILES = {
    "README.md": (
        "README_RELEASE_CHANNEL",
        "README_QUICKSTART_PIN",
        "README_INIT_PIN",
        "README_ACTION_PIN",
        "README_ATTESTATION_SCOPE",
    ),
    "docs/RELEASE_STATUS.md": (
        "RELEASE_STATUS_SUMMARY",
        "RELEASE_STATUS_CONSUMER_PIN",
        "RELEASE_STATUS_CURRENT_LEDGER",
    ),
    "docs/PROJECT_STATUS.md": (
        "PROJECT_STATUS_CORE_RELEASE",
        "PROJECT_STATUS_RELEASE_PIPELINE",
        "PROJECT_STATUS_RELEASE_EVIDENCE_ROWS",
    ),
    "ROADMAP.md": ("ROADMAP_LATEST_RELEASE", "ROADMAP_CURRENT_PIPELINE"),
    "docs/SBOM.md": ("SBOM_EXACT_STATUS", "SBOM_PIPELINE"),
    "docs/GITHUB_ARTIFACT_ATTESTATIONS.md": (
        "ATTESTATIONS_RELEASE_STATUS",
        "ATTESTATIONS_CONSUMER_VERIFICATION",
        "ATTESTATIONS_FUTURE_PIPELINE",
    ),
    "docs/RELEASE_TRUST_PIPELINE.md": ("RELEASE_TRUST_PIPELINE_STATUS",),
    "docs/architecture/REFACTOR_PROGRAM.md": ("REFACTOR_PROGRAM_STATUS",),
    "docs/ADOPTION.md": ("ADOPTION_CURRENT_RELEASE",),
    "docs/GUARD.md": (
        "GUARD_CURRENT_RELEASE",
        "GUARD_ACTION_EXAMPLE",
        "GUARD_NO_ACTION_EXAMPLE",
    ),
    "docs/EVIDENCE_BUNDLES.md": ("EVIDENCE_BUNDLES_RELEASE_PIN",),
    "docs/SIGNED_VERDICTS.md": ("SIGNED_VERDICTS_RELEASE_PIN",),
    "docs/TRUSTED_FINALIZER.md": ("TRUSTED_FINALIZER_RELEASE_PIN",),
    "SECURITY.md": ("SECURITY_SUPPORTED_VERSIONS",),
    "CHANGELOG.md": ("CHANGELOG_RELEASE_SUPPORT",),
}


class ProjectStatusError(ValueError):
    """Project status is ambiguous, stale, or inconsistent with repository truth."""


@dataclass(frozen=True)
class PublishedUnledgeredAuthority:
    record_path: str
    record_sha256: str
    erratum_path: str
    key_disposition_path: str


@dataclass(frozen=True)
class Status:
    schema_version: str
    lifecycle: str
    relation: str
    behavior_r2: str
    cli_extraction: str
    refactor_program: str
    ledger_path: str
    published_unledgered_record_path: str
    published_unledgered_record_sha256: str
    published_unledgered_erratum_path: str
    published_unledgered_key_disposition_path: str
    published_unledgered_authorities: tuple[PublishedUnledgeredAuthority, ...]
    pipeline_implementation: str


@dataclass(frozen=True)
class Ledger:
    schema_version: str
    version: str
    tag: str
    commit_sha: str
    release_url: str
    artifacts: tuple[str, ...]
    build_signer_workflow: str
    build_provenance_subjects: tuple[str, ...]
    release_attestation_subjects: tuple[str, ...]
    release_attestation_recorded: bool
    build_provenance_recorded: bool
    sbom_recorded: bool
    pipeline_operational_evidence_recorded: bool
    pipeline_publication_evidence_recorded: bool


@dataclass(frozen=True)
class PublishedUnledgeredRelease:
    version: str
    tag: str
    release_url: str
    record_path: str
    erratum_path: str
    recovery_version: str
    observed_ledger_path: str
    observed_consumer_pin: str
    key_disposition_path: str
    key_disposition_status: str
    authority_sha256: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class Context:
    status: Status
    ledger: Ledger
    source_version: str
    published_unledgered: PublishedUnledgeredRelease
    published_unledgered_history: tuple[PublishedUnledgeredRelease, ...] = ()


@dataclass(frozen=True)
class _WorkflowSpec:
    phase: str
    path: str
    jobs: tuple[tuple[str, tuple[str, ...]], ...]
    gate_job: str
    gate_expression: str
    asset_jobs: tuple[str, ...] = ()
    reviewed_sha256: str | None = None


@dataclass(frozen=True)
class _WorkflowJob:
    gate: str | None
    needs: frozenset[str]
    active_text: str


@dataclass(frozen=True)
class _FileIdentity:
    device: int
    inode: int
    mode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass
class _PendingWrite:
    target: Path
    staged: Path
    original: _FileIdentity
    expected_bytes: bytes


@dataclass(frozen=True)
class _TrustedGit:
    path: Path
    data: bytes
    identity: _FileIdentity
    parent_chain: Mapping[Path, tuple[int, int]]
    search_path: str


_GIT_LOCK = threading.RLock()
_ACTIVE_GIT: _TrustedGit | None = None
_MAX_GIT_EXECUTABLE_BYTES = 256 * 1024 * 1024


_SOURCE_GATE = "vars.EVOGUARD_RELEASE_SOURCE_V2_ENABLED == 'true'"
_ARTIFACT_GATE = "vars.EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1_ENABLED == 'true'"
_MAIN_SOURCE_GATE = f"github.ref == 'refs/heads/main' && {_SOURCE_GATE}"
_MAIN_ARTIFACT_GATE = f"github.ref == 'refs/heads/main' && {_ARTIFACT_GATE}"
_PUBLICATION_GATE = (
    f"{_ARTIFACT_GATE} && "
    "vars.EVOGUARD_RELEASE_PUBLICATION_ENABLED == "
    "github.event.workflow_run.head_sha"
)
_WORKFLOW_SPECS = (
    _WorkflowSpec(
        "A",
        ".github/workflows/evoguard-release-source-reverify.yml",
        (("metadata", ()), ("reverify", ("metadata",))),
        "metadata",
        _MAIN_SOURCE_GATE,
        reviewed_sha256="872f87892c92a69dcbde62799738b5935d9e0d3b604bfa4eb98442328d1da982",
    ),
    _WorkflowSpec(
        "B",
        ".github/workflows/evoguard-produce-release-source-receipt.yml",
        (("preflight", ()), ("receipt", ("preflight",))),
        "preflight",
        _SOURCE_GATE,
        reviewed_sha256="28b82ef90404a0773408b43d01646ff9b371aa84f8f6560b0277f96c6da9fb14",
    ),
    _WorkflowSpec(
        "C/D",
        ".github/workflows/evoguard-admit-release-source.yml",
        (
            ("preflight", ()),
            ("seal", ("preflight",)),
            ("detached-verify", ("preflight", "seal")),
        ),
        "preflight",
        _SOURCE_GATE,
        reviewed_sha256="3267183f42a817b9e4ab1842f61c1bb94ea7b2974bd5e49e885e3a2324acee1b",
    ),
    _WorkflowSpec(
        "E",
        ".github/workflows/evoguard-build-release-artifact.yml",
        (
            ("preflight", ()),
            ("build", ("preflight",)),
            ("attest", ("preflight", "build")),
        ),
        "preflight",
        _MAIN_ARTIFACT_GATE,
        ("build", "attest"),
        "c9ab62d29442ee6ecbf768d5868d25463fe1373ea31aa9a99ab7bfe8ccec8339",
    ),
    _WorkflowSpec(
        "F",
        ".github/workflows/evoguard-admit-release-artifact.yml",
        (
            ("preflight", ()),
            ("verify-attestations", ("preflight",)),
            ("seal", ("preflight", "verify-attestations")),
        ),
        "preflight",
        _ARTIFACT_GATE,
        ("preflight", "verify-attestations", "seal"),
        "619f9754c6825af99aefbf2f4c8950f08bdd8a843f8d9fdccee37e2eba642b05",
    ),
    _WorkflowSpec(
        "G",
        ".github/workflows/evoguard-verify-release-artifact.yml",
        (("detached-verify", ()),),
        "detached-verify",
        _ARTIFACT_GATE,
        ("detached-verify",),
        "b7100c92b1a770655b5124685d118db82d624e05eef59bf51903c122215e707f",
    ),
    _WorkflowSpec(
        "H",
        ".github/workflows/evoguard-publish-admitted-release.yml",
        (
            ("preflight", ()),
            ("draft", ("preflight",)),
            ("publish", ("preflight", "draft")),
        ),
        "preflight",
        _PUBLICATION_GATE,
        ("preflight", "draft", "publish"),
        "98c58f6205e4a63b8e163bf2d6c73ac164acdf4f935adcb28e275537559847e7",
    ),
)
_LEGACY_FALSE_GATE = (
    "false && github.ref == format('refs/heads/{0}', "
    "github.event.repository.default_branch)"
)
_LEGACY_SPEC = _WorkflowSpec(
    "legacy",
    ".github/workflows/release.yml",
    (
        ("validate-test", ()),
        ("release-e2e", ()),
        ("release-windows-e2e", ()),
        ("build-artifact", ("validate-test", "release-e2e", "release-windows-e2e")),
        ("attest-release-assets", ("validate-test", "build-artifact")),
        ("prepare-draft", ("validate-test", "attest-release-assets")),
    ),
    "validate-test",
    _LEGACY_FALSE_GATE,
    reviewed_sha256="36f61696fdee3da0baf7a85d199f0ff11b0d344ff80870b7e43776e0362e570c",
)
_ASSET_SENTINELS = {
    ("E", "build"): (
        "sha256sum evo-guard.pyz evo-guard.spdx.json > SHA256SUMS",
        "sha256sum --check --strict SHA256SUMS",
    ),
    ("E", "attest"): (
        "'SHA256SUMS': 512,",
        "lines = (root / 'SHA256SUMS').read_text(encoding='ascii').splitlines()",
    ),
    ("F", "preflight"): (
        "'SHA256SUMS': 512,",
        "checksum_lines = (root / 'SHA256SUMS').read_text(encoding='ascii').splitlines()",
    ),
    ("F", "verify-attestations"): (
        "create_slsa_receipt evo-guard.pyz build-provenance",
        "create_slsa_receipt evo-guard.spdx.json spdx-provenance",
        "--predicate-type https://spdx.dev/Document/v2.3",
    ),
    ("F", "seal"): (
        "for name in evo-guard.pyz evo-guard.spdx.json SHA256SUMS; do",
    ),
    ("G", "detached-verify"): (
        "for name in ('evo-guard.pyz', 'evo-guard.spdx.json', 'SHA256SUMS'):",
        "sha256sum --check --strict SHA256SUMS",
    ),
    ("H", "preflight"): (
        "for name in ('evo-guard.pyz', 'evo-guard.spdx.json', 'SHA256SUMS'):",
        "sha256sum --check --strict SHA256SUMS",
    ),
    ("H", "draft"): (
        "for name in ('evo-guard.pyz', 'evo-guard.spdx.json', 'SHA256SUMS'):",
        "sha256sum --check --strict SHA256SUMS",
    ),
    ("H", "publish"): (
        "for name in ('evo-guard.pyz', 'evo-guard.spdx.json', 'SHA256SUMS'):",
        "sha256sum --check --strict SHA256SUMS",
    ),
}


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _identity(metadata: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _same_open_file(left: os.stat_result, right: os.stat_result) -> bool:
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


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath(
            (os.path.normcase(os.fspath(_absolute(path))),
             os.path.normcase(os.fspath(_absolute(root))))
        ) == os.path.normcase(os.fspath(_absolute(root)))
    except ValueError:
        return False


def _host_directory_chain(path: Path) -> dict[Path, tuple[int, int]]:
    chain: dict[Path, tuple[int, int]] = {}
    for current in (path, *path.parents):
        try:
            metadata = os.lstat(current)
        except OSError as exc:
            raise ProjectStatusError(
                f"cannot inspect trusted Git path component: {current}"
            ) from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or _is_reparse_point(metadata)
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise ProjectStatusError(
                f"trusted Git path has a link-like component: {current}"
            )
        chain[current] = (metadata.st_dev, metadata.st_ino)
    return chain


def _read_host_executable(path: Path) -> tuple[bytes, _FileIdentity]:
    parent_chain = _host_directory_chain(path.parent)
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise ProjectStatusError(f"cannot inspect trusted Git executable: {path}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or _is_reparse_point(before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size < 1
        or before.st_size > _MAX_GIT_EXECUTABLE_BYTES
    ):
        raise ProjectStatusError("trusted Git executable is not one regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProjectStatusError("cannot open trusted Git executable") from exc
    try:
        opened = os.fstat(descriptor)
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        )
        path_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened_identity != path_identity
        ):
            raise ProjectStatusError("trusted Git executable changed while opening")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_GIT_EXECUTABLE_BYTES:
                raise ProjectStatusError("trusted Git executable exceeds its bound")
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        final = os.lstat(path)
    except OSError as exc:
        raise ProjectStatusError("cannot re-inspect trusted Git executable") from exc
    if (
        (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        != opened_identity
        or _identity(final) != _identity(before)
    ):
        raise ProjectStatusError("trusted Git executable changed while reading")
    for current, expected in parent_chain.items():
        metadata = os.lstat(current)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or _is_reparse_point(metadata)
            or not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != expected
        ):
            raise ProjectStatusError("trusted Git executable ancestry changed")
    return b"".join(chunks), _identity(before)


def _resolve_git(root: Path) -> _TrustedGit:
    blocked = (
        _absolute(root),
        _absolute(Path.cwd()),
        _absolute(Path(tempfile.gettempdir())),
    )
    executable_name = "git.exe" if os.name == "nt" else "git"
    seen: set[str] = set()
    for raw in os.environ.get("PATH", "").split(os.pathsep):
        if not raw or raw != raw.strip() or raw.startswith('"') or raw.endswith('"'):
            continue
        directory = Path(raw)
        if not directory.is_absolute():
            continue
        directory = _absolute(directory)
        portable = os.path.normcase(os.fspath(directory))
        if portable in seen or any(
            _path_is_within(directory, item) or _path_is_within(item, directory)
            for item in blocked
        ):
            continue
        seen.add(portable)
        candidate = directory / executable_name
        try:
            data, identity = _read_host_executable(candidate)
        except ProjectStatusError:
            continue
        if os.name != "nt" and not os.access(candidate, os.X_OK):
            continue
        return _TrustedGit(
            path=candidate,
            data=data,
            identity=identity,
            parent_chain=_host_directory_chain(candidate.parent),
            search_path=os.fspath(directory),
        )
    raise ProjectStatusError(
        "no trusted Git executable exists in an absolute host PATH directory"
    )


def _require_git_unchanged(git: _TrustedGit) -> None:
    data, identity = _read_host_executable(git.path)
    if data != git.data or identity != git.identity:
        raise ProjectStatusError("trusted Git executable changed during validation")
    for current, expected in git.parent_chain.items():
        try:
            metadata = os.lstat(current)
        except OSError as exc:
            raise ProjectStatusError(
                "cannot re-inspect trusted Git executable ancestry"
            ) from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or _is_reparse_point(metadata)
            or not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != expected
        ):
            raise ProjectStatusError("trusted Git executable ancestry changed")


def _git_environment(git: _TrustedGit) -> dict[str, str]:
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
    environment.update(
        {
            "PATH": git.search_path,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    return environment


@contextmanager
def _trusted_git_session(root: Path) -> Iterator[None]:
    """Freeze Git for one single-threaded project-status CLI operation."""

    global _ACTIVE_GIT
    with _GIT_LOCK:
        if _ACTIVE_GIT is not None:
            directory = _ACTIVE_GIT.path.parent
            blocked = (
                _absolute(root),
                _absolute(Path.cwd()),
                _absolute(Path(tempfile.gettempdir())),
            )
            if any(
                _path_is_within(directory, item)
                or _path_is_within(item, directory)
                for item in blocked
            ):
                raise ProjectStatusError(
                    "active trusted Git executable overlaps the new repository root"
                )
            _require_git_unchanged(_ACTIVE_GIT)
            yield
            return
        trusted = _resolve_git(root)
        _ACTIVE_GIT = trusted
        try:
            yield
        finally:
            try:
                _require_git_unchanged(trusted)
            finally:
                _ACTIVE_GIT = None


def _selected_git(root: Path) -> _TrustedGit:
    return _ACTIVE_GIT or _resolve_git(root)


def _safe_path(
    root: Path,
    path: Path,
    *,
    leaf: str,
    allow_missing_leaf: bool = False,
) -> Path:
    root_absolute = _absolute(root)
    path_absolute = _absolute(path)
    try:
        relative = path_absolute.relative_to(root_absolute)
    except ValueError as exc:
        raise ProjectStatusError(f"path escapes repository root: {path}") from exc
    current = root_absolute
    components: tuple[str, ...] = ("", *relative.parts)
    for index, component in enumerate(components):
        if component:
            current /= component
        is_leaf = index == len(components) - 1
        try:
            metadata = os.lstat(current)
        except FileNotFoundError as exc:
            if is_leaf and allow_missing_leaf:
                return path_absolute
            raise ProjectStatusError(f"required path is missing: {current}") from exc
        except OSError as exc:
            raise ProjectStatusError(f"cannot inspect path component: {current}") from exc
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
            raise ProjectStatusError(f"symlink or reparse point is forbidden: {current}")
        if not is_leaf and not stat.S_ISDIR(metadata.st_mode):
            raise ProjectStatusError(f"path component is not a directory: {current}")
        if is_leaf and leaf == "file" and not stat.S_ISREG(metadata.st_mode):
            raise ProjectStatusError(f"path must be a regular file: {current}")
        if is_leaf and leaf == "directory" and not stat.S_ISDIR(metadata.st_mode):
            raise ProjectStatusError(f"path must be a directory: {current}")
    return path_absolute


def _read_stable_bytes(root: Path, path: Path) -> tuple[bytes, _FileIdentity]:
    safe = _safe_path(root, path, leaf="file")
    try:
        before_metadata = os.lstat(safe)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(safe, flags)
    except OSError as exc:
        raise ProjectStatusError(f"cannot open regular file: {safe}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_open_file(
            opened,
            before_metadata,
        ):
            raise ProjectStatusError(f"file changed while opening: {safe}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after_read = os.fstat(descriptor)
        if _identity(after_read) != _identity(opened):
            raise ProjectStatusError(f"file changed while reading: {safe}")
    except OSError as exc:
        raise ProjectStatusError(f"cannot read regular file: {safe}") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            raise ProjectStatusError(f"cannot close regular file: {safe}") from exc
    try:
        after_close = os.lstat(safe)
    except OSError as exc:
        raise ProjectStatusError(f"cannot re-inspect regular file: {safe}") from exc
    if _identity(after_close) != _identity(before_metadata):
        raise ProjectStatusError(f"file changed during read: {safe}")
    return b"".join(chunks), _identity(before_metadata)


def _duplicate_safe_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProjectStatusError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _load_json_bytes(raw: bytes, path: Path) -> object:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ProjectStatusError(f"UTF-8 BOM is forbidden: {path}")
    try:
        text = raw.decode("utf-8")
        return cast(
            object,
            json.loads(text, object_pairs_hook=_duplicate_safe_object),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProjectStatusError(f"invalid UTF-8 JSON: {path}") from exc


def _load_json(root: Path, path: Path) -> object:
    raw, _ = _read_stable_bytes(root, path)
    return _load_json_bytes(raw, path)


def _mapping(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ProjectStatusError(f"{where} must be an object")
    result: dict[str, object] = {}
    for raw_key, raw_value in value.items():
        if not isinstance(raw_key, str):
            raise ProjectStatusError(f"{where} contains a non-string key")
        result[raw_key] = raw_value
    return result


def _exact_keys(
    value: dict[str, object],
    where: str,
    required: set[str],
) -> None:
    actual = set(value)
    if actual != required:
        missing = sorted(required - actual)
        extra = sorted(actual - required)
        raise ProjectStatusError(
            f"{where} keys differ; missing={missing!r}, extra={extra!r}"
        )


def _string(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise ProjectStatusError(f"{where} must be a string")
    return value


def _bounded_text(
    value: object,
    where: str,
    *,
    maximum: int = 2048,
) -> str:
    result = _string(value, where)
    if (
        not result
        or result != result.strip()
        or len(result) > maximum
        or "\r" in result
        or any(ord(character) < 32 and character not in "\n\t" for character in result)
    ):
        raise ProjectStatusError(f"{where} must be bounded canonical text")
    return result


def _positive_integer(value: object, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ProjectStatusError(f"{where} must be a positive integer")
    return value


def _enum(value: object, where: str, allowed: set[str]) -> str:
    result = _string(value, where)
    if result not in allowed:
        raise ProjectStatusError(f"{where} has unsupported value {result!r}")
    return result


def _canonical_utc(value: object, where: str) -> datetime:
    text = _string(value, where)
    if re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        text,
    ) is None:
        raise ProjectStatusError(f"{where} must be canonical UTC")
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ProjectStatusError(f"{where} is not a real UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != text:
        raise ProjectStatusError(f"{where} must be canonical UTC")
    return parsed


def _published_unledgered_authority(
    value: object,
    where: str,
) -> tuple[tuple[int, int, int], PublishedUnledgeredAuthority]:
    authority = _mapping(value, where)
    _exact_keys(
        authority,
        where,
        {"record", "record_sha256", "erratum", "key_disposition"},
    )
    record_path = _string(authority["record"], f"{where}.record")
    record_sha256 = _string(
        authority["record_sha256"],
        f"{where}.record_sha256",
    )
    erratum_path = _string(authority["erratum"], f"{where}.erratum")
    key_disposition_path = _string(
        authority["key_disposition"],
        f"{where}.key_disposition",
    )
    if re.fullmatch(r"[0-9a-f]{64}", record_sha256) is None:
        raise ProjectStatusError(f"{where}.record_sha256 is not canonical")
    record_match = _UNSEALED_RECORD_PATH_RE.fullmatch(record_path)
    erratum_match = _LEDGER_ERRATUM_PATH_RE.fullmatch(erratum_path)
    disposition_match = _KEY_DISPOSITION_PATH_RE.fullmatch(key_disposition_path)
    if (
        record_match is None
        or erratum_match is None
        or disposition_match is None
        or record_match.group(1) != erratum_match.group(1)
        or record_match.group(1) != disposition_match.group(1)
    ):
        raise ProjectStatusError(
            f"{where} authority paths must name one canonical version"
        )
    return (
        _version_tuple(record_match.group(1)),
        PublishedUnledgeredAuthority(
            record_path=record_path,
            record_sha256=record_sha256,
            erratum_path=erratum_path,
            key_disposition_path=key_disposition_path,
        ),
    )


def _published_unledgered_authority_tag(
    authority: PublishedUnledgeredAuthority,
) -> str:
    match = _UNSEALED_RECORD_PATH_RE.fullmatch(authority.record_path)
    if match is None:
        raise ProjectStatusError(
            "cannot derive a published-unledgered tag from PROJECT_STATUS.json"
        )
    return f"v{match.group(1)}"


def load_status(root: Path, *, raw: bytes | None = None) -> Status:
    status_path = root / _STATUS_PATH
    if raw is None:
        raw, _ = _read_stable_bytes(root, status_path)
    top = _mapping(_load_json_bytes(raw, status_path), "PROJECT_STATUS.json")
    _exact_keys(
        top,
        "PROJECT_STATUS.json",
        {
            "schema_version",
            "source",
            "published_release",
            "release_exceptions",
            "release_pipeline",
        },
    )
    schema_version = _enum(
        top["schema_version"],
        "PROJECT_STATUS.json.schema_version",
        {
            "evoguard-project-status-v1",
            "evoguard-project-status-v2",
        },
    )

    source = _mapping(top["source"], "source")
    _exact_keys(source, "source", {"lifecycle", "relation_to_latest_release", "architecture"})
    architecture = _mapping(source["architecture"], "source.architecture")
    _exact_keys(
        architecture,
        "source.architecture",
        {
            "behavior_preserving_r2",
            "cli_handler_extraction",
            "overall_refactor_program",
        },
    )
    published = _mapping(top["published_release"], "published_release")
    _exact_keys(published, "published_release", {"ledger"})
    exceptions = _mapping(top["release_exceptions"], "release_exceptions")
    _exact_keys(exceptions, "release_exceptions", {"published_unledgered"})
    raw_published_unledgered = exceptions["published_unledgered"]
    if schema_version == "evoguard-project-status-v1":
        if not isinstance(raw_published_unledgered, Mapping):
            raise ProjectStatusError(
                "project-status v1 requires one published-unledgered object"
            )
        raw_authorities = [raw_published_unledgered]
    else:
        if (
            not isinstance(raw_published_unledgered, list)
            or not 1
            <= len(raw_published_unledgered)
            <= _MAX_PUBLISHED_UNLEDGERED_EXCEPTIONS
        ):
            raise ProjectStatusError(
                "project-status v2 requires a bounded non-empty "
                "published-unledgered list"
            )
        raw_authorities = raw_published_unledgered

    parsed_authorities = tuple(
        _published_unledgered_authority(
            value,
            f"release_exceptions.published_unledgered[{index}]",
        )
        for index, value in enumerate(raw_authorities)
    )
    authority_versions = tuple(version for version, _ in parsed_authorities)
    authorities = tuple(authority for _, authority in parsed_authorities)
    authority_paths = tuple(
        path
        for authority in authorities
        for path in (
            authority.record_path,
            authority.erratum_path,
            authority.key_disposition_path,
        )
    )
    authority_digests = tuple(
        authority.record_sha256 for authority in authorities
    )
    if (
        any(
            left >= right
            for left, right in zip(
                authority_versions,
                authority_versions[1:],
                strict=False,
            )
        )
        or len(set(authority_versions)) != len(authority_versions)
        or len(set(authority_paths)) != len(authority_paths)
        or len(set(authority_digests)) != len(authority_digests)
    ):
        raise ProjectStatusError(
            "published-unledgered authorities must be strictly version-ordered "
            "with unique versions, paths, and record digests"
        )
    latest_authority = authorities[-1]
    pipeline = _mapping(top["release_pipeline"], "release_pipeline")
    _exact_keys(
        pipeline,
        "release_pipeline",
        {
            "activation_model",
            "contract",
            "evidence_scope",
            "implementation",
            "legacy_workflow",
        },
    )
    if pipeline["contract"] != "protected-a-h-v1":
        raise ProjectStatusError("release_pipeline.contract is not protected-a-h-v1")
    if pipeline["legacy_workflow"] != "hard-disabled":
        raise ProjectStatusError("legacy release workflow must remain hard-disabled")
    if pipeline["activation_model"] != "disabled-by-default":
        raise ProjectStatusError("A-H pipeline must remain disabled by default")
    if pipeline["evidence_scope"] != "durable-repository-record":
        raise ProjectStatusError("pipeline evidence must mean durable repository evidence")
    status = Status(
        schema_version=schema_version,
        lifecycle=_enum(
            source["lifecycle"],
            "source.lifecycle",
            {
                "unreleased-development",
                "release-candidate",
                "published-unledgered",
                "release-line",
            },
        ),
        relation=_enum(
            source["relation_to_latest_release"],
            "source.relation_to_latest_release",
            {"descendant"},
        ),
        behavior_r2=_enum(
            architecture["behavior_preserving_r2"],
            "source.architecture.behavior_preserving_r2",
            {"in-progress", "complete"},
        ),
        cli_extraction=_enum(
            architecture["cli_handler_extraction"],
            "source.architecture.cli_handler_extraction",
            {"in-progress", "complete"},
        ),
        refactor_program=_enum(
            architecture["overall_refactor_program"],
            "source.architecture.overall_refactor_program",
            {"in-progress", "complete"},
        ),
        ledger_path=_string(published["ledger"], "published_release.ledger"),
        published_unledgered_record_path=latest_authority.record_path,
        published_unledgered_record_sha256=latest_authority.record_sha256,
        published_unledgered_erratum_path=latest_authority.erratum_path,
        published_unledgered_key_disposition_path=(
            latest_authority.key_disposition_path
        ),
        published_unledgered_authorities=authorities,
        pipeline_implementation=_enum(
            pipeline["implementation"],
            "release_pipeline.implementation",
            {"scaffolded", "implemented"},
        ),
    )
    if (
        _V1_LEDGER_PATH_RE.fullmatch(status.ledger_path) is None
        and _V2_LEDGER_PATH_RE.fullmatch(status.ledger_path) is None
    ):
        raise ProjectStatusError("published_release.ledger is outside the ledger namespace")
    if status.relation != "descendant":
        raise ProjectStatusError(
            "the current lifecycle schema supports only source descendants"
        )
    return status


def _extract_source_version(root: Path) -> str:
    path = root / "evoom_guard/__init__.py"
    try:
        tree = ast.parse(_read_text(root, path), filename=str(path))
    except SyntaxError as exc:
        raise ProjectStatusError("cannot parse evoom_guard.__version__") from exc
    versions: list[str] = []
    for statement in tree.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        if not any(isinstance(target, ast.Name) and target.id == "__version__" for target in targets):
            continue
        value = statement.value
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            raise ProjectStatusError("__version__ must be one literal string")
        versions.append(value.value)
    if len(versions) != 1:
        raise ProjectStatusError("expected exactly one __version__ assignment")
    return versions[0]


def _version_tuple(version: str, *, development: bool = False) -> tuple[int, int, int]:
    match = (_DEV_VERSION_RE if development else _STABLE_VERSION_RE).fullmatch(version)
    if match is None:
        kind = "development" if development else "stable"
        raise ProjectStatusError(f"invalid canonical {kind} version: {version!r}")
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def _verify_published_unledgered_git_bindings(
    root: Path,
    *,
    trusted_head: str,
    trusted_exception_tag_commit: str,
    tag: str,
    release_commit: str,
    trusted_parent_commit: str,
    trusted_parent_tree: str,
    validator_path: str,
    validator_blob: str,
    corrected_commit: str,
    corrected_pr: int,
) -> None:
    tagged_commit = _git(
        root,
        "rev-parse",
        "--verify",
        f"refs/tags/{tag}^{{commit}}",
    )
    ancestry = _git(
        root,
        "rev-list",
        "--parents",
        "-n",
        "1",
        tagged_commit,
    ).split()
    if (
        tagged_commit != trusted_exception_tag_commit
        or trusted_exception_tag_commit != release_commit
        or len(ancestry) != 2
        or ancestry[0] != release_commit
        or ancestry[1] != trusted_parent_commit
    ):
        raise ProjectStatusError(
            "published-unledgered release and trusted parent are not bound to Git"
        )
    actual_parent_tree = _git(
        root,
        "rev-parse",
        "--verify",
        f"{trusted_parent_commit}^{{tree}}",
    )
    actual_validator_blob = _git(
        root,
        "rev-parse",
        "--verify",
        f"{trusted_parent_commit}:{validator_path}",
    )
    actual_corrected_commit = _git(
        root,
        "rev-parse",
        "--verify",
        f"{corrected_commit}^{{commit}}",
    )
    corrected_subject = _git(
        root,
        "show",
        "-s",
        "--format=%s",
        actual_corrected_commit,
    )
    if (
        actual_parent_tree != trusted_parent_tree
        or actual_validator_blob != validator_blob
        or actual_corrected_commit != corrected_commit
        or not corrected_subject.endswith(f"(#{corrected_pr})")
    ):
        raise ProjectStatusError(
            "published-unledgered failure boundary is not derived from Git"
        )
    _git(
        root,
        "merge-base",
        "--is-ancestor",
        release_commit,
        corrected_commit,
    )
    _git(
        root,
        "merge-base",
        "--is-ancestor",
        corrected_commit,
        trusted_head,
    )


def _load_published_unledgered(
    root: Path,
    status: Status,
    ledger: Ledger,
    source_version: str,
    *,
    verify_git: bool,
    authority: PublishedUnledgeredAuthority | None = None,
    validate_relation: bool = True,
    trusted_head: str | None = None,
    trusted_exception_tag_commit: str | None = None,
) -> PublishedUnledgeredRelease:
    if verify_git and (
        trusted_head is None
        or trusted_exception_tag_commit is None
        or re.fullmatch(r"[0-9a-f]{40}", trusted_head) is None
        or re.fullmatch(r"[0-9a-f]{40}", trusted_exception_tag_commit) is None
    ):
        raise ProjectStatusError(
            "published-unledgered Git verification requires frozen references"
        )
    selected_authority = authority or PublishedUnledgeredAuthority(
        record_path=status.published_unledgered_record_path,
        record_sha256=status.published_unledgered_record_sha256,
        erratum_path=status.published_unledgered_erratum_path,
        key_disposition_path=status.published_unledgered_key_disposition_path,
    )
    record_relative = selected_authority.record_path
    erratum_relative = selected_authority.erratum_path
    disposition_relative = selected_authority.key_disposition_path
    record_match = _UNSEALED_RECORD_PATH_RE.fullmatch(record_relative)
    erratum_match = _LEDGER_ERRATUM_PATH_RE.fullmatch(erratum_relative)
    disposition_match = _KEY_DISPOSITION_PATH_RE.fullmatch(disposition_relative)
    if (
        record_match is None
        or erratum_match is None
        or disposition_match is None
        or record_match.group(1) != erratum_match.group(1)
        or record_match.group(1) != disposition_match.group(1)
    ):
        raise ProjectStatusError("published-unledgered authority paths are inconsistent")
    path_version = record_match.group(1)

    record_path = root / record_relative
    record_bytes, _ = _read_stable_bytes(root, record_path)
    if verify_git:
        assert trusted_head is not None
        _verify_tracked_bytes(
            root,
            record_relative,
            record_bytes,
            revision=trusted_head,
        )
    if (
        hashlib.sha256(record_bytes).hexdigest()
        != selected_authority.record_sha256
    ):
        raise ProjectStatusError(
            "published-unledgered exception bytes differ from the reviewed digest"
        )
    record = _mapping(
        _load_json_bytes(record_bytes, record_path),
        "published-unledgered exception record",
    )
    current_record_bytes, _ = _read_stable_bytes(root, record_path)
    if current_record_bytes != record_bytes:
        raise ProjectStatusError("published-unledgered exception record changed during validation")
    _exact_keys(
        record,
        "published-unledgered exception record",
        {
            "schema_version",
            "recorded_utc",
            "record_scope",
            "release",
            "assets",
            "verification_observations",
            "failure_boundary",
            "ledger_state",
            "trust_boundary",
        },
    )
    record_schema_version = _enum(
        record["schema_version"],
        "published-unledgered exception schema_version",
        {
            "evoguard-unsealed-release-status-v1",
            "evoguard-unsealed-release-status-v2",
        },
    )
    if record["record_scope"] != (
        "Unsigned post-publication observation; not a release ledger or substitute for one."
    ):
        raise ProjectStatusError("published-unledgered exception overstates its scope")
    recorded_utc = _canonical_utc(
        record["recorded_utc"],
        "published-unledgered recorded_utc",
    )

    release = _mapping(record["release"], "published-unledgered release")
    _exact_keys(
        release,
        "published-unledgered release",
        {
            "repository",
            "repository_id",
            "version",
            "tag",
            "tag_object_type",
            "commit_sha",
            "release_id",
            "state",
            "draft",
            "prerelease",
            "immutable",
            "created_utc",
            "created_utc_semantics",
            "published_utc",
            "release_url",
        },
    )
    version = _string(release["version"], "published-unledgered release.version")
    tag = _string(release["tag"], "published-unledgered release.tag")
    release_url = _string(
        release["release_url"],
        "published-unledgered release.release_url",
    )
    commit_sha = _string(
        release["commit_sha"],
        "published-unledgered release.commit_sha",
    )
    created_utc = _canonical_utc(
        release["created_utc"],
        "published-unledgered release.created_utc",
    )
    published_utc = _canonical_utc(
        release["published_utc"],
        "published-unledgered release.published_utc",
    )
    repository_id = _positive_integer(
        release["repository_id"],
        "published-unledgered release.repository_id",
    )
    release_id = _positive_integer(
        release["release_id"],
        "published-unledgered release.release_id",
    )
    expected_url = f"https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v{version}"
    if (
        version != path_version
        or tag != f"v{version}"
        or release["repository"] != "EvoRiseKsa/EvoOM-Guard-m"
        or repository_id <= 0
        or release_id <= 0
        or release["tag_object_type"] != "commit"
        or re.fullmatch(r"[0-9a-f]{40}", commit_sha) is None
        or release["state"] != "published"
        or release["draft"] is not False
        or release["prerelease"] is not False
        or release["immutable"] is not True
        or release["created_utc_semantics"]
        != (
            "Exact GitHub Releases API created_at value; GitHub defines it as "
            "target-commit metadata, not a draft-creation or publication time."
        )
        or release_url != expected_url
        or created_utc > published_utc
        or recorded_utc < published_utc
    ):
        raise ProjectStatusError(
            "published-unledgered exception does not identify one immutable publication"
        )

    raw_assets = record["assets"]
    if not isinstance(raw_assets, list) or len(raw_assets) != len(_PIPELINE_ASSETS):
        raise ProjectStatusError(
            "published-unledgered assets must be the exact ordered release set"
        )
    asset_names: list[str] = []
    asset_ids: list[int] = []
    asset_digests: list[str] = []
    for index, raw_asset in enumerate(raw_assets):
        asset = _mapping(raw_asset, f"published-unledgered assets[{index}]")
        _exact_keys(
            asset,
            f"published-unledgered assets[{index}]",
            {"name", "asset_id", "size", "sha256", "url"},
        )
        name = _string(asset["name"], f"published-unledgered assets[{index}].name")
        asset_id = _positive_integer(
            asset["asset_id"],
            f"published-unledgered assets[{index}].asset_id",
        )
        _positive_integer(
            asset["size"],
            f"published-unledgered assets[{index}].size",
        )
        digest = _string(
            asset["sha256"],
            f"published-unledgered assets[{index}].sha256",
        )
        expected_asset_url = (
            "https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/download/"
            f"{tag}/{name}"
        )
        if (
            name != _PIPELINE_ASSETS[index]
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or asset["url"] != expected_asset_url
        ):
            raise ProjectStatusError(
                "published-unledgered asset identity is not canonical"
            )
        asset_names.append(name)
        asset_ids.append(asset_id)
        asset_digests.append(digest)
    if len(set(asset_ids)) != len(asset_ids) or len(set(asset_digests)) != len(
        asset_digests
    ):
        raise ProjectStatusError("published-unledgered asset identities are not unique")

    observations = _mapping(
        record["verification_observations"],
        "published-unledgered verification_observations",
    )
    _exact_keys(
        observations,
        "published-unledgered verification_observations",
        {"release_attestation", "build_provenance", "tag_ci", "action_smoke"},
    )
    release_attestation = _mapping(
        observations["release_attestation"],
        "published-unledgered release_attestation",
    )
    _exact_keys(
        release_attestation,
        "published-unledgered release_attestation",
        {"verified", "tag_commit_sha", "asset_subjects", "command"},
    )
    if (
        release_attestation["verified"] is not True
        or release_attestation["tag_commit_sha"] != commit_sha
        or release_attestation["asset_subjects"] != asset_names
        or release_attestation["command"]
        != f"gh release verify {tag} --repo EvoRiseKsa/EvoOM-Guard-m"
    ):
        raise ProjectStatusError(
            "published-unledgered release attestation is not cross-bound"
        )

    build_provenance = _mapping(
        observations["build_provenance"],
        "published-unledgered build_provenance",
    )
    _exact_keys(
        build_provenance,
        "published-unledgered build_provenance",
        {
            "verified",
            "subjects",
            "source_commit_sha",
            "source_ref",
            "signer_workflow",
            "runner_environment",
            "run_url",
        },
    )
    if (
        build_provenance["verified"] is not True
        or build_provenance["subjects"] != asset_names[:2]
        or build_provenance["source_commit_sha"] != commit_sha
        or build_provenance["source_ref"] != "refs/heads/main"
        or build_provenance["signer_workflow"]
        != (
            "EvoRiseKsa/EvoOM-Guard-m/"
            ".github/workflows/evoguard-build-release-artifact.yml"
        )
        or build_provenance["runner_environment"] != "github-hosted"
        or re.fullmatch(
            r"https://github\.com/EvoRiseKsa/EvoOM-Guard-m/actions/runs/"
            r"[1-9][0-9]*/attempts/[1-9][0-9]*",
            _string(
                build_provenance["run_url"],
                "published-unledgered build_provenance.run_url",
            ),
        )
        is None
    ):
        raise ProjectStatusError(
            "published-unledgered build provenance is not cross-bound"
        )

    ci_run_ids: list[int] = []
    for observation_name in ("tag_ci", "action_smoke"):
        ci_observation = _mapping(
            observations[observation_name],
            f"published-unledgered {observation_name}",
        )
        _exact_keys(
            ci_observation,
            f"published-unledgered {observation_name}",
            {
                "run_id",
                "run_url",
                "head_sha",
                "conclusion",
                "successful_jobs",
                "total_jobs",
            },
        )
        run_id = _positive_integer(
            ci_observation["run_id"],
            f"published-unledgered {observation_name}.run_id",
        )
        successful_jobs = _positive_integer(
            ci_observation["successful_jobs"],
            f"published-unledgered {observation_name}.successful_jobs",
        )
        total_jobs = _positive_integer(
            ci_observation["total_jobs"],
            f"published-unledgered {observation_name}.total_jobs",
        )
        if (
            ci_observation["run_url"]
            != (
                "https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/runs/"
                f"{run_id}"
            )
            or ci_observation["head_sha"] != commit_sha
            or ci_observation["conclusion"] != "success"
            or successful_jobs != total_jobs
        ):
            raise ProjectStatusError(
                f"published-unledgered {observation_name} is not cross-bound"
            )
        ci_run_ids.append(run_id)
    if len(set(ci_run_ids)) != len(ci_run_ids):
        raise ProjectStatusError("published-unledgered CI observations are ambiguous")

    failure_boundary = _mapping(
        record["failure_boundary"],
        "published-unledgered failure_boundary",
    )
    reason_code = _string(
        failure_boundary["reason_code"],
        "published-unledgered failure_boundary.reason_code",
    )
    trusted_parent_commit = _string(
        failure_boundary["trusted_parent_commit_sha"],
        "published-unledgered failure_boundary.trusted_parent_commit_sha",
    )
    trusted_parent_tree = _string(
        failure_boundary["trusted_parent_tree_sha"],
        "published-unledgered failure_boundary.trusted_parent_tree_sha",
    )
    validator_blob = _string(
        failure_boundary["validator_blob_sha"],
        "published-unledgered failure_boundary.validator_blob_sha",
    )
    validator_path = _string(
        failure_boundary["validator_path"],
        "published-unledgered failure_boundary.validator_path",
    )
    corrected_commit: str
    corrected_pr: int
    if record_schema_version == "evoguard-unsealed-release-status-v1":
        _exact_keys(
            failure_boundary,
            "published-unledgered failure_boundary",
            {
                "reason_code",
                "trusted_parent_commit_sha",
                "trusted_parent_tree_sha",
                "validator_path",
                "validator_blob_sha",
                "validator_rule_at_publication",
                "h_run_id",
                "h_run_attempt",
                "h_run_url",
                "h_observed_window",
                "release_created_utc",
                "release_published_utc",
                "release_created_before_h",
                "release_published_inside_h",
                "corrected_semantics_pr",
                "corrected_semantics_commit",
                "retroactive_correction_allowed",
                "explanation",
            },
        )
        corrected_commit = _string(
            failure_boundary["corrected_semantics_commit"],
            "published-unledgered failure_boundary.corrected_semantics_commit",
        )
        corrected_pr = _positive_integer(
            failure_boundary["corrected_semantics_pr"],
            "published-unledgered failure_boundary.corrected_semantics_pr",
        )
        h_run_id = _positive_integer(
            failure_boundary["h_run_id"],
            "published-unledgered failure_boundary.h_run_id",
        )
        h_run_attempt = _positive_integer(
            failure_boundary["h_run_attempt"],
            "published-unledgered failure_boundary.h_run_attempt",
        )
        h_window = _mapping(
            failure_boundary["h_observed_window"],
            "published-unledgered failure_boundary.h_observed_window",
        )
        _exact_keys(
            h_window,
            "published-unledgered failure_boundary.h_observed_window",
            {"started_utc", "completed_utc"},
        )
        h_started = _canonical_utc(
            h_window["started_utc"],
            "published-unledgered failure_boundary.h_observed_window.started_utc",
        )
        h_completed = _canonical_utc(
            h_window["completed_utc"],
            "published-unledgered failure_boundary.h_observed_window.completed_utc",
        )
        failure_is_valid = (
            reason_code == "FROZEN_VALIDATOR_CREATED_AT_SEMANTICS_MISMATCH"
            and failure_boundary["validator_rule_at_publication"]
            == (
                "Required both release.created_utc and release.published_utc to "
                "fall inside the observed phase-H window."
            )
            and failure_boundary["h_run_url"]
            == (
                "https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/runs/"
                f"{h_run_id}/attempts/{h_run_attempt}"
            )
            and failure_boundary["release_created_utc"] == release["created_utc"]
            and failure_boundary["release_published_utc"]
            == release["published_utc"]
            and h_started <= published_utc <= h_completed
            and recorded_utc >= h_completed
            and failure_boundary["release_created_before_h"]
            is (created_utc < h_started)
            and failure_boundary["release_published_inside_h"]
            is (h_started <= published_utc <= h_completed)
            and failure_boundary["retroactive_correction_allowed"] is False
            and failure_boundary["explanation"]
            == (
                "The release operation and descriptor are bound to the frozen "
                "trusted parent and validator blob. The later validator correction "
                "cannot replace those inputs retroactively."
            )
        )
    else:
        _exact_keys(
            failure_boundary,
            "published-unledgered failure_boundary",
            {
                "reason_code",
                "trusted_parent_commit_sha",
                "trusted_parent_tree_sha",
                "validator_path",
                "validator_blob_sha",
                "defects",
                "corrected_pr",
                "corrected_commit",
                "retroactive_correction_allowed",
                "explanation",
            },
        )
        corrected_commit = _string(
            failure_boundary["corrected_commit"],
            "published-unledgered failure_boundary.corrected_commit",
        )
        corrected_pr = _positive_integer(
            failure_boundary["corrected_pr"],
            "published-unledgered failure_boundary.corrected_pr",
        )
        raw_defects = failure_boundary["defects"]
        if (
            not isinstance(raw_defects, list)
            or not 1 <= len(raw_defects) <= _MAX_UNSEALED_DEFECTS
        ):
            raise ProjectStatusError(
                "published-unledgered v2 defects must be a bounded non-empty list"
            )
        defect_codes: list[str] = []
        material_paths: list[str] = []
        for defect_index, raw_defect in enumerate(raw_defects):
            defect_where = (
                "published-unledgered failure_boundary.defects"
                f"[{defect_index}]"
            )
            defect = _mapping(raw_defect, defect_where)
            _exact_keys(
                defect,
                defect_where,
                {"code", "boundary", "affected_material", "observation"},
            )
            defect_code = _string(defect["code"], f"{defect_where}.code")
            if re.fullmatch(r"[A-Z][A-Z0-9_]{2,127}", defect_code) is None:
                raise ProjectStatusError(
                    f"{defect_where}.code is not a canonical reason code"
                )
            _enum(
                defect["boundary"],
                f"{defect_where}.boundary",
                {
                    "trusted-import-cold-start",
                    "retained-result-encoding",
                },
            )
            _bounded_text(
                defect["observation"],
                f"{defect_where}.observation",
            )
            raw_material = defect["affected_material"]
            if (
                not isinstance(raw_material, list)
                or len(raw_material) > _MAX_UNSEALED_AFFECTED_MATERIAL
            ):
                raise ProjectStatusError(
                    f"{defect_where}.affected_material exceeds its bound"
                )
            for material_index, raw_item in enumerate(raw_material):
                item_where = (
                    f"{defect_where}.affected_material[{material_index}]"
                )
                item = _mapping(raw_item, item_where)
                _exact_keys(
                    item,
                    item_where,
                    {"path", "size_bytes", "sha256"},
                )
                material_path = _string(item["path"], f"{item_where}.path")
                portable_path = PurePosixPath(material_path)
                if (
                    not material_path
                    or "\\" in material_path
                    or portable_path.is_absolute()
                    or portable_path.as_posix() != material_path
                    or any(part in {"", ".", ".."} for part in portable_path.parts)
                    or re.fullmatch(r"[A-Za-z0-9._/-]+", material_path) is None
                ):
                    raise ProjectStatusError(
                        f"{item_where}.path is not canonical"
                    )
                _positive_integer(item["size_bytes"], f"{item_where}.size_bytes")
                digest = _string(item["sha256"], f"{item_where}.sha256")
                if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                    raise ProjectStatusError(
                        f"{item_where}.sha256 is not canonical"
                    )
                material_paths.append(material_path)
            defect_codes.append(defect_code)
        failure_is_valid = (
            re.fullmatch(r"[A-Z][A-Z0-9_]{2,127}", reason_code) is not None
            and len(set(defect_codes)) == len(defect_codes)
            and len(set(material_paths)) == len(material_paths)
            and failure_boundary["retroactive_correction_allowed"] is False
            and failure_boundary["explanation"]
            == (
                "The release operation and descriptor are bound to the frozen "
                "trusted parent and validator blob. Later corrections cannot "
                "replace those inputs retroactively."
            )
        )

    if (
        re.fullmatch(r"[0-9a-f]{40}", trusted_parent_commit) is None
        or re.fullmatch(r"[0-9a-f]{40}", trusted_parent_tree) is None
        or re.fullmatch(r"[0-9a-f]{40}", validator_blob) is None
        or re.fullmatch(r"[0-9a-f]{40}", corrected_commit) is None
        or trusted_parent_commit == corrected_commit
        or validator_path != "tools/ci/validate_release_ledger_v2.py"
        or not failure_is_valid
    ):
        raise ProjectStatusError(
            "published-unledgered failure boundary is not internally consistent"
        )
    if verify_git:
        assert trusted_head is not None
        assert trusted_exception_tag_commit is not None
        _verify_published_unledgered_git_bindings(
            root,
            trusted_head=trusted_head,
            trusted_exception_tag_commit=trusted_exception_tag_commit,
            tag=tag,
            release_commit=commit_sha,
            trusted_parent_commit=trusted_parent_commit,
            trusted_parent_tree=trusted_parent_tree,
            validator_path=validator_path,
            validator_blob=validator_blob,
            corrected_commit=corrected_commit,
            corrected_pr=corrected_pr,
        )

    ledger_state = _mapping(
        record["ledger_state"],
        "published-unledgered ledger_state",
    )
    presence_key = f"v{version.replace('.', '_')}_release_ledger_present"
    _exact_keys(
        ledger_state,
        "published-unledgered ledger_state",
        {
            "sealed",
            "canonical_ledger_issued",
            "signature_issued",
            presence_key,
            "reason_code",
            "latest_validated_repository_ledger",
            "ledger_recorded_consumer_pin",
            "recovery_release",
            "missing_claims",
        },
    )
    recovery_tag = _string(
        ledger_state["recovery_release"],
        "published-unledgered ledger_state.recovery_release",
    )
    if not recovery_tag.startswith("v") or _STABLE_VERSION_RE.fullmatch(recovery_tag[1:]) is None:
        raise ProjectStatusError("published-unledgered recovery release is not a canonical tag")
    recovery_version = recovery_tag[1:]
    observed_ledger_path = _string(
        ledger_state["latest_validated_repository_ledger"],
        "published-unledgered ledger_state.latest_validated_repository_ledger",
    )
    observed_ledger_match = _V1_LEDGER_PATH_RE.fullmatch(
        observed_ledger_path
    ) or _V2_LEDGER_PATH_RE.fullmatch(observed_ledger_path)
    observed_consumer_pin = _string(
        ledger_state["ledger_recorded_consumer_pin"],
        "published-unledgered ledger_state.ledger_recorded_consumer_pin",
    )
    missing_claims = [
        "signed post-publication v2 release ledger",
        "ledger-bound protected A-through-H operational evidence",
        "ledger-bound protected A-through-H publication evidence",
    ]
    if (
        ledger_state["sealed"] is not False
        or ledger_state["canonical_ledger_issued"] is not False
        or ledger_state["signature_issued"] is not False
        or ledger_state[presence_key] is not False
        or ledger_state["reason_code"] != reason_code
        or observed_ledger_match is None
        or observed_consumer_pin != f"v{observed_ledger_match.group(1)}"
        or ledger_state["missing_claims"] != missing_claims
    ):
        raise ProjectStatusError(
            "published-unledgered exception cannot substitute for a release ledger"
        )
    _safe_path(root, root / observed_ledger_path, leaf="file")

    exception_version = _version_tuple(version)
    recovery_version_tuple = _version_tuple(recovery_version)
    observed_ledger_version = _version_tuple(observed_ledger_match.group(1))
    if not (
        observed_ledger_version < exception_version < recovery_version_tuple
        and observed_consumer_pin == f"v{observed_ledger_match.group(1)}"
    ):
        raise ProjectStatusError(
            "published-unledgered observed, exception, and recovery versions "
            "are not strictly ordered"
        )

    exception_ledger_paths = (
        root / "tests" / "baseline" / f"v{version}" / "RELEASE_LEDGER.json",
        root
        / "evidence"
        / "release-ledgers"
        / f"v{version}"
        / "RELEASE_LEDGER.json",
    )
    if any(os.path.lexists(path) for path in exception_ledger_paths):
        raise ProjectStatusError(
            "published-unledgered exception conflicts with an existing release ledger"
        )

    expected_trust_boundary = [
        (
            "This file is an unsigned maintained observation and is intentionally "
            "outside evidence/release-ledgers."
        ),
        (
            "It records reproducible GitHub and provider observations but does not "
            "prove protected A-through-H completion."
        ),
        (
            f"The {tag} tag, release assets, checksums, and attestations must not be "
            "rewritten to repair the missing ledger."
        ),
        (
            (
                f"No canonical {tag} ledger or ledger signature can be issued "
                "retroactively from the corrected validator; recovery requires a "
                "new release."
            )
            if record_schema_version == "evoguard-unsealed-release-status-v1"
            else (
                f"No canonical {tag} ledger or ledger signature can be issued "
                "retroactively after the frozen validator contract has been "
                "corrected; recovery requires a new release."
            )
        ),
    ]
    if record["trust_boundary"] != expected_trust_boundary:
        raise ProjectStatusError(
            "published-unledgered trust boundary contains an unsupported claim"
        )

    disposition_path = root / disposition_relative
    disposition_bytes, _ = _read_stable_bytes(root, disposition_path)
    if verify_git:
        assert trusted_head is not None
        _verify_tracked_bytes(
            root,
            disposition_relative,
            disposition_bytes,
            revision=trusted_head,
        )
    disposition_record = _mapping(
        _load_json_bytes(disposition_bytes, disposition_path),
        "published-unledgered key disposition",
    )
    current_disposition_bytes, _ = _read_stable_bytes(root, disposition_path)
    if current_disposition_bytes != disposition_bytes:
        raise ProjectStatusError("published-unledgered key disposition changed during validation")
    _exact_keys(
        disposition_record,
        "published-unledgered key disposition",
        {
            "schema_version",
            "record_scope",
            "release",
            "key",
            "disposition",
            "non_claims",
        },
    )
    if disposition_record[
        "schema_version"
    ] != "evoguard-local-key-disposition-v1" or disposition_record["record_scope"] != (
        "Unsigned operator-local disposition statement; not a retirement "
        "receipt, revocation record, deletion proof, or secure-erasure proof."
    ):
        raise ProjectStatusError("local key disposition overstates its authority")

    disposition_release = _mapping(
        disposition_record["release"],
        "published-unledgered key disposition.release",
    )
    _exact_keys(
        disposition_release,
        "published-unledgered key disposition.release",
        {
            "version",
            "tag",
            "canonical_ledger_issued",
            "signature_issued",
            "reason_code",
        },
    )
    if (
        disposition_release["version"] != version
        or disposition_release["tag"] != tag
        or disposition_release["canonical_ledger_issued"] is not False
        or disposition_release["signature_issued"] is not False
        or disposition_release["reason_code"] != reason_code
    ):
        raise ProjectStatusError(
            "local key disposition is not bound to the unledgered release failure"
        )

    disposition_key = _mapping(
        disposition_record["key"],
        "published-unledgered key disposition.key",
    )
    _exact_keys(
        disposition_key,
        "published-unledgered key disposition.key",
        {
            "purpose",
            "public_key_path",
            "public_key_id",
            "private_file_basename",
            "storage_scope",
        },
    )
    public_key_relative = f"security/release-ledger-roots/v{version}.pub.pem"
    public_key_id = _string(
        disposition_key["public_key_id"],
        "published-unledgered key disposition.key.public_key_id",
    )
    if (
        disposition_key["purpose"] != f"prospective v{version} release-ledger signing only"
        or disposition_key["public_key_path"] != public_key_relative
        or disposition_key["private_file_basename"] != f"release-ledger-v{version}.private.pem"
        or disposition_key["storage_scope"] != "operator-local-outside-repository"
        or re.fullmatch(r"sha256:[0-9a-f]{64}", public_key_id) is None
    ):
        raise ProjectStatusError("local key disposition contains a non-canonical key identity")
    public_key_path = root / public_key_relative
    public_key_bytes, _ = _read_stable_bytes(root, public_key_path)
    if verify_git:
        assert trusted_head is not None
        _verify_tracked_bytes(
            root,
            public_key_relative,
            public_key_bytes,
            revision=trusted_head,
        )
    public_key_lines = public_key_bytes.splitlines()
    try:
        public_key_der = base64.b64decode(public_key_lines[1], validate=True)
    except (IndexError, ValueError) as exc:
        raise ProjectStatusError("local key disposition public key is not canonical PEM") from exc
    if (
        len(public_key_lines) != 3
        or public_key_lines[0] != b"-----BEGIN PUBLIC KEY-----"
        or public_key_lines[2] != b"-----END PUBLIC KEY-----"
        or len(public_key_der) != 44
        or not public_key_der.startswith(bytes.fromhex("302a300506032b6570032100"))
        or public_key_id != f"sha256:{hashlib.sha256(public_key_der).hexdigest()}"
    ):
        raise ProjectStatusError("local key disposition public key bytes do not match its key ID")

    disposition = _mapping(
        disposition_record["disposition"],
        "published-unledgered key disposition.disposition",
    )
    _exact_keys(
        disposition,
        "published-unledgered key disposition.disposition",
        {"status", "observed_utc", "trigger", "authorized_action"},
    )
    disposition_status = _enum(
        disposition["status"],
        "published-unledgered key disposition.disposition.status",
        {"pending-operator-removal", "local-file-removed"},
    )
    observed_utc = disposition["observed_utc"]
    if disposition_status == "pending-operator-removal":
        disposition_time_is_valid = observed_utc is None
    else:
        removed_utc = _canonical_utc(
            observed_utc,
            "published-unledgered key disposition.disposition.observed_utc",
        )
        disposition_time_is_valid = removed_utc >= recorded_utc
    if (
        disposition["trigger"]
        != (
            f"Canonical v{version} ledger issuance is impossible under the frozen "
            "release validator; the unused operator-local private-key file has no "
            "remaining authorized signing purpose."
        )
        or disposition["authorized_action"]
        != (
            "Remove only the named operator-local private-key file after "
            f"independently confirming the v{version} ledger failure boundary."
        )
        or not disposition_time_is_valid
    ):
        raise ProjectStatusError("local key disposition status is contradictory")

    non_claims = disposition_record["non_claims"]
    expected_non_claims = [
        "This unsigned statement is not KEY_RETIREMENT.json and is not a signed "
        "retirement receipt.",
        "Pending status does not claim that the local file has been removed.",
        "A future local-file-removed status may record only an operator observation, "
        "not secure erasure, revocation, absence of copies, or loss of key capability.",
        f"This record does not create, sign, validate, or repair a v{version} release ledger.",
    ]
    if non_claims != expected_non_claims:
        raise ProjectStatusError("local key disposition non-claims are incomplete")

    erratum_path = root / erratum_relative
    erratum_bytes, _ = _read_stable_bytes(root, erratum_path)
    if verify_git:
        assert trusted_head is not None
        _verify_tracked_bytes(
            root,
            erratum_relative,
            erratum_bytes,
            revision=trusted_head,
        )
    try:
        erratum = erratum_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProjectStatusError("published-unledgered erratum is not UTF-8") from exc
    if (
        erratum.startswith(f"# v{version} release-ledger erratum\n") is False
        or "This is a post-publication correction record." not in erratum
        or "**not** a release ledger" not in erratum
        or f"`{record_relative}`" not in erratum
        or f"Prepare `v{recovery_version}`" not in erratum
    ):
        raise ProjectStatusError(
            f"published-unledgered {tag} erratum does not preserve the "
            "required non-claim"
        )
    for stable_path, expected_bytes, label in (
        (record_path, record_bytes, "exception record"),
        (disposition_path, disposition_bytes, "key disposition"),
        (erratum_path, erratum_bytes, "erratum"),
        (public_key_path, public_key_bytes, "public key"),
    ):
        final_bytes, _ = _read_stable_bytes(root, stable_path)
        if final_bytes != expected_bytes:
            raise ProjectStatusError(
                f"published-unledgered {label} changed during validation"
            )

    result = PublishedUnledgeredRelease(
        version=version,
        tag=tag,
        release_url=release_url,
        record_path=record_relative,
        erratum_path=erratum_relative,
        recovery_version=recovery_version,
        observed_ledger_path=observed_ledger_path,
        observed_consumer_pin=observed_consumer_pin,
        key_disposition_path=disposition_relative,
        key_disposition_status=disposition_status,
        authority_sha256=(
            (record_relative, hashlib.sha256(record_bytes).hexdigest()),
            (erratum_relative, hashlib.sha256(erratum_bytes).hexdigest()),
            (disposition_relative, hashlib.sha256(disposition_bytes).hexdigest()),
            (public_key_relative, hashlib.sha256(public_key_bytes).hexdigest()),
        ),
    )
    if validate_relation:
        _validate_published_unledgered_chain(
            root,
            status,
            ledger,
            source_version,
            (result,),
        )
    return result


def _validate_published_unledgered_chain(
    root: Path,
    status: Status,
    ledger: Ledger,
    source_version: str,
    releases: Sequence[PublishedUnledgeredRelease],
) -> None:
    if (
        not releases
        or len(releases) > _MAX_PUBLISHED_UNLEDGERED_EXCEPTIONS
    ):
        raise ProjectStatusError(
            "published-unledgered exception history must be bounded and non-empty"
        )
    versions = tuple(_version_tuple(release.version) for release in releases)
    if any(
        left >= right
        for left, right in zip(versions, versions[1:], strict=False)
    ):
        raise ProjectStatusError(
            "published-unledgered exception history is not strictly ordered"
        )
    for current, following in zip(releases, releases[1:], strict=False):
        if current.recovery_version != following.version:
            raise ProjectStatusError(
                "published-unledgered recovery chain skips or rewrites a version"
            )

    latest = releases[-1]
    latest_exception_version = _version_tuple(latest.version)
    latest_recovery_version = _version_tuple(latest.recovery_version)
    latest_observed_match = _V1_LEDGER_PATH_RE.fullmatch(
        latest.observed_ledger_path
    ) or _V2_LEDGER_PATH_RE.fullmatch(latest.observed_ledger_path)
    if latest_observed_match is None:
        raise ProjectStatusError(
            "latest published-unledgered observed ledger path is invalid"
        )
    latest_observed_version = _version_tuple(latest_observed_match.group(1))
    ledger_version = _version_tuple(ledger.version)
    source_stable = (
        source_version.removesuffix(".dev0")
        if status.lifecycle == "unreleased-development"
        else source_version
    )
    source_stable_version = _version_tuple(source_stable)

    recovery_ledger_paths = (
        root
        / "tests"
        / "baseline"
        / f"v{latest.recovery_version}"
        / "RELEASE_LEDGER.json",
        root
        / "evidence"
        / "release-ledgers"
        / f"v{latest.recovery_version}"
        / "RELEASE_LEDGER.json",
    )
    recovery_in_inventory = False
    for recovery_ledger_path in recovery_ledger_paths:
        if os.path.lexists(recovery_ledger_path):
            _safe_path(root, recovery_ledger_path, leaf="file")
            recovery_in_inventory = True

    if status.lifecycle == "published-unledgered":
        relation_is_valid = (
            ledger_version == latest_observed_version
            and source_stable_version == latest_exception_version
            and latest.observed_ledger_path == status.ledger_path
            and latest.observed_consumer_pin == ledger.tag
        )
    elif status.lifecycle in {"unreleased-development", "release-candidate"}:
        if ledger_version < latest_recovery_version:
            relation_is_valid = (
                ledger_version == latest_observed_version
                and source_stable_version == latest_recovery_version
                and latest.observed_ledger_path == status.ledger_path
                and latest.observed_consumer_pin == ledger.tag
            )
        else:
            relation_is_valid = (
                latest_exception_version
                < latest_recovery_version
                <= ledger_version
                < source_stable_version
                and recovery_in_inventory
            )
    elif status.lifecycle == "release-line":
        relation_is_valid = (
            latest_exception_version
            < latest_recovery_version
            <= ledger_version
            == source_stable_version
            and recovery_in_inventory
        )
    else:
        relation_is_valid = False
    if not relation_is_valid:
        raise ProjectStatusError(
            "published-unledgered exception history is inconsistent with "
            "source recovery"
        )


def _discover_ledgers(
    root: Path,
    namespace: Path,
    *,
    maximum_version: tuple[int, int, int] | None = _LAST_V1_LEDGER_VERSION,
) -> list[tuple[tuple[int, int, int], Path]]:
    discovered: list[tuple[tuple[int, int, int], Path]] = []
    try:
        namespace_metadata = os.lstat(namespace)
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise ProjectStatusError("cannot inspect release-ledger namespace") from exc
    if (
        stat.S_ISLNK(namespace_metadata.st_mode)
        or _is_reparse_point(namespace_metadata)
        or not stat.S_ISDIR(namespace_metadata.st_mode)
    ):
        raise ProjectStatusError("release-ledger namespace is not a no-follow directory")
    namespace = _safe_path(root, namespace, leaf="directory")
    try:
        with os.scandir(namespace) as entries:
            version_entries = sorted(
                (
                    entry
                    for entry in entries
                    if _LEDGER_DIRECTORY_RE.fullmatch(entry.name) is not None
                ),
                key=lambda entry: entry.name,
            )
    except OSError as exc:
        raise ProjectStatusError("cannot enumerate immutable release ledgers") from exc
    if len(version_entries) > _MAX_LEDGER_DIRECTORIES:
        raise ProjectStatusError("release-ledger namespace exceeds the directory bound")
    for entry in version_entries:
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise ProjectStatusError(
                f"cannot inspect release ledger directory: {entry.name}"
            ) from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or _is_reparse_point(metadata)
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise ProjectStatusError(
                f"release ledger directory is not a no-follow directory: {entry.name}"
            )
        version_match = _LEDGER_DIRECTORY_RE.fullmatch(entry.name)
        if version_match is None:
            raise AssertionError("filtered ledger directory lost its version match")
        version = _version_tuple(version_match.group(1))
        version_directory = _safe_path(
            root,
            namespace / entry.name,
            leaf="directory",
        )
        try:
            with os.scandir(version_directory) as children:
                ledger_entries = [
                    child
                    for child in children
                    if child.name == "RELEASE_LEDGER.json"
                ]
        except OSError as exc:
            raise ProjectStatusError(
                f"cannot enumerate release ledger directory: {entry.name}"
            ) from exc
        if not ledger_entries:
            continue
        if maximum_version is not None and version > maximum_version:
            raise ProjectStatusError(
                "release-ledger v1 is frozen after v4.3.0; newer releases require v2"
            )
        if len(ledger_entries) != 1:
            raise ProjectStatusError(
                f"release ledger directory has an ambiguous ledger: {entry.name}"
            )
        ledger_entry = ledger_entries[0]
        try:
            ledger_metadata = ledger_entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise ProjectStatusError(
                f"cannot inspect release ledger file: {entry.name}"
            ) from exc
        if (
            stat.S_ISLNK(ledger_metadata.st_mode)
            or _is_reparse_point(ledger_metadata)
            or not stat.S_ISREG(ledger_metadata.st_mode)
        ):
            raise ProjectStatusError(
                f"release ledger is not a no-follow regular file: {entry.name}"
            )
        ledger_path = _safe_path(
            root,
            version_directory / "RELEASE_LEDGER.json",
            leaf="file",
        )
        discovered.append((version, ledger_path))
    return discovered


def _run_checked(
    command: Sequence[str],
    *,
    cwd: Path,
    label: str,
    timeout: int = 120,
) -> None:
    environment = os.environ.copy()
    environment["GIT_TERMINAL_PROMPT"] = "0"
    try:
        result = subprocess.run(
            list(command),
            cwd=cwd,
            check=False,
            capture_output=True,
            timeout=timeout,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProjectStatusError(f"{label} could not complete") from exc
    if len(result.stdout) + len(result.stderr) > 64 * 1024:
        raise ProjectStatusError(f"{label} produced excessive output")
    if result.returncode != 0:
        raise ProjectStatusError(f"{label} rejected the configured release ledger")


def _validate_v2_ledger_with_git(
    root: Path,
    ledger_directory: Path,
    version: str,
) -> None:
    ledger_object = _mapping(
        _load_json(root, ledger_directory / "RELEASE_LEDGER.json"),
        "release ledger",
    )
    if ledger_object.get("schema_version") != "evoguard-release-ledger-v2":
        raise ProjectStatusError("release-ledger v2 external validation got wrong schema")
    source = _mapping(ledger_object.get("source"), "release ledger.source")
    claimed_parent = _string(
        source.get("parent_commit_sha"),
        "release ledger.source.parent_commit_sha",
    )
    claimed_parent_tree = _string(
        source.get("parent_tree_sha"),
        "release ledger.source.parent_tree_sha",
    )
    release = _mapping(ledger_object.get("release"), "release ledger.release")
    release_commit = _string(
        release.get("commit_sha"),
        "release ledger.release.commit_sha",
    )
    if (
        re.fullmatch(r"[0-9a-f]{40}", claimed_parent) is None
        or re.fullmatch(r"[0-9a-f]{40}", claimed_parent_tree) is None
        or re.fullmatch(r"[0-9a-f]{40}", release_commit) is None
    ):
        raise ProjectStatusError("release-ledger v2 commit identities are not SHA-1")
    parent_files = (
        "tools/ci/validate_release_ledger_v2.py",
        "tools/ci/collect_repository_controls_v2.py",
        "tests/baseline/schema/release-ledger-v2.schema.json",
        f"security/release-ledger-roots/v{version}.pub.pem",
        "ops/build_pyz.py",
        "ops/generate_spdx_sbom.py",
        "tools/ci/verify_spdx_attestation.py",
    )
    with tempfile.TemporaryDirectory(prefix="evoguard-status-parent-") as temporary:
        trusted_parent = Path(temporary) / "trusted-parent.git"
        _git_bytes(
            Path(temporary),
            "-c",
            "protocol.file.allow=always",
            "clone",
            "--local",
            "--no-hardlinks",
            "--no-checkout",
            os.fspath(_absolute(root)),
            os.fspath(trusted_parent),
        )
        tag = f"v{version}"
        tag_commit = _git(
            trusted_parent,
            "rev-parse",
            "--verify",
            f"refs/tags/{tag}^{{commit}}",
        )
        if tag_commit != release_commit:
            raise ProjectStatusError(
                "release-ledger v2 release commit differs from the local release tag"
            )
        ancestry = _git(
            trusted_parent,
            "rev-list",
            "--parents",
            "-n",
            "1",
            tag_commit,
        ).split()
        if len(ancestry) != 2 or ancestry[0] != tag_commit:
            raise ProjectStatusError(
                "release-ledger v2 release commit must have exactly one parent"
            )
        parent = ancestry[1]
        parent_tree = _git(
            trusted_parent,
            "rev-parse",
            "--verify",
            f"{parent}^{{tree}}",
        )
        if parent != claimed_parent or parent_tree != claimed_parent_tree:
            raise ProjectStatusError(
                "release-ledger v2 parent claim differs from tag-derived ancestry"
            )
        snapshot_root = Path(temporary) / "validator-snapshot"
        snapshot_root.mkdir()
        for relative in parent_files:
            entry = _git_bytes(
                trusted_parent,
                "ls-tree",
                "-z",
                parent,
                "--",
                relative,
            )
            match = re.fullmatch(
                rb"100644 blob ([0-9a-f]{40})\t" + re.escape(relative.encode()) + rb"\0",
                entry,
            )
            if match is None:
                raise ProjectStatusError(
                    f"trusted parent validator input is not a regular blob: {relative}"
                )
            data = _git_bytes(
                trusted_parent,
                "cat-file",
                "blob",
                match.group(1).decode("ascii"),
            )
            target = snapshot_root.joinpath(*Path(relative).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with target.open("xb") as stream:
                    stream.write(data)
            except OSError as exc:
                raise ProjectStatusError(
                    f"cannot materialize trusted parent validator input: {relative}"
                ) from exc
        validator = snapshot_root / "tools/ci/validate_release_ledger_v2.py"
        trusted_key = (
            snapshot_root
            / "security"
            / "release-ledger-roots"
            / f"v{version}.pub.pem"
        )
        _run_checked(
            (
                sys.executable,
                "-I",
                os.fspath(validator),
                "validate",
                os.fspath(ledger_directory),
                "--trusted-ledger-pub",
                os.fspath(trusted_key),
                "--trusted-parent-repo",
                os.fspath(trusted_parent),
            ),
            cwd=snapshot_root,
            label="release-ledger-v2 validator",
        )


def _validate_v2_ledger(
    root: Path,
    ledger_directory: Path,
    version: str,
) -> None:
    with _trusted_git_session(root):
        _validate_v2_ledger_with_git(root, ledger_directory, version)


def _parse_common_ledger(
    top: dict[str, object],
    *,
    path: str,
    path_match: re.Match[str],
    schema_version: str,
) -> tuple[str, str, str, str, tuple[str, ...]]:
    project = _mapping(top.get("project"), "release ledger.project")
    release = _mapping(top.get("release"), "release ledger.release")
    artifacts_value = top.get("artifacts")
    if not isinstance(artifacts_value, list) or not artifacts_value:
        raise ProjectStatusError("release ledger.artifacts must be a non-empty array")
    artifacts: list[str] = []
    for index, raw_artifact in enumerate(artifacts_value):
        artifact = _mapping(raw_artifact, f"release ledger.artifacts[{index}]")
        name = _string(
            artifact.get("name"),
            f"release ledger.artifacts[{index}].name",
        )
        if name in artifacts:
            raise ProjectStatusError("release ledger artifact names are not unique")
        artifacts.append(name)
    version = _string(project.get("version"), "release ledger.project.version")
    _version_tuple(version)
    if path_match.group(1) != version:
        raise ProjectStatusError("release ledger directory version differs from content")
    if project.get("name") != "EvoOM Guard":
        raise ProjectStatusError("release ledger project identity is wrong")
    tag = _string(release.get("tag"), "release ledger.release.tag")
    commit_sha = _string(release.get("commit_sha"), "release ledger.release.commit_sha")
    release_url = _string(release.get("release_url"), "release ledger.release.release_url")
    if (
        tag != f"v{version}"
        or release.get("repository") != "EvoRiseKsa/EvoOM-Guard-m"
        or release.get("state") != "published"
        or release.get("prerelease") is not False
        or release.get("immutable") is not True
        or release_url
        != f"https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/{tag}"
        or re.fullmatch(r"[0-9a-f]{40}", commit_sha) is None
    ):
        raise ProjectStatusError(
            f"{schema_version} ledger does not identify one immutable release: {path}"
        )
    return version, tag, commit_sha, release_url, tuple(artifacts)


def _attestation_subject_names(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ProjectStatusError(f"{where} must be a non-empty array")
    subjects: list[str] = []
    for index, raw_subject in enumerate(value):
        subject = _mapping(raw_subject, f"{where}[{index}]")
        name = _string(subject.get("name"), f"{where}[{index}].name")
        if name in subjects:
            raise ProjectStatusError(f"{where} contains duplicate subjects")
        subjects.append(name)
    return tuple(subjects)


def _relative_ledger_path(root: Path, path: Path) -> str:
    try:
        return _absolute(path).relative_to(_absolute(root)).as_posix()
    except ValueError as exc:
        raise ProjectStatusError(f"release ledger escapes repository root: {path}") from exc


def _git_nul_fields(raw: bytes, label: str) -> tuple[str, ...]:
    if not raw:
        return ()
    if not raw.endswith(b"\0"):
        raise ProjectStatusError(f"{label} is not NUL terminated")
    try:
        return tuple(field.decode("utf-8") for field in raw[:-1].split(b"\0"))
    except UnicodeDecodeError as exc:
        raise ProjectStatusError(f"{label} contains a non-UTF-8 path") from exc


def _verify_append_only_v2_history(
    root: Path,
    discovered: Sequence[tuple[tuple[int, int, int], Path]],
) -> None:
    if _git(root, "rev-parse", "--is-shallow-repository") != "false":
        raise ProjectStatusError(
            "release-ledger append-only proof requires complete non-shallow Git history"
        )
    current = {
        relative
        for _, path in discovered
        if _V2_LEDGER_PATH_RE.fullmatch(
            relative := _relative_ledger_path(root, path)
        )
        is not None
    }
    history_pathspec = ":(glob)evidence/release-ledgers/v*/RELEASE_LEDGER.json"
    addition_fields = _git_nul_fields(
        _git_bytes(
            root,
            "log",
            "--full-history",
            "-m",
            "--root",
            "--format=",
            "--name-status",
            "-z",
            "--diff-filter=A",
            "HEAD",
            "--",
            history_pathspec,
        ),
        "release-ledger v2 Git history",
    )
    if len(addition_fields) % 2:
        raise ProjectStatusError("release-ledger v2 Git history is malformed")
    historical: set[str] = set()
    for index in range(0, len(addition_fields), 2):
        change, relative = addition_fields[index : index + 2]
        if change != "A" or _V2_LEDGER_PATH_RE.fullmatch(relative) is None:
            raise ProjectStatusError("release-ledger v2 Git history is ambiguous")
        historical.add(relative)
    non_additions = _git_bytes(
        root,
        "log",
        "--full-history",
        "-m",
        "--root",
        "--format=",
        "--name-status",
        "-z",
        "--diff-filter=CDMRTUXB",
        "HEAD",
        "--",
        history_pathspec,
    )
    if non_additions:
        raise ProjectStatusError(
            "release-ledger v2 Git history contains a non-append change"
        )

    tracked_namespace = _git_nul_fields(
        _git_bytes(
            root,
            "ls-tree",
            "-rz",
            "--name-only",
            "HEAD",
            "--",
            "evidence/release-ledgers",
        ),
        "tracked release-ledger v2 set",
    )
    tracked = {
        relative
        for relative in tracked_namespace
        if relative.endswith("/RELEASE_LEDGER.json")
    }
    if any(_V2_LEDGER_PATH_RE.fullmatch(relative) is None for relative in tracked):
        raise ProjectStatusError("tracked release-ledger v2 path is malformed")
    missing = historical - current
    if missing:
        raise ProjectStatusError(
            "release-ledger v2 history was rolled back; missing "
            + ", ".join(sorted(missing))
        )
    if tracked != current:
        raise ProjectStatusError(
            "working release-ledger v2 set differs from the tracked HEAD set"
        )


def _verify_frozen_v1_set(
    root: Path,
    discovered: Sequence[tuple[tuple[int, int, int], Path]],
) -> None:
    expected = {
        f"{directory}/RELEASE_LEDGER.json"
        for directory in _FROZEN_V1_TREES
    }
    current = {
        relative
        for _, path in discovered
        if _V1_LEDGER_PATH_RE.fullmatch(
            relative := _relative_ledger_path(root, path)
        )
        is not None
    }
    if current != expected:
        raise ProjectStatusError(
            "frozen v1 ledger set differs; missing="
            f"{sorted(expected - current)!r}, unexpected={sorted(current - expected)!r}"
        )


def _load_one_ledger(root: Path, path: Path, *, verify_git: bool) -> Ledger:
    relative = _relative_ledger_path(root, path)
    ledger_bytes, _ = _read_stable_bytes(root, path)
    if verify_git:
        _verify_tracked_bytes(root, relative, ledger_bytes)
    try:
        ledger_object = cast(
            object,
            json.loads(
                ledger_bytes.decode("utf-8"),
                object_pairs_hook=_duplicate_safe_object,
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProjectStatusError("invalid UTF-8 release ledger JSON") from exc
    top = _mapping(ledger_object, "release ledger")
    schema_version = _string(top.get("schema_version"), "release ledger.schema_version")
    if schema_version == "evoguard-release-ledger-v1":
        path_match = _V1_LEDGER_PATH_RE.fullmatch(relative)
        if path_match is None:
            raise ProjectStatusError("release-ledger v1 is outside its frozen namespace")
        if _version_tuple(path_match.group(1)) > _LAST_V1_LEDGER_VERSION:
            raise ProjectStatusError(
                "release-ledger v1 is frozen after v4.3.0; newer releases require v2"
            )
        identity = _parse_common_ledger(
            top,
            path=relative,
            path_match=path_match,
            schema_version=schema_version,
        )
        if identity[4] != (
            "evo-guard.pyz",
            "SHA256SUMS",
        ):
            raise ProjectStatusError("historical v1 ledger artifact set is invalid")
        release_attestation = _mapping(
            top.get("release_attestation"),
            "release ledger.release_attestation",
        )
        build_provenance = _mapping(
            top.get("build_provenance"),
            "release ledger.build_provenance",
        )
        if (
            release_attestation.get("verification_scope")
            != "recorded-external-attestation"
            or build_provenance.get("verification_scope")
            != "recorded-external-attestation"
        ):
            raise ProjectStatusError("historical v1 ledger lacks recorded attestations")
        signer_identity = _string(
            build_provenance.get("signer_identity"),
            "release ledger.build_provenance.signer_identity",
        )
        build_subject = _string(
            build_provenance.get("subject_name"),
            "release ledger.build_provenance.subject_name",
        )
        release_subjects = _attestation_subject_names(
            release_attestation.get("asset_subjects"),
            "release ledger.release_attestation.asset_subjects",
        )
        if build_subject != "evo-guard.pyz":
            raise ProjectStatusError(
                "historical v1 build provenance does not bind evo-guard.pyz"
            )
        if set(release_subjects) != set(identity[4]):
            raise ProjectStatusError(
                "historical v1 release attestation does not bind every release asset"
            )
        signer_match = re.fullmatch(
            r"https://github\.com/EvoRiseKsa/EvoOM-Guard-m/"
            r"(\.github/workflows/[A-Za-z0-9._/-]+)@refs/heads/main",
            signer_identity,
        )
        if signer_match is None:
            raise ProjectStatusError("historical v1 signer workflow identity is invalid")
        return Ledger(
            schema_version=schema_version,
            version=identity[0],
            tag=identity[1],
            commit_sha=identity[2],
            release_url=identity[3],
            artifacts=identity[4],
            build_signer_workflow=signer_match.group(1),
            build_provenance_subjects=(build_subject,),
            release_attestation_subjects=release_subjects,
            release_attestation_recorded=True,
            build_provenance_recorded=True,
            sbom_recorded=False,
            pipeline_operational_evidence_recorded=False,
            pipeline_publication_evidence_recorded=False,
        )
    if schema_version != "evoguard-release-ledger-v2":
        raise ProjectStatusError("release ledger schema_version is unsupported")
    path_match = _V2_LEDGER_PATH_RE.fullmatch(relative)
    if path_match is None:
        raise ProjectStatusError("release-ledger v2 is outside its signed namespace")
    if verify_git:
        _verify_clean_directory(
            root,
            Path(relative).parent.as_posix(),
        )
        _validate_v2_ledger(root, path.parent, path_match.group(1))
        validated_bytes, _ = _read_stable_bytes(root, path)
        if validated_bytes != ledger_bytes:
            raise ProjectStatusError(
                "release-ledger v2 changed during external validation"
            )
    identity = _parse_common_ledger(
        top,
        path=relative,
        path_match=path_match,
        schema_version=schema_version,
    )
    attestations = _mapping(top.get("attestations"), "release ledger.attestations")
    if not all(
        isinstance(attestations.get(name), Mapping)
        for name in (
            "build_provenance",
            "spdx_provenance",
            "sbom_provenance",
            "release",
        )
    ):
        raise ProjectStatusError("validated v2 ledger omits required attestations")
    if "evo-guard.spdx.json" not in identity[4]:
        raise ProjectStatusError("validated v2 ledger omits its SPDX SBOM asset")
    build_attestation = _mapping(
        attestations["build_provenance"],
        "release ledger.attestations.build_provenance",
    )
    signer_workflow = _string(
        build_attestation.get("signer_workflow"),
        "release ledger.attestations.build_provenance.signer_workflow",
    )
    build_subject = _string(
        build_attestation.get("subject_name"),
        "release ledger.attestations.build_provenance.subject_name",
    )
    spdx_attestation = _mapping(
        attestations["spdx_provenance"],
        "release ledger.attestations.spdx_provenance",
    )
    sbom_attestation = _mapping(
        attestations["sbom_provenance"],
        "release ledger.attestations.sbom_provenance",
    )
    release_attestation = _mapping(
        attestations["release"],
        "release ledger.attestations.release",
    )
    release_subjects = _attestation_subject_names(
        release_attestation.get("asset_subjects"),
        "release ledger.attestations.release.asset_subjects",
    )
    if build_subject != "evo-guard.pyz":
        raise ProjectStatusError("validated v2 build provenance subject is invalid")
    if (
        spdx_attestation.get("subject_name") != "evo-guard.spdx.json"
        or sbom_attestation.get("subject_name") != "evo-guard.pyz"
    ):
        raise ProjectStatusError("validated v2 SPDX provenance subjects are invalid")
    if set(release_subjects) != set(identity[4]):
        raise ProjectStatusError(
            "validated v2 release attestation does not bind every release asset"
        )
    if re.fullmatch(r"\.github/workflows/[A-Za-z0-9._/-]+", signer_workflow) is None:
        raise ProjectStatusError("validated v2 signer workflow path is invalid")
    return Ledger(
        schema_version=schema_version,
        version=identity[0],
        tag=identity[1],
        commit_sha=identity[2],
        release_url=identity[3],
        artifacts=identity[4],
        build_signer_workflow=signer_workflow,
        build_provenance_subjects=(build_subject,),
        release_attestation_subjects=release_subjects,
        release_attestation_recorded=True,
        build_provenance_recorded=True,
        sbom_recorded=True,
        pipeline_operational_evidence_recorded=True,
        pipeline_publication_evidence_recorded=True,
    )


def _load_ledger(root: Path, status: Status, *, verify_git: bool) -> Ledger:
    configured = root / status.ledger_path
    discovered = _discover_ledgers(root, root / "tests/baseline")
    discovered.extend(
        _discover_ledgers(
            root,
            root / "evidence/release-ledgers",
            maximum_version=None,
        )
    )
    if not discovered:
        raise ProjectStatusError("no immutable release ledger was found")
    versions = [version for version, _ in discovered]
    if len(versions) != len(set(versions)):
        raise ProjectStatusError("one release version exists in multiple ledger namespaces")
    configured_safe = _safe_path(root, configured, leaf="file")
    if verify_git:
        _verify_frozen_v1_set(root, discovered)
        _verify_append_only_v2_history(root, discovered)

    loaded: dict[Path, Ledger] = {}
    for version, path in sorted(discovered):
        ledger = _load_one_ledger(root, path, verify_git=verify_git)
        if _version_tuple(ledger.version) != version:
            raise ProjectStatusError("discovered ledger version changed during validation")
        loaded[path] = ledger

    latest = max(discovered, key=lambda item: item[0])[1]
    if configured_safe != latest:
        raise ProjectStatusError(
            f"configured ledger is not newest: {status.ledger_path}; "
            f"newest is {latest.relative_to(_absolute(root)).as_posix()}"
        )
    return loaded[configured_safe]


def _verify_source_relation(status: Status, ledger: Ledger, source_version: str) -> None:
    published = _version_tuple(ledger.version)
    if status.lifecycle == "unreleased-development":
        source = _version_tuple(source_version, development=True)
    else:
        source = _version_tuple(source_version)
    if status.relation != "descendant":
        raise ProjectStatusError(f"unsupported source relation: {status.relation}")
    if status.lifecycle == "release-line":
        if source != published:
            raise ProjectStatusError(
                "release-line source version must equal the ledger-recorded release"
            )
    elif source <= published:
        raise ProjectStatusError("source version must advance beyond the published release")


def _read_text(root: Path, path: Path) -> str:
    raw, _ = _read_stable_bytes(root, path)
    try:
        if raw.startswith(b"\xef\xbb\xbf"):
            raise ProjectStatusError(f"UTF-8 BOM is forbidden: {path}")
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProjectStatusError(f"cannot read UTF-8 file: {path}") from exc
    if "\r" in text:
        raise ProjectStatusError(f"CR line endings are forbidden: {path}")
    return text


def _strip_yaml_comment(line: str) -> str:
    single_quoted = False
    double_quoted = False
    escaped = False
    index = 0
    while index < len(line):
        character = line[index]
        if escaped:
            escaped = False
        elif double_quoted and character == "\\":
            escaped = True
        elif not double_quoted and character == "'":
            if single_quoted and index + 1 < len(line) and line[index + 1] == "'":
                index += 1
            else:
                single_quoted = not single_quoted
        elif not single_quoted and character == '"':
            double_quoted = not double_quoted
        elif (
            character == "#"
            and not single_quoted
            and not double_quoted
            and (index == 0 or line[index - 1].isspace())
        ):
            return line[:index].rstrip()
        index += 1
    return line.rstrip()


def _yaml_atom(value: str) -> str:
    atom = value.strip()
    if len(atom) >= 2 and atom[0] == atom[-1] and atom[0] in {"'", '"'}:
        atom = atom[1:-1]
    if re.fullmatch(r"[A-Za-z0-9_-]+", atom) is None:
        raise ProjectStatusError(f"unsupported workflow scalar: {value!r}")
    return atom


def _parse_needs(value: str, continuation: Sequence[str]) -> frozenset[str]:
    scalar = value.strip()
    if scalar:
        if scalar.startswith("[") and scalar.endswith("]"):
            inner = scalar[1:-1].strip()
            if not inner:
                return frozenset()
            return frozenset(_yaml_atom(item) for item in inner.split(","))
        return frozenset({_yaml_atom(scalar)})
    needs: set[str] = set()
    for line in continuation:
        cleaned = _strip_yaml_comment(line)
        match = re.fullmatch(r"\s{6,}-\s*(.+?)\s*", cleaned)
        if match is not None:
            needs.add(_yaml_atom(match.group(1)))
        elif cleaned.strip():
            raise ProjectStatusError("unsupported multiline needs syntax")
    return frozenset(needs)


def _parse_workflow_jobs(text: str, where: str) -> dict[str, _WorkflowJob]:
    if "\t" in text:
        raise ProjectStatusError(f"{where} contains forbidden YAML tabs")
    lines = text.splitlines()
    jobs_lines = [
        index
        for index, line in enumerate(lines)
        if _strip_yaml_comment(line).strip() == "jobs:"
        and len(line) - len(line.lstrip(" ")) == 0
    ]
    if len(jobs_lines) != 1:
        raise ProjectStatusError(f"{where} must contain exactly one top-level jobs map")
    jobs_start = jobs_lines[0] + 1
    jobs_end = len(lines)
    for index in range(jobs_start, len(lines)):
        cleaned = _strip_yaml_comment(lines[index])
        if cleaned.strip() and len(cleaned) - len(cleaned.lstrip(" ")) == 0:
            jobs_end = index
            break

    headers: list[tuple[int, str]] = []
    for index in range(jobs_start, jobs_end):
        cleaned = _strip_yaml_comment(lines[index])
        if not cleaned.strip():
            continue
        indent = len(cleaned) - len(cleaned.lstrip(" "))
        if indent == 2:
            match = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*", cleaned)
            if match is None:
                raise ProjectStatusError(f"{where} has unsupported job declaration")
            headers.append((index, match.group(1)))
    if not headers or len({name for _, name in headers}) != len(headers):
        raise ProjectStatusError(f"{where} has missing or duplicate jobs")

    jobs: dict[str, _WorkflowJob] = {}
    for header_index, (start, name) in enumerate(headers):
        end = headers[header_index + 1][0] if header_index + 1 < len(headers) else jobs_end
        segment = lines[start + 1 : end]
        gate: str | None = None
        needs: frozenset[str] | None = None
        active_lines: list[str] = []
        index = 0
        while index < len(segment):
            raw_line = segment[index]
            cleaned = _strip_yaml_comment(raw_line)
            if cleaned.strip() and not cleaned.lstrip().startswith("#"):
                active_lines.append(cleaned.strip())
            field = re.fullmatch(
                r"    ([A-Za-z0-9_-]+|<<):(?:\s*(.*?))?\s*",
                cleaned,
            )
            if field is None:
                if (
                    cleaned.strip()
                    and len(cleaned) - len(cleaned.lstrip(" ")) == 4
                ):
                    raise ProjectStatusError(
                        f"{where} job {name} has unsupported job-level YAML syntax"
                    )
                index += 1
                continue
            key = field.group(1)
            value = field.group(2) or ""
            if key == "<<":
                raise ProjectStatusError(
                    f"{where} job {name} uses an unsupported YAML merge key"
                )
            continuation_end = index + 1
            while continuation_end < len(segment):
                next_cleaned = _strip_yaml_comment(segment[continuation_end])
                if next_cleaned.strip():
                    next_indent = len(next_cleaned) - len(next_cleaned.lstrip(" "))
                    if next_indent <= 4:
                        break
                continuation_end += 1
            continuation = segment[index + 1 : continuation_end]
            if key == "if":
                if gate is not None:
                    raise ProjectStatusError(f"{where} job {name} has duplicate if")
                if re.fullmatch(r"[>|][+-]?[0-9]?", value):
                    expression_parts = [
                        _strip_yaml_comment(line).strip()
                        for line in continuation
                        if _strip_yaml_comment(line).strip()
                    ]
                    gate = " ".join(expression_parts)
                elif value:
                    gate = value.strip()
                else:
                    raise ProjectStatusError(f"{where} job {name} has an empty if")
            elif key == "needs":
                if needs is not None:
                    raise ProjectStatusError(f"{where} job {name} has duplicate needs")
                needs = _parse_needs(value, continuation)
            index += 1
        jobs[name] = _WorkflowJob(
            " ".join(gate.split()) if gate is not None else None,
            needs or frozenset(),
            "\n".join(active_lines),
        )
    return jobs


def _verify_workflow_text(
    text: str,
    spec: _WorkflowSpec,
    assets: Sequence[str],
) -> None:
    if (
        spec.reviewed_sha256 is not None
        and hashlib.sha256(text.encode("utf-8")).hexdigest()
        != spec.reviewed_sha256
    ):
        raise ProjectStatusError(
            f"phase {spec.phase} workflow bytes differ from the reviewed contract"
        )
    jobs = _parse_workflow_jobs(text, spec.path)
    expected_jobs = {name: frozenset(needs) for name, needs in spec.jobs}
    if set(jobs) != set(expected_jobs):
        raise ProjectStatusError(
            f"phase {spec.phase} job set differs; "
            f"expected={sorted(expected_jobs)!r}, actual={sorted(jobs)!r}"
        )
    for name, expected_needs in expected_jobs.items():
        job = jobs[name]
        if job.needs != expected_needs:
            raise ProjectStatusError(
                f"phase {spec.phase} job {name} needs {sorted(job.needs)!r}; "
                f"expected {sorted(expected_needs)!r}"
            )
        expected_gate = (
            spec.gate_expression
            if spec.phase == "legacy" or name == spec.gate_job
            else None
        )
        if job.gate != expected_gate:
            raise ProjectStatusError(
                f"phase {spec.phase} job {name} has an unexpected structural gate"
            )
    for name in spec.asset_jobs:
        active_text = jobs[name].active_text
        missing = [asset for asset in assets if asset not in active_text]
        if missing:
            raise ProjectStatusError(
                f"phase {spec.phase} job {name} omits active asset handling: {missing!r}"
            )
        missing_sentinels = [
            fragment
            for fragment in _ASSET_SENTINELS.get((spec.phase, name), ())
            if fragment not in active_text
        ]
        if missing_sentinels:
            raise ProjectStatusError(
                f"phase {spec.phase} job {name} omits reviewed asset operations"
            )


def _verify_pipeline(root: Path, status: Status) -> None:
    bootstrap = _mapping(
        _load_json(root, root / "security/release-pipeline-bootstrap.json"),
        "release pipeline bootstrap",
    )
    activation = _mapping(bootstrap.get("activation"), "release pipeline activation")
    expected_flags = {
        "EVOGUARD_RELEASE_SOURCE_V2_ENABLED",
        "EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1_ENABLED",
        "EVOGUARD_RELEASE_PUBLICATION_ENABLED",
    }
    if set(activation) != expected_flags or any(value is not False for value in activation.values()):
        raise ProjectStatusError("release bootstrap activation flags are not all false")
    for spec in (*_WORKFLOW_SPECS, _LEGACY_SPEC):
        workflow = _read_text(root, root / spec.path)
        _verify_workflow_text(workflow, spec, _PIPELINE_ASSETS)


def _git(root: Path, *arguments: str) -> str:
    raw = _git_bytes(root, *arguments)
    try:
        return raw.decode("utf-8", "strict").strip()
    except UnicodeDecodeError as exc:
        raise ProjectStatusError(
            f"git verification output is not UTF-8: {' '.join(arguments)}"
        ) from exc


def _git_bytes(root: Path, *arguments: str) -> bytes:
    trusted = _selected_git(root)
    _require_git_unchanged(trusted)
    try:
        result = subprocess.run(
            [os.fspath(trusted.path), *arguments],
            cwd=root,
            check=False,
            capture_output=True,
            timeout=30,
            env=_git_environment(trusted),
        )
    except (OSError, subprocess.TimeoutExpired) as primary:
        try:
            _require_git_unchanged(trusted)
        except BaseException as integrity:
            raise integrity from primary
        raise ProjectStatusError(
            f"git byte verification failed: {' '.join(arguments)}"
        ) from primary
    _require_git_unchanged(trusted)
    if len(result.stdout) + len(result.stderr) > 8 * 1024 * 1024:
        raise ProjectStatusError("git byte verification output exceeds the bound")
    if result.returncode != 0:
        raise ProjectStatusError(
            f"git byte verification failed: {' '.join(arguments)}"
        )
    return result.stdout


def _verify_clean_directory(root: Path, relative: str) -> None:
    dirty = _git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=matching",
        "--",
        relative,
    )
    if dirty:
        raise ProjectStatusError(f"frozen repository material is dirty: {relative}")


def _verify_tracked_bytes(
    root: Path,
    relative: str,
    working_bytes: bytes,
    *,
    revision: str = "HEAD",
) -> None:
    parent = Path(relative).parent.as_posix()
    _verify_clean_directory(root, relative if parent == "." else parent)
    tree_entry = _git(root, "ls-tree", revision, "--", relative)
    if re.fullmatch(rf"100644 blob [0-9a-f]{{40}}\t{re.escape(relative)}", tree_entry) is None:
        raise ProjectStatusError(f"ledger is not one tracked regular Git blob: {relative}")
    committed = _git_bytes(root, "show", f"{revision}:{relative}")
    if committed != working_bytes:
        raise ProjectStatusError(
            f"working ledger bytes differ from {revision}:{relative}"
        )


def _verify_git(root: Path, status: Status, ledger: Ledger) -> None:
    for relative, expected_tree in _FROZEN_V1_TREES.items():
        _verify_clean_directory(root, relative)
        frozen_tree = _git(root, "rev-parse", f"HEAD:{relative}")
        if frozen_tree != expected_tree:
            raise ProjectStatusError(f"frozen v1 baseline subtree changed: {relative}")
    if ledger.schema_version == "evoguard-release-ledger-v2":
        _verify_clean_directory(
            root,
            Path(status.ledger_path).parent.as_posix(),
        )
    _git(root, "merge-base", "--is-ancestor", ledger.commit_sha, "HEAD")
    tagged_commit = _git(root, "rev-parse", f"{ledger.tag}^{{commit}}")
    if tagged_commit != ledger.commit_sha:
        raise ProjectStatusError(f"{ledger.tag} does not resolve to its ledger commit")


def _git_refs_snapshot(
    root: Path,
    exception_tags: Sequence[str],
) -> tuple[str, tuple[tuple[str, str], ...]]:
    if (
        not exception_tags
        or len(exception_tags) > _MAX_PUBLISHED_UNLEDGERED_EXCEPTIONS
        or len(set(exception_tags)) != len(exception_tags)
        or any(
            re.fullmatch(
                r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
                r"\.(?:0|[1-9][0-9]*)",
                tag,
            )
            is None
            for tag in exception_tags
        )
    ):
        raise ProjectStatusError(
            "cannot freeze an invalid published-unledgered tag set"
        )
    values = _git(
        root,
        "rev-parse",
        "HEAD^{commit}",
        *(
            f"refs/tags/{exception_tag}^{{commit}}"
            for exception_tag in exception_tags
        ),
    ).splitlines()
    if len(values) != len(exception_tags) + 1 or any(
        re.fullmatch(r"[0-9a-f]{40}", value) is None for value in values
    ):
        raise ProjectStatusError("cannot freeze project-status Git references")
    return values[0], tuple(zip(exception_tags, values[1:], strict=True))


def _git_ref_snapshot(root: Path, exception_tag: str) -> tuple[str, str]:
    trusted_head, snapshots = _git_refs_snapshot(root, (exception_tag,))
    return trusted_head, snapshots[0][1]


def _load_context_with_trusted_git(root: Path, *, verify_git: bool) -> Context:
    _safe_path(root, root, leaf="directory")
    status_bytes, _ = _read_stable_bytes(root, root / _STATUS_PATH)
    status = load_status(root, raw=status_bytes)
    trusted_head: str | None = None
    trusted_exception_tag_commits: dict[str, str] = {}
    if verify_git:
        exception_tags: list[str] = []
        for authority in status.published_unledgered_authorities:
            exception_tags.append(
                _published_unledgered_authority_tag(authority)
            )
        trusted_head, frozen_tags = _git_refs_snapshot(
            root,
            exception_tags,
        )
        trusted_exception_tag_commits = dict(frozen_tags)
        _verify_tracked_bytes(
            root,
            _STATUS_PATH.as_posix(),
            status_bytes,
            revision=trusted_head,
        )
        current_status_bytes, _ = _read_stable_bytes(root, root / _STATUS_PATH)
        if current_status_bytes != status_bytes:
            raise ProjectStatusError("PROJECT_STATUS.json changed during validation")
    ledger = _load_ledger(root, status, verify_git=verify_git)
    source_version = _extract_source_version(root)
    _verify_source_relation(status, ledger, source_version)
    published_unledgered_history = tuple(
        _load_published_unledgered(
            root,
            status,
            ledger,
            source_version,
            verify_git=verify_git,
            authority=authority,
            validate_relation=False,
            trusted_head=trusted_head,
            trusted_exception_tag_commit=(
                trusted_exception_tag_commits.get(
                    _published_unledgered_authority_tag(authority)
                )
                if verify_git
                else None
            ),
        )
        for authority in status.published_unledgered_authorities
    )
    _validate_published_unledgered_chain(
        root,
        status,
        ledger,
        source_version,
        published_unledgered_history,
    )
    published_unledgered = published_unledgered_history[-1]
    _verify_pipeline(root, status)
    if verify_git:
        assert trusted_head is not None
        _verify_git(root, status, ledger)
        for exception in published_unledgered_history:
            for authority_relative, expected_sha256 in (
                exception.authority_sha256
            ):
                authority_bytes, _ = _read_stable_bytes(
                    root,
                    root / authority_relative,
                )
                if hashlib.sha256(authority_bytes).hexdigest() != expected_sha256:
                    raise ProjectStatusError(
                        "published-unledgered authority changed during validation: "
                        f"{authority_relative}"
                    )
                _verify_tracked_bytes(
                    root,
                    authority_relative,
                    authority_bytes,
                    revision=trusted_head,
                )
        final_status_bytes, _ = _read_stable_bytes(root, root / _STATUS_PATH)
        if final_status_bytes != status_bytes:
            raise ProjectStatusError("PROJECT_STATUS.json changed during validation")
        _verify_tracked_bytes(
            root,
            _STATUS_PATH.as_posix(),
            final_status_bytes,
            revision=trusted_head,
        )
        final_head, final_tags = _git_refs_snapshot(
            root,
            tuple(exception.tag for exception in published_unledgered_history),
        )
        if (
            final_head != trusted_head
            or dict(final_tags) != trusted_exception_tag_commits
        ):
            raise ProjectStatusError(
                "project-status Git references changed during validation"
            )
    return Context(
        status,
        ledger,
        source_version,
        published_unledgered,
        published_unledgered_history,
    )


def load_context(root: Path = _ROOT, *, verify_git: bool = True) -> Context:
    if not verify_git:
        return _load_context_with_trusted_git(root, verify_git=False)
    with _trusted_git_session(root):
        return _load_context_with_trusted_git(root, verify_git=True)


def _release_summary(context: Context) -> str:
    ledger = context.ledger
    exception = context.published_unledgered
    lifecycle: str | None
    if context.status.lifecycle == "published-unledgered":
        source_release_url = (
            "https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/"
            f"v{context.source_version}"
        )
        lifecycle = (
            f"a **published stable GitHub release** "
            f"([`v{context.source_version}`]({source_release_url})). It has no "
            "valid protected-tree release ledger. This maintained status is not a "
            "signed ledger, does not establish that release's assets, attestations, "
            "or protected A-through-H completion, and does not imply that a ledger "
            "for this version can be issued later"
        )
    else:
        lifecycle = {
            "unreleased-development": (
                "**unreleased development** and is not a consumer release"
            ),
            "release-candidate": (
                "a **release candidate** and is not yet a consumer release"
            ),
            "release-line": (
                "on the **ledger-recorded release line**; this protected source tree "
                "may be a post-tag descendant and is not a new consumer release"
            ),
        }.get(context.status.lifecycle)
    if lifecycle is None:
        raise ProjectStatusError(
            f"unsupported rendered source lifecycle: {context.status.lifecycle}"
        )
    exception_note = ""
    recovery_is_pending = _version_tuple(ledger.version) < _version_tuple(
        exception.recovery_version
    )
    if (
        context.status.lifecycle in {"unreleased-development", "release-candidate"}
        and recovery_is_pending
    ):
        exception_note = (
            f"The maintained unsigned exception record "
            f"`{exception.record_path}` reports "
            f"[`{exception.tag}`]({exception.release_url}) as a published immutable "
            "GitHub Release without a canonical protected-tree ledger. Its erratum "
            f"is `{exception.erratum_path}`. Neither record is a ledger or a consumer "
            f"pin. The unsigned local-key disposition "
            f"`{exception.key_disposition_path}` is "
            f"`{exception.key_disposition_status}` and is not a retirement or erasure "
            f"proof. This source is the unreleased `v{exception.recovery_version}` "
            f"recovery successor to `{exception.tag}`; no release or ledger is claimed "
            "for the recovery version. "
        )
    artifacts = "`, `".join(ledger.artifacts)
    release_subjects = "`, `".join(ledger.release_attestation_subjects)
    build_subjects = "`, `".join(ledger.build_provenance_subjects)
    sbom = (
        "The ledger records the SPDX SBOM release asset and its provenance."
        if ledger.sbom_recorded
        else "The ledger records no SBOM release asset."
    )
    return _wrap(
        f"Source version `{context.source_version}` is {lifecycle}. "
        f"{exception_note}"
        f"The latest immutable consumer release recorded by the protected source "
        f"tree is [`{ledger.tag}`]({ledger.release_url}) at commit "
        f"`{ledger.commit_sha}`. Its `{ledger.schema_version}` ledger records "
        f"the release assets `{artifacts}`. Its release attestation binds "
        f"`{release_subjects}`, while its build-provenance attestation binds "
        f"`{build_subjects}`. {sbom} "
        f"Canonical ledger: `{context.status.ledger_path}`."
    )


def _pipeline_summary(context: Context) -> str:
    assets = "`, `".join(_PIPELINE_ASSETS)
    implementation = {
        "scaffolded": (
            "scaffolded but is not implementation-complete"
        ),
        "implemented": "implemented in source",
    }.get(context.status.pipeline_implementation)
    if implementation is None:
        raise ProjectStatusError("unsupported rendered release-pipeline enum")
    if context.ledger.pipeline_operational_evidence_recorded:
        operational = (
            "The externally anchored signed v2 ledger records a completed protected "
            "A-H operation."
        )
    else:
        operational = (
            "No externally anchored signed v2 ledger records a completed protected "
            "A-H operation."
        )
    if context.ledger.pipeline_publication_evidence_recorded:
        publication = (
            "That validated ledger also records the resulting publication."
        )
    else:
        publication = (
            "No externally anchored signed v2 ledger records publication by this "
            "pipeline."
        )
    return _wrap(
        f"The protected A-H release pipeline is {implementation} and **disabled "
        f"by default**. The legacy release workflow is hard-disabled. {operational} "
        f"{publication} An admitted release is contracted to exactly `{assets}`; "
        "this source contract is not evidence that those assets were published."
    )


def _wrap(text: str) -> str:
    return textwrap.fill(
        " ".join(text.split()),
        width=88,
        break_long_words=False,
        break_on_hyphens=False,
    )


def _blocks(context: Context) -> dict[str, str]:
    release = _release_summary(context)
    pipeline = _pipeline_summary(context)
    architecture = context.status
    ledger = context.ledger
    published_unledgered = context.published_unledgered
    tag = ledger.tag
    version = ledger.version
    release_link = f"[`{tag}`]({ledger.release_url})"
    asset_names = "`, `".join(ledger.artifacts)
    release_subject_names = "`, `".join(ledger.release_attestation_subjects)
    build_subject_names = "`, `".join(ledger.build_provenance_subjects)
    download_patterns = " \\\n".join(
        f"  --pattern {name}" for name in ledger.artifacts
    )
    attestation_commands = "\n\n".join(
        textwrap.dedent(
            f"""\
            ```bash
            gh attestation verify ./{name} \\
              --repo EvoRiseKsa/EvoOM-Guard-m \\
              --signer-workflow EvoRiseKsa/EvoOM-Guard-m/{ledger.build_signer_workflow} \\
              --source-ref refs/heads/main \\
              --source-digest {ledger.commit_sha} \\
              --cert-oidc-issuer https://token.actions.githubusercontent.com \\
              --deny-self-hosted-runners \\
              --format json
            ```"""
        )
        for name in ledger.artifacts
        if name != "SHA256SUMS"
    )
    architecture_version_state = {
        "unreleased-development": "remains unreleased",
        "release-candidate": "remains unreleased",
        "published-unledgered": (
            "is published without a valid protected-tree release ledger"
        ),
        "release-line": "is on the ledger-recorded release line",
    }[architecture.lifecycle]
    source_support_status = {
        "unreleased-development": "Unreleased development source; not a consumer release",
        "release-candidate": "Release candidate; not a consumer release",
        "published-unledgered": (
            "Latest published stable release; supported; no valid protected-tree ledger"
        ),
        "release-line": "Source on the latest ledger-recorded release line",
    }[architecture.lifecycle]
    source_support_row = (
        f"| `{context.source_version}` | {source_support_status} |\n"
        if context.source_version != version or architecture.lifecycle != "release-line"
        else ""
    )
    unledgered_is_active = _version_tuple(published_unledgered.version) > _version_tuple(
        version
    ) and architecture.lifecycle in {
        "unreleased-development",
        "release-candidate",
        "published-unledgered",
    }
    if unledgered_is_active:
        unledgered_release_link = (
            f"[`{published_unledgered.tag}`]({published_unledgered.release_url})"
        )
        recovery_source_row = (
            f"| `{context.source_version}` | {source_support_status}; recovery successor "
            f"to `{published_unledgered.tag}` |\n"
            if not (
                architecture.lifecycle == "published-unledgered"
                and context.source_version == published_unledgered.version
            )
            else ""
        )
        security_support = (
            "Security fixes are provided on a best-effort basis for the latest\n"
            "published stable release. The previous ledger-recorded consumer release\n"
            "remains supported as an evidence-bound fallback until a later recovery\n"
            "release:\n\n"
            "| Version | Status |\n"
            "| --- | --- |\n"
            f"{recovery_source_row}"
            f"| {unledgered_release_link} | Latest published stable release; supported; "
            "no valid protected-tree ledger |\n"
            f"| {release_link} | Latest ledger-recorded consumer release; temporarily "
            "supported until a later recovery release |\n"
            "| Earlier published releases | Historical and unsupported; retained "
            "unchanged for reproducibility, verification, and rollback |\n"
            "| Unpublished draft candidates | Unsupported; never consumer releases |\n\n"
            "Users should reproduce a suspected issue on the latest published stable\n"
            "release before reporting when practical. A report that affects an older\n"
            "release may still be useful, but a fix will be delivered in a new immutable\n"
            "release rather than by rewriting an existing tag, asset, checksum, or\n"
            "attestation."
        )
        changelog_support = (
            (
                f"- Source `{context.source_version}` is the unreleased recovery "
                f"successor to `{published_unledgered.tag}`; it is not a consumer "
                "release and has no release ledger.\n"
                if recovery_source_row
                else ""
            )
            + f"- {unledgered_release_link} is the latest published stable and "
            "supported release; it has no valid protected-tree ledger.\n"
            f"- {release_link} remains the latest ledger-recorded consumer release and "
            "is temporarily supported until a later recovery release.\n"
            "- Earlier published versions are historical and unsupported. Their tags,\n"
            "  release assets, checksums, attestations, and records remain available\n"
            "  unchanged for reproducibility, verification, and rollback.\n"
            "- Draft candidates that were never published are labelled explicitly below\n"
            "  and are not supported releases."
        )
    else:
        security_support = (
            "Security fixes are provided on a best-effort basis for the latest stable\n"
            "consumer release only:\n\n"
            "| Version | Status |\n"
            "| --- | --- |\n"
            f"| {release_link} | Latest stable release; supported |\n"
            f"{source_support_row}"
            "| Earlier published releases | Historical and unsupported; retained "
            "unchanged for reproducibility, verification, and rollback |\n"
            "| Unpublished draft candidates | Unsupported; never consumer releases |\n\n"
            "Users should reproduce a suspected issue on the latest stable release before\n"
            "reporting when practical. A report that affects an older release may still be\n"
            "useful, but a fix will be delivered in a new immutable release rather than by\n"
            "rewriting an existing tag, asset, checksum, or attestation."
        )
        changelog_support = (
            f"- {release_link} is the latest stable and supported consumer release.\n"
            f"- Source `{context.source_version}`: {source_support_status.lower()}.\n"
            "- Earlier published versions are historical and unsupported. Their tags,\n"
            "  release assets, checksums, attestations, and records remain available\n"
            "  unchanged for reproducibility, verification, and rollback.\n"
            "- Draft candidates that were never published are labelled explicitly below "
            "and\n"
            "  are not supported releases."
        )
    return {
        "SECURITY_SUPPORTED_VERSIONS": security_support,
        "CHANGELOG_RELEASE_SUPPORT": changelog_support,
        "README_RELEASE_CHANNEL": release + "\n\n" + pipeline,
        "README_QUICKSTART_PIN": textwrap.dedent(
            f"""\
            ```bash
            pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m@{tag}"   # ledger-recorded release; pin a SHA for strictest CI

            # From the branch you want checked (the diff is reverse-applied to a
            # throwaway copy; your working tree is never modified):
            git diff main...HEAD | evo-guard guard --diff - --no-config --test-command "python -m pytest -q"
            ```"""
        ),
        "README_INIT_PIN": textwrap.dedent(
            f"""\
            ```bash
            evo-guard init --ref {tag} --test-command "python -m pytest -q"
            ```"""
        ),
        "README_ACTION_PIN": textwrap.dedent(
            f"""\
            ```yaml
            permissions:
              contents: read

            steps:
              - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
                with:
                  fetch-depth: 0
                  persist-credentials: false
              - uses: EvoRiseKsa/EvoOM-Guard-m@{tag}   # ledger-recorded release; pin a SHA for strictest CI
                with:
                  comment: "false"   # explicit for older releases; candidate jobs never comment
                  fail-on: "any-non-pass"
            ```"""
        ),
        "README_ATTESTATION_SCOPE": _wrap(
            f"Historical `v3.7.0` has a GitHub release attestation but no GitHub "
            f"Actions build-artifact attestation. The validated `{tag}` ledger "
            f"records build provenance whose subject is `{build_subject_names}` "
            f"under `{ledger.build_signer_workflow}`. Its release attestation "
            f"separately binds `{release_subject_names}`"
            + (
                " and records SPDX SBOM provenance."
                if ledger.sbom_recorded
                else "; it records no SBOM release asset."
            )
            + " Provider attestations are provenance evidence, not an EvoOM Guard "
            "verdict, artifact-admission decision, or proof of deployment. See "
            "[`docs/GITHUB_ARTIFACT_ATTESTATIONS.md`]"
            "(docs/GITHUB_ARTIFACT_ATTESTATIONS.md) for the bounded procedure."
        ),
        "RELEASE_STATUS_SUMMARY": release + "\n\n" + pipeline,
        "RELEASE_STATUS_CONSUMER_PIN": _wrap(
            f"Consumer usage should use ledger-recorded release `{tag}` only when "
            f"aligned with the acceptance policy; pin commit `{ledger.commit_sha}` "
            f"for the strictest reviewed identity. `evo-guard init` requires "
            f"`--ref` explicitly: supply `{tag}` or that full commit SHA. It "
            "refuses a moving branch and does not guess a latest release."
        ),
        "RELEASE_STATUS_CURRENT_LEDGER": _wrap(
            f"The protected source tree selects `{context.status.ledger_path}` as "
            f"the latest ledger. Its validated `{ledger.schema_version}` record "
            f"binds release `{tag}`, commit `{ledger.commit_sha}`, and assets "
            f"`{asset_names}`. "
            + (
                "It records the SPDX SBOM asset and provenance. "
                if ledger.sbom_recorded
                else "It records no SBOM asset. "
            )
            + "This bounded identity/provenance record is not a full behavioral "
            "capture, correctness verdict, production-readiness claim, independent "
            "review, or deployment authorization."
        ),
        "PROJECT_STATUS_CORE_RELEASE": release,
        "PROJECT_STATUS_RELEASE_PIPELINE": pipeline,
        "PROJECT_STATUS_RELEASE_EVIDENCE_ROWS": _wrap(
            f"Release evidence: validated ledger `{context.status.ledger_path}` "
            f"records `{tag}` assets `{asset_names}`. Its release attestation binds "
            f"`{release_subject_names}`; its build-provenance attestation binds "
            f"`{build_subject_names}` under `{ledger.build_signer_workflow}`. "
            + (
                "It also records the SPDX SBOM asset and SBOM provenance. "
                if ledger.sbom_recorded
                else "It records no SBOM release asset. "
            )
            + "These attestations establish bounded provenance, not correctness, "
            "security, deployment, or independent review."
        ),
        "ROADMAP_LATEST_RELEASE": release,
        "ROADMAP_CURRENT_PIPELINE": pipeline,
        "SBOM_EXACT_STATUS": release,
        "SBOM_PIPELINE": _wrap(
            pipeline
            + " The deterministic SPDX generator exists in source; SBOM publication "
            "status is derived only from the validated release ledger's artifact and "
            "attestation records."
        ),
        "ATTESTATIONS_RELEASE_STATUS": release,
        "ATTESTATIONS_CONSUMER_VERIFICATION": (
            "Download the exact ledger-recorded asset set and verify its checksum\n"
            "manifest:\n\n"
            "```bash\n"
            f"gh release download {tag} --repo EvoRiseKsa/EvoOM-Guard-m \\\n"
            f"{download_patterns}\n"
            "sha256sum --check SHA256SUMS\n"
            f"gh release verify {tag} --repo EvoRiseKsa/EvoOM-Guard-m\n"
            "```\n\n"
            "Verify the provider statement for each non-checksum subject against "
            "the\nexact workflow and source commit recorded by the validated "
            "ledger:\n\n"
            f"{attestation_commands}\n\n"
            "The release command and artifact commands are complementary. Neither\n"
            "substitutes for checksum verification. The ledger records "
            + (
                "SPDX SBOM provenance for the zipapp and SPDX asset."
                if ledger.sbom_recorded
                else "no SBOM release asset."
            )
            + "\nFor offline verification, retain the provider bundles and use "
            "their\ntrusted-root procedure; a copied JSON document is not a trust "
            "root."
        ),
        "ATTESTATIONS_FUTURE_PIPELINE": pipeline,
        "RELEASE_TRUST_PIPELINE_STATUS": pipeline,
        "REFACTOR_PROGRAM_STATUS": _wrap(
            f"Machine-readable status: behavior-preserving R2 is "
            f"**{architecture.behavior_r2}**; CLI handler extraction is "
            f"**{architecture.cli_extraction}**; the overall refactor program is "
            f"**{architecture.refactor_program}**. Source version "
            f"`{context.source_version}` {architecture_version_state}."
        ),
        "ADOPTION_CURRENT_RELEASE": textwrap.dedent(
            f"""\
            {release_link} is the latest immutable consumer release recorded by the
            protected source tree, at commit `{ledger.commit_sha}`. For stricter CI,
            pin that full commit SHA.

            From the repository you want to protect:

            ```bash
            pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m.git@{tag}"
            evo-guard init --ref {tag} --test-command "python -m pytest -q"
            git add .github/workflows/evoguard.yml .evoguard.json
            git commit -m "ci: add EvoOM Guard policy" && git push
            ```

            The no-Action alternative is `git diff | evo-guard guard --diff -`.
            Use `evo-guard init --ref {tag} --stdout` to review the workflow first."""
        ),
        "GUARD_CURRENT_RELEASE": textwrap.dedent(
            f"""\
            > **Release availability.** {release_link} is the latest immutable
            > consumer release recorded by the protected source tree. For strict CI,
            > pin commit `{ledger.commit_sha}` rather than a tag.

            EvoOM Guard is not published to PyPI. Obtain it from this repository.

            **GitHub Action:**

            ```yaml
            - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
              with:
                fetch-depth: 0
                persist-credentials: false
            - uses: EvoRiseKsa/EvoOM-Guard-m@{tag}
            ```

            **CLI:**

            ```bash
            pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m.git@{tag}"
            pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m.git@{ledger.commit_sha}"
            evo-guard guard --diff - --no-config --test-command "python -m pytest -q" < pr.diff
            ```

            Pin the full commit for the strictest reviewed identity. The ledger-recorded
            tag is the named consumer release. Do not use `@main` for a gate you depend on."""
        ),
        "GUARD_ACTION_EXAMPLE": textwrap.dedent(
            f"""\
            A composite action ships at the repository root
            ([`action.yml`](../action.yml)). Copy
            [`examples/evoguard.yml`](../examples/evoguard.yml) to
            `.github/workflows/evoguard.yml` in the repository you want to protect:

            ```yaml
            - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
              with:
                fetch-depth: 0
                persist-credentials: false
            - uses: EvoRiseKsa/EvoOM-Guard-m@{tag}
              with:
                comment: "false"
                fail-on: "any-non-pass"
            ```"""
        ),
        "GUARD_NO_ACTION_EXAMPLE": textwrap.dedent(
            f"""\
            ```yaml
            - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
              with:
                fetch-depth: 0
                persist-credentials: false
            - run: pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m.git@{tag}"
            - run: |
                BASE="${{{{ github.event.pull_request.base.sha }}}}"
                git fetch --no-tags origin "$BASE"
                git show "$BASE:.evoguard.json" > "$RUNNER_TEMP/evoguard-base-policy.json" \\
                  || printf '{{}}\\n' > "$RUNNER_TEMP/evoguard-base-policy.json"
                git diff "$BASE...HEAD" | evo-guard guard --diff - \\
                  --config "$RUNNER_TEMP/evoguard-base-policy.json" \\
                  --report "$GITHUB_STEP_SUMMARY"
            ```"""
        ),
        "EVIDENCE_BUNDLES_RELEASE_PIN": textwrap.dedent(
            f"""\
            Install the signing extra from ledger-recorded release `{tag}` and generate
            an Ed25519 key once:

            ```bash
            pip install "evoom-guard[sign] @ git+https://github.com/EvoRiseKsa/EvoOM-Guard-m.git@{tag}"
            evo-guard keygen --key judge.pem --pub judge.pub
            ```"""
        ),
        "SIGNED_VERDICTS_RELEASE_PIN": textwrap.dedent(
            f"""\
            Requires the `sign` extra (the core gate stays stdlib-only). Install it from
            ledger-recorded release `{tag}`:

            ```bash
            pip install "evoom-guard[sign] @ git+https://github.com/EvoRiseKsa/EvoOM-Guard-m@{tag}"
            ```"""
        ),
        "TRUSTED_FINALIZER_RELEASE_PIN": textwrap.dedent(
            f"""\
            They are not enforced as required merge gates by default in this repository.
            Each consumer must apply its own branch protection, Environment/reviewer
            controls, protected Guard-artifact digest, and audit.

            The implementation-ready workflows download ledger-recorded release `{tag}`.
            Before enabling them, download that release's `evo-guard.pyz` and
            `SHA256SUMS`, verify the manifest and release attestation, and copy the
            reviewed runtime digest into protected variable
            `EVOGUARD_GUARD_ARTIFACT_SHA256`. The workflow must not derive its trust root
            from the downloaded executable or a mutable URL.

            The `examples/trusted-finalizer/` pair remains a frozen v3.7.0 reference and
            must not be silently rewritten. New exercises should use `{tag}` (version
            `{version}`) or its exact commit pin and complete the audit before
            enforcement."""
        ),
    }


def _fence_opener(line: str) -> tuple[str, int] | None:
    match = re.fullmatch(r" {0,3}(`{3,}|~{3,})(.*)", line)
    if match is None:
        return None
    run = match.group(1)
    info = match.group(2)
    if run[0] == "`" and "`" in info:
        return None
    return run[0], len(run)


def _is_fence_closer(line: str, character: str, minimum: int) -> bool:
    match = re.fullmatch(r" {0,3}([`~]+)[ \t]*", line)
    return (
        match is not None
        and set(match.group(1)) == {character}
        and len(match.group(1)) >= minimum
    )


def _strip_complete_inline_code_spans(line: str) -> str:
    visible: list[str] = []
    cursor = 0
    while True:
        opener = re.search(r"`+", line[cursor:])
        if opener is None:
            visible.append(line[cursor:])
            break
        opener_start = cursor + opener.start()
        opener_end = cursor + opener.end()
        backslashes = 0
        escape_cursor = opener_start - 1
        while escape_cursor >= 0 and line[escape_cursor] == "\\":
            backslashes += 1
            escape_cursor -= 1
        if backslashes % 2:
            visible.append(line[cursor:opener_end])
            cursor = opener_end
            continue
        delimiter = opener.group(0)
        closer = re.search(
            rf"(?<!`){re.escape(delimiter)}(?!`)",
            line[opener_end:],
        )
        if closer is None:
            visible.append(line[cursor:])
            break
        closer_end = opener_end + closer.end()
        visible.append(line[cursor:opener_start])
        visible.append(" " * (closer_end - opener_start))
        cursor = closer_end
    return "".join(visible)


def _marker_locations(text: str) -> dict[str, tuple[int, int]]:
    if "\r" in text:
        raise ProjectStatusError("CR line endings are forbidden in marker documents")
    locations: dict[str, tuple[int, int]] = {}
    frontmatter_open = text.startswith("---\n")
    leading_comment_open = text.startswith("<!--\n")
    fence: tuple[str, int] | None = None
    offset = 0
    seen_markers: set[str] = set()
    active_token: str | None = None
    for line_number, line in enumerate(text.splitlines(keepends=True), start=1):
        content = line[:-1] if line.endswith("\n") else line
        marker = _MARKER_LINE_RE.fullmatch(content)
        marker_fragments = (
            list(_BEGIN_RE.finditer(content))
            + list(_END_RE.finditer(content))
        )
        if marker_fragments and marker is None:
            raise ProjectStatusError(
                "project-status markers must be exact standalone top-level lines"
            )

        if leading_comment_open:
            if marker is not None:
                raise ProjectStatusError("marker is hidden inside the leading HTML comment")
            if line_number > 1 and content == "-->":
                leading_comment_open = False
            offset += len(line)
            continue

        if frontmatter_open:
            if marker is not None:
                raise ProjectStatusError("marker is hidden inside Markdown frontmatter")
            if line_number > 1 and content == "---":
                frontmatter_open = False
            offset += len(line)
            continue

        if marker is not None:
            token = marker.group(2)
            kind = marker.group(1).lower()
            if fence is not None:
                raise ProjectStatusError(f"marker {token} is inside a code fence")
            identity = f"{kind}:{token}"
            if identity in seen_markers:
                raise ProjectStatusError(f"duplicate {kind} marker for {token}")
            seen_markers.add(identity)
            if kind == "begin":
                if active_token is not None:
                    raise ProjectStatusError(
                        f"nested marker {token} inside {active_token}"
                    )
                active_token = token
                locations[token] = (offset, -1)
            else:
                if (
                    active_token != token
                    or token not in locations
                    or locations[token][1] != -1
                ):
                    raise ProjectStatusError(f"unmatched end marker for {token}")
                locations[token] = (
                    locations[token][0],
                    offset + len(content),
                )
                active_token = None
            offset += len(line)
            continue

        if fence is not None:
            if _is_fence_closer(content, fence[0], fence[1]):
                fence = None
            offset += len(line)
            continue

        opener = _fence_opener(content)
        if opener is not None:
            fence = opener
            offset += len(line)
            continue

        if _RAW_HTML_RE.search(_strip_complete_inline_code_spans(content)) is not None:
            raise ProjectStatusError(
                "raw HTML containers and comments are forbidden in marker documents"
            )
        offset += len(line)

    if (
        fence is not None
        or frontmatter_open
        or leading_comment_open
        or active_token is not None
    ):
        raise ProjectStatusError(
            "unterminated marker, Markdown fence, frontmatter, or leading comment"
        )
    for token, (_, end) in locations.items():
        if end == -1:
            raise ProjectStatusError(f"unmatched begin marker for {token}")
    return locations


def _render_file(text: str, tokens: Sequence[str], blocks: Mapping[str, str]) -> str:
    locations = _marker_locations(text)
    if set(locations) != set(tokens):
        raise ProjectStatusError(
            f"marker set differs; expected={sorted(tokens)!r}, actual={sorted(locations)!r}"
        )
    result = text
    for token in sorted(tokens, key=lambda item: locations[item][0], reverse=True):
        begin = f"<!-- BEGIN EVOGUARD_PROJECT_STATUS:{token} -->"
        end = f"<!-- END EVOGUARD_PROJECT_STATUS:{token} -->"
        start_index, end_index = locations[token]
        replacement = f"{begin}\n{blocks[token]}\n{end}"
        result = result[:start_index] + replacement + result[end_index:]
    return result.rstrip("\n") + "\n"


def build_rendered_files(
    root: Path = _ROOT,
    *,
    verify_git: bool = True,
) -> dict[Path, bytes]:
    context = load_context(root, verify_git=verify_git)
    blocks = _blocks(context)
    rendered: dict[Path, bytes] = {}
    for relative, tokens in _MARKER_FILES.items():
        path = root / relative
        text = _read_text(root, path)
        rendered[path] = _render_file(text, tokens, blocks).encode("utf-8")
    return rendered


def _failure_label(error: BaseException) -> str:
    detail = str(error)
    return f"{type(error).__name__}: {detail}" if detail else type(error).__name__


def _stage_bytes(
    root: Path,
    target: Path,
    content: bytes,
    label: str,
    *,
    register: list[Path] | None = None,
) -> Path:
    safe_target = _safe_path(root, target, leaf="file")
    parent = _safe_path(root, safe_target.parent, leaf="directory")
    descriptor: int | None = None
    temporary: Path | None = None
    try:
        mode = stat.S_IMODE(os.lstat(safe_target).st_mode)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{safe_target.name}.{label}.",
            suffix=".tmp",
            dir=parent,
        )
        temporary = Path(temporary_name)
        if register is not None:
            register.append(temporary)
        _safe_path(root, temporary, leaf="file")
        os.chmod(temporary, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        descriptor = None
        staged_bytes, _ = _read_stable_bytes(root, temporary)
        if staged_bytes != content:
            raise ProjectStatusError(f"staged bytes differ for {target}")
        return temporary
    except BaseException as exc:
        cleanup_errors: list[str] = []
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
            except BaseException as cleanup_error:
                cleanup_errors.append(_failure_label(cleanup_error))
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            except OSError as cleanup_error:
                cleanup_errors.append(_failure_label(cleanup_error))
            except BaseException as cleanup_error:
                cleanup_errors.append(_failure_label(cleanup_error))
        if cleanup_errors:
            raise ProjectStatusError(
                f"cannot stage generated bytes for {target}; cleanup failed: "
                + "; ".join(cleanup_errors)
            ) from exc
        if not isinstance(exc, Exception):
            raise
        if isinstance(exc, ProjectStatusError):
            raise
        raise ProjectStatusError(f"cannot stage generated bytes for {target}") from exc


def _replace_path(root: Path, source: Path, target: Path) -> None:
    safe_source = _safe_path(root, source, leaf="file")
    safe_target = _safe_path(root, target, leaf="file")
    if safe_source.parent != safe_target.parent:
        raise ProjectStatusError("transaction replacements must remain in one directory")
    parent = _safe_path(root, safe_target.parent, leaf="directory")
    descriptor: int | None = None
    try:
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
        supports_directory_fd = (
            os.replace in os.supports_dir_fd
            and directory_flag != 0
            and nofollow_flag != 0
        )
        if supports_directory_fd:
            descriptor = os.open(
                parent,
                os.O_RDONLY | directory_flag | nofollow_flag,
            )
            opened = os.fstat(descriptor)
            current = os.lstat(parent)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or not _same_open_file(opened, current)
            ):
                raise ProjectStatusError("output directory changed before replacement")
            os.replace(
                safe_source.name,
                safe_target.name,
                src_dir_fd=descriptor,
                dst_dir_fd=descriptor,
            )
        else:
            _safe_path(root, parent, leaf="directory")
            os.replace(safe_source, safe_target)
    except OSError as exc:
        raise ProjectStatusError(f"cannot replace generated file: {target}") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _remove_temporary(root: Path, path: Path) -> str | None:
    try:
        safe = _safe_path(
            root,
            path,
            leaf="file",
            allow_missing_leaf=True,
        )
        os.unlink(safe)
        return None
    except FileNotFoundError:
        return None
    except (OSError, ProjectStatusError) as exc:
        return f"{path}: {exc}"


def _cleanup_temporary(root: Path, path: Path) -> str | None:
    try:
        return _remove_temporary(root, path)
    except BaseException as first_error:
        try:
            retry_error = _remove_temporary(root, path)
        except BaseException as second_error:
            return (
                f"{path}: cleanup interrupted by {_failure_label(first_error)}; "
                f"retry interrupted by {_failure_label(second_error)}"
            )
        if retry_error is not None:
            return (
                f"{path}: cleanup interrupted by {_failure_label(first_error)}; "
                f"retry failed: {retry_error}"
            )
        return None


def _renderer_lock_path(root: Path) -> Path:
    identity = os.path.normcase(os.fspath(_absolute(root))).encode(
        "utf-8",
        errors="surrogatepass",
    )
    digest = hashlib.sha256(identity).hexdigest()
    return Path(tempfile.gettempdir()) / f"evoguard-project-status-{digest}.lock"


@contextmanager
def _exclusive_renderer_lock(root: Path) -> Iterator[None]:
    """Serialize cooperating writers; this is not a filesystem-wide CAS.

    Atomic exclusive creation excludes other renderer processes using this
    function. A crash can leave a stale lock which must be inspected and
    removed manually. External, non-cooperating writers remain outside the
    contract.
    """

    lock_path = _renderer_lock_path(root)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
    )
    descriptor: int | None = None
    created_identity: tuple[int, int] | None = None
    try:
        try:
            descriptor = os.open(lock_path, flags, 0o600)
        except FileExistsError as exc:
            raise ProjectStatusError(
                "another project-status writer holds the exclusive renderer lock, "
                f"or a stale lock requires manual inspection: {lock_path}"
            ) from exc
        metadata = os.fstat(descriptor)
        created_identity = (metadata.st_dev, metadata.st_ino)
        if not stat.S_ISREG(metadata.st_mode) or _is_reparse_point(metadata):
            raise ProjectStatusError("renderer lock is not a regular file")
        yield
    except ProjectStatusError:
        raise
    except OSError as exc:
        raise ProjectStatusError("cannot acquire the exclusive renderer lock") from exc
    finally:
        cleanup_error: str | None = None
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as exc:
                cleanup_error = f"cannot close renderer lock: {exc}"
        if created_identity is not None:
            try:
                current = os.lstat(lock_path)
                if (
                    stat.S_ISREG(current.st_mode)
                    and not stat.S_ISLNK(current.st_mode)
                    and not _is_reparse_point(current)
                    and (current.st_dev, current.st_ino) == created_identity
                ):
                    os.unlink(lock_path)
                else:
                    cleanup_error = (
                        "renderer lock identity changed; manual inspection is required: "
                        f"{lock_path}"
                    )
            except FileNotFoundError:
                cleanup_error = f"renderer lock disappeared unexpectedly: {lock_path}"
            except OSError as exc:
                cleanup_error = f"cannot remove renderer lock {lock_path}: {exc}"
        if cleanup_error is not None and sys.exc_info()[0] is None:
            raise ProjectStatusError(cleanup_error)


def _write_transaction(
    root: Path,
    rendered: Mapping[Path, bytes],
    *,
    replace: Callable[[Path, Path], None] | None = None,
) -> None:
    """Write under a cooperating-writer lock with fail-stop commit semantics.

    There is no portable atomic compare-and-swap for this multi-file operation.
    A commit-phase failure is therefore never followed by automatic rollback:
    callers must inspect the possibly partial result and rerun ``--write``.
    """

    with _exclusive_renderer_lock(root):
        _write_transaction_locked(root, rendered, replace=replace)


def _write_transaction_locked(
    root: Path,
    rendered: Mapping[Path, bytes],
    *,
    replace: Callable[[Path, Path], None] | None = None,
) -> None:
    pending: list[_PendingWrite] = []
    loose_temporaries: list[Path] = []
    replacer = replace or (lambda source, target: _replace_path(root, source, target))
    try:
        for target in sorted(rendered, key=lambda item: item.as_posix()):
            expected = rendered[target]
            _, original = _read_stable_bytes(root, target)
            staged = _stage_bytes(
                root,
                target,
                expected,
                "new",
                register=loose_temporaries,
            )
            pending.append(
                _PendingWrite(
                    _absolute(target),
                    staged,
                    original,
                    expected,
                )
            )
    except BaseException as exc:
        cleanup_errors = [
            error
            for path in loose_temporaries
            if (error := _cleanup_temporary(root, path)) is not None
        ]
        if cleanup_errors:
            raise ProjectStatusError(
                "transaction staging failed and temporary cleanup failed: "
                + "; ".join(cleanup_errors)
            ) from exc
        if not isinstance(exc, Exception):
            raise
        if isinstance(exc, ProjectStatusError):
            raise
        raise ProjectStatusError("cannot stage project-status transaction") from exc

    try:
        for item in pending:
            _, current = _read_stable_bytes(root, item.target)
            if current != item.original:
                raise ProjectStatusError(
                    f"target changed before transaction commit: {item.target}"
                )
            replacer(item.staged, item.target)
            actual, _ = _read_stable_bytes(root, item.target)
            if actual != item.expected_bytes:
                raise ProjectStatusError(
                    f"committed bytes differ for {item.target}"
                )
    except BaseException as commit_error:
        cleanup_errors = [
            error
            for item in pending
            if (error := _cleanup_temporary(root, item.staged)) is not None
        ]
        if cleanup_errors:
            raise ProjectStatusError(
                "project-status multi-file commit failed; no automatic rollback was "
                "attempted and temporary cleanup was incomplete: "
                + "; ".join(cleanup_errors)
            ) from commit_error
        if not isinstance(commit_error, Exception):
            raise commit_error
        raise ProjectStatusError(
            "project-status multi-file commit failed; no automatic rollback was "
            "attempted because no portable atomic CAS exists. Inspect the partial "
            "outputs and rerun --write"
        ) from commit_error

    for item in pending:
        actual, _ = _read_stable_bytes(root, item.target)
        if actual != item.expected_bytes:
            raise ProjectStatusError(f"post-commit verification failed: {item.target}")


def _check(root: Path, rendered: Mapping[Path, bytes]) -> list[Path]:
    stale: list[Path] = []
    for path, expected in rendered.items():
        actual, _ = _read_stable_bytes(root, path)
        if actual != expected:
            stale.append(path)
    return stale


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        rendered = build_rendered_files()
        if arguments.check:
            stale = _check(_ROOT, rendered)
            if stale:
                for path in stale:
                    print(f"stale generated project status: {path.relative_to(_ROOT)}")
                return 1
            print("project status is consistent")
            return 0
        _write_transaction(_ROOT, rendered)
        print(f"rendered {len(rendered)} project-status documents")
        return 0
    except ProjectStatusError as exc:
        print(f"project status error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
