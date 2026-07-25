# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Collect a bounded, unsigned window of GitHub repository-control API bodies.

The collector is intentionally a transport recorder, not a verifier.  Its plan
contains exactly 19 ordered observation definitions/endpoints.  A paginated
observation can issue multiple bounded GET page requests, so 19 observations do
not imply 19 HTTP calls.  It retains parsed JSON page bodies and deterministic
canonical JSON, but does not derive protection claims, mutate GitHub state, or
sign the result.  From ``gh api --include`` it retains only validated HTTP
status and Link values; every other response header is discarded before the
evidence layer.

The observed window is non-atomic: repository controls can change between page
requests and between endpoints.  ``pagination.complete`` means validated Link
traversal reached its terminal page (with count checks where GitHub reports a
total); it never means all controls were observed simultaneously.

The execution boundary assumes a trusted operator host and trusted, absolute
PATH directories outside the repository and current working directory.
Pre/post identity and SHA-256 checks detect a persistent ``gh`` executable
change; they are not an atomic execution pin and do not defend against a
privileged hostile host that swaps and restores bytes during process creation.

Output uses exclusive creation and rejects observed link-like paths, but assumes
its parent directory is trusted and non-concurrently mutated.  It is not a
race-safe writer against an attacker replacing parent path components.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

FORMAT = "EVOGUARD_REPOSITORY_CONTROL_OBSERVATION_V2"
GITHUB_API_VERSION = "2022-11-28"
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_API_PAGE_BYTES = MAX_OUTPUT_BYTES
MAX_HTTP_HEADER_BYTES = 64 * 1024
MAX_INCLUDED_RESPONSE_BYTES = MAX_API_PAGE_BYTES + MAX_HTTP_HEADER_BYTES
MAX_GH_EXECUTABLE_BYTES = 256 * 1024 * 1024
GH_API_TIMEOUT_SECONDS = 60.0
GH_TREE_CLEANUP_TIMEOUT_SECONDS = 10.0
MAX_PAGES = 1024
PER_PAGE = 100
ROOT = Path(__file__).resolve().parents[2]
EXPECTED_REPOSITORY_ID = 1293651176
EXPECTED_REPOSITORY_OWNER_ID = 231647061

ENVIRONMENTS = (
    ("source", "evoguard-release-source-v2"),
    ("artifact", "evoguard-release-artifact-v1"),
    ("draft", "evoguard-release-draft"),
    ("publication", "evoguard-release-publication"),
)
ACTIVATION_VARIABLES = (
    "EVOGUARD_RELEASE_SOURCE_V2_ENABLED",
    "EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1_ENABLED",
    "EVOGUARD_RELEASE_PUBLICATION_ENABLED",
)

_REPOSITORY = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?\Z"
)
_CANONICAL_UTC = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z"
)
_FORBIDDEN_HEADER_KEYS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "headers",
        "request-headers",
        "response-headers",
    }
)
_HTTP_STATUS_LINE = re.compile(rb"HTTP/[0-9](?:\.[0-9])? ([0-9]{3})(?: [^\r\n]*)?\Z")
_HTTP_HEADER_NAME = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_LINK_ENTRY = re.compile(r'\s*<([^<>\s]+)>\s*;\s*rel="([^"]+)"\s*(?:,|\Z)')
_WINDOWS_RESERVED_COMPONENT = re.compile(
    r"(?i)(?:CON|PRN|AUX|NUL|CLOCK\$|COM[1-9¹²³]|LPT[1-9¹²³]|"
    r"CONIN\$|CONOUT\$)(?:\..*)?\Z"
)


class CollectionError(ValueError):
    """The requested observation could not be collected completely and safely."""


@dataclass(frozen=True)
class ApiResponse:
    """A testable API-runner result.

    Only the response status and validated ``Link`` header survive ``--include``
    parsing.  Authorization, Cookie, and every other response header are never
    returned to the evidence layer.
    """

    body: bytes
    status: int = 200
    link_header: str | None = None


@dataclass(frozen=True)
class _ExecutableSnapshot:
    path: Path
    identity: tuple[int, int, int, int, int]
    sha256: str


ApiRunner = Callable[[str, str, Mapping[str, int | str]], ApiResponse]
Clock = Callable[[], datetime]


@dataclass(frozen=True)
class _ObservationSpec:
    name: str
    endpoint: str
    pagination: str = "single"
    items_field: str | None = None
    identity_field: str | None = None
    total_field: str | None = None
    expected_variable: str | None = None


def _fail(message: str) -> NoReturn:
    raise CollectionError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail(f"duplicate JSON key in GitHub response: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> NoReturn:
    _fail(f"non-finite JSON constant in GitHub response: {value}")


def _check_unicode_scalars(value: Any, *, label: str = "GitHub response") -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            _fail(f"{label} contains a non-canonical Unicode surrogate")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _check_unicode_scalars(item, label=f"{label}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _check_unicode_scalars(key, label=f"{label} key")
            _check_unicode_scalars(item, label=f"{label}.{key}")


def _reject_header_material(value: Any, *, label: str = "GitHub response") -> None:
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_header_material(item, label=f"{label}[{index}]")
        return
    if not isinstance(value, dict):
        return
    for key, item in value.items():
        normalized = key.strip().lower().replace("_", "-")
        if normalized in _FORBIDDEN_HEADER_KEYS:
            _fail(f"{label} contains forbidden HTTP-header material")
        _reject_header_material(item, label=f"{label}.{key}")


def _load_response(data: bytes, *, label: str) -> Any:
    if len(data) > MAX_API_PAGE_BYTES:
        _fail(f"{label} exceeds the one-MiB response bound")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CollectionError(f"{label} is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise CollectionError(f"{label} is not strict JSON") from exc
    _check_unicode_scalars(value, label=label)
    _reject_header_material(value, label=label)
    return value


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Serialize one observation using the repository's canonical JSON form."""

    try:
        data = (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CollectionError("observation is not canonical JSON data") from exc
    if len(data) > MAX_OUTPUT_BYTES:
        _fail("canonical observation exceeds one MiB")
    return data


def _format_utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        _fail("collector clock must return a timezone-aware datetime")
    rendered = value.astimezone(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    if _CANONICAL_UTC.fullmatch(rendered) is None:
        _fail("collector clock did not produce canonical UTC")
    return rendered


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_repository(repository: str) -> str:
    if _REPOSITORY.fullmatch(repository) is None:
        _fail("repository must be canonical OWNER/REPO without URL, .git, or whitespace")
    owner, name = repository.split("/", 1)
    if owner.endswith("-") or name.endswith(".") or name.lower().endswith(".git"):
        _fail("repository must be canonical OWNER/REPO")
    return repository


def _validate_ruleset_id(ruleset_id: int) -> int:
    if (
        isinstance(ruleset_id, bool)
        or not isinstance(ruleset_id, int)
        or ruleset_id <= 0
        or ruleset_id > (2**63 - 1)
    ):
        _fail("ruleset ID must be a positive canonical 64-bit integer")
    return ruleset_id


def _validate_github_id(value: Any, *, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > (2**63 - 1)
    ):
        _fail(f"{label} must be a positive canonical 64-bit integer")
    return value


def _parse_positive_id(value: str) -> int:
    if re.fullmatch(r"[1-9][0-9]*", value) is None:
        raise argparse.ArgumentTypeError(
            "ID must be a positive decimal integer without leading zeroes"
        )
    parsed = int(value)
    if parsed > (2**63 - 1):
        raise argparse.ArgumentTypeError("ID exceeds the 64-bit bound")
    return parsed


def _parse_output_path(value: str) -> Path:
    try:
        _validate_windows_path_syntax(value, label="output path")
    except CollectionError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return Path(value)


def _specs(repository: str, ruleset_id: int) -> tuple[_ObservationSpec, ...]:
    base = f"/repos/{repository}"
    specs: list[_ObservationSpec] = [
        _ObservationSpec("repository-metadata", base),
        _ObservationSpec("main-ref", f"{base}/git/ref/heads/main"),
        _ObservationSpec("main-protection", f"{base}/branches/main/protection"),
        _ObservationSpec("actions-permissions", f"{base}/actions/permissions"),
        _ObservationSpec(
            "workflow-permissions", f"{base}/actions/permissions/workflow"
        ),
        _ObservationSpec("immutable-releases", f"{base}/immutable-releases"),
        _ObservationSpec("tag-ruleset", f"{base}/rulesets/{ruleset_id}"),
        _ObservationSpec(
            "deploy-keys",
            f"{base}/keys",
            pagination="array",
            identity_field="id",
        ),
        _ObservationSpec(
            "environments",
            f"{base}/environments",
            pagination="object",
            items_field="environments",
            identity_field="id",
            total_field="total_count",
        ),
    ]
    specs.extend(
        _ObservationSpec(
            f"{role}-deployment-branch-policies",
            f"{base}/environments/{environment}/deployment-branch-policies",
            pagination="object",
            items_field="branch_policies",
            identity_field="id",
            total_field="total_count",
        )
        for role, environment in ENVIRONMENTS
    )
    specs.extend(
        _ObservationSpec(
            f"activation-variable-{index}",
            f"{base}/actions/variables/{name}",
            expected_variable=name,
        )
        for index, name in enumerate(ACTIVATION_VARIABLES, start=1)
    )
    specs.append(
        _ObservationSpec(
            "post-h-repository-secrets",
            f"{base}/actions/secrets",
            pagination="object",
            items_field="secrets",
            identity_field="name",
            total_field="total_count",
        )
    )
    specs.extend(
        _ObservationSpec(
            f"post-h-{role}-environment-secrets",
            f"{base}/environments/{environment}/secrets",
            pagination="object",
            items_field="secrets",
            identity_field="name",
            total_field="total_count",
        )
        for role, environment in ENVIRONMENTS[:2]
    )
    if len(specs) != 19 or len({spec.name for spec in specs}) != 19:
        _fail("internal observation plan is not the frozen 19-entry contract")
    if len({spec.endpoint for spec in specs}) != 19:
        _fail("internal observation plan contains duplicate endpoints")
    return tuple(specs)


def _path_within(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath(
            (os.path.normcase(str(path)), os.path.normcase(str(root)))
        ) == os.path.normcase(str(root))
    except ValueError:
        return False


def _paths_overlap(first: Path, second: Path) -> bool:
    return _path_within(first, second) or _path_within(second, first)


def _validate_windows_path_syntax(path: Path | str, *, label: str) -> None:
    """Reject Win32 aliases and names that can resolve unlike their spelling."""

    if os.name != "nt":
        return
    raw = str(path)
    lowered = raw.lower()
    if lowered.startswith(("\\\\?\\", "\\\\.\\", "\\??\\")) or raw.startswith("\\\\"):
        _fail(f"{label} uses a device, extended, or UNC path alias")
    drive, tail = os.path.splitdrive(raw)
    if ":" in tail:
        _fail(f"{label} contains an NTFS alternate data stream")
    for component in re.split(r"[\\/]", tail):
        if not component:
            continue
        if component in {".", ".."}:
            _fail(f"{label} contains a relative path component")
        if component.endswith((" ", ".")):
            _fail(f"{label} contains a trailing dot or space")
        if "~" in component:
            _fail(f"{label} contains a possible 8.3 path alias")
        if _WINDOWS_RESERVED_COMPONENT.fullmatch(component) is not None:
            _fail(f"{label} contains a reserved Win32 name")
    if drive and re.fullmatch(r"[A-Za-z]:", drive) is None:
        _fail(f"{label} has a non-canonical drive prefix")


def _windows_final_path(path: Path, *, label: str) -> Path:
    """Return the DOS final path of an existing object, rejecting aliases."""

    if os.name != "nt":
        return Path(os.path.abspath(path))
    _validate_windows_path_syntax(path, label=label)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create_file.restype = ctypes.c_void_p
    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    get_final_path.restype = ctypes.c_uint32
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    handle = create_file(
        str(path),
        0,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x02000000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle in {None, invalid_handle}:
        raise CollectionError(f"cannot open {label} for final-path validation")
    try:
        size = get_final_path(handle, None, 0, 0)
        if size == 0 or size > 32768:
            _fail(f"cannot obtain a bounded final path for {label}")
        buffer = ctypes.create_unicode_buffer(size + 1)
        written = get_final_path(handle, buffer, len(buffer), 0)
        if written == 0 or written >= len(buffer):
            _fail(f"cannot obtain the final path for {label}")
        raw_final = buffer.value
    finally:
        close_handle(handle)
    if raw_final.lower().startswith("\\\\?\\unc\\"):
        _fail(f"{label} resolves through a UNC path")
    if not raw_final.lower().startswith("\\\\?\\"):
        _fail(f"{label} has a non-DOS final path")
    final = Path(raw_final[4:])
    _validate_windows_path_syntax(final, label=f"{label} final path")
    requested = os.path.normcase(os.path.normpath(os.path.abspath(path)))
    canonical = os.path.normcase(os.path.normpath(str(final)))
    if requested != canonical:
        _fail(f"{label} spelling is not its canonical final path")
    return final


def _require_no_link_ancestry(path: Path, *, label: str) -> None:
    current = path
    while True:
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise CollectionError(f"cannot inspect {label} ancestry") from exc
        if _is_link_like(metadata):
            _fail(f"{label} ancestry contains a link-like path")
        parent = current.parent
        if parent == current:
            return
        current = parent


def _executable_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_nlink,
    )


def _snapshot_gh_executable(path: Path) -> _ExecutableSnapshot:
    path = _windows_final_path(path, label="resolved GitHub CLI")
    try:
        before = path.lstat()
    except OSError as exc:
        raise CollectionError("cannot inspect the resolved GitHub CLI") from exc
    if (
        _is_link_like(before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size <= 0
        or before.st_size > MAX_GH_EXECUTABLE_BYTES
    ):
        _fail("resolved GitHub CLI is not a bounded non-link regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CollectionError("cannot open the resolved GitHub CLI") from exc
    try:
        opened = os.fstat(descriptor)
        if _executable_identity(opened) != _executable_identity(before):
            _fail("resolved GitHub CLI changed before hashing")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_GH_EXECUTABLE_BYTES:
                _fail("resolved GitHub CLI exceeds its byte bound")
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        _executable_identity(after) != _executable_identity(before)
        or total != before.st_size
    ):
        _fail("resolved GitHub CLI changed while hashing")
    return _ExecutableSnapshot(
        path=path,
        identity=_executable_identity(before),
        sha256=digest.hexdigest(),
    )


def _resolve_gh_executable() -> _ExecutableSnapshot:
    path_value = os.environ.get("PATH")
    if not path_value:
        _fail("PATH is unavailable for absolute GitHub CLI resolution")
    names = ("gh.exe",) if os.name == "nt" else ("gh",)
    cwd = _windows_final_path(Path.cwd(), label="current working directory")
    repository_root = _windows_final_path(ROOT, label="repository root")
    for raw_directory in path_value.split(os.pathsep):
        raw_directory = raw_directory.strip()
        if len(raw_directory) >= 2 and raw_directory[0] == raw_directory[-1] == '"':
            raw_directory = raw_directory[1:-1]
        if not raw_directory:
            continue
        candidate_directory = Path(raw_directory)
        if not candidate_directory.is_absolute():
            continue
        directory = Path(os.path.abspath(candidate_directory))
        try:
            directory = _windows_final_path(
                directory, label="GitHub CLI PATH directory"
            )
        except CollectionError:
            continue
        if _paths_overlap(directory, cwd) or _paths_overlap(
            directory, repository_root
        ):
            continue
        try:
            _require_no_link_ancestry(directory, label="GitHub CLI PATH directory")
        except CollectionError:
            continue
        for name in names:
            candidate = directory / name
            try:
                snapshot = _snapshot_gh_executable(candidate)
            except CollectionError:
                continue
            if _paths_overlap(snapshot.path.parent, cwd) or _paths_overlap(
                snapshot.path.parent, repository_root
            ):
                continue
            if not os.access(candidate, os.X_OK):
                continue
            return snapshot
    _fail("no safe absolute GitHub CLI executable was found on PATH")


def _parse_included_response(data: bytes) -> ApiResponse:
    if len(data) > MAX_INCLUDED_RESPONSE_BYTES:
        _fail("GitHub included response exceeds its total byte bound")
    search = data[: MAX_HTTP_HEADER_BYTES + 4]
    separator = b"\r\n\r\n"
    offset = search.find(separator)
    if offset < 0:
        separator = b"\n\n"
        offset = search.find(separator)
    if offset < 0:
        _fail("GitHub included response has no bounded HTTP header block")
    header_block = data[:offset]
    body = data[offset + len(separator) :]
    if len(header_block) > MAX_HTTP_HEADER_BYTES:
        _fail("GitHub HTTP header block exceeds its byte bound")
    # GitHub CLI currently emits the HTTP/2 status line with LF and the
    # remaining header lines with CRLF on Windows. ``splitlines`` accepts that
    # transport quirk without retaining line-ending bytes in evidence.
    lines = header_block.splitlines()
    if not lines or _HTTP_STATUS_LINE.fullmatch(lines[0]) is None:
        _fail("GitHub included response has no canonical HTTP status line")
    match = _HTTP_STATUS_LINE.fullmatch(lines[0])
    assert match is not None
    status = int(match.group(1))
    link_header: str | None = None
    for line in lines[1:]:
        if not line or line.startswith((b" ", b"\t")) or b":" not in line:
            _fail("GitHub included response has a malformed HTTP header")
        raw_name, raw_value = line.split(b":", 1)
        if _HTTP_HEADER_NAME.fullmatch(raw_name) is None:
            _fail("GitHub included response has a non-canonical HTTP header name")
        name = raw_name.decode("ascii").lower()
        normalized = name.replace("_", "-")
        if normalized in _FORBIDDEN_HEADER_KEYS:
            _fail("GitHub response contains forbidden sensitive header material")
        if name == "link":
            if link_header is not None:
                _fail("GitHub response contains duplicate Link headers")
            try:
                link_header = raw_value.strip().decode("ascii")
            except UnicodeDecodeError as exc:
                raise CollectionError("GitHub Link header is not ASCII") from exc
            if not link_header or len(link_header) > 16 * 1024:
                _fail("GitHub Link header is empty or oversized")
    if len(body) > MAX_API_PAGE_BYTES:
        _fail("GitHub API response body exceeds one MiB")
    return ApiResponse(body=body, status=status, link_header=link_header)


@dataclass
class _BoundedReadState:
    data: bytes | None = None
    error: Exception | None = None


def _windows_system_directory() -> Path:
    """Resolve System32 from the kernel, never from caller-controlled env."""

    if os.name != "nt":
        _fail("Windows system directory requested on a non-Windows host")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_system_directory = kernel32.GetSystemDirectoryW
    get_system_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    get_system_directory.restype = ctypes.c_uint32
    capacity = 32768
    buffer = ctypes.create_unicode_buffer(capacity)
    written = get_system_directory(buffer, capacity)
    if written == 0 or written >= capacity:
        _fail("cannot resolve the bounded Windows system directory")
    directory = Path(buffer.value)
    if not directory.is_absolute():
        _fail("Windows system directory is not absolute")
    return _windows_final_path(directory, label="Windows system directory")


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Best-effort bounded cleanup for the isolated ``gh`` process tree."""

    if os.name == "nt":
        try:
            system_directory = _windows_system_directory()
            taskkill = system_directory / "taskkill.exe"
            before = _snapshot_gh_executable(taskkill)
            windows_root = system_directory.parent
            subprocess.run(
                [
                    str(before.path),
                    "/PID",
                    str(process.pid),
                    "/T",
                    "/F",
                ],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=system_directory,
                env={
                    "PATH": str(system_directory),
                    "SystemRoot": str(windows_root),
                    "WINDIR": str(windows_root),
                },
                timeout=GH_TREE_CLEANUP_TIMEOUT_SECONDS,
            )
            after = _snapshot_gh_executable(taskkill)
            if before.identity != after.identity or before.sha256 != after.sha256:
                _fail("Windows process-tree cleanup helper changed during execution")
        except (OSError, subprocess.SubprocessError, CollectionError):
            pass
    else:
        try:
            kill_group = getattr(os, "killpg", None)
            if kill_group is not None:
                kill_group(process.pid, getattr(signal, "SIGKILL", 9))
        except OSError:
            pass
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=GH_TREE_CLEANUP_TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError):
        pass


def _bounded_process_output(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
) -> tuple[bytes, int]:
    assert process.stdout is not None
    stdout = process.stdout
    state = _BoundedReadState()

    def read_stdout() -> None:
        try:
            state.data = stdout.read(MAX_INCLUDED_RESPONSE_BYTES + 1)
        except Exception as exc:
            state.error = exc

    reader = threading.Thread(
        target=read_stdout,
        name="evoguard-gh-bounded-stdout",
        daemon=True,
    )
    reader.start()
    reader.join(max(0.0, deadline - time.monotonic()))
    if reader.is_alive():
        _terminate_process_tree(process)
        reader.join(GH_TREE_CLEANUP_TIMEOUT_SECONDS)
        _fail("GitHub API request exceeded its bounded timeout")
    if state.error is not None:
        _terminate_process_tree(process)
        raise CollectionError("cannot read the bounded GitHub included response") from (
            state.error
        )
    if state.data is None:
        _terminate_process_tree(process)
        _fail("GitHub bounded stdout reader produced no result")
    included = state.data
    if len(included) > MAX_INCLUDED_RESPONSE_BYTES:
        _terminate_process_tree(process)
        _fail("GitHub included response exceeds its total byte bound")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        _terminate_process_tree(process)
        _fail("GitHub API request exceeded its bounded timeout")
    try:
        return_code = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as exc:
        _terminate_process_tree(process)
        raise CollectionError("GitHub API request exceeded its bounded timeout") from exc
    return included, return_code


def _run_gh_api(
    method: str, endpoint: str, query: Mapping[str, int | str]
) -> ApiResponse:
    if method != "GET":
        _fail("collector attempted a non-GET GitHub operation")
    executable = _resolve_gh_executable()
    command = [
        str(executable.path),
        "api",
        "--method",
        "GET",
        "--hostname",
        "github.com",
        "--include",
        "-H",
        "Accept: application/vnd.github+json",
        "-H",
        f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
        endpoint,
    ]
    for key in sorted(query):
        value = query[key]
        if not isinstance(key, str) or not isinstance(value, (int, str)):
            _fail("collector attempted a non-canonical GitHub query")
        command.extend(("-f", f"{key}={value}"))
    environment = os.environ.copy()
    for key in ("GH_DEBUG", "DEBUG", "ACTIONS_STEP_DEBUG"):
        environment.pop(key, None)
    environment.update(
        {
            "GH_PROMPT_DISABLED": "1",
            "NO_COLOR": "1",
            "PATH": str(executable.path.parent),
        }
    )
    try:
        if (
            not isinstance(GH_API_TIMEOUT_SECONDS, (int, float))
            or not math.isfinite(GH_API_TIMEOUT_SECONDS)
            or GH_API_TIMEOUT_SECONDS <= 0
        ):
            _fail("GitHub API timeout configuration is not positive and finite")
        deadline = time.monotonic() + GH_API_TIMEOUT_SECONDS
        try:
            if os.name == "nt":
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    cwd=executable.path.parent,
                    env=environment,
                    creationflags=getattr(
                        subprocess, "CREATE_NEW_PROCESS_GROUP", 0
                    ),
                )
            else:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    cwd=executable.path.parent,
                    env=environment,
                    start_new_session=True,
                )
        except OSError as exc:
            raise CollectionError("cannot start the pinned GitHub CLI") from exc
        included, return_code = _bounded_process_output(
            process,
            deadline=deadline,
        )
        try:
            response = _parse_included_response(included)
        except CollectionError as exc:
            if return_code != 0:
                raise CollectionError(
                    f"GitHub CLI failed GET {endpoint} without a complete HTTP response"
                ) from exc
            raise
        if return_code != 0 and 200 <= response.status < 400:
            _fail("GitHub CLI failed despite a successful HTTP response")
        return response
    finally:
        current = _snapshot_gh_executable(executable.path)
        if (
            current.identity != executable.identity
            or current.sha256 != executable.sha256
        ):
            _fail("GitHub CLI identity or bytes changed during API invocation")


def _invoke(
    runner: ApiRunner,
    endpoint: str,
    query: Mapping[str, int | str],
    *,
    label: str,
) -> tuple[Any, ApiResponse]:
    try:
        response = runner("GET", endpoint, dict(query))
    except CollectionError:
        raise
    except Exception as exc:
        raise CollectionError(f"{label} API runner failed") from exc
    if not isinstance(response, ApiResponse):
        _fail(f"{label} API runner returned a non-canonical response")
    if (
        isinstance(response.status, bool)
        or not isinstance(response.status, int)
        or response.status != 200
    ):
        _fail(f"{label} was denied or incomplete (HTTP status is not 200)")
    if not isinstance(response.body, bytes):
        _fail(f"{label} API body is not bytes")
    if response.link_header is not None:
        if (
            not isinstance(response.link_header, str)
            or not response.link_header
            or len(response.link_header) > 16 * 1024
            or any(ord(character) < 0x20 for character in response.link_header)
            or any(
                0xD800 <= ord(character) <= 0xDFFF
                for character in response.link_header
            )
        ):
            _fail(f"{label} API Link header is not canonical")
    return _load_response(response.body, label=label), response


def _link_paths(endpoint: str, repository_id: int) -> set[str]:
    parts = endpoint.split("/")
    if len(parts) < 5 or parts[:2] != ["", "repos"]:
        _fail("internal endpoint cannot be bound to a GitHub Link header")
    suffix = "/" + "/".join(parts[4:])
    return {
        endpoint,
        f"/repositories/{repository_id}{suffix}",
    }


def _link_relations(
    link_header: str | None,
    *,
    endpoint: str,
    page_number: int,
    repository_id: int,
    expected_last_page: int | None = None,
) -> tuple[set[str], int | None]:
    if link_header is None:
        return set(), expected_last_page
    relations: set[str] = set()
    linked_pages: dict[str, int] = {}
    position = 0
    allowed_paths = _link_paths(endpoint, repository_id)
    for match in _LINK_ENTRY.finditer(link_header):
        if match.start() != position:
            _fail("GitHub Link header has non-canonical syntax")
        position = match.end()
        url, relation_text = match.groups()
        relation_parts = relation_text.split()
        if len(relation_parts) != 1:
            _fail("GitHub Link header relation is not singular")
        relation = relation_parts[0]
        if relation not in {"next", "prev", "first", "last"}:
            _fail("GitHub Link header contains an unknown relation")
        if relation in relations:
            _fail("GitHub Link header contains a duplicate relation")
        relations.add(relation)
        prefix = "https://api.github.com"
        if not url.startswith(prefix):
            _fail("GitHub Link header URL is outside the exact API endpoint")
        target = url[len(prefix) :]
        if target.count("?") != 1:
            _fail("GitHub Link header query is not exact")
        raw_path, raw_query = target.split("?", 1)
        if raw_path not in allowed_paths:
            _fail("GitHub Link header URL is outside the exact API endpoint")
        query_match = re.fullmatch(
            rf"page=([1-9][0-9]*)&per_page={PER_PAGE}",
            raw_query,
            flags=re.ASCII,
        )
        if query_match is None:
            _fail("GitHub Link header pagination values are not canonical")
        page_text = query_match.group(1)
        linked_page = int(page_text)
        linked_pages[relation] = linked_page
        if relation == "next" and linked_page != page_number + 1:
            _fail("GitHub Link next relation skips or repeats a page")
        if relation == "prev" and (
            page_number <= 1 or linked_page != page_number - 1
        ):
            _fail("GitHub Link prev relation is inconsistent")
        if relation == "first" and linked_page != 1:
            _fail("GitHub Link first relation is inconsistent")
        if relation == "last" and linked_page < page_number:
            _fail("GitHub Link last relation is inconsistent")
    if position != len(link_header):
        _fail("GitHub Link header has trailing non-canonical syntax")
    if not relations:
        _fail("GitHub Link header contains no relations")
    next_page = linked_pages.get("next")
    last_page = linked_pages.get("last")
    if next_page is not None:
        if last_page is None:
            _fail("GitHub Link next relation has no last-page bound")
        if last_page < next_page:
            _fail("GitHub Link last relation precedes its next relation")
    elif last_page is not None and last_page != page_number:
        _fail("terminal GitHub Link last relation is not the current page")
    stable_last_page: int | None
    if expected_last_page is not None:
        if last_page is not None and last_page != expected_last_page:
            _fail("GitHub Link last relation changed during pagination")
        if page_number > expected_last_page:
            _fail("GitHub pagination advanced beyond its stable last page")
        stable_last_page = expected_last_page
    else:
        stable_last_page = last_page
    return relations, stable_last_page


def _require_object(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} root must be an object")
    if "message" in value and len(value) <= 4:
        _fail(f"{label} looks like a denied GitHub error body")
    return value


def _repository_metadata_identity(
    body: Mapping[str, Any],
    *,
    repository: str,
) -> tuple[int, int]:
    owner = body.get("owner")
    expected_owner = repository.split("/", 1)[0]
    if (
        body.get("full_name") != repository
        or body.get("private") is not False
        or body.get("visibility") != "public"
        or not isinstance(owner, dict)
        or owner.get("login") != expected_owner
        or owner.get("type") != "User"
    ):
        _fail("repository-metadata response is not the exact requested repository")
    repository_id = _validate_github_id(body.get("id"), label="repository API ID")
    repository_owner_id = _validate_github_id(
        owner.get("id"), label="repository owner API ID"
    )
    if (
        repository_id != EXPECTED_REPOSITORY_ID
        or repository_owner_id != EXPECTED_REPOSITORY_OWNER_ID
    ):
        _fail("repository-metadata response changed the trusted namespace identity")
    return repository_id, repository_owner_id


def _validate_single_body(
    spec: _ObservationSpec,
    value: Any,
    *,
    repository: str,
    ruleset_id: int,
) -> None:
    body = _require_object(value, label=spec.name)
    if spec.name == "repository-metadata":
        _repository_metadata_identity(body, repository=repository)
    elif spec.name == "main-ref":
        target = body.get("object")
        if (
            body.get("ref") != "refs/heads/main"
            or not isinstance(target, dict)
            or target.get("type") != "commit"
            or not isinstance(target.get("sha"), str)
            or re.fullmatch(r"[0-9a-f]{40}", target["sha"]) is None
        ):
            _fail("main-ref response is not bound to refs/heads/main and one Git commit")
    elif spec.name == "main-protection":
        required = {
            "required_status_checks",
            "enforce_admins",
            "required_pull_request_reviews",
        }
        if not required.issubset(body):
            _fail("main-protection response is not a complete branch-protection body")
    elif spec.name == "actions-permissions":
        if (
            not isinstance(body.get("enabled"), bool)
            or body.get("allowed_actions") not in {"all", "local_only", "selected"}
        ):
            _fail("actions-permissions response is not canonical")
    elif spec.name == "workflow-permissions":
        if (
            body.get("default_workflow_permissions") not in {"read", "write"}
            or not isinstance(body.get("can_approve_pull_request_reviews"), bool)
        ):
            _fail("workflow-permissions response is not canonical")
    elif spec.name == "immutable-releases":
        if (
            body.get("enabled") is not True
            or not isinstance(body.get("enforced_by_owner"), bool)
        ):
            _fail("immutable-releases response does not prove the enabled endpoint")
    elif spec.name == "tag-ruleset":
        if (
            body.get("id") != ruleset_id
            or body.get("target") != "tag"
            or body.get("enforcement") not in {"active", "evaluate", "disabled"}
        ):
            _fail("tag-ruleset response is not bound to the recorded tag ruleset")
    elif spec.expected_variable is not None:
        if (
            body.get("name") != spec.expected_variable
            or not isinstance(body.get("value"), str)
        ):
            _fail(f"{spec.name} response is not the exact activation variable")


def _item_identity(item: Any, field: str, *, label: str) -> tuple[str, int | str]:
    if not isinstance(item, dict):
        _fail(f"{label} item must be an object")
    identity = item.get(field)
    if isinstance(identity, bool) or not isinstance(identity, (int, str)):
        _fail(f"{label} item has no canonical {field} identity")
    if isinstance(identity, str) and not identity:
        _fail(f"{label} item has an empty {field} identity")
    return type(identity).__name__, identity


def _collect_single(
    spec: _ObservationSpec,
    *,
    runner: ApiRunner,
    repository: str,
    ruleset_id: int,
    observed_utc: str,
) -> dict[str, Any]:
    value, response = _invoke(runner, spec.endpoint, {}, label=spec.name)
    if response.link_header is not None:
        _fail(f"{spec.name} returned a Link header for a non-paginated endpoint")
    _validate_single_body(
        spec,
        value,
        repository=repository,
        ruleset_id=ruleset_id,
    )
    return {
        "endpoint": spec.endpoint,
        "method": "GET",
        "name": spec.name,
        "observed_utc": observed_utc,
        "pages": [
            {
                "body": value,
                "http_status": response.status,
                "link_header": response.link_header,
                "number": 1,
                "query": {},
            }
        ],
        "pagination": {
            "completion_basis": "single-successful-response",
            "complete": True,
            "kind": "single",
            "observed_item_count": None,
            "page_count": 1,
            "per_page": None,
            "reported_total_count": None,
            "termination": "single-response",
        },
        "query": {},
    }


def _collect_paginated(
    spec: _ObservationSpec,
    *,
    runner: ApiRunner,
    repository_id: int,
    observed_utc: str,
) -> dict[str, Any]:
    pages: list[dict[str, Any]] = []
    identities: set[tuple[str, int | str]] = set()
    reported_total: int | None = None
    linked_last_page: int | None = None
    termination: str | None = None

    for page_number in range(1, MAX_PAGES + 1):
        query = {"page": page_number, "per_page": PER_PAGE}
        value, response = _invoke(
            runner,
            spec.endpoint,
            query,
            label=f"{spec.name} page {page_number}",
        )
        relations, linked_last_page = _link_relations(
            response.link_header,
            endpoint=spec.endpoint,
            page_number=page_number,
            repository_id=repository_id,
            expected_last_page=linked_last_page,
        )
        has_next = "next" in relations
        if (
            not has_next
            and linked_last_page is not None
            and page_number != linked_last_page
        ):
            _fail(f"{spec.name} Link terminated before its stable last page")
        if spec.pagination == "array":
            if not isinstance(value, list):
                _fail(f"{spec.name} page {page_number} root must be an array")
            items = value
        else:
            body = _require_object(value, label=f"{spec.name} page {page_number}")
            assert spec.items_field is not None
            assert spec.total_field is not None
            candidate_items = body.get(spec.items_field)
            total = body.get(spec.total_field)
            if not isinstance(candidate_items, list):
                _fail(
                    f"{spec.name} page {page_number} has no {spec.items_field} array"
                )
            items = candidate_items
            if isinstance(total, bool) or not isinstance(total, int) or total < 0:
                _fail(
                    f"{spec.name} page {page_number} has no canonical "
                    f"{spec.total_field}"
                )
            if reported_total is None:
                reported_total = total
            elif total != reported_total:
                _fail(f"{spec.name} total count changed during pagination")
        if len(items) > PER_PAGE:
            _fail(f"{spec.name} page {page_number} exceeds per_page")
        assert spec.identity_field is not None
        for item in items:
            identity = _item_identity(
                item,
                spec.identity_field,
                label=f"{spec.name} page {page_number}",
            )
            if identity in identities:
                _fail(f"{spec.name} contains a duplicate paginated item")
            identities.add(identity)
        pages.append(
            {
                "body": value,
                "http_status": response.status,
                "link_header": response.link_header,
                "number": page_number,
                "query": dict(query),
            }
        )
        canonical_json_bytes({"pages": pages})

        if spec.pagination == "array":
            if not has_next:
                termination = "link-terminal"
                break
        else:
            assert reported_total is not None
            observed_count = len(identities)
            if observed_count > reported_total:
                _fail(f"{spec.name} contains more items than its reported total")
            if observed_count == reported_total:
                if has_next:
                    _fail(f"{spec.name} Link continues beyond its reported total")
                termination = "reported-total-link-terminal"
                break
            if not has_next:
                _fail(f"{spec.name} Link ended before its reported total")
    else:
        _fail(f"{spec.name} pagination exceeds the page bound")

    if termination is None:
        _fail(f"{spec.name} pagination is incomplete")
    return {
        "endpoint": spec.endpoint,
        "method": "GET",
        "name": spec.name,
        "observed_utc": observed_utc,
        "pages": pages,
        "pagination": {
            "completion_basis": "validated-link-traversal",
            "complete": True,
            "kind": "page-number",
            "link_complete": True,
            "linked_last_page": linked_last_page,
            "observed_item_count": len(identities),
            "page_count": len(pages),
            "per_page": PER_PAGE,
            "reported_total_count": reported_total,
            "termination": termination,
        },
        "query": {"per_page": PER_PAGE},
    }


def collect(
    repository: str,
    ruleset_id: int,
    *,
    api_runner: ApiRunner = _run_gh_api,
    clock: Clock = _now,
) -> dict[str, Any]:
    """Collect the frozen unsigned V2 observation document in memory."""

    repository = _validate_repository(repository)
    ruleset_id = _validate_ruleset_id(ruleset_id)
    started_utc = _format_utc(clock())
    observations: list[dict[str, Any]] = []
    document: dict[str, Any] = {
        "collector": {
            "name": "evoguard-release-ledger",
            "version": "2",
        },
        "evidence_boundary": (
            "owner-collected-bounded-window-github-api-observation"
        ),
        "format": FORMAT,
        "github_api_version": GITHUB_API_VERSION,
        "observed_window": {
            "completed_utc": started_utc,
            "started_utc": started_utc,
        },
        "observations": observations,
        "repository": repository,
    }
    repository_id: int | None = None
    repository_owner_id: int | None = None
    previous_utc = started_utc
    for spec in _specs(repository, ruleset_id):
        observed_utc = _format_utc(clock())
        if observed_utc < previous_utc:
            _fail("collector clock moved backwards between API observations")
        if spec.pagination == "single":
            observation = _collect_single(
                spec,
                runner=api_runner,
                repository=repository,
                ruleset_id=ruleset_id,
                observed_utc=observed_utc,
            )
            if spec.name == "repository-metadata":
                metadata_body = observation["pages"][0]["body"]
                assert isinstance(metadata_body, dict)
                repository_id, repository_owner_id = _repository_metadata_identity(
                    metadata_body,
                    repository=repository,
                )
                document["repository_id"] = repository_id
                document["repository_owner_id"] = repository_owner_id
        else:
            if repository_id is None or repository_owner_id is None:
                _fail("repository metadata was not observed before pagination")
            observation = _collect_paginated(
                spec,
                runner=api_runner,
                repository_id=repository_id,
                observed_utc=observed_utc,
            )
        observations.append(observation)
        canonical_json_bytes(document)
        previous_utc = observed_utc
    if repository_id is None or repository_owner_id is None:
        _fail("repository metadata observation is missing")
    completed_utc = _format_utc(clock())
    if completed_utc < previous_utc:
        _fail("collector clock moved backwards during the observation window")
    if any(
        not (started_utc <= item["observed_utc"] <= completed_utc)
        for item in observations
    ):
        _fail("an observation timestamp falls outside the collection window")
    document["observed_window"]["completed_utc"] = completed_utc
    if [item["name"] for item in observations] != [
        spec.name for spec in _specs(repository, ruleset_id)
    ]:
        _fail("observation order changed during collection")
    return document


def _is_link_like(metadata: os.stat_result) -> bool:
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse)


def _prepare_output(path: Path) -> None:
    _validate_windows_path_syntax(path, label="output path")
    if not path.name or path.name in {".", ".."}:
        _fail("output path must name a new file")
    if os.path.lexists(path):
        _fail("refusing to overwrite an existing or link-like output")
    parent = path.absolute().parent
    current = parent
    while True:
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise CollectionError("output parent must already exist") from exc
        if _is_link_like(metadata):
            _fail("output parent ancestry must contain no link-like path")
        if current == parent and not stat.S_ISDIR(metadata.st_mode):
            _fail("output parent must be a non-link directory")
        next_path = current.parent
        if next_path == current:
            break
        current = next_path


def write_new_output(path: Path, data: bytes) -> None:
    """Write one new regular file under a trusted, non-concurrent parent.

    ``O_EXCL`` and link checks prevent ordinary overwrite mistakes.  They do not
    make parent-path traversal atomic against a concurrent hostile operator.
    """

    if len(data) > MAX_OUTPUT_BYTES:
        _fail("canonical observation exceeds one MiB")
    _prepare_output(path)
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
        raise CollectionError("cannot create output without overwriting") from exc
    created_identity: tuple[int, int] | None = None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_link_like(opened)
            or opened.st_nlink != 1
        ):
            _fail("new output is not a single-link regular file")
        created_identity = (opened.st_dev, opened.st_ino)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                _fail("output write did not make progress")
            offset += written
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino) != created_identity
            or after.st_size != len(data)
            or after.st_nlink != 1
        ):
            _fail("output changed during writing")
    except Exception:
        os.close(descriptor)
        descriptor = -1
        try:
            metadata = path.lstat()
            if (
                created_identity is not None
                and (metadata.st_dev, metadata.st_ino) == created_identity
            ):
                path.unlink()
        except OSError:
            pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Collect the unsigned, read-only EvoOM Guard repository-control "
            "observation V2: 19 ordered endpoints, with additional bounded "
            "page requests where Link pagination requires them."
        )
    )
    parser.add_argument("--repo", required=True, help="canonical OWNER/REPO")
    parser.add_argument(
        "--ruleset",
        required=True,
        type=_parse_positive_id,
        help="recorded tag-ruleset numeric ID",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=_parse_output_path,
        help="new output JSON path (existing/link-like targets are refused)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        document = collect(
            args.repo,
            args.ruleset,
        )
        write_new_output(args.output, canonical_json_bytes(document))
    except CollectionError as exc:
        print(f"repository-control collection failed: {exc}", file=sys.stderr)
        return 1
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
