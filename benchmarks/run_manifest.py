"""Create and verify self-consistency evidence for live benchmark runs.

The manifest intentionally does not hash itself.  Its source identity is a
domain-separated digest over an explicit runtime-source inventory, while the
corpus is canonical JSON and the result digest covers the exact JSONL bytes.
Committing or reformatting the manifest therefore cannot change the source
digest it reports.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from benchmarks.evaluate import (
    CASE_KINDS,
    VERDICTS,
    derive_baseline_prediction,
    evaluate_baseline_rows,
    evaluate_rows,
    evaluate_security_evasions_rows,
    parse_rows_payload,
    timing_summary,
)

MANIFEST_SCHEMA = "evoguard-benchmark-run-v5"
BENCHMARK_ID = "live-labelled-corpus-global-phases-contained-worker-v5"
PROVENANCE_WORKFLOW = "two-phase-results-then-manifest-v1"
SOURCE_DIGEST_DOMAIN = "EVOGUARD_BENCHMARK_SOURCE_V1"
CORPUS_DIGEST_DOMAIN = "EVOGUARD_BENCHMARK_CORPUS_V1"
ENVIRONMENT_DIGEST_DOMAIN = "EVOGUARD_BENCHMARK_ENVIRONMENT_COMMITMENTS_V2"
INTERPRETER_DIGEST_DOMAIN = "EVOGUARD_BENCHMARK_INTERPRETER_V1"
DEPENDENCY_LOCK_PATH = "requirements/ci.lock"
EXECUTION_ENVIRONMENT_SCHEMA = "evoguard-benchmark-environment-v2"
TOOL_IDENTITY_SCHEMA = "evoguard-benchmark-tool-identity-v2"
PYTEST_RUNTIME_DIGEST_DOMAIN = "EVOGUARD_PYTEST_RUNTIME_DISTRIBUTIONS_V1"
PYTEST_DISTRIBUTION_DIGEST_DOMAIN = "EVOGUARD_PYTEST_DISTRIBUTION_FILES_V1"

MAX_SOURCE_FILE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 128 * 1024 * 1024
MAX_RESULTS_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_LOCK_BYTES = 8 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
RUN_ID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

EXECUTION_ENV_INHERIT_ALLOWLIST = (
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "WINDIR",
)
EXECUTION_ENV_FORCED = {
    "NO_COLOR": "1",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    "TZ": "UTC",
}
INFLUENTIAL_ENV_REMOVALS = (
    "COVERAGE_FILE",
    "COVERAGE_PROCESS_START",
    "COVERAGE_RCFILE",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "PYTEST_ADDOPTS",
    "PYTEST_CURRENT_TEST",
    "PYTEST_DEBUG",
    "PYTEST_PLUGINS",
    "PYTHONBREAKPOINT",
    "PYTHONCOERCECLOCALE",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONHASHSEED",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONIOENCODING",
    "PYTHONMALLOC",
    "PYTHONNOUSERSITE",
    "PYTHONPATH",
    "PYTHONPROFILEIMPORTTIME",
    "PYTHONPYCACHEPREFIX",
    "PYTHONSAFEPATH",
    "PYTHONSTARTUP",
    "PYTHONTRACEMALLOC",
    "PYTHONUSERBASE",
    "PYTHONUTF8",
    "PYTHONWARNINGS",
    "SSLKEYLOGFILE",
    "VIRTUAL_ENV",
)
GIT_REDIRECT_ENV_KEYS = (
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_WORK_TREE",
)

# These selectors are the reviewed definition of "source content" for this
# benchmark.  Outputs and this manifest's JSON are deliberately absent.
SOURCE_FIXED_PATHS = (
    "benchmarks/evaluate.py",
    "benchmarks/run_live.py",
    "benchmarks/run_manifest.py",
    "pyproject.toml",
    "requirements/ci.lock",
)
SOURCE_GLOBS = (
    "evoom_guard/**/*.py",
    "evoom_guard/**/*.json",
)
RELEASE_VERSION_SOURCE_PATH = "evoom_guard/__init__.py"
_STABLE_RELEASE_VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z"
)


@dataclass(frozen=True)
class StableFileSnapshot:
    """One bounded regular-file read whose descriptor identity stayed stable."""

    path: Path
    payload: bytes
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class EvidenceInitialization:
    """Preflight capability for the one canonical results-only migration."""

    root: Path
    results_path: Path
    manifest_path: Path
    head: str
    results_snapshot: StableFileSnapshot
    results_parent_identity: tuple[int, int]
    manifest_parent_identity: tuple[int, int]


@dataclass(frozen=True)
class SourceBundle:
    """Exact source evidence plus the captured bytes used to stage execution."""

    evidence: dict[str, object]
    files: dict[str, bytes]


def canonical_json_bytes(value: object) -> bytes:
    """Return the canonical UTF-8 JSON encoding used by corpus identities."""
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _path_descriptor_identity(
    value: os.stat_result,
) -> tuple[int, int, int, int]:
    # Windows reports creation time through path stat but a metadata-change
    # surrogate through descriptor stat. Descriptor-to-descriptor comparisons
    # below still include ctime; path association uses stable file ID/size/mtime.
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
    )


def _read_stable_regular_file(
    path: Path,
    *,
    max_bytes: int,
    label: str,
    follow_symlinks: bool,
) -> StableFileSnapshot:
    """Read one regular file once and reject observable path/target swaps."""
    if max_bytes <= 0:
        raise ValueError("stable-read bound must be positive")
    path = Path(path)
    before_path = path.lstat()
    if not follow_symlinks and (
        stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode)
    ):
        raise ValueError(f"{label} must be a non-symlink regular file")
    before_target = path.stat() if follow_symlinks else before_path
    if not stat.S_ISREG(before_target.st_mode):
        qualifier = " target" if follow_symlinks else ""
        raise ValueError(f"{label}{qualifier} must be a regular file")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    if follow_symlinks:
        # A path can be retargeted after the pre-open stat. Nonblocking mode
        # prevents a raced FIFO from hanging before fstat can reject it.
        flags |= getattr(os, "O_NONBLOCK", 0)
    else:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} descriptor is not a regular file")
        if _path_descriptor_identity(before_target) != _path_descriptor_identity(before):
            raise RuntimeError(f"{label} changed before its stable read")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"{label} exceeds the {max_bytes}-byte bound")
        after = os.fstat(descriptor)
        if _stat_identity(before) != _stat_identity(after) or size != after.st_size:
            raise RuntimeError(f"{label} changed during its stable read")
    finally:
        os.close(descriptor)

    after_path = path.lstat()
    if follow_symlinks:
        if _stat_identity(before_path) != _stat_identity(after_path):
            raise RuntimeError(f"{label} link changed during its stable read")
        after_target = path.stat()
        if not stat.S_ISREG(after_target.st_mode) or _path_descriptor_identity(
            after_target
        ) != _path_descriptor_identity(after):
            raise RuntimeError(f"{label} target was replaced during its stable read")
    elif (
        stat.S_ISLNK(after_path.st_mode)
        or not stat.S_ISREG(after_path.st_mode)
        or _path_descriptor_identity(after_path) != _path_descriptor_identity(after)
    ):
        raise RuntimeError(f"{label} path was replaced during its stable read")
    return StableFileSnapshot(
        path=path,
        payload=b"".join(chunks),
        device=after.st_dev,
        inode=after.st_ino,
        size=after.st_size,
        mtime_ns=after.st_mtime_ns,
        ctime_ns=after.st_ctime_ns,
    )


def read_stable_regular_file(
    path: Path,
    *,
    max_bytes: int,
    label: str,
) -> StableFileSnapshot:
    """Read one non-symlink regular file once and reject observable swaps."""
    return _read_stable_regular_file(
        path,
        max_bytes=max_bytes,
        label=label,
        follow_symlinks=False,
    )


def _read_stable_interpreter_executable(
    path: Path,
    *,
    max_bytes: int,
    label: str,
) -> StableFileSnapshot:
    """Read a stable regular interpreter target without retaining its path."""
    return _read_stable_regular_file(
        path,
        max_bytes=max_bytes,
        label=label,
        follow_symlinks=True,
    )


def _sha256_file(
    path: Path,
    *,
    max_bytes: int,
    label: str,
) -> tuple[str, int]:
    snapshot = read_stable_regular_file(
        path,
        max_bytes=max_bytes,
        label=label,
    )
    return _sha256(snapshot.payload), snapshot.size


def _normalised_environment(source: Mapping[str, str]) -> dict[str, str]:
    if os.name == "nt":
        return {key.upper(): value for key, value in sorted(source.items())}
    return dict(sorted(source.items()))


def _environment_commitment_sha256(
    value_digests: Mapping[str, str],
) -> str:
    entries = tuple((key, bytes.fromhex(digest)) for key, digest in sorted(value_digests.items()))
    return _framed_digest(
        ENVIRONMENT_DIGEST_DOMAIN,
        entries,
    )


def execution_environment_sha256(environment: Mapping[str, str]) -> str:
    """Commit to exact values through reproducible per-key value digests."""
    normalized = _normalised_environment(environment)
    return _environment_commitment_sha256(
        {key: _sha256(value.encode("utf-8")) for key, value in normalized.items()}
    )


def build_execution_environment(
    parent: Mapping[str, str] | None = None,
) -> tuple[dict[str, str], dict[str, object]]:
    """Construct the exact allowlisted environment used by benchmark children."""
    source = _normalised_environment(os.environ if parent is None else parent)
    inherited = {key: source[key] for key in EXECUTION_ENV_INHERIT_ALLOWLIST if key in source}
    effective = {**inherited, **EXECUTION_ENV_FORCED}
    inherited_digests = {
        key: _sha256(value.encode("utf-8")) for key, value in sorted(inherited.items())
    }
    forced_digests = {
        key: _sha256(value.encode("utf-8")) for key, value in sorted(EXECUTION_ENV_FORCED.items())
    }
    evidence: dict[str, object] = {
        "schema_version": EXECUTION_ENVIRONMENT_SCHEMA,
        "inherited_keys": sorted(inherited),
        "inherited_value_sha256": inherited_digests,
        "forced_values": dict(sorted(EXECUTION_ENV_FORCED.items())),
        "forced_value_sha256": forced_digests,
        "removed_influential_keys_present": sorted(
            key for key in INFLUENTIAL_ENV_REMOVALS if key in source
        ),
        "all_non_allowlisted_parent_keys_removed": True,
        "effective_key_names": sorted(effective),
        "effective_environment_sha256": _environment_commitment_sha256(
            {**inherited_digests, **forced_digests}
        ),
        "value_digest_privacy": "commitment_not_confidentiality",
    }
    return effective, evidence


def _validated_execution_environment_evidence(
    evidence: Mapping[str, object],
) -> dict[str, object]:
    """Copy only the fixed, non-secret environment evidence schema."""
    expected_keys = {
        "schema_version",
        "inherited_keys",
        "inherited_value_sha256",
        "forced_values",
        "forced_value_sha256",
        "removed_influential_keys_present",
        "all_non_allowlisted_parent_keys_removed",
        "effective_key_names",
        "effective_environment_sha256",
        "value_digest_privacy",
    }
    inherited = evidence.get("inherited_keys")
    inherited_digests = evidence.get("inherited_value_sha256")
    forced = evidence.get("forced_values")
    forced_digests = evidence.get("forced_value_sha256")
    removed = evidence.get("removed_influential_keys_present")
    effective_keys = evidence.get("effective_key_names")
    environment_digest = evidence.get("effective_environment_sha256")
    if (
        set(evidence) != expected_keys
        or evidence.get("schema_version") != EXECUTION_ENVIRONMENT_SCHEMA
        or not isinstance(inherited, list)
        or inherited != sorted(set(inherited))
        or not all(
            isinstance(key, str) and key in EXECUTION_ENV_INHERIT_ALLOWLIST for key in inherited
        )
        or not isinstance(inherited_digests, dict)
        or set(inherited_digests) != set(inherited)
        or not all(
            isinstance(value, str)
            and len(value) == 64
            and all(character in "0123456789abcdef" for character in value)
            for value in inherited_digests.values()
        )
        or forced != EXECUTION_ENV_FORCED
        or not isinstance(forced_digests, dict)
        or forced_digests
        != {
            key: _sha256(value.encode("utf-8"))
            for key, value in sorted(EXECUTION_ENV_FORCED.items())
        }
        or not isinstance(removed, list)
        or removed != sorted(set(removed))
        or not all(isinstance(key, str) and key in INFLUENTIAL_ENV_REMOVALS for key in removed)
        or evidence.get("all_non_allowlisted_parent_keys_removed") is not True
        or not isinstance(effective_keys, list)
        or effective_keys != sorted(set(effective_keys))
        or set(effective_keys) != set(inherited) | set(EXECUTION_ENV_FORCED)
        or not isinstance(environment_digest, str)
        or len(environment_digest) != 64
        or any(character not in "0123456789abcdef" for character in environment_digest)
        or evidence.get("value_digest_privacy") != "commitment_not_confidentiality"
    ):
        raise ValueError("invalid benchmark execution-environment evidence")
    committed_digests = {
        **inherited_digests,
        **forced_digests,
    }
    if environment_digest != _environment_commitment_sha256(committed_digests):
        raise ValueError("benchmark execution-environment digest contradiction")
    return {
        "schema_version": EXECUTION_ENVIRONMENT_SCHEMA,
        "inherited_keys": sorted(inherited),
        "inherited_value_sha256": {
            key: inherited_digests[key] for key in sorted(inherited_digests)
        },
        "forced_values": dict(sorted(EXECUTION_ENV_FORCED.items())),
        "forced_value_sha256": {key: forced_digests[key] for key in sorted(forced_digests)},
        "removed_influential_keys_present": sorted(removed),
        "all_non_allowlisted_parent_keys_removed": True,
        "effective_key_names": sorted(effective_keys),
        "effective_environment_sha256": environment_digest,
        "value_digest_privacy": "commitment_not_confidentiality",
    }


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key in benchmark evidence: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number in benchmark evidence: {value}")


def _framed_digest(domain: str, entries: Sequence[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256()
    domain_bytes = domain.encode("ascii")
    digest.update(len(domain_bytes).to_bytes(8, "big"))
    digest.update(domain_bytes)
    for label, payload in entries:
        label_bytes = label.encode("utf-8")
        digest.update(len(label_bytes).to_bytes(8, "big"))
        digest.update(label_bytes)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def source_inventory_paths(root: Path) -> tuple[str, ...]:
    """Resolve the exact, sorted source inventory selected by the contract."""
    root = root.resolve()
    selected = set(SOURCE_FIXED_PATHS)
    for pattern in SOURCE_GLOBS:
        for path in root.glob(pattern):
            if path.is_file():
                selected.add(path.relative_to(root).as_posix())

    for relative in sorted(selected):
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"benchmark source must be a regular file: {relative}")
    return tuple(sorted(selected))


def _source_bundle_from_files(files: Mapping[str, bytes]) -> SourceBundle:
    """Build canonical source evidence from an already captured exact inventory."""
    inventory: list[dict[str, object]] = []
    framed: list[tuple[str, bytes]] = []
    total_bytes = 0
    for relative in sorted(files):
        payload = files[relative]
        if len(payload) > MAX_SOURCE_FILE_BYTES:
            raise ValueError(f"benchmark source exceeds its byte bound: {relative}")
        total_bytes += len(payload)
        if total_bytes > MAX_SOURCE_TOTAL_BYTES:
            raise ValueError("benchmark source inventory exceeds its aggregate byte bound")
        inventory.append(
            {
                "path": relative,
                "bytes": len(payload),
                "sha256": _sha256(payload),
            }
        )
        framed.append((relative, payload))
    evidence: dict[str, object] = {
        "algorithm": "sha256",
        "format": "length-prefixed path and exact bytes",
        "domain": SOURCE_DIGEST_DOMAIN,
        "selectors": {
            "fixed_paths": list(SOURCE_FIXED_PATHS),
            "globs": list(SOURCE_GLOBS),
        },
        "sha256": _framed_digest(SOURCE_DIGEST_DOMAIN, framed),
        "file_count": len(inventory),
        "total_bytes": total_bytes,
        "files": inventory,
    }
    return SourceBundle(evidence=evidence, files=dict(files))


def collect_source_bundle(root: Path) -> SourceBundle:
    """Read and retain the exact stable bytes used for execution staging."""
    root = root.resolve()
    files: dict[str, bytes] = {}
    for relative in source_inventory_paths(root):
        snapshot = read_stable_regular_file(
            root / relative,
            max_bytes=MAX_SOURCE_FILE_BYTES,
            label=f"benchmark source {relative}",
        )
        files[relative] = snapshot.payload
    return _source_bundle_from_files(files)


def _release_promotion_source_bundle(
    root: Path,
    *,
    recorded_engine_version: object,
    current_engine_version: str,
) -> SourceBundle:
    """Reconstruct the exact dev0 source represented by a stable promotion.

    This is a verification-only compatibility rule. It accepts precisely one
    stable ``X.Y.Z`` assignment in the current version file and rewrites that
    byte sequence to the manifest's exact ``X.Y.Z.dev0`` value. Every other
    captured source byte remains exact and must still match the manifest.
    """
    if (
        not isinstance(recorded_engine_version, str)
        or not _STABLE_RELEASE_VERSION_RE.fullmatch(current_engine_version)
        or recorded_engine_version != f"{current_engine_version}.dev0"
    ):
        raise ValueError("benchmark engine versions are not an exact dev0 promotion")
    current = collect_source_bundle(root)
    payload = current.files.get(RELEASE_VERSION_SOURCE_PATH)
    if payload is None:
        raise ValueError("release version source is absent from benchmark inventory")
    stable_assignment = f'__version__ = "{current_engine_version}"'.encode("ascii")
    development_assignment = f'__version__ = "{recorded_engine_version}"'.encode("ascii")
    if payload.count(stable_assignment) != 1 or development_assignment in payload:
        raise ValueError("release version source is not an exact stable assignment")
    normalized = dict(current.files)
    normalized[RELEASE_VERSION_SOURCE_PATH] = payload.replace(
        stable_assignment,
        development_assignment,
        1,
    )
    return _source_bundle_from_files(normalized)


def collect_source_evidence(root: Path) -> dict[str, object]:
    """Return the exact source inventory, per-file hashes, and aggregate hash."""
    return collect_source_bundle(root).evidence


def collect_corpus_evidence(corpus: Mapping[str, object]) -> dict[str, object]:
    """Return a canonical logical-corpus digest, independent of result timing."""
    canonical = canonical_json_bytes(corpus)
    cases = corpus.get("cases")
    if not isinstance(cases, list):
        raise ValueError("benchmark corpus cases must be a list")
    case_ids: list[str] = []
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str):
            raise ValueError("each benchmark corpus case must have a string id")
        case_ids.append(case["id"])
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("benchmark corpus case ids must be unique")
    return {
        "algorithm": "sha256",
        "format": "canonical JSON (UTF-8, sorted keys, compact separators)",
        "domain": CORPUS_DIGEST_DOMAIN,
        "sha256": _framed_digest(
            CORPUS_DIGEST_DOMAIN,
            (("corpus.json", canonical),),
        ),
        "canonical_bytes": len(canonical),
        "case_count": len(case_ids),
        "case_ids": case_ids,
    }


def collect_results_evidence(
    path: Path,
    root: Path,
    *,
    snapshot: StableFileSnapshot | None = None,
) -> dict[str, object]:
    """Return a raw-byte digest and bounded structural facts for JSONL results."""
    stable = snapshot or read_stable_regular_file(
        path,
        max_bytes=MAX_RESULTS_BYTES,
        label="benchmark results",
    )
    payload = stable.payload
    rows = parse_rows_payload(payload)
    return {
        "path": _display_path(path, root),
        "algorithm": "sha256",
        "format": "exact file bytes",
        "sha256": _sha256(payload),
        "bytes": len(payload),
        "rows": len(rows),
    }


def validate_results_contract(
    rows: Sequence[Mapping[str, object]],
    *,
    corpus: Mapping[str, object],
    run_id: str,
    engine_version: str,
    source_digest: str,
    execution_environment_digest: str,
    interpreter_digest: str,
) -> tuple[str, ...]:
    """Validate the semantic relation between the labelled corpus and results."""
    raw_cases = corpus.get("cases")
    if not isinstance(raw_cases, list):
        return ("corpus cases are not a list",)
    errors: list[str] = []
    row_keys = {
        "id",
        "run_id",
        "engine_version",
        "case_kind",
        "truth",
        "verdict",
        "expected_verdict",
        "as_expected",
        "reason_code",
        "elapsed_s",
        "note",
        "baseline",
        "execution_source_sha256",
        "execution_environment_sha256",
        "interpreter_identity_sha256",
        "python_isolated",
        "pytest_plugin_autoload",
        "managed_worker_cleanup_proven",
    }
    if not RUN_ID_PATTERN.fullmatch(run_id):
        errors.append("manifest run id is invalid")
    if len(rows) != len(raw_cases):
        errors.append(f"result row count {len(rows)} does not match corpus count {len(raw_cases)}")

    for index, (row, raw_case) in enumerate(zip(rows, raw_cases, strict=False), 1):
        if not isinstance(raw_case, dict):
            errors.append(f"corpus case {index} is not an object")
            continue
        if set(row) != row_keys:
            errors.append(f"result row {index} schema is invalid")
        case_id = raw_case.get("id")
        if row.get("id") != case_id:
            errors.append(f"result row {index} id does not match corpus order")
        if row.get("run_id") != run_id:
            errors.append(f"result row {index} run id drift")
        if row.get("truth") != raw_case.get("truth"):
            errors.append(f"result row {index} truth does not match corpus")
        case_kind = raw_case.get("case_kind")
        if case_kind not in CASE_KINDS:
            errors.append(f"corpus case {index} kind is invalid")
        if row.get("case_kind") != case_kind:
            errors.append(f"result row {index} case kind does not match corpus")
        if (case_kind == "legitimate") is not (raw_case.get("truth") == "accept"):
            errors.append(f"corpus case {index} kind/truth relation is invalid")
        expected_verdict = raw_case.get("expect")
        if row.get("expected_verdict") != expected_verdict:
            errors.append(f"result row {index} expected verdict does not match corpus")
        if row.get("note") != raw_case.get("note"):
            errors.append(f"result row {index} note does not match corpus")
        verdict = row.get("verdict")
        if verdict not in VERDICTS:
            errors.append(f"result row {index} has an invalid verdict")
        if row.get("as_expected") is not (verdict == expected_verdict):
            errors.append(f"result row {index} has an invalid as_expected flag")
        if row.get("engine_version") != engine_version:
            errors.append(f"result row {index} engine version drift")
        if row.get("execution_source_sha256") != source_digest:
            errors.append(f"result row {index} execution source drift")
        if row.get("execution_environment_sha256") != execution_environment_digest:
            errors.append(f"result row {index} execution environment drift")
        if row.get("interpreter_identity_sha256") != interpreter_digest:
            errors.append(f"result row {index} interpreter identity drift")
        if row.get("python_isolated") is not True:
            errors.append(f"result row {index} was not produced under Python -I")
        if row.get("pytest_plugin_autoload") is not False:
            errors.append(f"result row {index} pytest plugin policy drift")
        if row.get("managed_worker_cleanup_proven") is not True:
            errors.append(f"result row {index} managed worker cleanup was not proven")
        if not isinstance(row.get("reason_code"), str) or not row.get("reason_code"):
            errors.append(f"result row {index} has no reason code")
        elapsed = row.get("elapsed_s")
        if (
            isinstance(elapsed, bool)
            or not isinstance(elapsed, (int, float))
            or not math.isfinite(float(elapsed))
            or float(elapsed) < 0.0
        ):
            errors.append(f"result row {index} elapsed time is invalid")

        baseline = row.get("baseline")
        if not isinstance(baseline, dict):
            errors.append(f"result row {index} has no baseline observation")
            continue
        try:
            prediction = derive_baseline_prediction(baseline, row=index)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if case_kind in {"viable_evasion", "nonviable_evasion"}:
            derived_kind = "viable_evasion" if prediction == "accept" else "nonviable_evasion"
            if case_kind != derived_kind:
                errors.append(
                    f"result row {index} evasion viability label contradicts its baseline"
                )
    return tuple(errors)


def _display_path(path: Path, root: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return "{external-results}"


def _safe_version_line(value: str) -> str | None:
    line = value.splitlines()[0].strip() if value.strip() else ""
    if not line:
        return None
    line = "".join(character if character.isprintable() else " " for character in line)[:200]
    sensitive = {
        str(Path.cwd().resolve()),
        str(Path.home().resolve()),
        sys.executable,
    }
    if any(
        item and item.casefold() in line.casefold() for item in sensitive
    ) or _contains_absolute_path_fragment(line):
        return None
    return line


def _external_tool_identity(
    name: str,
    *,
    execution_environment: Mapping[str, str],
) -> dict[str, object]:
    resolved = shutil.which(name, path=execution_environment.get("PATH"))
    if resolved is None:
        return {
            "schema_version": TOOL_IDENTITY_SCHEMA,
            "available": False,
            "executable_sha256": None,
            "executable_bytes": None,
            "version_line": None,
            "version_line_sha256": None,
        }
    try:
        executable = Path(resolved).resolve(strict=True)
        snapshot = read_stable_regular_file(
            executable,
            max_bytes=MAX_EXECUTABLE_BYTES,
            label=f"{name} executable",
        )
        completed = subprocess.run(
            [str(executable), "--version"],
            check=False,
            capture_output=True,
            cwd=tempfile.gettempdir(),
            env=dict(execution_environment),
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return {
            "schema_version": TOOL_IDENTITY_SCHEMA,
            "available": False,
            "executable_sha256": None,
            "executable_bytes": None,
            "version_line": None,
            "version_line_sha256": None,
        }
    output = completed.stdout.strip() or completed.stderr.strip()
    raw_line = output.splitlines()[0].strip() if output else ""
    return {
        "schema_version": TOOL_IDENTITY_SCHEMA,
        "available": True,
        "executable_sha256": _sha256(snapshot.payload),
        "executable_bytes": snapshot.size,
        "version_line": _safe_version_line(raw_line),
        "version_line_sha256": (_sha256(raw_line.encode("utf-8")) if raw_line else None),
    }


def _normalized_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _requirement_distribution_name(value: str) -> str | None:
    if re.search(r"(?i)\bextra\s*==", value):
        return None
    matched = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", value)
    return None if matched is None else matched.group(1)


def _sum_distribution_field(
    records: Sequence[Mapping[str, object]],
    field: str,
) -> int:
    total = 0
    for record in records:
        value = record.get(field)
        if type(value) is not int:
            raise ValueError(f"pytest runtime {field} is invalid")
        total += value
    return total


def _pytest_runtime_distributions() -> list[dict[str, object]]:
    pending = ["pytest"]
    seen: set[str] = set()
    records: list[dict[str, object]] = []
    aggregate_bytes = 0
    while pending:
        requested = pending.pop()
        normalized_requested = _normalized_distribution_name(requested)
        if normalized_requested in seen:
            continue
        try:
            distribution = importlib.metadata.distribution(requested)
        except importlib.metadata.PackageNotFoundError:
            if normalized_requested == "pytest":
                raise
            continue
        raw_name = distribution.metadata["Name"] or requested
        name = _normalized_distribution_name(raw_name)
        if name in seen:
            continue
        seen.add(name)
        files = distribution.files
        if not files:
            raise ValueError(f"{name} distribution file inventory is unavailable")
        framed: list[tuple[str, bytes]] = []
        distribution_bytes = 0
        for package_path in sorted(files, key=lambda item: str(item)):
            label = str(package_path).replace("\\", "/")
            snapshot = read_stable_regular_file(
                Path(str(distribution.locate_file(package_path))),
                max_bytes=MAX_SOURCE_FILE_BYTES,
                label=f"{name} distribution file",
            )
            framed.append((label, snapshot.payload))
            distribution_bytes += snapshot.size
            aggregate_bytes += snapshot.size
            if aggregate_bytes > MAX_SOURCE_TOTAL_BYTES:
                raise ValueError("pytest runtime exceeds its aggregate byte bound")
        version = _safe_version_line(distribution.version)
        if version is None:
            raise ValueError(f"{name} distribution version is unsafe")
        records.append(
            {
                "name": name,
                "version": version,
                "files": len(framed),
                "bytes": distribution_bytes,
                "files_sha256": _framed_digest(
                    f"{PYTEST_DISTRIBUTION_DIGEST_DOMAIN}:{name}",
                    framed,
                ),
            }
        )
        for requirement in distribution.requires or ():
            dependency = _requirement_distribution_name(requirement)
            if dependency is not None:
                pending.append(dependency)
    return sorted(records, key=lambda item: str(item["name"]))


def _pytest_identity() -> dict[str, object]:
    try:
        version = importlib.metadata.version("pytest")
        runtime_distributions = _pytest_runtime_distributions()
        runtime_sha256 = _framed_digest(
            PYTEST_RUNTIME_DIGEST_DOMAIN,
            tuple(
                (
                    str(record["name"]),
                    canonical_json_bytes(record),
                )
                for record in runtime_distributions
            ),
        )
    except (
        importlib.metadata.PackageNotFoundError,
        OSError,
        RuntimeError,
        ValueError,
    ):
        return {
            "schema_version": TOOL_IDENTITY_SCHEMA,
            "available": False,
            "distribution": "pytest",
            "version": None,
            "runtime_distributions": [],
            "runtime_sha256": None,
            "runtime_files": 0,
            "runtime_bytes": 0,
            "installed_environment_match_claim": False,
        }
    return {
        "schema_version": TOOL_IDENTITY_SCHEMA,
        "available": True,
        "distribution": "pytest",
        "version": _safe_version_line(version),
        "runtime_distributions": runtime_distributions,
        "runtime_sha256": runtime_sha256,
        "runtime_files": _sum_distribution_field(
            runtime_distributions,
            "files",
        ),
        "runtime_bytes": _sum_distribution_field(
            runtime_distributions,
            "bytes",
        ),
        "installed_environment_match_claim": False,
    }


def collect_tool_identities(
    execution_environment: Mapping[str, str],
) -> dict[str, object]:
    """Bind actual resolved tool bytes without recording their host paths."""
    return {
        "git": _external_tool_identity(
            "git",
            execution_environment=execution_environment,
        ),
        "patch": _external_tool_identity(
            "patch",
            execution_environment=execution_environment,
        ),
        "pytest": _pytest_identity(),
    }


def collect_interpreter_identity() -> dict[str, object]:
    """Return a path-free identity for Python executable bytes and metadata."""
    executable = _read_stable_interpreter_executable(
        Path(sys.executable),
        max_bytes=MAX_EXECUTABLE_BYTES,
        label="Python interpreter executable",
    )
    identity: dict[str, object] = {
        "implementation": platform.python_implementation(),
        "version": platform.python_version(),
        "hexversion": sys.hexversion,
        "cache_tag": sys.implementation.cache_tag,
        "compiler": platform.python_compiler(),
        "build": list(platform.python_build()),
        "executable_sha256": _sha256(executable.payload),
        "executable_bytes": executable.size,
    }
    identity["identity_sha256"] = _framed_digest(
        INTERPRETER_DIGEST_DOMAIN,
        (("interpreter.json", canonical_json_bytes(identity)),),
    )
    return identity


def collect_dependency_lock(root: Path) -> dict[str, object]:
    path = root.resolve() / DEPENDENCY_LOCK_PATH
    digest, size = _sha256_file(
        path,
        max_bytes=MAX_LOCK_BYTES,
        label="benchmark dependency lock",
    )
    return {
        "path": DEPENDENCY_LOCK_PATH,
        "algorithm": "sha256",
        "sha256": digest,
        "bytes": size,
        "role": "declared CI dependency lock",
        "installed_environment_match_claim": False,
    }


def _validated_interpreter_identity(
    evidence: Mapping[str, object],
) -> dict[str, object]:
    expected_keys = {
        "implementation",
        "version",
        "hexversion",
        "cache_tag",
        "compiler",
        "build",
        "executable_sha256",
        "executable_bytes",
        "identity_sha256",
    }
    text_fields = ("implementation", "version", "cache_tag", "compiler")
    build = evidence.get("build")
    executable_digest = evidence.get("executable_sha256")
    executable_bytes = evidence.get("executable_bytes")
    identity_digest = evidence.get("identity_sha256")
    if (
        set(evidence) != expected_keys
        or not all(
            isinstance(evidence.get(field), str) and evidence.get(field) for field in text_fields
        )
        or any(_is_absolute_path_token(str(evidence.get(field))) for field in text_fields)
        or type(evidence.get("hexversion")) is not int
        or not isinstance(build, list)
        or len(build) != 2
        or not all(isinstance(value, str) for value in build)
        or any(_is_absolute_path_token(value) for value in build if isinstance(value, str))
        or type(executable_bytes) is not int
        or executable_bytes <= 0
        or not isinstance(executable_digest, str)
        or len(executable_digest) != 64
        or any(character not in "0123456789abcdef" for character in executable_digest)
        or not isinstance(identity_digest, str)
        or len(identity_digest) != 64
        or any(character not in "0123456789abcdef" for character in identity_digest)
    ):
        raise ValueError("invalid benchmark interpreter identity")
    canonical = {key: evidence[key] for key in expected_keys if key != "identity_sha256"}
    expected_identity_digest = _framed_digest(
        INTERPRETER_DIGEST_DOMAIN,
        (("interpreter.json", canonical_json_bytes(canonical)),),
    )
    if identity_digest != expected_identity_digest:
        raise ValueError("benchmark interpreter identity digest mismatch")
    return {**canonical, "identity_sha256": identity_digest}


def collect_environment(
    execution_environment: Mapping[str, object],
    *,
    effective_environment: Mapping[str, str],
    tool_identities: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Capture path-free runtime identity and allowlisted child-env evidence."""
    return {
        "captured_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "os": {
            "name": os.name,
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
        },
        "case_interpreter": _validated_interpreter_identity(collect_interpreter_identity()),
        "case_python_flags": ["-I"],
        "controller": {
            "python_isolated": sys.flags.isolated == 1,
            "observed_python_flags": (["-I"] if sys.flags.isolated == 1 else []),
        },
        "tools": dict(
            tool_identities
            if tool_identities is not None
            else collect_tool_identities(effective_environment)
        ),
        "execution_environment": _validated_execution_environment_evidence(execution_environment),
    }


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_git_oid(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) in {40, 64}
        and all(character in "0123456789abcdef" for character in value)
    )


def _validated_external_tool_identity(
    value: Mapping[str, object],
) -> dict[str, object]:
    expected_keys = {
        "schema_version",
        "available",
        "executable_sha256",
        "executable_bytes",
        "version_line",
        "version_line_sha256",
    }
    available = value.get("available")
    executable_bytes = value.get("executable_bytes")
    if (
        set(value) != expected_keys
        or value.get("schema_version") != TOOL_IDENTITY_SCHEMA
        or type(available) is not bool
    ):
        raise ValueError("invalid external tool identity")
    if available is False:
        if any(
            value.get(key) is not None for key in expected_keys - {"schema_version", "available"}
        ):
            raise ValueError("unavailable external tool has identity fields")
    else:
        version_line = value.get("version_line")
        if (
            not _is_sha256(value.get("executable_sha256"))
            or type(executable_bytes) is not int
            or (isinstance(executable_bytes, int) and executable_bytes <= 0)
            or (
                version_line is not None
                and (
                    not isinstance(version_line, str)
                    or not version_line
                    or len(version_line) > 200
                    or _contains_absolute_path_fragment(version_line)
                )
            )
            or (
                value.get("version_line_sha256") is not None
                and not _is_sha256(value.get("version_line_sha256"))
            )
        ):
            raise ValueError("invalid available external tool identity")
    return dict(value)


def _validated_pytest_identity(
    value: Mapping[str, object],
) -> dict[str, object]:
    expected_keys = {
        "schema_version",
        "available",
        "distribution",
        "version",
        "runtime_distributions",
        "runtime_sha256",
        "runtime_files",
        "runtime_bytes",
        "installed_environment_match_claim",
    }
    available = value.get("available")
    distributions = value.get("runtime_distributions")
    runtime_files = value.get("runtime_files")
    runtime_bytes = value.get("runtime_bytes")
    if (
        set(value) != expected_keys
        or value.get("schema_version") != TOOL_IDENTITY_SCHEMA
        or value.get("distribution") != "pytest"
        or type(available) is not bool
        or value.get("installed_environment_match_claim") is not False
    ):
        raise ValueError("invalid pytest identity")
    if available is False:
        if (
            value.get("version") is not None
            or distributions != []
            or value.get("runtime_sha256") is not None
            or runtime_files != 0
            or runtime_bytes != 0
        ):
            raise ValueError("unavailable pytest has identity fields")
    else:
        if (
            not isinstance(value.get("version"), str)
            or not value.get("version")
            or _contains_absolute_path_fragment(str(value.get("version")))
            or not isinstance(distributions, list)
            or not distributions
            or not _is_sha256(value.get("runtime_sha256"))
            or type(runtime_files) is not int
            or runtime_files <= 0
            or type(runtime_bytes) is not int
            or runtime_bytes <= 0
        ):
            raise ValueError("invalid available pytest identity")
        normalized_records: list[dict[str, object]] = []
        names: list[str] = []
        for record in distributions:
            record_keys = {"name", "version", "files", "bytes", "files_sha256"}
            if (
                not isinstance(record, dict)
                or set(record) != record_keys
                or not isinstance(record.get("name"), str)
                or not record.get("name")
                or record.get("name") != _normalized_distribution_name(str(record.get("name")))
                or not isinstance(record.get("version"), str)
                or not record.get("version")
                or _contains_absolute_path_fragment(str(record.get("version")))
                or type(record.get("files")) is not int
                or int(record.get("files", 0)) <= 0
                or type(record.get("bytes")) is not int
                or int(record.get("bytes", 0)) <= 0
                or not _is_sha256(record.get("files_sha256"))
            ):
                raise ValueError("invalid pytest runtime distribution identity")
            normalized_records.append(dict(record))
            names.append(str(record["name"]))
        if names != sorted(set(names)) or "pytest" not in names:
            raise ValueError("pytest runtime distribution inventory is not canonical")
        if runtime_files != _sum_distribution_field(
            normalized_records,
            "files",
        ):
            raise ValueError("pytest runtime file count contradiction")
        if runtime_bytes != _sum_distribution_field(
            normalized_records,
            "bytes",
        ):
            raise ValueError("pytest runtime byte count contradiction")
        expected_runtime_sha256 = _framed_digest(
            PYTEST_RUNTIME_DIGEST_DOMAIN,
            tuple(
                (
                    str(record["name"]),
                    canonical_json_bytes(record),
                )
                for record in normalized_records
            ),
        )
        if value.get("runtime_sha256") != expected_runtime_sha256:
            raise ValueError("pytest runtime digest contradiction")
    return dict(value)


def _validated_tool_identities(
    value: Mapping[str, object],
) -> dict[str, object]:
    if set(value) != {"git", "patch", "pytest"}:
        raise ValueError("invalid benchmark tool identity schema")
    git = value.get("git")
    patch = value.get("patch")
    pytest_identity = value.get("pytest")
    if (
        not isinstance(git, dict)
        or not isinstance(patch, dict)
        or not isinstance(pytest_identity, dict)
    ):
        raise ValueError("invalid benchmark tool identity")
    return {
        "git": _validated_external_tool_identity(git),
        "patch": _validated_external_tool_identity(patch),
        "pytest": _validated_pytest_identity(pytest_identity),
    }


def _validated_environment_record(
    value: Mapping[str, object],
) -> dict[str, object]:
    expected_keys = {
        "captured_at_utc",
        "os",
        "case_interpreter",
        "case_python_flags",
        "controller",
        "tools",
        "execution_environment",
    }
    if set(value) != expected_keys:
        raise ValueError("invalid runtime environment schema")
    captured_at = value.get("captured_at_utc")
    if not isinstance(captured_at, str) or not captured_at.endswith("Z"):
        raise ValueError("invalid runtime capture timestamp")
    try:
        datetime.fromisoformat(captured_at.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ValueError("invalid runtime capture timestamp") from exc

    os_record = value.get("os")
    os_keys = {"name", "platform", "system", "release", "machine", "cpu_count"}
    if not isinstance(os_record, dict) or set(os_record) != os_keys:
        raise ValueError("invalid runtime OS identity")
    for field in ("name", "platform", "system", "release", "machine"):
        item = os_record.get(field)
        if not isinstance(item, str) or _contains_absolute_path_fragment(item):
            raise ValueError("invalid runtime OS identity")
    cpu_count = os_record.get("cpu_count")
    if cpu_count is not None and (type(cpu_count) is not int or cpu_count <= 0):
        raise ValueError("invalid runtime CPU count")

    interpreter = value.get("case_interpreter")
    execution_environment = value.get("execution_environment")
    controller = value.get("controller")
    tools = value.get("tools")
    if (
        not isinstance(interpreter, dict)
        or not isinstance(execution_environment, dict)
        or not isinstance(controller, dict)
        or not isinstance(tools, dict)
        or value.get("case_python_flags") != ["-I"]
    ):
        raise ValueError("invalid runtime execution identity")
    if (
        set(controller) != {"python_isolated", "observed_python_flags"}
        or type(controller.get("python_isolated")) is not bool
        or controller.get("observed_python_flags")
        != (["-I"] if controller.get("python_isolated") is True else [])
    ):
        raise ValueError("invalid controller identity")
    return {
        "captured_at_utc": captured_at,
        "os": dict(os_record),
        "case_interpreter": _validated_interpreter_identity(interpreter),
        "case_python_flags": ["-I"],
        "controller": dict(controller),
        "tools": _validated_tool_identities(tools),
        "execution_environment": _validated_execution_environment_evidence(execution_environment),
    }


def _reviewed_git_environment() -> dict[str, str]:
    environment, _evidence = build_execution_environment()
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _git_command(root: Path, arguments: Sequence[str]) -> list[str]:
    return [
        "git",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-C",
        str(root),
        *arguments,
    ]


def _git(
    root: Path,
    arguments: Sequence[str],
) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            _git_command(root, arguments),
            check=False,
            capture_output=True,
            encoding="utf-8",
            env=_reviewed_git_environment(),
            errors="replace",
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _git_bytes(
    root: Path,
    arguments: Sequence[str],
) -> subprocess.CompletedProcess[bytes] | None:
    try:
        return subprocess.run(
            _git_command(root, arguments),
            check=False,
            capture_output=True,
            env=_reviewed_git_environment(),
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _git_relative_path(git_root: Path, path: Path) -> str | None:
    try:
        return path.resolve().relative_to(git_root.resolve()).as_posix()
    except ValueError:
        return None


def _head_blobs(
    git_root: Path,
    head: str,
    paths: Sequence[Path],
) -> dict[Path, bytes | None] | None:
    """Read exact HEAD blobs in one Git process; missing paths map to ``None``."""
    resolved_paths = tuple(dict.fromkeys(path.resolve() for path in paths))
    output: dict[Path, bytes | None] = {path: None for path in resolved_paths}
    queries: list[tuple[Path, str]] = []
    for path in resolved_paths:
        relative = _git_relative_path(git_root, path)
        if relative is None or "\n" in relative or "\r" in relative:
            continue
        queries.append((path, f"{head}:{relative}"))
    if not queries:
        return output
    try:
        completed = subprocess.run(
            _git_command(git_root, ("cat-file", "--batch")),
            input="".join(f"{query}\n" for _, query in queries).encode("utf-8"),
            check=False,
            capture_output=True,
            env=_reviewed_git_environment(),
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None

    cursor = 0
    payload = completed.stdout
    for path, _query in queries:
        header_end = payload.find(b"\n", cursor)
        if header_end < 0:
            return None
        header = payload[cursor:header_end]
        cursor = header_end + 1
        if header.endswith(b" missing"):
            continue
        fields = header.rsplit(b" ", 2)
        if len(fields) != 3 or fields[1] != b"blob":
            return None
        try:
            size = int(fields[2])
        except ValueError:
            return None
        end = cursor + size
        if end >= len(payload) or payload[end : end + 1] != b"\n":
            return None
        output[path] = payload[cursor:end]
        cursor = end + 1
    return output


def _head_tree_entries(
    git_root: Path,
    head: str,
    paths: Sequence[Path],
) -> dict[Path, tuple[str, str] | None] | None:
    """Read exact Git modes and object kinds for selected paths at one commit."""
    resolved_paths = tuple(dict.fromkeys(path.resolve() for path in paths))
    output: dict[Path, tuple[str, str] | None] = {path: None for path in resolved_paths}
    relative_to_path: dict[bytes, Path] = {}
    for path in resolved_paths:
        relative = _git_relative_path(git_root, path)
        if relative is None or "\n" in relative or "\r" in relative:
            return None
        relative_to_path[relative.encode("utf-8")] = path
    result = _git_bytes(
        git_root,
        ("ls-tree", "-z", head, "--", *(item.decode() for item in relative_to_path)),
    )
    if result is None or result.returncode != 0:
        return None
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, record_relative = record.split(b"\t", 1)
            mode, kind, _object_id = metadata.decode("ascii").split(" ", 2)
        except (UnicodeDecodeError, ValueError):
            return None
        matched_path = relative_to_path.get(record_relative)
        if matched_path is None or output[matched_path] is not None:
            return None
        output[matched_path] = (mode, kind)
    return output


def _head_source_inventory(
    git_root: Path,
    root: Path,
    head: str,
) -> frozenset[str] | None:
    """Select benchmark source paths from the exact Git tree at ``head``."""
    listing = _git_bytes(
        git_root,
        ("ls-tree", "-r", "-z", "--name-only", head),
    )
    if listing is None or listing.returncode != 0:
        return None
    try:
        names = listing.stdout.decode("utf-8").split("\0")
        root_prefix_path = root.resolve().relative_to(git_root.resolve())
    except (UnicodeDecodeError, ValueError):
        return None
    root_prefix = root_prefix_path.as_posix()
    prefix = f"{root_prefix}/" if root_prefix not in {"", "."} else ""
    selected: set[str] = set()
    for name in names:
        if not name:
            continue
        if prefix:
            if not name.startswith(prefix):
                continue
            relative = name[len(prefix) :]
        else:
            relative = name
        if relative in SOURCE_FIXED_PATHS or (
            relative.startswith("evoom_guard/")
            and (relative.endswith(".py") or relative.endswith(".json"))
        ):
            selected.add(relative)
    return frozenset(selected)


def _unbound_git_state(reason: str) -> dict[str, object]:
    return {
        "head": None,
        "dirty": None,
        "porcelain_dirty": None,
        "bound_paths_tracked_at_head": False,
        "bound_paths_match_head": False,
        "source_inventory_matches_head": False,
        "source_and_results_commit_bound": False,
        "binding": "content-digests-only",
        "reason": reason,
        "observation_point": "after result assembly and before pair publication",
    }


def collect_git_state(
    root: Path,
    *,
    bound_paths: Sequence[Path],
    source_paths: Sequence[Path] = (),
    bound_payloads: Mapping[Path, bytes] | None = None,
) -> dict[str, object]:
    """Derive Git truth from status plus exact worktree/HEAD blob comparisons."""
    root = root.resolve()
    parent_environment = _normalised_environment(os.environ)
    if any(key in parent_environment for key in GIT_REDIRECT_ENV_KEYS):
        return _unbound_git_state("redirected_git_environment_refused")
    top_result = _git(root, ("rev-parse", "--show-toplevel"))
    head_result = _git(root, ("rev-parse", "--verify", "HEAD"))
    status_result = _git(
        root,
        ("status", "--porcelain=v1", "--untracked-files=all"),
    )
    if (
        top_result is None
        or head_result is None
        or status_result is None
        or top_result.returncode != 0
        or head_result.returncode != 0
        or status_result.returncode != 0
    ):
        return _unbound_git_state("git_state_unavailable")

    git_root = Path(top_result.stdout.strip()).resolve()
    head = head_result.stdout.strip()
    porcelain_dirty = bool(status_result.stdout)
    tracked = True
    bound_paths_match_head = True
    head_blobs = _head_blobs(git_root, head, bound_paths)
    intended_payloads = {
        path.resolve(): payload for path, payload in (bound_payloads or {}).items()
    }
    for path in bound_paths:
        blob = None if head_blobs is None else head_blobs.get(path.resolve())
        if blob is None:
            tracked = False
            bound_paths_match_head = False
            continue
        try:
            payload = intended_payloads.get(path.resolve())
            if payload is None:
                snapshot = read_stable_regular_file(
                    path,
                    max_bytes=MAX_SOURCE_FILE_BYTES,
                    label="Git-bound file",
                )
                payload = snapshot.payload
            if path.is_symlink() or payload != blob:
                bound_paths_match_head = False
        except (OSError, RuntimeError, ValueError):
            bound_paths_match_head = False

    source_inventory_matches_head = True
    if source_paths:
        current_source_inventory: set[str] = set()
        for path in source_paths:
            try:
                current_source_inventory.add(path.resolve().relative_to(root).as_posix())
            except ValueError:
                source_inventory_matches_head = False
                break
        head_source_inventory = _head_source_inventory(git_root, root, head)
        if (
            head_source_inventory is None
            or frozenset(current_source_inventory) != head_source_inventory
        ):
            source_inventory_matches_head = False

    dirty = (
        porcelain_dirty
        or not tracked
        or not bound_paths_match_head
        or not source_inventory_matches_head
    )
    commit_bound = not dirty
    if not tracked:
        reason = "one_or_more_bound_paths_are_not_tracked_at_head"
    elif not source_inventory_matches_head:
        reason = "source_inventory_differs_from_head"
    elif not bound_paths_match_head:
        reason = "one_or_more_bound_paths_differ_from_head"
    elif porcelain_dirty:
        reason = "dirty_worktree"
    else:
        reason = "clean_worktree_and_all_bound_paths_tracked"
    return {
        "head": head,
        "dirty": dirty,
        "porcelain_dirty": porcelain_dirty,
        "bound_paths_tracked_at_head": tracked,
        "bound_paths_match_head": bound_paths_match_head,
        "source_inventory_matches_head": source_inventory_matches_head,
        "source_and_results_commit_bound": commit_bound,
        "binding": "git-head" if commit_bound else "content-digests-only",
        "reason": reason,
        "observation_point": "after result assembly and before pair publication",
    }


def _source_commit_record(git: Mapping[str, object]) -> dict[str, object]:
    """Project a source-only Git observation into an unambiguous contract."""
    head = git.get("head")
    tracked = git.get("bound_paths_tracked_at_head")
    paths_match = git.get("bound_paths_match_head")
    inventory_match = git.get("source_inventory_matches_head")
    worktree_dirty = git.get("porcelain_dirty")
    bound = git.get("source_and_results_commit_bound") is True
    if head is None:
        reason = str(git.get("reason"))
    elif tracked is not True:
        reason = "one_or_more_source_paths_not_tracked_at_commit"
    elif inventory_match is not True:
        reason = "source_inventory_differs_from_commit"
    elif paths_match is not True:
        reason = "one_or_more_source_paths_differ_from_commit"
    elif worktree_dirty is True:
        reason = "dirty_worktree"
    else:
        reason = "clean_worktree_and_source_matches_commit"
    return {
        "commit": head,
        "bound": bound,
        "binding": "git-commit" if bound else "content-digests-only",
        "worktree_dirty": worktree_dirty,
        "source_paths_tracked_at_commit": tracked,
        "source_paths_match_commit": paths_match,
        "source_inventory_matches_commit": inventory_match,
        "reason": reason,
        "observation_point": "after result assembly and before pair publication",
    }


def _claim_record(
    *,
    source_commit_bound: bool,
    evidence_commit_bound: bool,
) -> dict[str, object]:
    if evidence_commit_bound:
        content_identity = "source-and-results-git-commits-plus-content-digests"
    elif source_commit_bound:
        content_identity = "source-git-commit-plus-content-digests"
    else:
        content_identity = "content-digests-only"
    return {
        "authenticated": False,
        "evidence_status": "self_consistent_unattributed",
        "execution_authenticity_claim": False,
        "source_commit_bound": source_commit_bound,
        "evidence_commit_bound": evidence_commit_bound,
        # This compatibility field now has one precise meaning: an evidence
        # commit contains both the exact source inventory and exact result
        # bytes. It is never inferred from the pre-publication observation.
        "source_and_results_commit_bound": evidence_commit_bound,
        # The finalized manifest is necessarily written after the evidence
        # commit and is deliberately excluded from that claim.
        "final_manifest_in_evidence_commit": False,
        "execution_source_snapshot_bound": True,
        "source_snapshot_matches_worktree_at_manifest_build": True,
        "content_identity": content_identity,
        "installed_environment_matches_lock": False,
        "general_performance_claim": False,
    }


def _is_absolute_path_token(token: str) -> bool:
    return (
        Path(token).is_absolute()
        or PurePosixPath(token).is_absolute()
        or PureWindowsPath(token).is_absolute()
    )


def _contains_absolute_path_fragment(value: str) -> bool:
    if _is_absolute_path_token(value):
        return True
    if re.search(r"(?i)(?:^|[\s=(,'\"])[a-z]:[\\/][^\s,;)\]'\"]*", value):
        return True
    if re.search(r"(?:^|[\s=(,'\"])/(?:[^\s,;)\]'\"]+)", value):
        return True
    return False


def _all_manifest_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        strings: list[str] = []
        for key, item in value.items():
            strings.extend(_all_manifest_strings(key))
            strings.extend(_all_manifest_strings(item))
        return strings
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        strings = []
        for item in value:
            strings.extend(_all_manifest_strings(item))
        return strings
    return []


def _validate_no_host_paths(value: Mapping[str, object]) -> None:
    sensitive = {
        str(Path.cwd().resolve()),
        str(Path.home().resolve()),
        str(Path(sys.executable).resolve()),
    }
    for item in _all_manifest_strings(value):
        folded = item.casefold()
        if _contains_absolute_path_fragment(item) or any(
            path and path.casefold() in folded for path in sensitive
        ):
            raise ValueError("benchmark manifest contains forbidden host path context")


def _dependency_lock_from_source(
    source: SourceBundle,
) -> dict[str, object]:
    payload = source.files.get(DEPENDENCY_LOCK_PATH)
    if payload is None:
        raise ValueError("source snapshot has no dependency lock")
    return {
        "path": DEPENDENCY_LOCK_PATH,
        "algorithm": "sha256",
        "sha256": _sha256(payload),
        "bytes": len(payload),
        "role": "declared CI dependency lock",
        "installed_environment_match_claim": False,
    }


def build_run_manifest(
    *,
    root: Path,
    results_path: Path,
    results_snapshot: StableFileSnapshot,
    source_bundle: SourceBundle,
    corpus: Mapping[str, object],
    settings: Mapping[str, object],
    baseline_definition: Mapping[str, object],
    run_id: str,
    engine_version: str,
    execution_environment: Mapping[str, object],
    effective_environment: Mapping[str, str],
    tool_identities: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build a manifest from one captured source and one stable result snapshot."""
    root = root.resolve()
    source = source_bundle.evidence
    if collect_source_evidence(root) != source:
        raise RuntimeError("benchmark source differs from the staged execution snapshot")
    source_inventory = source.get("files")
    if not isinstance(source_inventory, list):
        raise ValueError("benchmark source evidence has no file inventory")
    source_files: list[Path] = []
    for item in source_inventory:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ValueError("benchmark source evidence contains an invalid path")
        source_files.append(root / item["path"])
    environment = collect_environment(
        execution_environment,
        effective_environment=effective_environment,
        tool_identities=tool_identities,
    )
    environment = _validated_environment_record(environment)
    environment_record = environment["execution_environment"]
    interpreter_record = environment["case_interpreter"]
    assert isinstance(environment_record, dict)
    assert isinstance(interpreter_record, dict)
    environment_digest = environment_record["effective_environment_sha256"]
    interpreter_digest = interpreter_record["identity_sha256"]
    assert isinstance(environment_digest, str)
    assert isinstance(interpreter_digest, str)
    source_digest = source.get("sha256")
    if not isinstance(source_digest, str):
        raise ValueError("benchmark source digest is missing")
    rows = parse_rows_payload(results_snapshot.payload)
    results = collect_results_evidence(
        results_path,
        root,
        snapshot=results_snapshot,
    )
    contract_errors = validate_results_contract(
        rows,
        corpus=corpus,
        run_id=run_id,
        engine_version=engine_version,
        source_digest=source_digest,
        execution_environment_digest=environment_digest,
        interpreter_digest=interpreter_digest,
    )
    if contract_errors:
        raise ValueError("; ".join(contract_errors))
    observed_metrics = evaluate_rows(rows)
    observed_baseline_metrics = evaluate_baseline_rows(rows)
    security_evasion_metrics = evaluate_security_evasions_rows(rows)
    observed_timing = timing_summary(rows)
    bound_payloads = {
        **{(root / relative): payload for relative, payload in source_bundle.files.items()},
        results_path: results_snapshot.payload,
    }
    source_git = collect_git_state(
        root,
        bound_paths=tuple(source_files),
        source_paths=source_files,
        bound_payloads={
            root / relative: payload for relative, payload in source_bundle.files.items()
        },
    )
    source_commit = _source_commit_record(source_git)
    git = collect_git_state(
        root,
        bound_paths=(*source_files, results_path),
        source_paths=source_files,
        bound_payloads=bound_payloads,
    )
    dependency_lock = _dependency_lock_from_source(source_bundle)
    if collect_source_evidence(root) != source:
        raise RuntimeError("benchmark source content changed during manifest assembly")
    source_commit_bound = source_commit["bound"] is True
    manifest: dict[str, object] = {
        "schema_version": MANIFEST_SCHEMA,
        "benchmark_id": BENCHMARK_ID,
        "run_id": run_id,
        "engine_version": engine_version,
        "source": source,
        "corpus": collect_corpus_evidence(corpus),
        "results": results,
        "dependency_lock": dependency_lock,
        "metrics": observed_metrics,
        "security_evasion_metrics": security_evasion_metrics,
        "settings": dict(settings),
        "baseline": {
            "definition": dict(baseline_definition),
            "metrics": observed_baseline_metrics,
        },
        "timing": observed_timing,
        "invocation": {
            "entrypoint": "benchmarks/run_live.py",
            "required_controller_python_flags": ["-I"],
            "operation": "run-corpus",
            "reproduction_command": [
                "{python}",
                "-I",
                "benchmarks/run_live.py",
                "--out",
                "{results}",
                "--manifest",
                "{manifest}",
            ],
        },
        "environment": environment,
        "git": git,
        "provenance": {
            "workflow": PROVENANCE_WORKFLOW,
            "source_commit": source_commit,
            "evidence_commit": None,
            "final_manifest_in_evidence_commit": False,
        },
        "claims": _claim_record(
            source_commit_bound=source_commit_bound,
            evidence_commit_bound=False,
        ),
    }
    _validate_no_host_paths(manifest)
    return manifest


def manifest_bytes(manifest: Mapping[str, object]) -> bytes:
    return (
        json.dumps(
            manifest,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _validate_windows_destination_spelling(path: Path, *, label: str) -> None:
    if os.name != "nt":
        return
    supplied = os.fspath(path).replace("/", "\\")
    if supplied.startswith(("\\\\?\\", "\\\\.\\", "\\??\\")):
        raise ValueError(f"{label} must not use a Windows device namespace")
    lexical = Path(os.path.abspath(os.fspath(path)))
    anchor = Path(lexical.anchor)
    for component in lexical.relative_to(anchor).parts:
        if (
            ":" in component
            or component.endswith((" ", "."))
            or PureWindowsPath(component).is_reserved()
        ):
            raise ValueError(f"{label} has an unsafe Windows path component")


def _destination_path_without_symlinks(path: Path, *, label: str) -> Path:
    """Return an absolute path only when no existing component redirects it."""
    _validate_windows_destination_spelling(path, label=label)
    lexical = Path(os.path.abspath(os.fspath(path)))
    parts = lexical.parts
    current = Path(parts[0])
    for part in parts[1:]:
        current /= part
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            break
        is_junction = getattr(current, "is_junction", None)
        if stat.S_ISLNK(current_stat.st_mode) or (callable(is_junction) and is_junction()):
            raise ValueError(f"{label} must use a non-symlink path")
    resolved = lexical.resolve(strict=False)
    if os.path.normcase(str(resolved)) != os.path.normcase(str(lexical)):
        raise ValueError(f"{label} must use a non-symlink path")
    return resolved


@dataclass
class _PinnedDirectory:
    """An open destination directory that cannot be redirected by a later symlink."""

    path: Path
    identity: tuple[int, int]
    descriptor: int | None = None
    windows_handles: tuple[int, ...] = ()

    def close(self) -> None:
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None
        for handle in reversed(self.windows_handles):
            _close_windows_handle(handle)
        self.windows_handles = ()


@dataclass(frozen=True)
class _PinnedTarget:
    path: Path
    directory: _PinnedDirectory
    name: str


@dataclass
class _StagedFile:
    directory: _PinnedDirectory
    name: str
    identity: tuple[int, int]
    windows_handle: int | None = None
    published: bool = False

    @property
    def path(self) -> Path:
        return self.directory.path / self.name


def _file_identity(value: os.stat_result) -> tuple[int, int]:
    return (value.st_dev, value.st_ino)


def _load_windows_library(name: str, *, use_last_error: bool = False) -> Any:
    if os.name != "nt":
        raise RuntimeError("Windows library loading requires Windows")
    import ctypes

    loader = getattr(ctypes, "WinDLL", None)
    if not callable(loader):
        raise RuntimeError("ctypes WinDLL support is unavailable")
    return loader(name, use_last_error=use_last_error)


def _format_windows_error(error: int) -> str:
    import ctypes

    format_error = getattr(ctypes, "FormatError", None)
    if not callable(format_error):
        raise RuntimeError("ctypes Windows error formatting is unavailable")
    return str(format_error(error))


def _windows_last_error() -> tuple[int, str]:
    import ctypes

    get_last_error = getattr(ctypes, "get_last_error", None)
    if not callable(get_last_error):
        raise RuntimeError("ctypes Windows last-error support is unavailable")
    error = int(get_last_error())
    return error, _format_windows_error(error)


def _close_windows_handle(handle: int) -> None:
    if os.name != "nt":
        return
    from ctypes import wintypes

    close_handle = _load_windows_library(
        "kernel32",
        use_last_error=True,
    ).CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    close_handle(wintypes.HANDLE(handle))


def _windows_handle_information(handle: int) -> tuple[int, tuple[int, int]]:
    import ctypes
    from ctypes import wintypes

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    kernel32 = _load_windows_library("kernel32", use_last_error=True)
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    get_information.restype = wintypes.BOOL

    information = _ByHandleFileInformation()
    if not get_information(wintypes.HANDLE(handle), ctypes.byref(information)):
        error, detail = _windows_last_error()
        raise OSError(error, detail)
    identity = (
        int(information.dwVolumeSerialNumber),
        (int(information.nFileIndexHigh) << 32) | int(information.nFileIndexLow),
    )
    return int(information.dwFileAttributes), identity


def _open_windows_directory(path: Path) -> tuple[int, tuple[int, int]]:
    """Open one Windows directory without following its final reparse point."""
    import ctypes
    from ctypes import wintypes

    kernel32 = _load_windows_library("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    file_read_attributes = 0x0080
    synchronize = 0x00100000
    file_share_read = 0x00000001
    file_share_write = 0x00000002
    open_existing = 3
    file_flag_backup_semantics = 0x02000000
    file_flag_open_reparse_point = 0x00200000
    invalid_handle = ctypes.c_void_p(-1).value

    raw_handle = create_file(
        str(path),
        file_read_attributes | synchronize,
        file_share_read | file_share_write,
        None,
        open_existing,
        file_flag_backup_semantics | file_flag_open_reparse_point,
        None,
    )
    handle = int(raw_handle) if raw_handle is not None else 0
    if handle == invalid_handle:
        error, detail = _windows_last_error()
        raise OSError(error, detail, str(path))

    file_attribute_directory = 0x00000010
    file_attribute_reparse_point = 0x00000400
    try:
        attributes, identity = _windows_handle_information(handle)
    except BaseException:
        _close_windows_handle(handle)
        raise
    if not attributes & file_attribute_directory:
        _close_windows_handle(handle)
        raise NotADirectoryError(str(path))
    if attributes & file_attribute_reparse_point:
        _close_windows_handle(handle)
        raise ValueError("benchmark evidence destination must use a non-symlink path")
    return handle, identity


def _create_windows_staged_file(path: Path, payload: bytes) -> tuple[int, tuple[int, int]]:
    import ctypes
    from ctypes import wintypes

    kernel32 = _load_windows_library("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    write_file = kernel32.WriteFile
    write_file.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    write_file.restype = wintypes.BOOL
    flush_file = kernel32.FlushFileBuffers
    flush_file.argtypes = [wintypes.HANDLE]
    flush_file.restype = wintypes.BOOL

    generic_read = 0x80000000
    generic_write = 0x40000000
    delete_access = 0x00010000
    file_read_attributes = 0x00000080
    synchronize = 0x00100000
    create_new = 1
    file_attribute_temporary = 0x00000100
    file_flag_open_reparse_point = 0x00200000
    invalid_handle = ctypes.c_void_p(-1).value
    raw_handle = create_file(
        str(path),
        generic_read | generic_write | delete_access | file_read_attributes | synchronize,
        0,
        None,
        create_new,
        file_attribute_temporary | file_flag_open_reparse_point,
        None,
    )
    handle = int(raw_handle) if raw_handle is not None else 0
    if handle == invalid_handle:
        error, detail = _windows_last_error()
        if error in {80, 183}:
            raise FileExistsError(error, detail, str(path))
        raise OSError(error, detail, str(path))
    try:
        if payload:
            buffer = ctypes.create_string_buffer(payload)
            written = wintypes.DWORD()
            if not write_file(
                wintypes.HANDLE(handle),
                buffer,
                len(payload),
                ctypes.byref(written),
                None,
            ) or written.value != len(payload):
                error, detail = _windows_last_error()
                raise OSError(error, detail, str(path))
        if not flush_file(wintypes.HANDLE(handle)):
            error, detail = _windows_last_error()
            raise OSError(error, detail, str(path))
        attributes, identity = _windows_handle_information(handle)
        if attributes & (0x00000010 | 0x00000400):
            raise ValueError("benchmark staging object is not a regular file")
    except BaseException:
        _dispose_windows_file(handle)
        _close_windows_handle(handle)
        raise
    return handle, identity


def _windows_rename_relative(
    source_handle: int,
    destination_directory_handle: int,
    destination_name: str,
    *,
    replace: bool,
) -> None:
    """Rename an open file relative to a retained directory handle."""
    import ctypes
    from ctypes import wintypes

    class _FileRenameInformation(ctypes.Structure):
        _fields_ = [
            ("ReplaceIfExists", wintypes.BOOLEAN),
            ("RootDirectory", wintypes.HANDLE),
            ("FileNameLength", wintypes.DWORD),
            ("FileName", wintypes.WCHAR * 1),
        ]

    class _IoStatusBlock(ctypes.Structure):
        _fields_ = [
            ("Status", ctypes.c_void_p),
            ("Information", ctypes.c_size_t),
        ]

    encoded_name = destination_name.encode("utf-16-le")
    name_offset = _FileRenameInformation.FileName.offset
    buffer = ctypes.create_string_buffer(name_offset + len(encoded_name))
    information = ctypes.cast(
        buffer,
        ctypes.POINTER(_FileRenameInformation),
    ).contents
    information.ReplaceIfExists = replace
    information.RootDirectory = wintypes.HANDLE(destination_directory_handle)
    information.FileNameLength = len(encoded_name)
    ctypes.memmove(
        ctypes.addressof(buffer) + name_offset,
        encoded_name,
        len(encoded_name),
    )

    ntdll = _load_windows_library("ntdll")
    try:
        set_information = ntdll.NtSetInformationFile
        convert_status = ntdll.RtlNtStatusToDosError
    except AttributeError as exc:
        raise RuntimeError("required Windows relative-rename primitive is unavailable") from exc
    set_information.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_IoStatusBlock),
        wintypes.LPVOID,
        wintypes.ULONG,
        ctypes.c_int,
    ]
    set_information.restype = ctypes.c_long
    status_block = _IoStatusBlock()
    file_rename_information = 10
    status = set_information(
        wintypes.HANDLE(source_handle),
        ctypes.byref(status_block),
        buffer,
        len(buffer),
        file_rename_information,
    )
    if status != 0:
        convert_status.argtypes = [ctypes.c_long]
        convert_status.restype = wintypes.ULONG
        error = int(convert_status(status))
        if error in {80, 183}:
            raise FileExistsError(
                error,
                _format_windows_error(error),
                destination_name,
            )
        raise OSError(error, _format_windows_error(error), destination_name)


def _dispose_windows_file(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    class _FileDispositionInformation(ctypes.Structure):
        _fields_ = [("DeleteFile", wintypes.BOOLEAN)]

    kernel32 = _load_windows_library("kernel32", use_last_error=True)
    set_information = kernel32.SetFileInformationByHandle
    set_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    set_information.restype = wintypes.BOOL
    information = _FileDispositionInformation(True)
    file_disposition_info = 4
    if not set_information(
        wintypes.HANDLE(handle),
        file_disposition_info,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        error, detail = _windows_last_error()
        raise OSError(error, detail)


def _open_pinned_directory(path: Path) -> _PinnedDirectory:
    if not path.is_absolute():
        raise ValueError("benchmark evidence parent must be absolute")
    if os.name == "nt":
        anchor = Path(path.anchor)
        current = anchor
        handles: list[int] = []
        identity = (0, 0)
        try:
            handle, identity = _open_windows_directory(current)
            handles.append(handle)
            for component in path.relative_to(anchor).parts:
                current /= component
                handle, identity = _open_windows_directory(current)
                handles.append(handle)
        except BaseException:
            for handle in reversed(handles):
                _close_windows_handle(handle)
            raise
        return _PinnedDirectory(
            path=path,
            identity=identity,
            windows_handles=tuple(handles),
        )

    required_dir_fd_operations = (os.open, os.link, os.rename, os.stat, os.unlink)
    if any(operation not in os.supports_dir_fd for operation in required_dir_fd_operations):
        raise RuntimeError("secure directory-relative publication is unavailable")
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not no_follow or not directory_flag:
        raise RuntimeError("secure no-follow directory opening is unavailable")
    flags = os.O_RDONLY | no_follow | directory_flag | getattr(os, "O_CLOEXEC", 0)
    anchor = Path(path.anchor)
    descriptor = os.open(anchor, flags)
    try:
        for component in path.relative_to(anchor).parts:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        identity = _file_identity(os.fstat(descriptor))
    except BaseException:
        os.close(descriptor)
        raise
    return _PinnedDirectory(path=path, identity=identity, descriptor=descriptor)


def _assert_pinned_directory_binding(directory: _PinnedDirectory) -> None:
    current = _open_pinned_directory(directory.path)
    try:
        if current.identity != directory.identity:
            raise RuntimeError("benchmark evidence destination namespace changed")
    finally:
        current.close()


def _target_lstat(target: _PinnedTarget) -> os.stat_result | None:
    try:
        if target.directory.descriptor is not None:
            return os.stat(
                target.name,
                dir_fd=target.directory.descriptor,
                follow_symlinks=False,
            )
        return target.path.lstat()
    except FileNotFoundError:
        return None


def _validate_pinned_target(target: _PinnedTarget) -> None:
    target_stat = _target_lstat(target)
    if target_stat is None:
        return
    is_junction = getattr(target.path, "is_junction", None)
    if (
        stat.S_ISLNK(target_stat.st_mode)
        or not stat.S_ISREG(target_stat.st_mode)
        or (callable(is_junction) and is_junction())
    ):
        raise ValueError("benchmark evidence destination must be a non-symlink regular file")


@contextmanager
def _pin_targets(paths: Sequence[Path]) -> Iterator[tuple[_PinnedTarget, ...]]:
    directories: dict[str, _PinnedDirectory] = {}
    targets: list[_PinnedTarget] = []
    try:
        for supplied in paths:
            path = _destination_path_without_symlinks(
                supplied,
                label="benchmark evidence destination",
            )
            if not path.parent.exists():
                raise FileNotFoundError(f"benchmark evidence parent does not exist: {path.parent}")
            key = os.path.normcase(str(path.parent))
            directory = directories.get(key)
            if directory is None:
                directory = _open_pinned_directory(path.parent)
                directories[key] = directory
            target = _PinnedTarget(path=path, directory=directory, name=path.name)
            _validate_pinned_target(target)
            targets.append(target)
        for directory in directories.values():
            _assert_pinned_directory_binding(directory)
        yield tuple(targets)
        for directory in directories.values():
            _assert_pinned_directory_binding(directory)
    finally:
        for directory in reversed(tuple(directories.values())):
            directory.close()


def _unlink_from_directory(directory: _PinnedDirectory, name: str) -> None:
    try:
        if directory.descriptor is not None:
            os.unlink(name, dir_fd=directory.descriptor)
        else:
            (directory.path / name).unlink()
    except FileNotFoundError:
        pass


def _stage_bytes(target: _PinnedTarget, payload: bytes) -> _StagedFile:
    if target.directory.descriptor is None:
        for _attempt in range(128):
            temporary_name = f".evoguard-{secrets.token_hex(16)}.tmp"
            try:
                windows_handle, identity = _create_windows_staged_file(
                    target.directory.path / temporary_name,
                    payload,
                )
            except FileExistsError:
                continue
            staged = _StagedFile(
                directory=target.directory,
                name=temporary_name,
                identity=identity,
                windows_handle=windows_handle,
            )
            try:
                _assert_pinned_directory_binding(target.directory)
            except BaseException:
                _cleanup_staged_file(staged)
                raise
            return staged
        raise FileExistsError("unable to allocate an evidence staging file")

    descriptor = -1
    temporary_name = ""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    for _attempt in range(128):
        temporary_name = f".evoguard-{secrets.token_hex(16)}.tmp"
        try:
            if target.directory.descriptor is not None:
                descriptor = os.open(
                    temporary_name,
                    flags,
                    0o600,
                    dir_fd=target.directory.descriptor,
                )
            else:
                descriptor = os.open(
                    target.directory.path / temporary_name,
                    flags,
                    0o600,
                )
        except FileExistsError:
            continue
        break
    if descriptor < 0:
        raise FileExistsError("unable to allocate an evidence staging file")
    identity = _file_identity(os.fstat(descriptor))
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        _unlink_from_directory(target.directory, temporary_name)
        raise
    return _StagedFile(
        directory=target.directory,
        name=temporary_name,
        identity=identity,
    )


def _assert_staged_identity(staged: _StagedFile, target: _PinnedTarget | None = None) -> None:
    if staged.windows_handle is not None:
        _attributes, observed_identity = _windows_handle_information(staged.windows_handle)
        if observed_identity != staged.identity:
            raise RuntimeError("benchmark evidence staging identity changed")
        if target is not None:
            observed = _target_lstat(target)
            if observed is None or observed.st_ino != staged.identity[1]:
                raise RuntimeError("benchmark evidence staging identity changed")
        return
    checked_target = (
        _PinnedTarget(
            path=staged.path,
            directory=staged.directory,
            name=staged.name,
        )
        if target is None
        else target
    )
    observed = _target_lstat(checked_target)
    if observed is None or _file_identity(observed) != staged.identity:
        raise RuntimeError("benchmark evidence staging identity changed")


def _cleanup_staged_file(staged: _StagedFile) -> None:
    if staged.windows_handle is not None:
        handle = staged.windows_handle
        staged.windows_handle = None
        try:
            if not staged.published:
                _dispose_windows_file(handle)
        finally:
            _close_windows_handle(handle)
        return
    _unlink_from_directory(staged.directory, staged.name)


def _target_matches_published(
    target: _PinnedTarget,
    published: _StagedFile,
) -> bool:
    observed = _target_lstat(target)
    if observed is None:
        return False
    if os.name == "nt":
        if published.windows_handle is None:
            return False
        _attributes, handle_identity = _windows_handle_information(published.windows_handle)
        return (
            handle_identity == published.identity
            and target.directory.identity[0] == published.identity[0]
            and observed.st_ino == published.identity[1]
        )
    return _file_identity(observed) == published.identity


def _read_windows_published_file(
    staged: _StagedFile,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    """Read back exact published bytes through the retained exclusive handle."""
    if os.name != "nt" or staged.windows_handle is None or not staged.published:
        raise RuntimeError(f"{label} has no retained Windows publication handle")
    import ctypes
    from ctypes import wintypes

    kernel32 = _load_windows_library("kernel32", use_last_error=True)
    get_size = kernel32.GetFileSizeEx
    get_size.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
    get_size.restype = wintypes.BOOL
    set_pointer = kernel32.SetFilePointerEx
    set_pointer.argtypes = [
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.DWORD,
    ]
    set_pointer.restype = wintypes.BOOL
    read_file = kernel32.ReadFile
    read_file.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    read_file.restype = wintypes.BOOL

    size = ctypes.c_longlong()
    if not get_size(wintypes.HANDLE(staged.windows_handle), ctypes.byref(size)):
        error, detail = _windows_last_error()
        raise OSError(error, detail, label)
    if size.value < 0 or size.value > max_bytes:
        raise ValueError(f"{label} exceeds the {max_bytes}-byte bound")
    new_position = ctypes.c_longlong()
    if not set_pointer(
        wintypes.HANDLE(staged.windows_handle),
        0,
        ctypes.byref(new_position),
        0,
    ):
        error, detail = _windows_last_error()
        raise OSError(error, detail, label)

    chunks: list[bytes] = []
    remaining = size.value
    while remaining:
        requested = min(1024 * 1024, remaining)
        buffer = ctypes.create_string_buffer(requested)
        received = wintypes.DWORD()
        if not read_file(
            wintypes.HANDLE(staged.windows_handle),
            buffer,
            requested,
            ctypes.byref(received),
            None,
        ):
            error, detail = _windows_last_error()
            raise OSError(error, detail, label)
        if received.value == 0 or received.value > requested:
            raise RuntimeError(f"{label} returned an invalid read length")
        chunks.append(buffer.raw[: received.value])
        remaining -= received.value
    _assert_staged_identity(staged)
    return b"".join(chunks)


def _publish_staged_file(
    temporary: _StagedFile,
    target: _PinnedTarget,
    *,
    replace: bool,
) -> None:
    _assert_staged_identity(temporary)
    if temporary.windows_handle is not None:
        if not target.directory.windows_handles:
            raise RuntimeError("Windows destination directory is not pinned")
        _windows_rename_relative(
            temporary.windows_handle,
            target.directory.windows_handles[-1],
            target.name,
            replace=replace,
        )
        temporary.published = True
        _assert_staged_identity(temporary)
        return
    if replace:
        if target.directory.descriptor is not None:
            os.rename(
                temporary.name,
                target.name,
                src_dir_fd=temporary.directory.descriptor,
                dst_dir_fd=target.directory.descriptor,
            )
        else:
            os.replace(temporary.path, target.path)
    else:
        if target.directory.descriptor is not None:
            os.link(
                temporary.name,
                target.name,
                src_dir_fd=temporary.directory.descriptor,
                dst_dir_fd=target.directory.descriptor,
                follow_symlinks=False,
            )
        else:
            os.link(temporary.path, target.path)
        _unlink_from_directory(temporary.directory, temporary.name)
    temporary.published = True
    _assert_staged_identity(temporary, target)


def write_run_manifest(
    path: Path,
    manifest: Mapping[str, object],
    *,
    replace: bool = False,
) -> None:
    """Publish one manifest create-only by default; replacement is explicit."""
    _publish_single_file(path, manifest_bytes(manifest), replace=replace)


def _existing_path_is_protected_alias(
    target: Path,
    protected: Sequence[Path],
) -> bool:
    if not target.exists():
        return False
    for candidate in protected:
        try:
            if candidate.exists() and os.path.samefile(target, candidate):
                return True
        except OSError:
            return True
    return False


def validate_evidence_destinations(
    *,
    root: Path,
    results_path: Path,
    manifest_path: Path,
    replace: bool,
    _allow_results_only_initialization: bool = False,
) -> tuple[Path, Path]:
    """Resolve output targets without mutation and reject aliases/protected paths."""
    root = root.resolve()
    results = _destination_path_without_symlinks(
        results_path,
        label="results destination",
    )
    manifest = _destination_path_without_symlinks(
        manifest_path,
        label="manifest destination",
    )
    if results == manifest:
        raise ValueError("results and manifest destinations must be distinct")
    if results.suffix != ".jsonl" or manifest.suffix != ".json":
        raise ValueError("benchmark evidence destinations have invalid file types")
    for label, target in (("results", results), ("manifest", manifest)):
        try:
            relative = target.relative_to(root)
        except ValueError:
            relative = None
        if relative is not None and (
            not relative.parts or relative.parts[0] not in {"benchmarks", "work"}
        ):
            raise ValueError(f"{label} destination inside the repository is not evidence-only")
        try:
            target_stat = target.lstat()
        except FileNotFoundError:
            target_stat = None
        if target_stat is not None and (
            stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode)
        ):
            raise ValueError(f"{label} destination must be a non-symlink regular file")

    protected = [
        *(root / relative for relative in source_inventory_paths(root)),
        root / "benchmarks" / "sample.jsonl",
        root / "adversarial" / "corpus.jsonl",
    ]
    for label, target in (("results", results), ("manifest", manifest)):
        if target in {path.resolve(strict=False) for path in protected}:
            raise ValueError(f"{label} destination aliases protected project input")
        if _existing_path_is_protected_alias(target, protected):
            raise ValueError(f"{label} destination hard-links protected project input")
    if results.exists() and manifest.exists():
        try:
            if os.path.samefile(results, manifest):
                raise ValueError("results and manifest destinations alias one file")
        except OSError as exc:
            raise ValueError("evidence destination identity is unreadable") from exc

    existence = (results.exists(), manifest.exists())
    if not replace and any(existence):
        raise FileExistsError("benchmark evidence exists; pass --replace explicitly")
    if (
        replace
        and existence[0] is not existence[1]
        and not (_allow_results_only_initialization and existence == (True, False))
    ):
        raise ValueError("refusing to replace a pre-existing torn evidence pair")
    return results, manifest


def validate_initial_evidence_destinations(
    *,
    root: Path,
    results_path: Path,
    manifest_path: Path,
    replace: bool,
) -> tuple[Path, Path, EvidenceInitialization]:
    """Authorize the one canonical results-only to evidence-pair migration."""
    root = root.resolve()
    if not replace:
        raise ValueError("initial evidence publication requires explicit replacement")
    results, manifest = validate_evidence_destinations(
        root=root,
        results_path=results_path,
        manifest_path=manifest_path,
        replace=True,
        _allow_results_only_initialization=True,
    )
    canonical_results = (root / "benchmarks" / "results.jsonl").resolve(strict=False)
    canonical_manifest = (root / "benchmarks" / "run-manifest.json").resolve(strict=False)
    if (results, manifest) != (canonical_results, canonical_manifest):
        raise ValueError("initial evidence publication is limited to the canonical benchmark pair")
    if not results.exists() or manifest.exists():
        raise ValueError("initial evidence publication requires existing results and no manifest")
    snapshot = read_stable_regular_file(
        results,
        max_bytes=MAX_RESULTS_BYTES,
        label="existing canonical benchmark results",
    )
    results_stat = results.lstat()
    if results_stat.st_nlink != 1:
        raise ValueError("initial evidence publication refuses hard-linked canonical results")
    git = collect_git_state(
        root,
        bound_paths=(results,),
        bound_payloads={results: snapshot.payload},
    )
    if git.get("source_and_results_commit_bound") is not True:
        raise ValueError("initial evidence publication requires clean results matching Git HEAD")
    head = git.get("head")
    top_result = _git(root, ("rev-parse", "--show-toplevel"))
    if not isinstance(head, str) or top_result is None or top_result.returncode != 0:
        raise ValueError("initial evidence publication Git identity is unavailable")
    git_root = Path(top_result.stdout.strip()).resolve()
    entries = _head_tree_entries(git_root, head, (results, manifest))
    if (
        entries is None
        or entries.get(results) != ("100644", "blob")
        or entries.get(manifest) is not None
    ):
        raise ValueError(
            "initial evidence publication requires a 100644 results blob "
            "and no manifest at Git HEAD"
        )
    with _pin_targets((results, manifest)) as (
        results_target,
        manifest_target,
    ):
        pinned_results_stat = _target_lstat(results_target)
        if (
            pinned_results_stat is None
            or _path_descriptor_identity(pinned_results_stat)
            != (
                snapshot.device,
                snapshot.inode,
                snapshot.size,
                snapshot.mtime_ns,
            )
            or pinned_results_stat.st_nlink != 1
            or _target_lstat(manifest_target) is not None
        ):
            raise RuntimeError(
                "canonical benchmark destinations changed during initialization preflight"
            )
        initialization = EvidenceInitialization(
            root=root,
            results_path=results,
            manifest_path=manifest,
            head=head,
            results_snapshot=snapshot,
            results_parent_identity=results_target.directory.identity,
            manifest_parent_identity=manifest_target.directory.identity,
        )
    return results, manifest, initialization


def validate_results_destination(
    *,
    root: Path,
    results_path: Path,
    replace: bool,
) -> Path:
    """Validate a standalone preflight-result destination without mutation."""
    root = root.resolve()
    results = _destination_path_without_symlinks(
        results_path,
        label="result destination",
    )
    if results.suffix != ".jsonl":
        raise ValueError("benchmark result destination must end in .jsonl")
    try:
        relative = results.relative_to(root)
    except ValueError:
        relative = None
    if relative is not None and (
        not relative.parts or relative.parts[0] not in {"benchmarks", "work"}
    ):
        raise ValueError("result destination inside the repository is not evidence-only")
    try:
        target_stat = results.lstat()
    except FileNotFoundError:
        target_stat = None
    if target_stat is not None and (
        stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode)
    ):
        raise ValueError("result destination must be a non-symlink regular file")
    protected = [
        *(root / relative for relative in source_inventory_paths(root)),
        root / "benchmarks" / "sample.jsonl",
        root / "adversarial" / "corpus.jsonl",
    ]
    if results in {
        path.resolve(strict=False) for path in protected
    } or _existing_path_is_protected_alias(results, protected):
        raise ValueError("result destination aliases protected project input")
    if results.exists() and not replace:
        raise FileExistsError("benchmark results exist; pass --replace explicitly")
    return results


def _read_pinned_regular_file(
    target: _PinnedTarget,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    before_path = _target_lstat(target)
    if before_path is None:
        raise FileNotFoundError(str(target.path))
    if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
        raise ValueError(f"{label} must be a non-symlink regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if target.directory.descriptor is not None:
        descriptor = os.open(
            target.name,
            flags,
            dir_fd=target.directory.descriptor,
        )
    else:
        descriptor = os.open(target.path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or _path_descriptor_identity(
            before_path
        ) != _path_descriptor_identity(before):
            raise RuntimeError(f"{label} changed before its stable read")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"{label} exceeds the {max_bytes}-byte bound")
        after = os.fstat(descriptor)
        if _stat_identity(before) != _stat_identity(after) or size != after.st_size:
            raise RuntimeError(f"{label} changed during its stable read")
    finally:
        os.close(descriptor)
    after_path = _target_lstat(target)
    if (
        after_path is None
        or stat.S_ISLNK(after_path.st_mode)
        or not stat.S_ISREG(after_path.st_mode)
        or _path_descriptor_identity(after_path) != _path_descriptor_identity(after)
    ):
        raise RuntimeError(f"{label} path was replaced during its stable read")
    return b"".join(chunks)


def _fsync_parent(target: _PinnedTarget) -> None:
    if os.name == "nt":
        return
    if target.directory.descriptor is None:
        raise RuntimeError("benchmark destination directory is not pinned")
    os.fsync(target.directory.descriptor)


def _restore_target(
    target: _PinnedTarget,
    payload: bytes | None,
    *,
    published: _StagedFile | None = None,
    rollback: _StagedFile | None = None,
) -> None:
    if published is not None:
        if not _target_matches_published(target, published):
            raise RuntimeError(
                "benchmark evidence changed before rollback; automatic recovery was refused"
            )
    disposed_by_windows_handle = False
    if published is not None and published.windows_handle is not None:
        published_handle = published.windows_handle
        published.windows_handle = None
        try:
            if payload is None:
                _dispose_windows_file(published_handle)
                disposed_by_windows_handle = True
        finally:
            _close_windows_handle(published_handle)
    if payload is None:
        if not disposed_by_windows_handle:
            _unlink_from_directory(target.directory, target.name)
        return
    temporary = rollback if rollback is not None else _stage_bytes(target, payload)
    try:
        _publish_staged_file(temporary, target, replace=True)
    finally:
        if rollback is None:
            _cleanup_staged_file(temporary)


def _publish_single_file(path: Path, payload: bytes, *, replace: bool) -> None:
    with _pin_targets((path,)) as (target,):
        target_exists = _target_lstat(target) is not None
        if not replace and target_exists:
            raise FileExistsError("benchmark evidence exists; replacement was not requested")
        old_payload: bytes | None = None
        if replace and target_exists:
            old_payload = _read_pinned_regular_file(
                target,
                max_bytes=max(MAX_RESULTS_BYTES, MAX_MANIFEST_BYTES),
                label="existing benchmark evidence",
            )
        temporary = _stage_bytes(target, payload)
        rollback: _StagedFile | None = None
        try:
            if old_payload is not None:
                rollback = _stage_bytes(target, old_payload)
            _assert_pinned_directory_binding(target.directory)
            _publish_staged_file(temporary, target, replace=replace)
            _assert_pinned_directory_binding(target.directory)
            _fsync_parent(target)
            _assert_pinned_directory_binding(target.directory)
        except BaseException:
            if temporary.published:
                _restore_target(
                    target,
                    old_payload,
                    published=temporary,
                    rollback=rollback,
                )
                _fsync_parent(target)
                _assert_pinned_directory_binding(target.directory)
            raise
        finally:
            _cleanup_staged_file(temporary)
            if rollback is not None:
                _cleanup_staged_file(rollback)


def publish_evidence_pair(
    *,
    results_path: Path,
    results_payload: bytes,
    manifest_path: Path,
    manifest_payload: bytes,
    replace: bool,
    initialization: EvidenceInitialization | None = None,
) -> None:
    """Publish a generation-linked pair and roll back ordinary second-write failure."""
    if results_path.suffix != ".jsonl" or manifest_path.suffix != ".json":
        raise ValueError("benchmark evidence destinations have invalid file types")
    if os.path.normcase(os.path.abspath(results_path)) == os.path.normcase(
        os.path.abspath(manifest_path)
    ):
        raise ValueError("results and manifest destinations must be distinct")
    parsed_manifest = json.loads(
        manifest_payload.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    if not isinstance(parsed_manifest, dict):
        raise ValueError("benchmark manifest root must be an object")
    run_id = parsed_manifest.get("run_id")
    if not isinstance(run_id, str) or not RUN_ID_PATTERN.fullmatch(run_id):
        raise ValueError("benchmark evidence pair has an invalid run id")
    rows = parse_rows_payload(results_payload)
    if not rows or any(row.get("run_id") != run_id for row in rows):
        raise ValueError("benchmark evidence pair run ids do not match")
    recorded_results = parsed_manifest.get("results")
    if (
        not isinstance(recorded_results, dict)
        or recorded_results.get("sha256") != _sha256(results_payload)
        or recorded_results.get("bytes") != len(results_payload)
        or recorded_results.get("rows") != len(rows)
    ):
        raise ValueError("benchmark evidence pair result digest does not match")

    with _pin_targets((results_path, manifest_path)) as (
        results_target,
        manifest_target,
    ):
        results_stat = _target_lstat(results_target)
        manifest_stat = _target_lstat(manifest_target)
        existence = (results_stat is not None, manifest_stat is not None)
        if not replace and any(existence):
            raise FileExistsError("benchmark evidence exists; replacement was not requested")
        if initialization is not None and not replace:
            raise ValueError("initial evidence publication requires explicit replacement")
        if initialization is not None and existence != (True, False):
            raise ValueError("initial evidence publication state changed before publication")
        if replace and existence[0] is not existence[1] and initialization is None:
            raise ValueError("refusing to replace a pre-existing torn evidence pair")
        if (
            results_stat is not None
            and manifest_stat is not None
            and _file_identity(results_stat) == _file_identity(manifest_stat)
        ):
            raise ValueError("results and manifest destinations alias one file")
        old_results: bytes | None = None
        old_manifest: bytes | None = None
        if initialization is not None:
            expected_paths = (
                initialization.results_path.resolve(strict=False),
                initialization.manifest_path.resolve(strict=False),
            )
            actual_paths = (
                results_target.path.resolve(strict=False),
                manifest_target.path.resolve(strict=False),
            )
            if actual_paths != expected_paths:
                raise ValueError("initial evidence publication capability targets another pair")
            if (
                results_target.directory.identity != initialization.results_parent_identity
                or manifest_target.directory.identity != initialization.manifest_parent_identity
            ):
                raise RuntimeError(
                    "canonical benchmark parent changed after initialization preflight"
                )
            snapshot = initialization.results_snapshot
            if (
                results_stat is None
                or _path_descriptor_identity(results_stat)
                != (
                    snapshot.device,
                    snapshot.inode,
                    snapshot.size,
                    snapshot.mtime_ns,
                )
                or results_stat.st_nlink != 1
            ):
                raise RuntimeError(
                    "canonical benchmark results changed after initialization preflight"
                )
            current_git = collect_git_state(
                initialization.root,
                bound_paths=(results_target.path,),
                bound_payloads={results_target.path: initialization.results_snapshot.payload},
            )
            if (
                current_git.get("head") != initialization.head
                or current_git.get("source_and_results_commit_bound") is not True
            ):
                raise RuntimeError("Git state changed after evidence initialization preflight")
        if replace and all(existence):
            old_results = _read_pinned_regular_file(
                results_target,
                max_bytes=MAX_RESULTS_BYTES,
                label="existing benchmark results",
            )
            old_manifest = _read_pinned_regular_file(
                manifest_target,
                max_bytes=MAX_MANIFEST_BYTES,
                label="existing benchmark manifest",
            )
        elif initialization is not None:
            old_results = _read_pinned_regular_file(
                results_target,
                max_bytes=MAX_RESULTS_BYTES,
                label="existing canonical benchmark results",
            )
            if old_results != initialization.results_snapshot.payload:
                raise RuntimeError(
                    "canonical benchmark results changed after initialization preflight"
                )

        staged_results: _StagedFile | None = None
        staged_manifest: _StagedFile | None = None
        rollback_results: _StagedFile | None = None
        rollback_manifest: _StagedFile | None = None
        try:
            staged_results = _stage_bytes(results_target, results_payload)
            staged_manifest = _stage_bytes(manifest_target, manifest_payload)
            if old_results is not None:
                rollback_results = _stage_bytes(results_target, old_results)
            if old_manifest is not None:
                rollback_manifest = _stage_bytes(manifest_target, old_manifest)
            _assert_pinned_directory_binding(results_target.directory)
            _assert_pinned_directory_binding(manifest_target.directory)
            if initialization is not None:
                current_results_stat = _target_lstat(results_target)
                if (
                    current_results_stat is None
                    or results_stat is None
                    or _stat_identity(current_results_stat) != _stat_identity(results_stat)
                    or _target_lstat(manifest_target) is not None
                ):
                    raise RuntimeError(
                        "canonical benchmark destinations changed before publication"
                    )
            _publish_staged_file(
                staged_results,
                results_target,
                replace=replace,
            )
            _assert_pinned_directory_binding(results_target.directory)
            _publish_staged_file(
                staged_manifest,
                manifest_target,
                replace=False if initialization is not None else replace,
            )
            _assert_pinned_directory_binding(results_target.directory)
            _assert_pinned_directory_binding(manifest_target.directory)
            _fsync_parent(results_target)
            if manifest_target.directory is not results_target.directory:
                _fsync_parent(manifest_target)
            _assert_pinned_directory_binding(results_target.directory)
            _assert_pinned_directory_binding(manifest_target.directory)
            if os.name == "nt":
                observed_results = _read_windows_published_file(
                    staged_results,
                    max_bytes=MAX_RESULTS_BYTES,
                    label="published benchmark results",
                )
                observed_manifest = _read_windows_published_file(
                    staged_manifest,
                    max_bytes=MAX_MANIFEST_BYTES,
                    label="published benchmark manifest",
                )
            else:
                observed_results = _read_pinned_regular_file(
                    results_target,
                    max_bytes=MAX_RESULTS_BYTES,
                    label="published benchmark results",
                )
                observed_manifest = _read_pinned_regular_file(
                    manifest_target,
                    max_bytes=MAX_MANIFEST_BYTES,
                    label="published benchmark manifest",
                )
            if observed_results != results_payload or observed_manifest != manifest_payload:
                raise RuntimeError("benchmark evidence publication readback mismatch")
        except BaseException:
            rollback_errors: list[BaseException] = []
            result_published = staged_results is not None and staged_results.published
            manifest_published = staged_manifest is not None and staged_manifest.published
            if manifest_published and staged_manifest is not None:
                try:
                    _restore_target(
                        manifest_target,
                        old_manifest,
                        published=staged_manifest,
                        rollback=rollback_manifest,
                    )
                except BaseException as exc:
                    rollback_errors.append(exc)
            if result_published and staged_results is not None:
                try:
                    _restore_target(
                        results_target,
                        old_results,
                        published=staged_results,
                        rollback=rollback_results,
                    )
                except BaseException as exc:
                    rollback_errors.append(exc)
            restored_directories: set[int] = set()
            for restored, target in (
                (result_published, results_target),
                (manifest_published, manifest_target),
            ):
                directory_key = id(target.directory)
                if not restored or directory_key in restored_directories:
                    continue
                restored_directories.add(directory_key)
                try:
                    _fsync_parent(target)
                    _assert_pinned_directory_binding(target.directory)
                except BaseException as exc:
                    rollback_errors.append(exc)
            if rollback_errors:
                raise RuntimeError(
                    "benchmark evidence publication and rollback both failed"
                ) from rollback_errors[0]
            raise
        finally:
            if staged_results is not None:
                _cleanup_staged_file(staged_results)
            if staged_manifest is not None:
                _cleanup_staged_file(staged_manifest)
            if rollback_results is not None:
                _cleanup_staged_file(rollback_results)
            if rollback_manifest is not None:
                _cleanup_staged_file(rollback_manifest)


def publish_results_file(
    path: Path,
    payload: bytes,
    *,
    replace: bool,
) -> None:
    """Publish a standalone preflight result without implicit replacement."""
    _publish_single_file(path, payload, replace=replace)


def load_run_manifest(path: Path) -> dict[str, object]:
    snapshot = read_stable_regular_file(
        path,
        max_bytes=MAX_MANIFEST_BYTES,
        label="benchmark manifest",
    )
    value = json.loads(
        snapshot.payload.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    if not isinstance(value, dict):
        raise ValueError("benchmark manifest root must be an object")
    return value


def _results_path_from_evidence(
    root: Path,
    results: object,
) -> Path | None:
    if not isinstance(results, dict) or not isinstance(results.get("path"), str):
        return None
    candidate = Path(results["path"])
    if results["path"] == "{external-results}":
        return None
    return candidate if candidate.is_absolute() else root / candidate


def _source_items_and_paths(
    root: Path,
    source: object,
) -> tuple[list[dict[str, object]], list[Path], list[str]]:
    items: list[dict[str, object]] = []
    paths: list[Path] = []
    errors: list[str] = []
    if not isinstance(source, dict) or not isinstance(source.get("files"), list):
        return items, paths, ["commit-bound source inventory is invalid"]
    for item in source["files"]:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("path"), str)
            or not isinstance(item.get("sha256"), str)
            or type(item.get("bytes")) is not int
        ):
            errors.append("commit-bound source inventory entry is invalid")
            continue
        items.append(item)
        paths.append(root / str(item["path"]))
    return items, paths, errors


def _verify_commit_bound_source_blobs(
    root: Path,
    *,
    head: object,
    source: object,
) -> tuple[str, ...]:
    """Verify the selected source inventory against one recorded Git commit."""
    if not isinstance(head, str) or not head:
        return ("source commit binding has no usable Git commit",)
    top_result = _git(root, ("rev-parse", "--show-toplevel"))
    if top_result is None or top_result.returncode != 0:
        return ("source commit-bound Git repository is unavailable",)
    git_root = Path(top_result.stdout.strip()).resolve()
    source_items, blob_paths, errors = _source_items_and_paths(root, source)
    recorded_paths = frozenset(str(item["path"]) for item in source_items)
    head_paths = _head_source_inventory(git_root, root, head)
    if head_paths is None or recorded_paths != head_paths:
        errors.append("source commit inventory differs from recorded commit")
    blobs = _head_blobs(git_root, head, blob_paths)
    if blobs is None:
        errors.append("source commit blobs are unreadable")
        return tuple(errors)
    for item in source_items:
        source_path = root / str(item["path"])
        blob = blobs.get(source_path.resolve())
        if blob is None:
            errors.append(f"source missing at recorded commit: {item['path']}")
        elif len(blob) != item["bytes"] or _sha256(blob) != item["sha256"]:
            errors.append(f"source digest mismatch at recorded commit: {item['path']}")
    return tuple(errors)


def _validate_source_commit_record(value: object) -> tuple[tuple[str, ...], bool]:
    expected_keys = {
        "commit",
        "bound",
        "binding",
        "worktree_dirty",
        "source_paths_tracked_at_commit",
        "source_paths_match_commit",
        "source_inventory_matches_commit",
        "reason",
        "observation_point",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        return (("source commit provenance schema invalid",), False)
    if value.get("observation_point") != ("after result assembly and before pair publication"):
        return (("source commit observation point invalid",), False)
    head = value.get("commit")
    bound = value.get("bound")
    binding = value.get("binding")
    dirty = value.get("worktree_dirty")
    tracked = value.get("source_paths_tracked_at_commit")
    paths_match = value.get("source_paths_match_commit")
    inventory_match = value.get("source_inventory_matches_commit")
    reason = value.get("reason")
    errors: list[str] = []
    if type(bound) is not bool:
        return (("source commit bound flag invalid",), False)
    if head is None:
        if (
            bound is not False
            or binding != "content-digests-only"
            or dirty is not None
            or tracked is not False
            or paths_match is not False
            or inventory_match is not False
            or reason
            not in {
                "git_state_unavailable",
                "redirected_git_environment_refused",
            }
        ):
            errors.append("unbound source commit provenance is contradictory")
        return tuple(errors), False
    if not _is_git_oid(head):
        errors.append("source commit identity invalid")
    if not all(type(item) is bool for item in (dirty, tracked, paths_match, inventory_match)):
        errors.append("source commit provenance booleans invalid")
        return tuple(errors), False
    assert isinstance(dirty, bool)
    assert isinstance(tracked, bool)
    assert isinstance(paths_match, bool)
    assert isinstance(inventory_match, bool)
    derived_bound = not dirty and tracked and paths_match and inventory_match
    if bound is not derived_bound:
        errors.append("source commit bound flag contradicts observation")
    if binding != ("git-commit" if derived_bound else "content-digests-only"):
        errors.append("source commit binding mode contradicts observation")
    if not tracked:
        expected_reason = "one_or_more_source_paths_not_tracked_at_commit"
    elif not inventory_match:
        expected_reason = "source_inventory_differs_from_commit"
    elif not paths_match:
        expected_reason = "one_or_more_source_paths_differ_from_commit"
    elif dirty:
        expected_reason = "dirty_worktree"
    else:
        expected_reason = "clean_worktree_and_source_matches_commit"
    if reason != expected_reason:
        errors.append("source commit reason contradicts observation")
    return tuple(errors), derived_bound


def _validate_evidence_commit_record(value: object) -> tuple[tuple[str, ...], bool]:
    if value is None:
        return (), False
    expected_keys = {
        "commit",
        "bound",
        "binding",
        "source_paths_match_commit",
        "source_inventory_matches_commit",
        "results_match_commit",
        "final_manifest_in_commit",
        "reason",
        "observation_point",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        return (("evidence commit provenance schema invalid",), False)
    errors: list[str] = []
    if not _is_git_oid(value.get("commit")):
        errors.append("evidence commit identity invalid")
    expected_values = {
        "bound": True,
        "binding": "git-commit",
        "source_paths_match_commit": True,
        "source_inventory_matches_commit": True,
        "results_match_commit": True,
        "final_manifest_in_commit": False,
        "reason": "source_and_results_match_commit_final_manifest_excluded",
        "observation_point": ("after results commit and before final manifest publication"),
    }
    if any(value.get(key) != expected for key, expected in expected_values.items()):
        errors.append("evidence commit provenance is contradictory")
    return tuple(errors), not errors


def _verify_provenance_commit_chain(
    root: Path,
    *,
    source_commit: object,
    evidence_commit: object,
    required_history_tip: str | None = None,
) -> tuple[str, ...]:
    """Require a distinct source-to-evidence chain and optionally a trusted tip."""
    if not _is_git_oid(source_commit) or not _is_git_oid(evidence_commit):
        return ("provenance commit chain identities are invalid",)
    assert isinstance(source_commit, str)
    assert isinstance(evidence_commit, str)
    errors: list[str] = []
    if source_commit == evidence_commit:
        errors.append("source and evidence commits must be distinct")
    else:
        relation = _git(
            root,
            ("merge-base", "--is-ancestor", source_commit, evidence_commit),
        )
        if relation is None or relation.returncode not in {0, 1}:
            errors.append("source-to-evidence commit ancestry is unverifiable")
        elif relation.returncode == 1:
            errors.append("evidence commit is not a descendant of source commit")

    if required_history_tip is not None:
        tip = _git(
            root,
            ("rev-parse", "--verify", f"{required_history_tip}^{{commit}}"),
        )
        if tip is None or tip.returncode != 0 or not _is_git_oid(tip.stdout.strip()):
            errors.append("required provenance history tip is invalid")
        else:
            tip_commit = tip.stdout.strip()
            relation = _git(
                root,
                ("merge-base", "--is-ancestor", evidence_commit, tip_commit),
            )
            if relation is None or relation.returncode not in {0, 1}:
                errors.append("evidence-to-tip commit ancestry is unverifiable")
            elif relation.returncode == 1:
                errors.append("evidence commit is not an ancestor of required history tip")
    return tuple(errors)


def _verify_commit_bound_head_blobs(
    root: Path,
    *,
    head: object,
    source: object,
    results: object,
) -> tuple[str, ...]:
    """Verify every claimed content digest against exact blobs at Git HEAD."""
    if not isinstance(head, str) or not head:
        return ("commit binding has no usable Git head",)
    top_result = _git(root, ("rev-parse", "--show-toplevel"))
    if top_result is None or top_result.returncode != 0:
        return ("commit-bound Git repository is unavailable",)
    git_root = Path(top_result.stdout.strip()).resolve()
    errors: list[str] = []

    source_items: list[dict[str, object]] = []
    blob_paths: list[Path] = []
    if not isinstance(source, dict) or not isinstance(source.get("files"), list):
        errors.append("commit-bound source inventory is invalid")
    else:
        for item in source["files"]:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("path"), str)
                or not isinstance(item.get("sha256"), str)
                or not isinstance(item.get("bytes"), int)
            ):
                errors.append("commit-bound source inventory entry is invalid")
                continue
            source_items.append(item)
            blob_paths.append(root / item["path"])

    recorded_source_paths = frozenset(str(item["path"]) for item in source_items)
    head_source_paths = _head_source_inventory(git_root, root, head)
    if head_source_paths is None or recorded_source_paths != head_source_paths:
        errors.append("commit-bound source inventory differs from recorded HEAD")

    results_path = _results_path_from_evidence(root, results)
    if (
        results_path is None
        or not isinstance(results, dict)
        or not isinstance(results.get("sha256"), str)
        or not isinstance(results.get("bytes"), int)
    ):
        errors.append("commit-bound result evidence is invalid")
    else:
        blob_paths.append(results_path)

    blobs = _head_blobs(git_root, head, blob_paths)
    if blobs is None:
        errors.append("commit-bound HEAD blobs are unreadable")
        return tuple(errors)
    for item in source_items:
        source_path = root / str(item["path"])
        blob = blobs.get(source_path.resolve())
        if blob is None:
            errors.append(f"commit-bound source missing at HEAD: {item['path']}")
        elif len(blob) != item["bytes"] or _sha256(blob) != item["sha256"]:
            errors.append(f"commit-bound source digest mismatch: {item['path']}")
    if (
        results_path is not None
        and isinstance(results, dict)
        and isinstance(results.get("sha256"), str)
        and isinstance(results.get("bytes"), int)
    ):
        blob = blobs.get(results_path.resolve())
        if blob is None:
            errors.append("commit-bound results missing at HEAD")
        elif len(blob) != results["bytes"] or _sha256(blob) != results["sha256"]:
            errors.append("commit-bound results digest mismatch")
    return tuple(errors)


def _collect_evidence_commit_record(
    root: Path,
    *,
    source: object,
    results: object,
) -> dict[str, object]:
    """Bind exact source and result blobs to HEAD, excluding the future manifest."""
    parent_environment = _normalised_environment(os.environ)
    if any(key in parent_environment for key in GIT_REDIRECT_ENV_KEYS):
        raise ValueError("redirected Git environment prevents evidence finalization")
    head_result = _git(root, ("rev-parse", "--verify", "HEAD"))
    if (
        head_result is None
        or head_result.returncode != 0
        or not _is_git_oid(head_result.stdout.strip())
    ):
        raise ValueError("Git commit is unavailable for evidence finalization")
    head = head_result.stdout.strip()
    binding_errors = _verify_commit_bound_head_blobs(
        root,
        head=head,
        source=source,
        results=results,
    )
    if binding_errors:
        raise ValueError(
            "results must be committed with the exact source before provenance "
            f"finalization: {'; '.join(binding_errors)}"
        )
    return {
        "commit": head,
        "bound": True,
        "binding": "git-commit",
        "source_paths_match_commit": True,
        "source_inventory_matches_commit": True,
        "results_match_commit": True,
        "final_manifest_in_commit": False,
        "reason": "source_and_results_match_commit_final_manifest_excluded",
        "observation_point": ("after results commit and before final manifest publication"),
    }


def _validate_historical_git_observation(
    git: Mapping[str, object],
) -> tuple[str, ...]:
    """Validate the internal logic of the pre-publication Git observation."""
    errors: list[str] = []
    head = git.get("head")
    dirty = git.get("dirty")
    porcelain_dirty = git.get("porcelain_dirty")
    tracked = git.get("bound_paths_tracked_at_head")
    bound_match = git.get("bound_paths_match_head")
    inventory_match = git.get("source_inventory_matches_head")
    commit_bound = git.get("source_and_results_commit_bound")
    binding = git.get("binding")
    reason = git.get("reason")
    observation = git.get("observation_point")
    if observation != "after result assembly and before pair publication":
        errors.append("Git observation point invalid")
    if type(commit_bound) is not bool:
        errors.append("Git commit-binding flag invalid")
        return tuple(errors)

    if head is None:
        expected = {
            "dirty": None,
            "porcelain_dirty": None,
            "bound_paths_tracked_at_head": False,
            "bound_paths_match_head": False,
            "source_inventory_matches_head": False,
            "source_and_results_commit_bound": False,
            "binding": "content-digests-only",
        }
        if any(git.get(key) != value for key, value in expected.items()):
            errors.append("unbound Git observation is contradictory")
        if reason not in {
            "git_state_unavailable",
            "redirected_git_environment_refused",
        }:
            errors.append("unbound Git reason invalid")
        return tuple(errors)

    if (
        not isinstance(head, str)
        or len(head) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in head)
    ):
        errors.append("Git head identity invalid")
    if not all(
        type(value) is bool
        for value in (dirty, porcelain_dirty, tracked, bound_match, inventory_match)
    ):
        errors.append("Git observation booleans invalid")
        return tuple(errors)

    assert isinstance(dirty, bool)
    assert isinstance(porcelain_dirty, bool)
    assert isinstance(tracked, bool)
    assert isinstance(bound_match, bool)
    assert isinstance(inventory_match, bool)
    derived_dirty = porcelain_dirty or not tracked or not bound_match or not inventory_match
    derived_commit_bound = not derived_dirty
    if dirty != derived_dirty or commit_bound != derived_commit_bound:
        errors.append("Git cleanliness and binding flags contradict")
    expected_binding = "git-head" if derived_commit_bound else "content-digests-only"
    if binding != expected_binding:
        errors.append("Git binding mode contradicts observation")
    if not tracked:
        expected_reason = "one_or_more_bound_paths_are_not_tracked_at_head"
    elif not inventory_match:
        expected_reason = "source_inventory_differs_from_head"
    elif not bound_match:
        expected_reason = "one_or_more_bound_paths_differ_from_head"
    elif porcelain_dirty:
        expected_reason = "dirty_worktree"
    else:
        expected_reason = "clean_worktree_and_all_bound_paths_tracked"
    if reason != expected_reason:
        errors.append("Git reason contradicts observation")
    return tuple(errors)


def verify_run_manifest(
    path: Path,
    *,
    root: Path,
    corpus: Mapping[str, object],
    settings: Mapping[str, object],
    baseline_definition: Mapping[str, object],
    engine_version: str,
    results_path: Path | None = None,
    require_release_promotion: bool = False,
    required_history_tip: str | None = None,
) -> tuple[str, ...]:
    """Verify historical self-consistency without claiming authentication.

    ``require_release_promotion`` is a narrow carry-forward rule for a manifest
    measured on ``X.Y.Z.dev0`` and verified on ``X.Y.Z``. It normalizes only
    the exact version-assignment bytes for comparison, requires that relation
    to be used, and keeps all recorded source, result, and commit bindings
    mandatory.

    ``required_history_tip`` additionally proves that the distinct
    source-to-evidence chain is retained below one trusted Git commit.
    """
    root = root.resolve()
    manifest = load_run_manifest(path)
    errors: list[str] = []
    top_level_keys = {
        "schema_version",
        "benchmark_id",
        "run_id",
        "engine_version",
        "source",
        "corpus",
        "results",
        "dependency_lock",
        "metrics",
        "security_evasion_metrics",
        "settings",
        "baseline",
        "timing",
        "invocation",
        "environment",
        "git",
        "provenance",
        "claims",
    }
    if set(manifest) != top_level_keys:
        errors.append("manifest schema keys invalid")
    try:
        _validate_no_host_paths(manifest)
    except ValueError:
        errors.append("manifest contains forbidden host path context")
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        errors.append("schema_version drift")
    if manifest.get("benchmark_id") != BENCHMARK_ID:
        errors.append("benchmark_id drift")
    recorded_engine_version = manifest.get("engine_version")
    verification_engine_version = engine_version
    expected_source_bundle = collect_source_bundle(root)
    if require_release_promotion:
        try:
            expected_source_bundle = _release_promotion_source_bundle(
                root,
                recorded_engine_version=recorded_engine_version,
                current_engine_version=engine_version,
            )
        except ValueError:
            errors.append("exact dev0 release-promotion relation is not satisfied")
        else:
            assert isinstance(recorded_engine_version, str)
            verification_engine_version = recorded_engine_version
    if recorded_engine_version != verification_engine_version:
        errors.append("engine_version drift")
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or not RUN_ID_PATTERN.fullmatch(run_id):
        errors.append("run_id invalid")
        run_id = ""

    expected_source = expected_source_bundle.evidence
    if manifest.get("source") != expected_source:
        errors.append("source content drift")
    expected_lock = _dependency_lock_from_source(expected_source_bundle)
    if manifest.get("dependency_lock") != expected_lock:
        errors.append("dependency lock drift")
    expected_corpus = collect_corpus_evidence(corpus)
    if manifest.get("corpus") != expected_corpus:
        errors.append("corpus drift")

    environment_digest = ""
    interpreter_digest = ""
    recorded_environment = manifest.get("environment")
    if not isinstance(recorded_environment, dict):
        errors.append("runtime environment evidence missing")
    else:
        try:
            safe_environment = _validated_environment_record(recorded_environment)
        except ValueError:
            errors.append("runtime environment evidence invalid")
        else:
            if recorded_environment != safe_environment:
                errors.append("runtime environment evidence is not canonical")
            raw_execution_environment = safe_environment["execution_environment"]
            raw_interpreter = safe_environment["case_interpreter"]
            assert isinstance(raw_execution_environment, dict)
            assert isinstance(raw_interpreter, dict)
            environment_digest_value = raw_execution_environment["effective_environment_sha256"]
            interpreter_digest_value = raw_interpreter["identity_sha256"]
            assert isinstance(environment_digest_value, str)
            assert isinstance(interpreter_digest_value, str)
            environment_digest = environment_digest_value
            interpreter_digest = interpreter_digest_value

    expected_invocation = {
        "entrypoint": "benchmarks/run_live.py",
        "required_controller_python_flags": ["-I"],
        "operation": "run-corpus",
        "reproduction_command": [
            "{python}",
            "-I",
            "benchmarks/run_live.py",
            "--out",
            "{results}",
            "--manifest",
            "{manifest}",
        ],
    }
    if manifest.get("invocation") != expected_invocation:
        errors.append("invocation identity drift")

    recorded_results = manifest.get("results")
    selected_results = results_path
    if selected_results is None:
        selected_results = _results_path_from_evidence(root, recorded_results)
    result_snapshot: StableFileSnapshot | None = None
    rows: list[dict[str, object]] | None = None
    if selected_results is None:
        errors.append("results path missing; external results require an explicit path")
    else:
        try:
            result_snapshot = read_stable_regular_file(
                selected_results,
                max_bytes=MAX_RESULTS_BYTES,
                label="benchmark results",
            )
            rows = parse_rows_payload(result_snapshot.payload)
            expected_results = collect_results_evidence(
                selected_results,
                root,
                snapshot=result_snapshot,
            )
        except (OSError, RuntimeError, UnicodeError, ValueError, json.JSONDecodeError):
            errors.append("results unreadable")
        else:
            recorded_identity = (
                {key: value for key, value in recorded_results.items() if key != "path"}
                if isinstance(recorded_results, dict)
                else recorded_results
            )
            expected_identity = {
                key: value for key, value in expected_results.items() if key != "path"
            }
            if recorded_identity != expected_identity:
                errors.append("results drift")
            source_digest = expected_source.get("sha256")
            assert isinstance(source_digest, str)
            contract_errors = validate_results_contract(
                rows,
                corpus=corpus,
                run_id=run_id,
                engine_version=verification_engine_version,
                source_digest=source_digest,
                execution_environment_digest=environment_digest,
                interpreter_digest=interpreter_digest,
            )
            errors.extend(f"results/corpus contract: {error}" for error in contract_errors)
            if not contract_errors:
                observed_metrics = evaluate_rows(rows)
                observed_baseline_metrics = evaluate_baseline_rows(rows)
                observed_security_metrics = evaluate_security_evasions_rows(rows)
                observed_timing = timing_summary(rows)
                if manifest.get("metrics") != observed_metrics:
                    errors.append("Guard metrics drift")
                if manifest.get("security_evasion_metrics") != observed_security_metrics:
                    errors.append("security-evasion metrics drift")
                if manifest.get("timing") != observed_timing:
                    errors.append("timing evidence drift")
                baseline = manifest.get("baseline")
                if (
                    not isinstance(baseline, dict)
                    or set(baseline) != {"definition", "metrics"}
                    or baseline.get("metrics") != observed_baseline_metrics
                ):
                    errors.append("baseline metrics drift")

    if manifest.get("settings") != dict(settings):
        errors.append("settings drift")
    baseline = manifest.get("baseline")
    if (
        not isinstance(baseline, dict)
        or set(baseline) != {"definition", "metrics"}
        or baseline.get("definition") != dict(baseline_definition)
    ):
        errors.append("baseline definition drift")

    git = manifest.get("git")
    provenance = manifest.get("provenance")
    claims = manifest.get("claims")
    expected_claim_keys = {
        "authenticated",
        "evidence_status",
        "execution_authenticity_claim",
        "source_commit_bound",
        "evidence_commit_bound",
        "source_and_results_commit_bound",
        "final_manifest_in_evidence_commit",
        "execution_source_snapshot_bound",
        "source_snapshot_matches_worktree_at_manifest_build",
        "content_identity",
        "installed_environment_matches_lock",
        "general_performance_claim",
    }
    git_keys = {
        "head",
        "dirty",
        "porcelain_dirty",
        "bound_paths_tracked_at_head",
        "bound_paths_match_head",
        "source_inventory_matches_head",
        "source_and_results_commit_bound",
        "binding",
        "reason",
        "observation_point",
    }
    if not isinstance(git, dict) or set(git) != git_keys:
        errors.append("Git observation schema invalid")
    else:
        errors.extend(_validate_historical_git_observation(git))

        if git.get("source_and_results_commit_bound") is True:
            errors.extend(
                _verify_commit_bound_head_blobs(
                    root,
                    head=git.get("head"),
                    source=manifest.get("source"),
                    results=recorded_results,
                )
            )

    source_bound = False
    evidence_bound = False
    if (
        not isinstance(provenance, dict)
        or set(provenance)
        != {
            "workflow",
            "source_commit",
            "evidence_commit",
            "final_manifest_in_evidence_commit",
        }
        or provenance.get("workflow") != PROVENANCE_WORKFLOW
        or provenance.get("final_manifest_in_evidence_commit") is not False
    ):
        errors.append("provenance record schema invalid")
    else:
        source_errors, source_bound = _validate_source_commit_record(
            provenance.get("source_commit")
        )
        evidence_errors, evidence_bound = _validate_evidence_commit_record(
            provenance.get("evidence_commit")
        )
        errors.extend(source_errors)
        errors.extend(evidence_errors)
        source_record = provenance.get("source_commit")
        if source_bound and isinstance(source_record, dict):
            errors.extend(
                _verify_commit_bound_source_blobs(
                    root,
                    head=source_record.get("commit"),
                    source=manifest.get("source"),
                )
            )
        evidence_record = provenance.get("evidence_commit")
        if evidence_bound and isinstance(evidence_record, dict):
            errors.extend(
                _verify_commit_bound_head_blobs(
                    root,
                    head=evidence_record.get("commit"),
                    source=manifest.get("source"),
                    results=recorded_results,
                )
            )
        if (
            source_bound
            and evidence_bound
            and isinstance(source_record, dict)
            and isinstance(evidence_record, dict)
        ):
            errors.extend(
                _verify_provenance_commit_chain(
                    root,
                    source_commit=source_record.get("commit"),
                    evidence_commit=evidence_record.get("commit"),
                    required_history_tip=required_history_tip,
                )
            )
        elif required_history_tip is not None:
            errors.append("required provenance history tip needs bound source and evidence commits")

    if not isinstance(claims, dict) or set(claims) != expected_claim_keys:
        errors.append("claims record schema invalid")
    else:
        expected_claims = _claim_record(
            source_commit_bound=source_bound,
            evidence_commit_bound=evidence_bound,
        )
        if claims != expected_claims:
            errors.append("claim boundary drift")
    return tuple(errors)


def finalize_run_manifest_provenance(
    path: Path,
    *,
    root: Path,
    corpus: Mapping[str, object],
    settings: Mapping[str, object],
    baseline_definition: Mapping[str, object],
    engine_version: str,
    results_path: Path | None = None,
) -> dict[str, object]:
    """Finalize a draft only after exact source and result bytes exist at HEAD.

    The returned manifest binds a source commit and an evidence commit. It
    explicitly does not claim that its own final bytes are in the evidence
    commit, because those bytes are created by this second phase.
    """
    root = root.resolve()
    before = read_stable_regular_file(
        path,
        max_bytes=MAX_MANIFEST_BYTES,
        label="benchmark manifest draft",
    )
    verification_errors = verify_run_manifest(
        path,
        root=root,
        corpus=corpus,
        settings=settings,
        baseline_definition=baseline_definition,
        engine_version=engine_version,
        results_path=results_path,
    )
    after = read_stable_regular_file(
        path,
        max_bytes=MAX_MANIFEST_BYTES,
        label="benchmark manifest draft",
    )
    if before.payload != after.payload:
        raise RuntimeError("benchmark manifest draft changed during finalization")
    if verification_errors:
        raise ValueError("benchmark manifest draft is invalid: " + "; ".join(verification_errors))
    manifest = json.loads(
        before.payload.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    if not isinstance(manifest, dict):
        raise ValueError("benchmark manifest draft root must be an object")
    provenance = manifest.get("provenance")
    if (
        not isinstance(provenance, dict)
        or provenance.get("workflow") != PROVENANCE_WORKFLOW
        or provenance.get("evidence_commit") is not None
    ):
        raise ValueError("benchmark manifest is not an unfinalized two-phase draft")
    recorded_results = manifest.get("results")
    selected_results = results_path
    if selected_results is None:
        selected_results = _results_path_from_evidence(root, recorded_results)
    if selected_results is None:
        raise ValueError("external results require an explicit path for provenance finalization")
    result_snapshot = read_stable_regular_file(
        selected_results,
        max_bytes=MAX_RESULTS_BYTES,
        label="benchmark results",
    )
    expected_results = collect_results_evidence(
        selected_results,
        root,
        snapshot=result_snapshot,
    )
    recorded_identity = (
        {key: value for key, value in recorded_results.items() if key != "path"}
        if isinstance(recorded_results, dict)
        else recorded_results
    )
    expected_identity = {key: value for key, value in expected_results.items() if key != "path"}
    if recorded_identity != expected_identity:
        raise ValueError("benchmark results changed before provenance finalization")
    if manifest.get("source") != collect_source_evidence(root):
        raise ValueError("benchmark source changed before provenance finalization")
    source_record = provenance.get("source_commit")
    source_errors, source_bound = _validate_source_commit_record(source_record)
    if source_errors:
        raise ValueError("benchmark source provenance is invalid: " + "; ".join(source_errors))
    if not source_bound:
        raise ValueError(
            "benchmark source provenance is not commit-bound; "
            "rerun the measurement from a clean source commit"
        )
    evidence_commit = _collect_evidence_commit_record(
        root,
        source=manifest.get("source"),
        results=recorded_results,
    )
    assert isinstance(source_record, dict)
    chain_errors = _verify_provenance_commit_chain(
        root,
        source_commit=source_record.get("commit"),
        evidence_commit=evidence_commit.get("commit"),
    )
    if chain_errors:
        raise ValueError("benchmark provenance commit chain is invalid: " + "; ".join(chain_errors))
    finalized = dict(manifest)
    finalized["provenance"] = {
        "workflow": PROVENANCE_WORKFLOW,
        "source_commit": source_record,
        "evidence_commit": evidence_commit,
        "final_manifest_in_evidence_commit": False,
    }
    finalized["claims"] = _claim_record(
        source_commit_bound=source_bound,
        evidence_commit_bound=True,
    )
    _validate_no_host_paths(finalized)
    return finalized


def verify_reproduction_environment(
    path: Path,
    *,
    parent_environment: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Compare current observable runtime inputs with a valid historical record."""
    manifest = load_run_manifest(path)
    recorded = manifest.get("environment")
    if not isinstance(recorded, dict):
        return ("runtime environment evidence missing",)
    try:
        safe_recorded = _validated_environment_record(recorded)
    except ValueError:
        return ("runtime environment evidence invalid",)
    effective, evidence = build_execution_environment(parent_environment)
    current = collect_environment(
        evidence,
        effective_environment=effective,
    )
    errors: list[str] = []
    if safe_recorded.get("os") != current.get("os"):
        errors.append("current OS identity does not match record")
    if safe_recorded.get("execution_environment") != current.get("execution_environment"):
        errors.append("current execution environment does not match record")
    if safe_recorded.get("case_interpreter") != current.get("case_interpreter"):
        errors.append("current interpreter does not match record")
    if safe_recorded.get("tools") != current.get("tools"):
        errors.append("current tool identities do not match record")
    recorded_controller = safe_recorded.get("controller")
    current_controller = current.get("controller")
    if recorded_controller != current_controller:
        errors.append("current controller isolation does not match record")
    return tuple(errors)
