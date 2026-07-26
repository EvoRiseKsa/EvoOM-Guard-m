"""Reproducible, evidence-producing Docker isolation conformance probes.

The kit is intentionally separate from verdict policy.  It executes bounded
negative probes, records exactly what the daemon delivered, and distinguishes
an unavailable runtime from a passing runtime.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, cast

from evoom_guard.execution import run_bounded_subprocess
from evoom_guard.isolation.docker import (
    ContainerCleanup,
    ContainerStartedProbe,
    DockerContainerCleanupResult,
    DockerRunContainmentError,
    DockerRunRequest,
    DockerRunTimeout,
    cleanup_named_container,
    docker_container_name,
    inspect_docker_image,
    probe_container_started,
    require_canonical_docker_image_id,
    resolve_docker_image,
    run_named_docker_client,
)
from tools.conformance.secure_io import read_stable_regular_file, write_create_only_bytes

JSONObject = dict[str, Any]
Profile = dict[str, Any]
Probe = dict[str, Any]

CONFORMANCE_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = CONFORMANCE_DIR.parents[1]
DEFAULT_MANIFEST = CONFORMANCE_DIR / "isolation-manifest.json"
RESULT_SCHEMA = CONFORMANCE_DIR / "isolation-result.schema.json"
PROBE_SOURCE = CONFORMANCE_DIR / "probe" / "isolation_probe.py"
RESULT_SCHEMA_LABEL = "tools/conformance/isolation-result.schema.json"
PROBE_SOURCE_LABEL = "tools/conformance/probe/isolation_probe.py"

MANIFEST_VERSION = "evoom-isolation-conformance-manifest-1"
RESULT_VERSION = "evoom-isolation-conformance-result-1"
PROBE_VERSION = "evoom-isolation-probe-1"

_STATUS_VALUES = ("pass", "fail", "error", "skip", "unsupported")
_MAX_DIAGNOSTIC_CHARS = 2_000
MANDATORY_SECURITY_PROBES = (
    "network_none",
    "candidate_mount_read_only",
    "root_filesystem_read_only",
    "forbidden_path_read",
    "security_profile",
    "normal_cleanup",
    "timeout_cleanup",
)
_SOURCE_PATHS = (
    "tools/conformance/isolation_kit.py",
    "tools/conformance/run_isolation_conformance.py",
    "tools/conformance/isolation-manifest.schema.json",
    "tools/conformance/isolation-result.schema.json",
    "tools/conformance/secure_io.py",
    PROBE_SOURCE_LABEL,
    "evoom_guard/execution/__init__.py",
    "evoom_guard/execution/process.py",
    "evoom_guard/execution/judge.py",
    "evoom_guard/execution/command.py",
    "evoom_guard/isolation/__init__.py",
    "evoom_guard/isolation/docker.py",
    "evoom_guard/isolation/candidate.py",
    "evoom_guard/isolation/invocation.py",
)


class ManifestError(ValueError):
    """The conformance manifest is malformed or internally inconsistent."""


class ResultVerificationError(ValueError):
    """A retained isolation result is inconsistent with trusted local inputs."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _capture_source_bytes() -> dict[str, bytes]:
    return {
        relative: read_stable_regular_file(
            REPOSITORY_ROOT / relative,
            label=f"isolation source {relative}",
        )
        for relative in _SOURCE_PATHS
    }


def _source_file_inventory(source_bytes: Mapping[str, bytes]) -> JSONObject:
    files: list[JSONObject] = []
    aggregate = hashlib.sha256()
    for relative in _SOURCE_PATHS:
        raw = source_bytes[relative]
        digest = _sha256_bytes(raw)
        files.append({"path": relative, "sha256": digest, "bytes": len(raw)})
        aggregate.update(relative.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(digest.encode("ascii"))
        aggregate.update(b"\n")
    return {"files": files, "aggregate_sha256": aggregate.hexdigest()}


def _bounded(value: object) -> str:
    text = str(value)
    local_paths = {
        str(REPOSITORY_ROOT.resolve()),
        str(Path.home().resolve()),
        str(Path(sys.executable).resolve()),
    }
    for local_path in sorted(local_paths, key=len, reverse=True):
        text = text.replace(local_path, "<local-path>")
    return text[:_MAX_DIAGNOSTIC_CHARS]


def _logical_repo_path(path: Path, fallback: str) -> str:
    """Return a portable source label without publishing a local host path."""

    try:
        return path.resolve().relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError:
        return fallback


def _object(value: object, label: str) -> JSONObject:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ManifestError(f"{label} must be a JSON object with string keys")
    return cast(JSONObject, value)


def _objects(value: object, label: str) -> list[JSONObject]:
    if not isinstance(value, list):
        raise ManifestError(f"{label} must be a JSON array")
    return [_object(item, f"{label}[{index}]") for index, item in enumerate(value)]


def _strings(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ManifestError(f"{label} must be a JSON string array")
    return cast(list[str], value)


def _positive_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ManifestError(f"{label} must be a positive number")
    return float(value)


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ManifestError(f"{label} must be a positive integer")
    return value


def _manifest_keys(value: JSONObject, required: set[str], context: str) -> None:
    missing = sorted(required - value.keys())
    extra = sorted(value.keys() - required)
    if missing or extra:
        raise ManifestError(
            f"{context} keys differ: missing={missing}, extra={extra}"
        )


def _normalize_csv_options(value: str) -> list[str] | None:
    options = [item.strip().casefold() for item in value.split(",")]
    if not options or any(not item for item in options) or len(options) != len(set(options)):
        return None
    return sorted(options)


def _normalize_manifest_tmpfs(values: Sequence[str]) -> JSONObject:
    normalized: JSONObject = {}
    for entry in values:
        path, separator, raw_options = entry.partition(":")
        options = _normalize_csv_options(raw_options)
        if (
            separator != ":"
            or not path.startswith("/")
            or path in normalized
            or options is None
        ):
            raise ManifestError(
                "container.tmpfs entries must be unique absolute "
                "'/path:option[,option]' values"
            )
        normalized[path] = options
    return dict(sorted(normalized.items()))


def _normalize_inspect_tmpfs(value: object) -> JSONObject | None:
    if not isinstance(value, dict) or any(
        not isinstance(path, str) or not isinstance(options, str)
        for path, options in value.items()
    ):
        return None
    normalized: JSONObject = {}
    for path, raw_options in value.items():
        options = _normalize_csv_options(raw_options)
        if not path.startswith("/") or path in normalized or options is None:
            return None
        normalized[path] = options
    return dict(sorted(normalized.items()))


def _parse_ulimit_value(value: str) -> JSONObject | None:
    name, separator, bounds = value.partition("=")
    soft_raw, colon, hard_raw = bounds.partition(":")
    if (
        separator != "="
        or colon != ":"
        or not name
        or not soft_raw
        or not hard_raw
    ):
        return None
    try:
        soft = int(soft_raw, 10)
        hard = int(hard_raw, 10)
    except ValueError:
        return None
    if soft < -1 or hard < -1:
        return None
    return {"name": name.casefold(), "soft": soft, "hard": hard}


def _normalize_manifest_ulimits(values: Sequence[str]) -> list[JSONObject]:
    normalized: list[JSONObject] = []
    names: set[str] = set()
    for entry in values:
        parsed = _parse_ulimit_value(entry)
        if parsed is None or str(parsed["name"]) in names:
            raise ManifestError(
                "container.ulimit entries must be unique "
                "'name=soft:hard' integer limits"
            )
        names.add(str(parsed["name"]))
        normalized.append(parsed)
    return sorted(normalized, key=lambda item: str(item["name"]))


def _normalize_inspect_ulimits(value: object) -> list[JSONObject] | None:
    if not isinstance(value, list):
        return None
    normalized: list[JSONObject] = []
    names: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"Name", "Soft", "Hard"}:
            return None
        name = item.get("Name")
        soft = item.get("Soft")
        hard = item.get("Hard")
        if (
            not isinstance(name, str)
            or not name
            or isinstance(soft, bool)
            or not isinstance(soft, int)
            or isinstance(hard, bool)
            or not isinstance(hard, int)
            or name.casefold() in names
        ):
            return None
        names.add(name.casefold())
        normalized.append(
            {"name": name.casefold(), "soft": soft, "hard": hard}
        )
    return sorted(normalized, key=lambda item: str(item["name"]))


def _nano_cpus(value: object) -> int:
    try:
        nano = Decimal(str(value)) * Decimal(1_000_000_000)
    except (InvalidOperation, ValueError) as exc:
        raise ManifestError("container.cpus cannot be represented as NanoCpus") from exc
    if not nano.is_finite() or nano != nano.to_integral_value() or nano <= 0:
        raise ManifestError(
            "container.cpus must produce a positive integral NanoCpus value"
        )
    return int(nano)


def _normalize_security_options(values: Sequence[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        option = value.casefold()
        if option in {"no-new-privileges", "no-new-privileges:true"}:
            option = "no-new-privileges"
        normalized.append(option)
    return sorted(normalized)


def _expected_security_profile(manifest: JSONObject) -> JSONObject:
    container = _object(manifest["container"], "container")
    return {
        "cap_drop": sorted(
            item.casefold()
            for item in _strings(container["cap_drop"], "container.cap_drop")
        ),
        "security_opt": _normalize_security_options(
            _strings(container["security_opt"], "container.security_opt")
        ),
        "tmpfs": _normalize_manifest_tmpfs(
            _strings(container["tmpfs"], "container.tmpfs")
        ),
        "pids_limit": int(container["pids_limit"]),
        "nano_cpus": _nano_cpus(container["cpus"]),
        "ulimits": _normalize_manifest_ulimits(
            _strings(container["ulimit"], "container.ulimit")
        ),
    }


def _observed_security_profile(metadata: JSONObject) -> JSONObject:
    cap_drop = metadata.get("cap_drop")
    security_opt = metadata.get("security_opt")
    return {
        "cap_drop": (
            sorted(item.casefold() for item in cap_drop)
            if isinstance(cap_drop, list)
            and all(isinstance(item, str) for item in cap_drop)
            else None
        ),
        "security_opt": (
            _normalize_security_options(security_opt)
            if isinstance(security_opt, list)
            and all(isinstance(item, str) for item in security_opt)
            else None
        ),
        "tmpfs": _normalize_inspect_tmpfs(metadata.get("tmpfs")),
        "pids_limit": metadata.get("pids_limit"),
        "nano_cpus": metadata.get("nano_cpus"),
        "ulimits": _normalize_inspect_ulimits(metadata.get("ulimits")),
    }


def validate_manifest(manifest: JSONObject) -> None:
    """Validate security-significant manifest invariants without dependencies."""

    _manifest_keys(
        manifest,
        {
            "$schema",
            "schema_version",
            "suite_id",
            "default_image",
            "control_timeout_seconds",
            "image_pull_timeout_seconds",
            "run_timeout_seconds",
            "timeout_probe_seconds",
            "cleanup",
            "container",
            "network_probe",
            "forbidden_paths",
            "required_probes",
            "profiles",
        },
        "manifest",
    )
    if manifest.get("schema_version") != MANIFEST_VERSION:
        raise ManifestError(f"schema_version must be {MANIFEST_VERSION!r}")
    if not isinstance(manifest.get("suite_id"), str) or not manifest["suite_id"]:
        raise ManifestError("suite_id must be a non-empty string")
    if not isinstance(manifest.get("default_image"), str) or not manifest["default_image"]:
        raise ManifestError("default_image must be a non-empty string")

    for key in (
        "control_timeout_seconds",
        "image_pull_timeout_seconds",
        "run_timeout_seconds",
        "timeout_probe_seconds",
    ):
        _positive_number(manifest.get(key), key)

    cleanup = _object(manifest.get("cleanup"), "cleanup")
    _manifest_keys(
        cleanup,
        {
            "total_timeout_seconds",
            "reconcile_attempts",
            "reconcile_interval_seconds",
            "required_final_absent_observations",
        },
        "cleanup",
    )
    _positive_number(cleanup.get("total_timeout_seconds"), "cleanup.total_timeout_seconds")
    attempts = _positive_integer(
        cleanup.get("reconcile_attempts"),
        "cleanup.reconcile_attempts",
    )
    interval = cleanup.get("reconcile_interval_seconds")
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or interval < 0:
        raise ManifestError("cleanup.reconcile_interval_seconds must be a non-negative number")
    required_observations = _positive_integer(
        cleanup.get("required_final_absent_observations"),
        "cleanup.required_final_absent_observations",
    )
    if required_observations > attempts:
        raise ManifestError(
            "cleanup.required_final_absent_observations cannot exceed cleanup.reconcile_attempts"
        )

    container = _object(manifest.get("container"), "container")
    _manifest_keys(
        container,
        {
            "network",
            "read_only_root",
            "candidate_mount_path",
            "candidate_mount_mode",
            "workdir",
            "tmpfs",
            "pids_limit",
            "cpus",
            "cap_drop",
            "security_opt",
            "ulimit",
            "user_policy",
            "require_non_root_when_applied",
        },
        "container",
    )
    fixed_values = {
        "network": "none",
        "read_only_root": True,
        "candidate_mount_path": "/candidate",
        "candidate_mount_mode": "ro",
        "workdir": "/candidate",
        "user_policy": "host_uid_gid_when_available",
    }
    for key, expected in fixed_values.items():
        if container.get(key) != expected:
            raise ManifestError(f"container.{key} must be {expected!r}")
    for key in ("tmpfs", "cap_drop", "security_opt", "ulimit"):
        if not _strings(container.get(key), f"container.{key}"):
            raise ManifestError(f"container.{key} must not be empty")
    _normalize_manifest_tmpfs(_strings(container["tmpfs"], "container.tmpfs"))
    _normalize_manifest_ulimits(_strings(container["ulimit"], "container.ulimit"))
    if "ALL" not in _strings(container["cap_drop"], "container.cap_drop"):
        raise ManifestError("container.cap_drop must include ALL")
    if "no-new-privileges" not in _strings(
        container["security_opt"],
        "container.security_opt",
    ):
        raise ManifestError("container.security_opt must include no-new-privileges")
    _positive_integer(container.get("pids_limit"), "container.pids_limit")
    _positive_number(container.get("cpus"), "container.cpus")
    _nano_cpus(container["cpus"])
    if not isinstance(container.get("require_non_root_when_applied"), bool):
        raise ManifestError("container.require_non_root_when_applied must be a boolean")

    network_probe = _object(manifest.get("network_probe"), "network_probe")
    _manifest_keys(
        network_probe,
        {"host", "port", "timeout_seconds"},
        "network_probe",
    )
    if not isinstance(network_probe.get("host"), str) or not network_probe["host"]:
        raise ManifestError("network_probe.host must be a non-empty string")
    port = network_probe.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ManifestError("network_probe.port must be an integer from 1 to 65535")
    _positive_number(
        network_probe.get("timeout_seconds"),
        "network_probe.timeout_seconds",
    )

    forbidden = _strings(manifest.get("forbidden_paths"), "forbidden_paths")
    if not forbidden or any(not path.startswith("/") for path in forbidden):
        raise ManifestError("forbidden_paths must contain absolute container paths")
    required_probes = _strings(manifest.get("required_probes"), "required_probes")
    if len(required_probes) != len(set(required_probes)):
        raise ManifestError("required_probes must not contain duplicates")
    unknown_probes = sorted(set(required_probes) - set(MANDATORY_SECURITY_PROBES))
    missing_probes = sorted(set(MANDATORY_SECURITY_PROBES) - set(required_probes))
    if unknown_probes or missing_probes:
        raise ManifestError(
            "required_probes must be the exact mandatory security set "
            f"(unknown={unknown_probes}, missing={missing_probes})"
        )

    profiles = _objects(manifest.get("profiles"), "profiles")
    if not profiles:
        raise ManifestError("profiles must not be empty")
    ids: set[str] = set()
    for index, profile in enumerate(profiles):
        _manifest_keys(profile, {"id", "runtime", "required"}, f"profiles[{index}]")
        profile_id = profile.get("id")
        if not isinstance(profile_id, str) or not profile_id:
            raise ManifestError(f"profiles[{index}].id must be a non-empty string")
        if profile_id in ids:
            raise ManifestError(f"duplicate profile id: {profile_id}")
        ids.add(profile_id)
        runtime = profile.get("runtime")
        if runtime is not None and (not isinstance(runtime, str) or not runtime):
            raise ManifestError(f"profiles[{index}].runtime must be null or a non-empty string")
        if not isinstance(profile.get("required"), bool):
            raise ManifestError(f"profiles[{index}].required must be a boolean")


def _parse_manifest_bytes(raw_bytes: bytes, path: Path) -> JSONObject:
    try:
        raw = json.loads(raw_bytes)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"could not load manifest {path}: {exc}") from exc
    manifest = _object(raw, "manifest")
    validate_manifest(manifest)
    return manifest


def _load_manifest_snapshot(path: Path) -> tuple[JSONObject, bytes]:
    try:
        raw = read_stable_regular_file(path, label="isolation manifest")
    except OSError as exc:
        raise ManifestError(f"could not load manifest {path}: {exc}") from exc
    return _parse_manifest_bytes(raw, path), raw


def load_manifest(path: Path = DEFAULT_MANIFEST) -> JSONObject:
    """Load and validate one bounded, stable, non-link manifest."""

    manifest, _ = _load_manifest_snapshot(path)
    return manifest


def _control(
    command: list[str],
    *,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    completed: subprocess.CompletedProcess[str] = run_bounded_subprocess(
        command,
        cwd=None,
        env=dict(os.environ),
        timeout=timeout,
    )
    return completed


def _json_control(command: list[str], *, timeout: float) -> JSONObject:
    completed = _control(command, timeout=timeout)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(
            f"{' '.join(command[:2])} exited {completed.returncode}: {_bounded(detail)}"
        )
    try:
        return _object(json.loads(completed.stdout), "Docker JSON output")
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Docker returned malformed JSON for {' '.join(command[:2])}: {exc}"
        ) from exc


def collect_host_metadata() -> JSONObject:
    """Collect bounded host facts without copying environment variables."""

    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    uid = cast(Callable[[], int], getuid)() if callable(getuid) else None
    gid = cast(Callable[[], int], getgid)() if callable(getgid) else None
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "os_name": os.name,
        "uid": uid,
        "gid": gid,
    }


def collect_source_metadata(
    source_bytes: Mapping[str, bytes] | None = None,
) -> JSONObject:
    """Bind the result to Git state and the exact evaluator/helper source bytes."""

    try:
        commit = run_bounded_subprocess(
            ["git", "rev-parse", "HEAD"],
            cwd=str(REPOSITORY_ROOT),
            env=dict(os.environ),
            timeout=10,
        )
        dirty = run_bounded_subprocess(
            ["git", "status", "--porcelain=v1"],
            cwd=str(REPOSITORY_ROOT),
            env=dict(os.environ),
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError, RuntimeError):
        git: JSONObject = {"git_commit": None, "git_dirty": None}
        snapshot = source_bytes if source_bytes is not None else _capture_source_bytes()
        return {**git, **_source_file_inventory(snapshot)}
    if commit.returncode != 0 or dirty.returncode != 0:
        git = {"git_commit": None, "git_dirty": None}
    else:
        git = {
        "git_commit": commit.stdout.strip() or None,
        "git_dirty": bool(dirty.stdout),
    }
    snapshot = source_bytes if source_bytes is not None else _capture_source_bytes()
    return {**git, **_source_file_inventory(snapshot)}


def collect_docker_metadata(control_timeout: float) -> JSONObject:
    """Collect actual client/daemon/runtime metadata or an unsupported fact."""

    executable = shutil.which("docker")
    if executable is None:
        return {
            "available": False,
            "executable": None,
            "error": "docker executable not found",
            "client": None,
            "server": None,
            "info": None,
            "available_runtimes": [],
        }
    try:
        version = _json_control(
            ["docker", "version", "--format", "{{json .}}"],
            timeout=control_timeout,
        )
        info = _json_control(
            ["docker", "info", "--format", "{{json .}}"],
            timeout=control_timeout,
        )
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        return {
            "available": False,
            "executable": Path(executable).name,
            "error": _bounded(exc),
            "client": None,
            "server": None,
            "info": None,
            "available_runtimes": [],
        }

    runtimes_raw = info.get("Runtimes")
    runtimes = sorted(str(key) for key in runtimes_raw) if isinstance(runtimes_raw, dict) else []
    client = version.get("Client")
    server = version.get("Server")
    compact_info = {
        "server_version": info.get("ServerVersion"),
        "operating_system": info.get("OperatingSystem"),
        "os_type": info.get("OSType"),
        "architecture": info.get("Architecture"),
        "kernel_version": info.get("KernelVersion"),
        "default_runtime": info.get("DefaultRuntime"),
        "cgroup_driver": info.get("CgroupDriver"),
        "cgroup_version": info.get("CgroupVersion"),
        "security_options": info.get("SecurityOptions"),
    }
    return {
        "available": True,
        "executable": Path(executable).name,
        "error": None,
        "client": client if isinstance(client, dict) else None,
        "server": server if isinstance(server, dict) else None,
        "info": compact_info,
        "available_runtimes": runtimes,
    }


def resolve_image_metadata(
    image: str,
    *,
    control_timeout: float,
    pull_timeout: float,
    pull: bool,
) -> JSONObject:
    """Resolve a mutable image reference to the exact image ID used by probes."""

    if pull:
        resolution = resolve_docker_image(
            image,
            control_runner=_control,
            pull_when_inspection_empty=True,
            control_timeout=control_timeout,
            pull_timeout=pull_timeout,
        )
    else:
        inspected_without_pull = inspect_docker_image(
            image,
            control_runner=_control,
            timeout=control_timeout,
        )
        inspected_id = (
            inspected_without_pull.stdout.strip() if inspected_without_pull.returncode == 0 else ""
        )
        if not inspected_id:
            detail = (inspected_without_pull.stderr or inspected_without_pull.stdout).strip()
            return {
                "requested": image,
                "image_id": None,
                "repo_digests": [],
                "pull_attempted": False,
                "error": _bounded(detail or "image is unavailable and --no-pull was requested"),
            }
        image_id = require_canonical_docker_image_id(inspected_id)
        resolution = resolve_docker_image(
            image_id,
            control_runner=_control,
            pull_when_inspection_empty=False,
            control_timeout=control_timeout,
            pull_timeout=pull_timeout,
        )
    if resolution.image_id is None:
        final = resolution.final_inspection or resolution.initial_inspection
        detail = (final.stderr or final.stdout).strip()
        return {
            "requested": image,
            "image_id": None,
            "repo_digests": [],
            "pull_attempted": resolution.pull_attempted,
            "error": _bounded(detail or "image identity could not be resolved"),
        }

    repo_digests: list[str] = []
    inspected = _control(
        [
            "docker",
            "image",
            "inspect",
            "--format",
            "{{json .RepoDigests}}",
            resolution.image_id,
        ],
        timeout=control_timeout,
    )
    if inspected.returncode == 0:
        try:
            values = json.loads(inspected.stdout)
            if isinstance(values, list):
                repo_digests = [str(value) for value in values]
        except json.JSONDecodeError:
            pass
    return {
        "requested": image,
        "image_id": resolution.image_id,
        "repo_digests": repo_digests,
        "pull_attempted": resolution.pull_attempted,
        "error": None,
    }


def expected_container_user(manifest: JSONObject) -> tuple[int, int] | None:
    """Apply the same conditional host UID/GID contract as the runtime code."""

    container = _object(manifest["container"], "container")
    if container["user_policy"] != "host_uid_gid_when_available":
        raise ManifestError("unsupported container user policy")
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if not callable(getuid) or not callable(getgid):
        return None
    return cast(Callable[[], int], getuid)(), cast(Callable[[], int], getgid)()


def build_container_command(
    manifest: JSONObject,
    profile: JSONObject,
    *,
    image_id: str,
    candidate_dir: str,
    name: str,
    payload_command: Sequence[str],
    environment: Mapping[str, str] | None = None,
    user: tuple[int, int] | None = None,
) -> list[str]:
    """Build the exact hardened Docker argv exercised by the kit."""

    container = _object(manifest["container"], "container")
    command = [
        "docker",
        "run",
        "--name",
        name,
        "--network",
        str(container["network"]),
        "--read-only",
        "--pids-limit",
        str(container["pids_limit"]),
        "--cpus",
        str(container["cpus"]),
    ]
    for tmpfs in _strings(container["tmpfs"], "container.tmpfs"):
        command += ["--tmpfs", tmpfs]
    for capability in _strings(container["cap_drop"], "container.cap_drop"):
        command += ["--cap-drop", capability]
    for option in _strings(container["security_opt"], "container.security_opt"):
        command += ["--security-opt", option]
    for limit in _strings(container["ulimit"], "container.ulimit"):
        command += ["--ulimit", limit]
    command += [
        "-e",
        "HOME=/tmp",
        "-e",
        "PYTHONDONTWRITEBYTECODE=1",
        "-e",
        "LANG=C.UTF-8",
    ]
    for key, value in sorted((environment or {}).items()):
        command += ["-e", f"{key}={value}"]
    mount_path = str(container["candidate_mount_path"])
    mount_mode = str(container["candidate_mount_mode"])
    command += [
        "-v",
        f"{candidate_dir}:{mount_path}:{mount_mode}",
        "-w",
        str(container["workdir"]),
    ]
    if user is not None:
        command += ["--user", f"{user[0]}:{user[1]}"]
    runtime = profile.get("runtime")
    if runtime is not None:
        command += ["--runtime", str(runtime)]
    return [*command, image_id, *payload_command]


def command_template(
    command: Sequence[str],
    *,
    candidate_dir: str,
    container_name: str,
) -> list[str]:
    """Replace run-specific paths/names while retaining exact settings."""

    template = [
        str(part)
        .replace(candidate_dir, "${CANDIDATE_DIR}")
        .replace(container_name, "${CONTAINER_NAME}")
        for part in command
    ]
    return template


def _cleanup(
    name: str,
    manifest: JSONObject,
) -> DockerContainerCleanupResult:
    cleanup = _object(manifest["cleanup"], "cleanup")
    return cleanup_named_container(
        name,
        control_runner=_control,
        control_timeout=float(manifest["control_timeout_seconds"]),
        total_timeout=float(cleanup["total_timeout_seconds"]),
        reconcile_attempts=int(cleanup["reconcile_attempts"]),
        reconcile_interval=float(cleanup["reconcile_interval_seconds"]),
        required_final_absent_observations=int(cleanup["required_final_absent_observations"]),
    )


def cleanup_evidence(result: DockerContainerCleanupResult) -> JSONObject:
    """Serialize bounded cleanup proof without raw daemon output."""

    return {
        "proven_absent": result.proven_absent,
        "error": result.error,
        "removal_returncodes": [removal.returncode for removal in result.removals],
        "absence_observations": [
            {
                "absent": observation.absent,
                "error": observation.error,
                "query_returncode": (
                    observation.query.returncode if observation.query is not None else None
                ),
            }
            for observation in result.observations
        ],
    }


def _inspect_container(name: str, control_timeout: float) -> JSONObject:
    return _json_control(
        ["docker", "inspect", "--format", "{{json .}}", name],
        timeout=control_timeout,
    )


def extract_container_metadata(inspected: JSONObject) -> JSONObject:
    """Keep only isolation-relevant fields from the Docker inspect payload."""

    config = _object(inspected.get("Config"), "docker inspect Config")
    host = _object(inspected.get("HostConfig"), "docker inspect HostConfig")
    mounts = _objects(inspected.get("Mounts"), "docker inspect Mounts")
    return {
        "id": inspected.get("Id"),
        "image": inspected.get("Image"),
        "user": config.get("User"),
        "network_mode": host.get("NetworkMode"),
        "read_only_rootfs": host.get("ReadonlyRootfs"),
        "runtime": host.get("Runtime"),
        "cap_drop": host.get("CapDrop"),
        "security_opt": host.get("SecurityOpt"),
        "tmpfs": host.get("Tmpfs"),
        "pids_limit": host.get("PidsLimit"),
        "nano_cpus": host.get("NanoCpus"),
        "ulimits": host.get("Ulimits"),
        "mounts": [
            {
                "type": mount.get("Type"),
                "destination": mount.get("Destination"),
                "rw": mount.get("RW"),
            }
            for mount in mounts
        ],
    }


def _probe(
    probe_id: str,
    *,
    required: bool,
    status: str,
    expected: object,
    observed: object,
    detail: str | None = None,
) -> Probe:
    if status not in _STATUS_VALUES:
        raise ValueError(f"unknown probe status: {status}")
    return {
        "id": probe_id,
        "required": required,
        "status": status,
        "expected": expected,
        "observed": observed,
        "detail": detail,
    }


def _attempt_blocked(payload: JSONObject, attempt_name: str) -> bool:
    attempts = _object(payload.get("attempts"), "probe attempts")
    attempt = _object(attempts.get(attempt_name), f"probe attempt {attempt_name}")
    return attempt.get("blocked") is True


def evaluate_isolation_probes(
    manifest: JSONObject,
    profile: JSONObject,
    *,
    payload: JSONObject,
    inspected: JSONObject,
    expected_user: tuple[int, int] | None,
    cleanup: DockerContainerCleanupResult,
) -> list[Probe]:
    """Compare active attempts and daemon facts with the manifest contract."""

    if payload.get("schema_version") != PROBE_VERSION:
        raise RuntimeError("container probe returned an unsupported schema version")
    container = _object(manifest["container"], "container")
    required_ids = set(_strings(manifest["required_probes"], "required_probes"))
    metadata = extract_container_metadata(inspected)
    mounts = _objects(metadata["mounts"], "container metadata mounts")
    candidate_mount = next(
        (
            mount
            for mount in mounts
            if mount.get("destination") == container["candidate_mount_path"]
        ),
        None,
    )

    network_observed = {
        "attempt_blocked": _attempt_blocked(payload, "network_connect"),
        "network_mode": metadata["network_mode"],
    }
    probes = [
        _probe(
            "network_none",
            required="network_none" in required_ids,
            status=(
                "pass"
                if network_observed["attempt_blocked"]
                and network_observed["network_mode"] == "none"
                else "fail"
            ),
            expected={"attempt_blocked": True, "network_mode": "none"},
            observed=network_observed,
        ),
        _probe(
            "candidate_mount_read_only",
            required="candidate_mount_read_only" in required_ids,
            status=(
                "pass"
                if _attempt_blocked(payload, "candidate_mount_write")
                and candidate_mount is not None
                and candidate_mount.get("rw") is False
                else "fail"
            ),
            expected={"attempt_blocked": True, "destination": "/candidate", "rw": False},
            observed={
                "attempt_blocked": _attempt_blocked(
                    payload,
                    "candidate_mount_write",
                ),
                "mount": candidate_mount,
            },
        ),
        _probe(
            "root_filesystem_read_only",
            required="root_filesystem_read_only" in required_ids,
            status=(
                "pass"
                if _attempt_blocked(payload, "root_filesystem_write")
                and metadata["read_only_rootfs"] is True
                else "fail"
            ),
            expected={"attempt_blocked": True, "read_only_rootfs": True},
            observed={
                "attempt_blocked": _attempt_blocked(
                    payload,
                    "root_filesystem_write",
                ),
                "read_only_rootfs": metadata["read_only_rootfs"],
            },
        ),
    ]

    attempts = _object(payload["attempts"], "probe attempts")
    forbidden_attempts = _object(
        attempts.get("forbidden_path_read"),
        "forbidden path attempts",
    )
    forbidden_paths = _strings(manifest["forbidden_paths"], "forbidden_paths")
    mount_destinations = [
        str(mount["destination"]) for mount in mounts if isinstance(mount.get("destination"), str)
    ]
    forbidden_observed = {
        path: {
            "attempt_blocked": _object(
                forbidden_attempts.get(path),
                f"forbidden path {path}",
            ).get("blocked"),
            "covering_mounts": [
                destination
                for destination in mount_destinations
                if path == destination or path.startswith(destination.rstrip("/") + "/")
            ],
        }
        for path in forbidden_paths
    }
    probes.append(
        _probe(
            "forbidden_path_read",
            required="forbidden_path_read" in required_ids,
            status=(
                "pass"
                if all(
                    observation["attempt_blocked"] is True and not observation["covering_mounts"]
                    for observation in forbidden_observed.values()
                )
                else "fail"
            ),
            expected={
                path: {"attempt_blocked": True, "covering_mounts": []} for path in forbidden_paths
            },
            observed=forbidden_observed,
        )
    )

    expected_security = _expected_security_profile(manifest)
    observed_security = _observed_security_profile(metadata)
    probes.append(
        _probe(
            "security_profile",
            required="security_profile" in required_ids,
            status="pass" if observed_security == expected_security else "fail",
            expected=expected_security,
            observed=observed_security,
        )
    )

    requested_runtime = profile.get("runtime")
    observed_runtime = metadata.get("runtime")
    runtime_ok = requested_runtime is None or observed_runtime == requested_runtime
    probes.append(
        _probe(
            "runtime_selection",
            required=requested_runtime is not None,
            status="pass" if runtime_ok else "fail",
            expected=requested_runtime or "daemon_default",
            observed=observed_runtime,
        )
    )

    identity = _object(payload.get("identity"), "probe identity")
    require_non_root = bool(container["require_non_root_when_applied"])
    if expected_user is None:
        probes.append(
            _probe(
                "user_identity",
                required=False,
                status="skip",
                expected="host UID/GID only when the host exposes os.getuid/os.getgid",
                observed={
                    "uid": identity.get("uid"),
                    "gid": identity.get("gid"),
                    "configured_user": metadata.get("user"),
                },
                detail="host contract did not apply a UID/GID on this platform",
            )
        )
    else:
        observed_uid = identity.get("uid")
        observed_gid = identity.get("gid")
        non_root_ok = not require_non_root or (expected_user[0] != 0 and expected_user[1] != 0)
        identity_ok = (
            observed_uid == expected_user[0]
            and observed_gid == expected_user[1]
            and metadata.get("user") == f"{expected_user[0]}:{expected_user[1]}"
            and non_root_ok
        )
        probes.append(
            _probe(
                "user_identity",
                required=True,
                status="pass" if identity_ok else "fail",
                expected={
                    "uid": expected_user[0],
                    "gid": expected_user[1],
                    "non_root": require_non_root,
                },
                observed={
                    "uid": observed_uid,
                    "gid": observed_gid,
                    "configured_user": metadata.get("user"),
                },
            )
        )

    probes.append(
        _probe(
            "normal_cleanup",
            required="normal_cleanup" in required_ids,
            status="pass" if cleanup.proven_absent else "fail",
            expected={"proven_absent": True},
            observed=cleanup_evidence(cleanup),
        )
    )
    return probes


def _execute_main_probe(
    manifest: JSONObject,
    profile: JSONObject,
    *,
    image_id: str,
    expected_user_value: tuple[int, int] | None,
    probe_source_bytes: bytes,
) -> tuple[JSONObject | None, list[Probe]]:
    control_timeout = float(manifest["control_timeout_seconds"])
    network_probe = _object(manifest["network_probe"], "network_probe")
    environment = {
        "EVOGUARD_CONFORMANCE_FORBIDDEN_PATHS": json.dumps(
            manifest["forbidden_paths"],
            separators=(",", ":"),
        ),
        "EVOGUARD_CONFORMANCE_NETWORK_HOST": str(network_probe["host"]),
        "EVOGUARD_CONFORMANCE_NETWORK_PORT": str(network_probe["port"]),
        "EVOGUARD_CONFORMANCE_NETWORK_TIMEOUT": str(network_probe["timeout_seconds"]),
    }

    with tempfile.TemporaryDirectory(prefix=".tmp_evoguard_conformance_") as tmp:
        candidate = Path(tmp) / "candidate"
        candidate.mkdir()
        write_create_only_bytes(candidate / "isolation_probe.py", probe_source_bytes)
        name = docker_container_name(f"conformance-{profile['id']}")
        command = build_container_command(
            manifest,
            profile,
            image_id=image_id,
            candidate_dir=str(candidate.resolve()),
            name=name,
            payload_command=["python", "/candidate/isolation_probe.py"],
            environment=environment,
            user=expected_user_value,
        )
        template = command_template(
            command,
            candidate_dir=str(candidate.resolve()),
            container_name=name,
        )
        cleanup_result: DockerContainerCleanupResult | None = None
        completed: subprocess.CompletedProcess[str] | None = None
        inspected: JSONObject | None = None
        payload: JSONObject | None = None
        execution_error: str | None = None
        try:
            completed = run_bounded_subprocess(
                command,
                cwd=None,
                env=dict(os.environ),
                timeout=float(manifest["run_timeout_seconds"]),
            )
            if completed.returncode == 0:
                inspected = _inspect_container(name, control_timeout)
            else:
                execution_error = (
                    f"probe container exited {completed.returncode}: {_bounded(completed.stderr)}"
                )
        except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
            execution_error = f"{type(exc).__name__}: {_bounded(exc)}"
        finally:
            cleanup_result = _cleanup(name, manifest)

        container_evidence: JSONObject = {
            "command_template": template,
            "returncode": completed.returncode if completed is not None else None,
            "stderr": _bounded(completed.stderr) if completed is not None else "",
            "inspect": (extract_container_metadata(inspected) if inspected is not None else None),
            "probe_payload": None,
        }
        if execution_error is not None or completed is None or inspected is None:
            return container_evidence, [
                _probe(
                    "probe_execution",
                    required=True,
                    status="error",
                    expected={"returncode": 0, "inspect_available": True},
                    observed={
                        "returncode": (completed.returncode if completed is not None else None),
                        "inspect_available": inspected is not None,
                        "cleanup": cleanup_evidence(cleanup_result),
                    },
                    detail=execution_error or "probe execution evidence incomplete",
                )
            ]

        try:
            payload = _object(json.loads(completed.stdout), "container probe output")
            probes = evaluate_isolation_probes(
                manifest,
                profile,
                payload=payload,
                inspected=inspected,
                expected_user=expected_user_value,
                cleanup=cleanup_result,
            )
        except (json.JSONDecodeError, ManifestError, RuntimeError, ValueError) as exc:
            probes = [
                _probe(
                    "probe_output",
                    required=True,
                    status="error",
                    expected=PROBE_VERSION,
                    observed=_bounded(completed.stdout),
                    detail=f"{type(exc).__name__}: {_bounded(exc)}",
                )
            ]
        container_evidence["probe_payload"] = payload
        return container_evidence, probes


def _execute_timeout_probe(
    manifest: JSONObject,
    profile: JSONObject,
    *,
    image_id: str,
    expected_user_value: tuple[int, int] | None,
) -> Probe:
    with tempfile.TemporaryDirectory(prefix=".tmp_evoguard_timeout_") as tmp:
        candidate = Path(tmp) / "candidate"
        candidate.mkdir()
        name = docker_container_name(f"conformance-timeout-{profile['id']}")
        command = build_container_command(
            manifest,
            profile,
            image_id=image_id,
            candidate_dir=str(candidate.resolve()),
            name=name,
            payload_command=[
                "python",
                "-c",
                "import time; print('ready', flush=True); time.sleep(600)",
            ],
            user=expected_user_value,
        )
        cleanup_results: list[DockerContainerCleanupResult] = []

        def started(container_name: str) -> bool:
            proven: bool = probe_container_started(
                container_name,
                control_runner=_control,
                timeout=float(manifest["control_timeout_seconds"]),
            ).proven
            return proven

        def cleanup_container(container_name: str) -> bool:
            result = _cleanup(container_name, manifest)
            cleanup_results.append(result)
            proven_absent: bool = result.proven_absent
            return proven_absent

        timeout_seen = False
        container_started = False
        error: str | None = None
        returned: subprocess.CompletedProcess[str] | None = None
        try:
            returned = run_named_docker_client(
                DockerRunRequest.from_command(
                    command,
                    name=name,
                    timeout=float(manifest["timeout_probe_seconds"]),
                    environment=dict(os.environ),
                ),
                process_runner=run_bounded_subprocess,
                container_started=cast(ContainerStartedProbe, started),
                cleanup_container=cast(ContainerCleanup, cleanup_container),
                process_argv=command,
            )
        except DockerRunTimeout as exc:
            timeout_seen = True
            container_started = exc.container_started
        except DockerRunContainmentError as exc:
            container_started = exc.container_started
            error = f"{type(exc).__name__}: {_bounded(exc)}"
        except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
            error = f"{type(exc).__name__}: {_bounded(exc)}"
        finally:
            if not cleanup_results:
                cleanup_results.append(_cleanup(name, manifest))

        cleanup_result = cleanup_results[-1]
        passed = timeout_seen and container_started and cleanup_result.proven_absent
        return _probe(
            "timeout_cleanup",
            required="timeout_cleanup"
            in set(_strings(manifest["required_probes"], "required_probes")),
            status="pass" if passed else ("error" if error else "fail"),
            expected={
                "timeout_raised": True,
                "container_started": True,
                "cleanup_proven_absent": True,
            },
            observed={
                "timeout_raised": timeout_seen,
                "container_started": container_started,
                "returned_code": (returned.returncode if returned is not None else None),
                "cleanup": cleanup_evidence(cleanup_result),
                "command_template": command_template(
                    command,
                    candidate_dir=str(candidate.resolve()),
                    container_name=name,
                ),
            },
            detail=error,
        )


def profile_status(probes: Sequence[Probe]) -> str:
    """Derive one profile status without converting skip/unsupported to pass."""

    required = [probe for probe in probes if probe.get("required") is True]
    if not required:
        return "error"
    if any(probe.get("status") == "error" for probe in required):
        return "error"
    if any(probe.get("status") == "fail" for probe in required):
        return "fail"
    if any(probe.get("status") in {"skip", "unsupported"} for probe in required):
        return "unsupported"
    return "pass"


def unsupported_profile(
    profile: JSONObject,
    available_runtimes: Sequence[str],
) -> Profile:
    """Represent a missing OCI runtime as unsupported, never as PASS."""

    runtime = profile.get("runtime")
    reason = f"Docker runtime {runtime!r} is not registered by the daemon"
    return {
        "id": profile["id"],
        "required": profile["required"],
        "requested_runtime": runtime,
        "status": "unsupported",
        "reason": reason,
        "runtime": {
            "requested": runtime,
            "available": False,
            "available_runtimes": list(available_runtimes),
            "observed": None,
        },
        "container": None,
        "probes": [
            _probe(
                "runtime_available",
                required=bool(profile["required"]),
                status="unsupported",
                expected={"registered": True, "runtime": runtime},
                observed={
                    "registered": False,
                    "available_runtimes": list(available_runtimes),
                },
                detail=reason,
            )
        ],
    }


def execute_profile(
    manifest: JSONObject,
    profile: JSONObject,
    *,
    image_id: str,
    available_runtimes: Sequence[str],
    probe_source_bytes: bytes,
) -> Profile:
    """Run all probes for one available Docker runtime profile."""

    runtime = profile.get("runtime")
    if runtime is not None and runtime not in available_runtimes:
        return unsupported_profile(profile, available_runtimes)

    expected_user_value = expected_container_user(manifest)
    try:
        container, probes = _execute_main_probe(
            manifest,
            profile,
            image_id=image_id,
            expected_user_value=expected_user_value,
            probe_source_bytes=probe_source_bytes,
        )
        probes.append(
            _execute_timeout_probe(
                manifest,
                profile,
                image_id=image_id,
                expected_user_value=expected_user_value,
            )
        )
        status = profile_status(probes)
        observed_runtime = None
        if container is not None:
            inspect = container.get("inspect")
            if isinstance(inspect, dict):
                observed_runtime = inspect.get("runtime")
        return {
            "id": profile["id"],
            "required": profile["required"],
            "requested_runtime": runtime,
            "status": status,
            "reason": None if status == "pass" else "one or more probes did not pass",
            "runtime": {
                "requested": runtime,
                "available": True,
                "available_runtimes": list(available_runtimes),
                "observed": observed_runtime,
            },
            "container": container,
            "probes": probes,
        }
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as exc:
        detail = f"{type(exc).__name__}: {_bounded(exc)}"
        return _harness_error_profile(profile, available_runtimes, detail)


def overall_status(profiles: Sequence[Profile]) -> str:
    """Aggregate profiles while preserving optional runtime unavailability."""

    if any(profile.get("status") == "error" for profile in profiles):
        return "error"
    if any(profile.get("status") == "fail" for profile in profiles):
        return "fail"
    if any(
        profile.get("status") == "unsupported" and profile.get("required") is True
        for profile in profiles
    ):
        return "unsupported"
    if any(profile.get("status") == "pass" for profile in profiles):
        return "pass"
    return "unsupported"


def _status_counts(statuses: Sequence[object]) -> dict[str, int]:
    return {status: sum(value == status for value in statuses) for status in _STATUS_VALUES}


def summarize(profiles: Sequence[Profile]) -> JSONObject:
    profile_statuses = [profile.get("status") for profile in profiles]
    probe_statuses = [
        probe.get("status")
        for profile in profiles
        for probe in cast(list[Probe], profile.get("probes", []))
    ]
    return {
        "profiles": _status_counts(profile_statuses),
        "probes": _status_counts(probe_statuses),
    }


def _docker_unavailable_profile(profile: JSONObject, reason: str) -> Profile:
    return {
        "id": profile["id"],
        "required": profile["required"],
        "requested_runtime": profile.get("runtime"),
        "status": "unsupported",
        "reason": reason,
        "runtime": {
            "requested": profile.get("runtime"),
            "available": False,
            "available_runtimes": [],
            "observed": None,
        },
        "container": None,
        "probes": [
            _probe(
                "docker_available",
                required=bool(profile["required"]),
                status="unsupported",
                expected={"available": True},
                observed={"available": False},
                detail=reason,
            )
        ],
    }


def _image_unavailable_profile(
    profile: JSONObject,
    available_runtimes: Sequence[str],
    reason: str,
) -> Profile:
    runtime = profile.get("runtime")
    runtime_available = runtime is None or runtime in available_runtimes
    return {
        "id": profile["id"],
        "required": profile["required"],
        "requested_runtime": runtime,
        "status": "error",
        "reason": reason,
        "runtime": {
            "requested": runtime,
            "available": runtime_available,
            "available_runtimes": list(available_runtimes),
            "observed": None,
        },
        "container": None,
        "probes": [
            _probe(
                "image_available",
                required=True,
                status="error",
                expected={"resolved_image_id": True},
                observed={"resolved_image_id": False},
                detail=reason,
            )
        ],
    }


def _harness_error_profile(
    profile: JSONObject,
    available_runtimes: Sequence[str],
    reason: str,
) -> Profile:
    return {
        "id": profile["id"],
        "required": profile["required"],
        "requested_runtime": profile.get("runtime"),
        "status": "error",
        "reason": reason,
        "runtime": {
            "requested": profile.get("runtime"),
            "available": True,
            "available_runtimes": list(available_runtimes),
            "observed": None,
        },
        "container": None,
        "probes": [
            _probe(
                "harness_execution",
                required=True,
                status="error",
                expected="bounded probe completion",
                observed=None,
                detail=reason,
            )
        ],
    }


def _select_profiles(
    manifest: JSONObject,
    selected: Sequence[str] | None,
    *,
    require_gvisor: bool,
) -> list[JSONObject]:
    profiles = _objects(manifest["profiles"], "profiles")
    by_id = {str(profile["id"]): profile for profile in profiles}
    selected_ids = list(by_id) if not selected or "all" in selected else list(selected)
    unknown = sorted(set(selected_ids) - set(by_id))
    if unknown:
        raise ManifestError(f"unknown profile(s): {', '.join(unknown)}")
    chosen: list[JSONObject] = []
    for profile_id in selected_ids:
        profile = dict(by_id[profile_id])
        if require_gvisor and profile_id == "gvisor":
            profile["required"] = True
        chosen.append(profile)
    if require_gvisor and "gvisor" not in selected_ids:
        raise ManifestError("--require-gvisor requires selecting the gvisor profile")
    return chosen


def _reproduce(
    *,
    manifest_path: Path,
    image: str,
    selected_profiles: Sequence[str] | None,
    require_gvisor: bool,
    pull: bool,
    output_path: Path | None,
) -> JSONObject:
    manifest_label = _logical_repo_path(manifest_path, "external-manifest.json")
    argv = [
        "python",
        "-m",
        "tools.conformance.run_isolation_conformance",
        "--manifest",
        manifest_label,
        "--image",
        image,
    ]
    if selected_profiles:
        for profile in selected_profiles:
            argv += ["--profile", profile]
    if require_gvisor:
        argv.append("--require-gvisor")
    if not pull:
        argv.append("--no-pull")
    if output_path is not None:
        argv += ["--output", "<result.json>"]
    shell = subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv)
    return {"argv": argv, "shell": shell}


def run_conformance(
    *,
    manifest_path: Path = DEFAULT_MANIFEST,
    image: str | None = None,
    selected_profiles: Sequence[str] | None = None,
    require_gvisor: bool = False,
    pull: bool = True,
    output_path: Path | None = None,
) -> JSONObject:
    """Run selected profiles and return one schema-versioned evidence object."""

    started = _utc_now()
    manifest, manifest_bytes = _load_manifest_snapshot(manifest_path)
    source_bytes = _capture_source_bytes()
    probe_source_bytes = source_bytes[PROBE_SOURCE_LABEL]
    profiles_config = _select_profiles(
        manifest,
        selected_profiles,
        require_gvisor=require_gvisor,
    )
    requested_image = image or str(manifest["default_image"])
    control_timeout = float(manifest["control_timeout_seconds"])
    docker = collect_docker_metadata(control_timeout)
    image_metadata: JSONObject = {
        "requested": requested_image,
        "image_id": None,
        "repo_digests": [],
        "pull_attempted": False,
        "error": "Docker was not available",
    }

    if docker["available"] is not True:
        reason = str(docker.get("error") or "Docker daemon is unavailable")
        profiles = [
            _docker_unavailable_profile(profile, reason)
            for profile in profiles_config
        ]
    else:
        try:
            image_metadata = resolve_image_metadata(
                requested_image,
                control_timeout=control_timeout,
                pull_timeout=float(manifest["image_pull_timeout_seconds"]),
                pull=pull,
            )
        except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as exc:
            image_metadata = {
                "requested": requested_image,
                "image_id": None,
                "repo_digests": [],
                "pull_attempted": False,
                "error": f"{type(exc).__name__}: {_bounded(exc)}",
            }
        image_id = image_metadata.get("image_id")
        if not isinstance(image_id, str):
            reason = str(image_metadata.get("error") or "image resolution failed")
            runtimes = _strings(
                docker.get("available_runtimes"),
                "Docker available runtimes",
            )
            profiles = [
                _image_unavailable_profile(profile, runtimes, reason)
                for profile in profiles_config
            ]
        else:
            runtimes = _strings(
                docker.get("available_runtimes"),
                "Docker available runtimes",
            )
            profiles = [
                execute_profile(
                    manifest,
                    profile,
                    image_id=image_id,
                    available_runtimes=runtimes,
                    probe_source_bytes=probe_source_bytes,
                )
                for profile in profiles_config
            ]

    source_metadata = collect_source_metadata(source_bytes)
    host_metadata = collect_host_metadata()
    finished = _utc_now()
    result: JSONObject = {
        "$schema": RESULT_SCHEMA_LABEL,
        "schema_version": RESULT_VERSION,
        "suite_id": manifest["suite_id"],
        "run_id": uuid.uuid4().hex,
        "started_at_utc": started,
        "finished_at_utc": finished,
        "status": overall_status(profiles),
        "manifest": {
            "path": _logical_repo_path(manifest_path, "external-manifest.json"),
            "sha256": _sha256_bytes(manifest_bytes),
            "bytes": len(manifest_bytes),
        },
        "probe_source": {
            "path": PROBE_SOURCE_LABEL,
            "sha256": _sha256_bytes(probe_source_bytes),
            "bytes": len(probe_source_bytes),
        },
        "source": source_metadata,
        "reproduce": _reproduce(
            manifest_path=manifest_path,
            image=(
                str(image_metadata["image_id"])
                if isinstance(image_metadata.get("image_id"), str)
                else requested_image
            ),
            selected_profiles=selected_profiles,
            require_gvisor=require_gvisor,
            pull=pull,
            output_path=output_path,
        ),
        "environment": {
            "host": host_metadata,
            "docker": docker,
            "image": image_metadata,
        },
        "profiles": profiles,
        "summary": summarize(profiles),
    }
    return result


def write_result(result: JSONObject, path: Path | None) -> None:
    """Write canonical pretty JSON create-only, or emit it to stdout."""

    payload = (
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    if path is None:
        sys.stdout.write(payload)
        return
    write_create_only_bytes(path, payload.encode("utf-8"))


def load_result(path: Path) -> JSONObject:
    """Load one bounded, stable, non-link isolation result."""

    try:
        raw = read_stable_regular_file(path, label="isolation result")
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ResultVerificationError(f"cannot load isolation result: {exc}") from exc
    if not isinstance(value, dict):
        raise ResultVerificationError("isolation result root must be an object")
    return cast(JSONObject, value)


def _verification_keys(value: object, required: set[str], context: str) -> JSONObject:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ResultVerificationError(f"{context} must be an object")
    mapped = cast(JSONObject, value)
    missing = sorted(required - mapped.keys())
    extra = sorted(mapped.keys() - required)
    if missing or extra:
        raise ResultVerificationError(
            f"{context} keys differ: missing={missing}, extra={extra}"
        )
    return mapped


def _verify_bound_file(
    value: object,
    *,
    expected_path: str,
    expected_bytes: bytes,
    context: str,
) -> None:
    bound = _verification_keys(value, {"path", "sha256", "bytes"}, context)
    expected = {
        "path": expected_path,
        "sha256": _sha256_bytes(expected_bytes),
        "bytes": len(expected_bytes),
    }
    if bound != expected:
        raise ResultVerificationError(f"{context} does not bind trusted bytes")


def _verify_source_inventory(value: object, source_bytes: Mapping[str, bytes]) -> None:
    source = _verification_keys(
        value,
        {"git_commit", "git_dirty", "files", "aggregate_sha256"},
        "source",
    )
    if source != collect_source_metadata(source_bytes):
        raise ResultVerificationError("source inventory/digests do not match trusted source")


def _probe_status_from_observation(
    probe: JSONObject,
    *,
    profile: JSONObject,
    manifest: JSONObject,
    host: JSONObject,
    inspected: JSONObject,
) -> tuple[bool, str]:
    probe_id = probe["id"]
    observed = probe["observed"]
    required = probe_id in set(MANDATORY_SECURITY_PROBES)
    status = "fail"
    expected: object
    if probe_id == "network_none":
        expected = {"attempt_blocked": True, "network_mode": "none"}
        status = "pass" if observed == expected else "fail"
    elif probe_id == "candidate_mount_read_only":
        expected = {"attempt_blocked": True, "destination": "/candidate", "rw": False}
        data = _verification_keys(observed, {"attempt_blocked", "mount"}, "candidate probe")
        mount = data["mount"]
        status = (
            "pass"
            if data["attempt_blocked"] is True
            and isinstance(mount, dict)
            and mount.get("destination") == "/candidate"
            and mount.get("rw") is False
            else "fail"
        )
    elif probe_id == "root_filesystem_read_only":
        expected = {"attempt_blocked": True, "read_only_rootfs": True}
        status = "pass" if observed == expected else "fail"
    elif probe_id == "forbidden_path_read":
        expected = {
            path: {"attempt_blocked": True, "covering_mounts": []}
            for path in _strings(manifest["forbidden_paths"], "forbidden_paths")
        }
        status = "pass" if observed == expected else "fail"
    elif probe_id == "security_profile":
        expected = _expected_security_profile(manifest)
        data = _verification_keys(
            observed,
            {
                "cap_drop",
                "security_opt",
                "tmpfs",
                "pids_limit",
                "nano_cpus",
                "ulimits",
            },
            "security profile probe",
        )
        trusted_observed = _observed_security_profile(inspected)
        if data != trusted_observed:
            raise ResultVerificationError(
                "security profile observation contradicts container inspect"
            )
        status = "pass" if trusted_observed == expected else "fail"
    elif probe_id == "runtime_selection":
        requested = profile.get("runtime")
        expected = requested or "daemon_default"
        required = requested is not None
        status = "pass" if requested is None or observed == requested else "fail"
    elif probe_id == "user_identity":
        host_uid = host.get("uid")
        host_gid = host.get("gid")
        if isinstance(host_uid, int) and isinstance(host_gid, int):
            required = True
            expected = {
                "uid": host_uid,
                "gid": host_gid,
                "non_root": bool(
                    _object(manifest["container"], "container")[
                        "require_non_root_when_applied"
                    ]
                ),
            }
            data = _verification_keys(
                observed,
                {"uid", "gid", "configured_user"},
                "user identity probe",
            )
            non_root_ok = not expected["non_root"] or (host_uid != 0 and host_gid != 0)
            status = (
                "pass"
                if data["uid"] == host_uid
                and data["gid"] == host_gid
                and data["configured_user"] == f"{host_uid}:{host_gid}"
                and non_root_ok
                else "fail"
            )
        else:
            required = False
            expected = "host UID/GID only when the host exposes os.getuid/os.getgid"
            status = "skip"
    elif probe_id == "normal_cleanup":
        expected = {"proven_absent": True}
        status = (
            "pass"
            if isinstance(observed, dict) and observed.get("proven_absent") is True
            else "fail"
        )
    elif probe_id == "timeout_cleanup":
        expected = {
            "timeout_raised": True,
            "container_started": True,
            "cleanup_proven_absent": True,
        }
        data = _verification_keys(
            observed,
            {
                "timeout_raised",
                "container_started",
                "returned_code",
                "cleanup",
                "command_template",
            },
            "timeout cleanup probe",
        )
        cleanup = data["cleanup"]
        status = (
            "pass"
            if data["timeout_raised"] is True
            and data["container_started"] is True
            and isinstance(cleanup, dict)
            and cleanup.get("proven_absent") is True
            else "fail"
        )
    else:
        raise ResultVerificationError(f"unknown isolation probe id: {probe_id}")
    if probe.get("expected") != expected:
        raise ResultVerificationError(f"probe {probe_id} expected value is inconsistent")
    return required, status


def _verify_available_profile(
    profile_result: JSONObject,
    *,
    profile: JSONObject,
    manifest: JSONObject,
    host: JSONObject,
    image_id: str,
    available_runtimes: Sequence[str],
) -> None:
    container = _verification_keys(
        profile_result["container"],
        {"command_template", "returncode", "stderr", "inspect", "probe_payload"},
        f"profile {profile['id']} container",
    )
    inspected = _verification_keys(
        container["inspect"],
        {
            "id",
            "image",
            "user",
            "network_mode",
            "read_only_rootfs",
            "runtime",
            "cap_drop",
            "security_opt",
            "tmpfs",
            "pids_limit",
            "nano_cpus",
            "ulimits",
            "mounts",
        },
        f"profile {profile['id']} inspect",
    )
    if inspected["image"] != image_id:
        raise ResultVerificationError(f"profile {profile['id']} image identity mismatch")
    command = container["command_template"]
    if (
        not isinstance(command, list)
        or image_id not in command
        or not any("${CANDIDATE_DIR}" in str(item) for item in command)
        or not any("${CONTAINER_NAME}" in str(item) for item in command)
    ):
        raise ResultVerificationError(f"profile {profile['id']} command template is unbound")
    expected_runtime = {
        "requested": profile.get("runtime"),
        "available": True,
        "available_runtimes": list(available_runtimes),
        "observed": inspected["runtime"],
    }
    if profile_result["runtime"] != expected_runtime:
        raise ResultVerificationError(
            f"profile {profile['id']} runtime evidence contradicts container inspect"
        )

    probes = profile_result["probes"]
    if not isinstance(probes, list):
        raise ResultVerificationError("profile probes must be an array")
    expected_ids = {*MANDATORY_SECURITY_PROBES, "runtime_selection", "user_identity"}
    ids = [item.get("id") for item in probes if isinstance(item, dict)]
    if len(ids) != len(expected_ids) or set(ids) != expected_ids:
        raise ResultVerificationError(f"profile {profile['id']} probe coverage mismatch")
    for raw_probe in probes:
        probe = _verification_keys(
            raw_probe,
            {"id", "required", "status", "expected", "observed", "detail"},
            f"profile {profile['id']} probe",
        )
        required, status = _probe_status_from_observation(
            probe,
            profile=profile,
            manifest=manifest,
            host=host,
            inspected=inspected,
        )
        if probe["required"] is not required or probe["status"] != status:
            raise ResultVerificationError(
                f"profile {profile['id']} probe {probe['id']} status mismatch"
            )
    expected_status = profile_status(cast(list[Probe], probes))
    if profile_result["status"] != expected_status:
        raise ResultVerificationError(f"profile {profile['id']} aggregate mismatch")
    expected_reason = (
        None if expected_status == "pass" else "one or more probes did not pass"
    )
    if profile_result["reason"] != expected_reason:
        raise ResultVerificationError(f"profile {profile['id']} reason is inconsistent")


def verify_result(
    result: Mapping[str, Any],
    *,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> None:
    """Verify unsigned self-consistency against trusted manifest and source bytes."""

    top = _verification_keys(
        result,
        {
            "$schema",
            "schema_version",
            "suite_id",
            "run_id",
            "started_at_utc",
            "finished_at_utc",
            "status",
            "manifest",
            "probe_source",
            "source",
            "reproduce",
            "environment",
            "profiles",
            "summary",
        },
        "result",
    )
    manifest, manifest_bytes = _load_manifest_snapshot(manifest_path)
    source_bytes = _capture_source_bytes()
    if (
        top["$schema"] != RESULT_SCHEMA_LABEL
        or top["schema_version"] != RESULT_VERSION
        or top["suite_id"] != manifest["suite_id"]
    ):
        raise ResultVerificationError("isolation result identity mismatch")
    _verify_bound_file(
        top["manifest"],
        expected_path=_logical_repo_path(manifest_path, "external-manifest.json"),
        expected_bytes=manifest_bytes,
        context="manifest",
    )
    _verify_bound_file(
        top["probe_source"],
        expected_path=PROBE_SOURCE_LABEL,
        expected_bytes=source_bytes[PROBE_SOURCE_LABEL],
        context="probe_source",
    )
    _verify_source_inventory(top["source"], source_bytes)

    environment = _verification_keys(
        top["environment"],
        {"host", "docker", "image"},
        "environment",
    )
    host = _verification_keys(
        environment["host"],
        {"platform", "system", "release", "machine", "python", "os_name", "uid", "gid"},
        "environment.host",
    )
    docker = _verification_keys(
        environment["docker"],
        {
            "available",
            "executable",
            "error",
            "client",
            "server",
            "info",
            "available_runtimes",
        },
        "environment.docker",
    )
    image = _verification_keys(
        environment["image"],
        {"requested", "image_id", "repo_digests", "pull_attempted", "error"},
        "environment.image",
    )
    reproduce = _verification_keys(top["reproduce"], {"argv", "shell"}, "reproduce")
    reproduce_argv = reproduce["argv"]
    if not isinstance(reproduce_argv, list):
        raise ResultVerificationError("reproduce.argv must be an array")
    selected_from_argv: list[str] = []
    for index, item in enumerate(reproduce_argv):
        if item == "--profile":
            if index + 1 >= len(reproduce_argv) or not isinstance(
                reproduce_argv[index + 1], str
            ):
                raise ResultVerificationError("reproduce profile selection is malformed")
            selected_from_argv.append(reproduce_argv[index + 1])
    require_gvisor = "--require-gvisor" in reproduce_argv
    pull = "--no-pull" not in reproduce_argv
    has_output = "--output" in reproduce_argv
    replay_image = image.get("image_id") or image.get("requested")
    if not isinstance(replay_image, str):
        raise ResultVerificationError("reproduce image identity is unavailable")
    expected_reproduce = _reproduce(
        manifest_path=manifest_path,
        image=replay_image,
        selected_profiles=selected_from_argv or None,
        require_gvisor=require_gvisor,
        pull=pull,
        output_path=Path("result.json") if has_output else None,
    )
    if reproduce != expected_reproduce:
        raise ResultVerificationError("reproduce command is inconsistent")

    profiles = top["profiles"]
    if not isinstance(profiles, list) or not profiles:
        raise ResultVerificationError("isolation result profiles must not be empty")
    docker_available = docker["available"]
    if not isinstance(docker_available, bool):
        raise ResultVerificationError("environment.docker.available must be a boolean")
    available_runtimes_raw = docker["available_runtimes"]
    if not isinstance(available_runtimes_raw, list) or not all(
        isinstance(runtime_name, str) for runtime_name in available_runtimes_raw
    ):
        raise ResultVerificationError(
            "environment.docker.available_runtimes must be a string array"
        )
    available_runtimes = cast(list[str], available_runtimes_raw)
    docker_error = docker["error"]
    if docker_error is not None and not isinstance(docker_error, str):
        raise ResultVerificationError("environment.docker.error must be a string or null")
    image_id = image["image_id"]
    if image_id is not None and not isinstance(image_id, str):
        raise ResultVerificationError("environment.image.image_id must be a string or null")
    image_error = image["error"]
    if image_error is not None and not isinstance(image_error, str):
        raise ResultVerificationError("environment.image.error must be a string or null")
    if docker_available is False:
        expected_image = {
            "requested": image["requested"],
            "image_id": None,
            "repo_digests": [],
            "pull_attempted": False,
            "error": "Docker was not available",
        }
        if image != expected_image or not docker_error:
            raise ResultVerificationError(
                "unavailable Docker environment has inconsistent image evidence"
            )
    elif image_id is None:
        if not image_error or image["repo_digests"] != []:
            raise ResultVerificationError(
                "unresolved image environment lacks exact error evidence"
            )
    elif image_error is not None:
        raise ResultVerificationError(
            "resolved image environment must not retain an error"
        )
    manifest_profiles = {
        str(item["id"]): item for item in _objects(manifest["profiles"], "profiles")
    }
    seen: set[str] = set()
    verified_profiles: list[Profile] = []
    for raw_profile in profiles:
        profile_result = _verification_keys(
            raw_profile,
            {
                "id",
                "required",
                "requested_runtime",
                "status",
                "reason",
                "runtime",
                "container",
                "probes",
            },
            "profile",
        )
        profile_id = profile_result.get("id")
        if (
            not isinstance(profile_id, str)
            or profile_id in seen
            or profile_id not in manifest_profiles
        ):
            raise ResultVerificationError("profile id is duplicate or not trusted")
        seen.add(profile_id)
        configured = manifest_profiles[profile_id]
        expected_required = bool(configured["required"]) or (
            profile_id == "gvisor" and require_gvisor
        )
        effective_profile = dict(configured)
        effective_profile["required"] = expected_required
        if (
            profile_result["required"] is not expected_required
            or profile_result["requested_runtime"] != configured.get("runtime")
        ):
            raise ResultVerificationError(f"profile {profile_id} policy binding mismatch")
        runtime = _verification_keys(
            profile_result["runtime"],
            {"requested", "available", "available_runtimes", "observed"},
            f"profile {profile_id} runtime",
        )
        if (
            runtime["requested"] != configured.get("runtime")
            or runtime["available_runtimes"] != available_runtimes
        ):
            raise ResultVerificationError(f"profile {profile_id} runtime evidence mismatch")
        raw_probes = profile_result["probes"]
        if not isinstance(raw_probes, list) or not raw_probes:
            raise ResultVerificationError(f"profile {profile_id} probes must not be empty")
        for raw_probe in raw_probes:
            _verification_keys(
                raw_probe,
                {"id", "required", "status", "expected", "observed", "detail"},
                f"profile {profile_id} probe",
            )
        expected_no_container: Profile | None = None
        if docker_available is False:
            expected_no_container = _docker_unavailable_profile(
                effective_profile,
                cast(str, docker_error),
            )
        elif image_id is None:
            expected_no_container = _image_unavailable_profile(
                effective_profile,
                available_runtimes,
                cast(str, image_error),
            )
        elif (
            configured.get("runtime") is not None
            and configured.get("runtime") not in available_runtimes
        ):
            expected_no_container = unsupported_profile(
                effective_profile,
                available_runtimes,
            )
        elif profile_result["container"] is None:
            reason = profile_result["reason"]
            if not isinstance(reason, str) or len(reason) > _MAX_DIAGNOSTIC_CHARS:
                raise ResultVerificationError(
                    f"profile {profile_id} harness reason is malformed"
                )
            exception_name, separator, _detail = reason.partition(": ")
            if separator != ": " or not exception_name.isidentifier():
                raise ResultVerificationError(
                    f"profile {profile_id} harness reason is malformed"
                )
            expected_no_container = _harness_error_profile(
                effective_profile,
                available_runtimes,
                reason,
            )

        if expected_no_container is not None:
            if profile_result != expected_no_container:
                raise ResultVerificationError(
                    f"profile {profile_id} no-container state evidence mismatch"
                )
        elif profile_result["status"] in {"pass", "fail", "error"}:
            _verify_available_profile(
                profile_result,
                profile=effective_profile,
                manifest=manifest,
                host=host,
                image_id=cast(str, image_id),
                available_runtimes=available_runtimes,
            )
        else:
            raise ResultVerificationError(f"profile {profile_id} status is invalid")
        verified_profiles.append(profile_result)

    expected_profile_ids = (
        set(manifest_profiles)
        if not selected_from_argv or "all" in selected_from_argv
        else set(selected_from_argv)
    )
    if seen != expected_profile_ids:
        raise ResultVerificationError("result profiles do not match reproduce selection")
    if top["summary"] != summarize(verified_profiles):
        raise ResultVerificationError("isolation summary is inconsistent")
    if top["status"] != overall_status(verified_profiles):
        raise ResultVerificationError("isolation aggregate status is inconsistent")


def exit_code(status: object) -> int:
    """Return a CI-friendly code without treating unsupported as success."""

    if status == "pass":
        return 0
    if status == "unsupported":
        return 2
    return 1


__all__ = [
    "CONFORMANCE_DIR",
    "DEFAULT_MANIFEST",
    "MANDATORY_SECURITY_PROBES",
    "ManifestError",
    "PROBE_SOURCE",
    "RESULT_SCHEMA",
    "ResultVerificationError",
    "build_container_command",
    "cleanup_evidence",
    "collect_docker_metadata",
    "command_template",
    "evaluate_isolation_probes",
    "execute_profile",
    "exit_code",
    "expected_container_user",
    "extract_container_metadata",
    "load_manifest",
    "load_result",
    "overall_status",
    "profile_status",
    "run_conformance",
    "summarize",
    "unsupported_profile",
    "validate_manifest",
    "verify_result",
    "write_result",
]
