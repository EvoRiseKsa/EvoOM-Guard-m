"""Offline, schema-versioned runner-adapter conformance evidence.

This kit exercises EvoOM Guard's instrumentation adapters as Python contracts.
It deliberately does not execute test suites and therefore cannot establish
that any external runner version works on any operating system.
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import subprocess
import sys
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import evoom_guard
from evoom_guard.execution import (
    ProcessLimits,
    ProcessOutputLimitExceeded,
    run_bounded_subprocess,
)
from evoom_guard.runners import registry
from evoom_guard.runners.gotestsum import GotestsumAdapter
from evoom_guard.runners.jest import JestAdapter
from evoom_guard.runners.maven import MavenAdapter
from evoom_guard.runners.mocha import MochaAdapter
from evoom_guard.runners.node_test import NodeTestAdapter
from evoom_guard.runners.protocol import RunnerAdapter
from evoom_guard.runners.pytest import PytestAdapter
from evoom_guard.runners.rspec import RspecAdapter
from evoom_guard.runners.shell import ShellAdapter
from evoom_guard.runners.vitest import VitestAdapter
from tools.conformance.secure_io import read_stable_regular_file, write_create_only_bytes

MANIFEST_SCHEMA_VERSION = "evoom-runner-conformance-manifest-1"
RESULT_SCHEMA_VERSION = "evoom-runner-conformance-result-1"
KIT_VERSION = "1.0.0"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = Path(__file__).with_name("runner-manifest.json")
RESULT_SCHEMA_LABEL = "tools/conformance/runner-result.schema.json"
_VERSION_PATTERN = re.compile(r"(?<!\d)(\d+\.\d+(?:\.\d+)?(?:[-+._][A-Za-z0-9.-]+)?)")
_CATEGORIES = frozenset(("accept", "decline", "mismatch", "windows_path", "shell"))
_DECLINE_OWNERS = frozenset(
    ("shell", "node_test", "vitest", "jest", "gotestsum", "rspec", "mocha", "maven")
)
_SOURCE_PATHS = (
    "evoom_guard/runners/_command.py",
    "evoom_guard/runners/protocol.py",
    "evoom_guard/runners/registry.py",
    "evoom_guard/runners/shell.py",
    "evoom_guard/runners/pytest.py",
    "evoom_guard/runners/node_test.py",
    "evoom_guard/runners/vitest.py",
    "evoom_guard/runners/jest.py",
    "evoom_guard/runners/gotestsum.py",
    "evoom_guard/runners/rspec.py",
    "evoom_guard/runners/mocha.py",
    "evoom_guard/runners/maven.py",
    "tools/conformance/runner_kit.py",
    "tools/conformance/run_runner_conformance.py",
    "tools/conformance/runner-manifest.schema.json",
    "tools/conformance/runner-result.schema.json",
    "tools/conformance/secure_io.py",
)


class ManifestError(ValueError):
    """The runner conformance manifest is malformed or non-canonical."""


class ResultVerificationError(ValueError):
    """A retained runner result is not a self-consistent result for trusted inputs."""


@dataclass(frozen=True)
class OwnerSpec:
    """Identity and safe version-discovery command for one adapter owner."""

    owner_id: str
    module: str
    class_name: str
    adapter_name: str
    adapter_type: type[RunnerAdapter]
    discovery_argv: tuple[str, ...]
    actual_discovery_argv: tuple[str, ...] | None = None

    def adapter(self) -> RunnerAdapter:
        """Create an isolated adapter instance."""

        return self.adapter_type()

    def manifest_record(self) -> dict[str, Any]:
        """Return the exact owner record allowed in a manifest."""

        return {
            "id": self.owner_id,
            "module": self.module,
            "class": self.class_name,
            "adapter_name": self.adapter_name,
            "discovery_argv": list(self.discovery_argv),
        }


OWNER_SPECS = (
    OwnerSpec(
        "shell",
        "evoom_guard.runners.shell",
        "ShellAdapter",
        "sh -c",
        ShellAdapter,
        ("sh", "--version"),
    ),
    OwnerSpec(
        "pytest",
        "evoom_guard.runners.pytest",
        "PytestAdapter",
        "pytest",
        PytestAdapter,
        ("python", "-I", "-m", "pytest", "--version"),
        (sys.executable, "-I", "-m", "pytest", "--version"),
    ),
    OwnerSpec(
        "node_test",
        "evoom_guard.runners.node_test",
        "NodeTestAdapter",
        "node --test",
        NodeTestAdapter,
        ("node", "--version"),
    ),
    OwnerSpec(
        "vitest",
        "evoom_guard.runners.vitest",
        "VitestAdapter",
        "vitest",
        VitestAdapter,
        ("vitest", "--version"),
    ),
    OwnerSpec(
        "jest",
        "evoom_guard.runners.jest",
        "JestAdapter",
        "jest",
        JestAdapter,
        ("jest", "--version"),
    ),
    OwnerSpec(
        "gotestsum",
        "evoom_guard.runners.gotestsum",
        "GotestsumAdapter",
        "gotestsum",
        GotestsumAdapter,
        ("gotestsum", "--version"),
    ),
    OwnerSpec(
        "rspec",
        "evoom_guard.runners.rspec",
        "RspecAdapter",
        "rspec",
        RspecAdapter,
        ("rspec", "--version"),
    ),
    OwnerSpec(
        "mocha",
        "evoom_guard.runners.mocha",
        "MochaAdapter",
        "mocha",
        MochaAdapter,
        ("mocha", "--version"),
    ),
    OwnerSpec(
        "maven",
        "evoom_guard.runners.maven",
        "MavenAdapter",
        "maven",
        MavenAdapter,
        ("mvn", "--version"),
    ),
)
OWNER_BY_ID = {spec.owner_id: spec for spec in OWNER_SPECS}
CANONICAL_REGISTRY_ORDER = tuple(spec.owner_id for spec in OWNER_SPECS)
CANONICAL_INNER_ORDER = CANONICAL_REGISTRY_ORDER[1:]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_json_object(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = read_stable_regular_file(path, label="runner manifest")
    except OSError as exc:
        raise ManifestError(f"cannot read manifest: {exc}") from exc
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"manifest is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ManifestError("manifest root must be an object")
    return value, raw


def _require_keys(
    value: Mapping[str, Any],
    *,
    required: set[str],
    context: str,
) -> None:
    missing = sorted(required - value.keys())
    extra = sorted(value.keys() - required)
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append(f"missing={missing}")
        if extra:
            details.append(f"extra={extra}")
        raise ManifestError(f"{context} has invalid keys ({', '.join(details)})")


def _require_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{context} must be a non-empty string")
    return value


def _require_string_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ManifestError(f"{context} must be a non-empty string array")
    if any(not isinstance(item, str) or not item for item in value):
        raise ManifestError(f"{context} must contain only non-empty strings")
    return value


def _validate_expected(value: Any, context: str, *, registry_case: bool) -> None:
    if not isinstance(value, dict):
        raise ManifestError(f"{context} must be an object")
    required = {"matched", "applied", "argv", "env"}
    if registry_case:
        required.add("selected_owner")
    _require_keys(value, required=required, context=context)
    if type(value["matched"]) is not bool or type(value["applied"]) is not bool:
        raise ManifestError(f"{context}.matched/applied must be booleans")
    _require_string_list(value["argv"], f"{context}.argv")
    env = value["env"]
    if not isinstance(env, dict) or any(
        not isinstance(key, str) or not isinstance(item, str) for key, item in env.items()
    ):
        raise ManifestError(f"{context}.env must be a string map")
    if registry_case and value["selected_owner"] is not None:
        owner = _require_string(value["selected_owner"], f"{context}.selected_owner")
        if owner not in OWNER_BY_ID:
            raise ManifestError(f"{context}.selected_owner is unknown")


def validate_manifest(manifest: Mapping[str, Any]) -> None:
    """Validate shape plus the canonical owner and coverage invariants."""

    _require_keys(
        manifest,
        required={
            "$schema",
            "schema_version",
            "suite_id",
            "report_path",
            "discovery_timeout_seconds",
            "owners",
            "registry_order",
            "inner_registry_order",
            "cases",
            "registry_cases",
        },
        context="manifest",
    )
    if manifest["schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise ManifestError("unsupported manifest schema_version")
    _require_string(manifest["$schema"], "manifest.$schema")
    _require_string(manifest["suite_id"], "manifest.suite_id")
    _require_string(manifest["report_path"], "manifest.report_path")
    timeout = manifest["discovery_timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ManifestError("manifest.discovery_timeout_seconds must be positive")

    owners = manifest["owners"]
    if not isinstance(owners, list):
        raise ManifestError("manifest.owners must be an array")
    expected_owners = [spec.manifest_record() for spec in OWNER_SPECS]
    if owners != expected_owners:
        raise ManifestError("manifest.owners does not match the canonical nine owners")
    if manifest["registry_order"] != list(CANONICAL_REGISTRY_ORDER):
        raise ManifestError("manifest.registry_order is not canonical")
    if manifest["inner_registry_order"] != list(CANONICAL_INNER_ORDER):
        raise ManifestError("manifest.inner_registry_order is not canonical")

    cases = manifest["cases"]
    if not isinstance(cases, list) or not cases:
        raise ManifestError("manifest.cases must be a non-empty array")
    seen_ids: set[str] = set()
    coverage: dict[str, set[str]] = {owner: set() for owner in OWNER_BY_ID}
    for index, case in enumerate(cases):
        context = f"manifest.cases[{index}]"
        if not isinstance(case, dict):
            raise ManifestError(f"{context} must be an object")
        _require_keys(
            case,
            required={"id", "owner", "category", "argv", "expected"},
            context=context,
        )
        case_id = _require_string(case["id"], f"{context}.id")
        if case_id in seen_ids:
            raise ManifestError(f"duplicate case id: {case_id}")
        seen_ids.add(case_id)
        owner = _require_string(case["owner"], f"{context}.owner")
        if owner not in OWNER_BY_ID:
            raise ManifestError(f"{context}.owner is unknown")
        category = _require_string(case["category"], f"{context}.category")
        if category not in _CATEGORIES:
            raise ManifestError(f"{context}.category is unknown")
        _require_string_list(case["argv"], f"{context}.argv")
        _validate_expected(case["expected"], f"{context}.expected", registry_case=False)
        coverage[owner].add(category)

    baseline = {"accept", "mismatch", "windows_path"}
    for owner, categories in coverage.items():
        missing = baseline - categories
        if owner in _DECLINE_OWNERS and "decline" not in categories:
            missing.add("decline")
        if missing:
            raise ManifestError(f"owner {owner} lacks categories: {sorted(missing)}")
    if "shell" not in coverage["shell"]:
        raise ManifestError("shell owner lacks a shell-category case")

    registry_cases = manifest["registry_cases"]
    if not isinstance(registry_cases, list) or not registry_cases:
        raise ManifestError("manifest.registry_cases must be a non-empty array")
    for index, case in enumerate(registry_cases):
        context = f"manifest.registry_cases[{index}]"
        if not isinstance(case, dict):
            raise ManifestError(f"{context} must be an object")
        _require_keys(
            case,
            required={"id", "argv", "expected"},
            context=context,
        )
        case_id = _require_string(case["id"], f"{context}.id")
        if case_id in seen_ids:
            raise ManifestError(f"duplicate case id: {case_id}")
        seen_ids.add(case_id)
        _require_string_list(case["argv"], f"{context}.argv")
        _validate_expected(case["expected"], f"{context}.expected", registry_case=True)


def load_manifest(path: Path = DEFAULT_MANIFEST) -> tuple[dict[str, Any], bytes]:
    """Load and validate a runner conformance manifest."""

    manifest, raw = _read_json_object(path)
    validate_manifest(manifest)
    return manifest, raw


def _owner_id(adapter: RunnerAdapter) -> str | None:
    for spec in OWNER_SPECS:
        if type(adapter) is spec.adapter_type:
            return spec.owner_id
    return None


def _instrument_owner(
    owner: str,
    argv: list[str],
    report_path: str,
) -> dict[str, Any]:
    spec = OWNER_BY_ID[owner]
    adapter = spec.adapter()
    matched = adapter.matches(argv)
    if not matched:
        return {"matched": False, "applied": False, "argv": list(argv), "env": {}}
    if type(adapter) is ShellAdapter:
        instrumented = adapter.instrument_with_adapters(
            argv,
            report_path,
            registry.INNER_ADAPTERS,
        )
    else:
        instrumented = adapter.instrument(argv, report_path)
    if instrumented is None:
        return {"matched": True, "applied": False, "argv": list(argv), "env": {}}
    env_fn = getattr(adapter, "report_env", None)
    report_env: dict[str, str] = env_fn(report_path) if env_fn else {}
    return {
        "matched": True,
        "applied": True,
        "argv": list(instrumented),
        "env": report_env,
    }


def _instrument_registry(argv: list[str], report_path: str) -> dict[str, Any]:
    selected = next((adapter for adapter in registry.ADAPTERS if adapter.matches(argv)), None)
    instrumented, applied, env = registry.instrument_command(argv, report_path)
    return {
        "selected_owner": None if selected is None else _owner_id(selected),
        "matched": selected is not None,
        "applied": applied,
        "argv": instrumented,
        "env": env,
    }


def _mismatch_fields(expected: Mapping[str, Any], observed: Mapping[str, Any]) -> list[str]:
    return sorted(key for key in expected if expected[key] != observed.get(key))


def _run_owner_cases(
    cases: Sequence[Mapping[str, Any]],
    report_path: str,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for case in cases:
        expected = dict(case["expected"])
        observed = _instrument_owner(
            str(case["owner"]),
            list(case["argv"]),
            report_path,
        )
        mismatches = _mismatch_fields(expected, observed)
        results.append(
            {
                "id": case["id"],
                "owner": case["owner"],
                "category": case["category"],
                "status": "pass" if not mismatches else "fail",
                "expected": expected,
                "observed": observed,
                "mismatch_fields": mismatches,
            }
        )
    return results


def _run_registry_cases(
    cases: Sequence[Mapping[str, Any]],
    report_path: str,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for case in cases:
        expected = dict(case["expected"])
        observed = _instrument_registry(list(case["argv"]), report_path)
        mismatches = _mismatch_fields(expected, observed)
        results.append(
            {
                "id": case["id"],
                "status": "pass" if not mismatches else "fail",
                "expected": expected,
                "observed": observed,
                "mismatch_fields": mismatches,
            }
        )
    return results


def _owner_identity_results() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for spec in OWNER_SPECS:
        adapter = spec.adapter()
        observed = {
            "module": type(adapter).__module__,
            "class": type(adapter).__name__,
            "adapter_name": adapter.name,
        }
        expected = {
            "module": spec.module,
            "class": spec.class_name,
            "adapter_name": spec.adapter_name,
        }
        mismatches = _mismatch_fields(expected, observed)
        results.append(
            {
                "id": spec.owner_id,
                "status": "pass" if not mismatches else "fail",
                "expected": expected,
                "observed": observed,
                "mismatch_fields": mismatches,
            }
        )
    return results


def _registry_order_result() -> dict[str, Any]:
    observed = [_owner_id(adapter) for adapter in registry.ADAPTERS]
    observed_inner = [_owner_id(adapter) for adapter in registry.INNER_ADAPTERS]
    expected = list(CANONICAL_REGISTRY_ORDER)
    expected_inner = list(CANONICAL_INNER_ORDER)
    mismatches: list[str] = []
    if observed != expected:
        mismatches.append("registry_order")
    if observed_inner != expected_inner:
        mismatches.append("inner_registry_order")
    return {
        "status": "pass" if not mismatches else "fail",
        "expected": expected,
        "observed": observed,
        "expected_inner": expected_inner,
        "observed_inner": observed_inner,
        "mismatch_fields": mismatches,
    }


def _bounded_run(
    command: Sequence[str],
    *,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    completed: subprocess.CompletedProcess[str] = run_bounded_subprocess(
        command,
        cwd=str(REPOSITORY_ROOT),
        env=None,
        timeout=timeout,
        limits=ProcessLimits(max_output_bytes=32_768),
    )
    return completed


def _discover_one(spec: OwnerSpec, timeout: float) -> dict[str, Any]:
    command = spec.actual_discovery_argv or spec.discovery_argv
    base: dict[str, Any] = {
        "owner": spec.owner_id,
        "argv": list(spec.discovery_argv),
    }
    try:
        completed = _bounded_run(command, timeout=timeout)
    except FileNotFoundError:
        return {**base, "status": "unsupported", "reason": "not_found"}
    except subprocess.TimeoutExpired:
        return {**base, "status": "unsupported", "reason": "timeout"}
    except ProcessOutputLimitExceeded:
        return {**base, "status": "unsupported", "reason": "output_limit"}
    except (OSError, RuntimeError):
        return {**base, "status": "unsupported", "reason": "process_error"}
    if completed.returncode != 0:
        return {**base, "status": "unsupported", "reason": "nonzero"}
    match = _VERSION_PATTERN.search(f"{completed.stdout}\n{completed.stderr}")
    if match is None:
        return {**base, "status": "unsupported", "reason": "version_unparseable"}
    return {**base, "status": "observed", "version": match.group(1)}


def discover_tool_versions(timeout: float) -> dict[str, Any]:
    """Observe version strings without executing suites or affecting status."""

    return {
        "requested": True,
        "non_gating": True,
        "proves_runner_execution": False,
        "tools": [_discover_one(spec, timeout) for spec in OWNER_SPECS],
    }


def _git_state() -> dict[str, Any]:
    commit: str | None = None
    dirty: bool | None = None
    try:
        completed = _bounded_run(("git", "rev-parse", "--verify", "HEAD"), timeout=5.0)
        candidate = completed.stdout.strip()
        if completed.returncode == 0 and re.fullmatch(r"[0-9a-fA-F]{40,64}", candidate):
            commit = candidate.lower()
        status = _bounded_run(
            ("git", "status", "--porcelain=v1", "--untracked-files=normal"),
            timeout=5.0,
        )
        if status.returncode == 0:
            dirty = bool(status.stdout)
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        pass
    return {"git_commit": commit, "git_dirty": dirty}


def _source_inventory() -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    aggregate = hashlib.sha256()
    for relative in _SOURCE_PATHS:
        raw = read_stable_regular_file(
            REPOSITORY_ROOT / relative,
            label=f"runner source {relative}",
        )
        digest = _sha256(raw)
        files.append({"path": relative, "sha256": digest, "bytes": len(raw)})
        aggregate.update(relative.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(digest.encode("ascii"))
        aggregate.update(b"\n")
    return {
        "tool_version": evoom_guard.__version__,
        "kit_version": KIT_VERSION,
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
        },
        "platform": {
            "system": platform.system() or "unknown",
            "release": platform.release() or "unknown",
            "machine": platform.machine() or "unknown",
        },
        **_git_state(),
        "files": files,
        "aggregate_sha256": aggregate.hexdigest(),
    }


def _manifest_label(path: Path) -> str:
    try:
        relative = path.resolve().relative_to(REPOSITORY_ROOT)
    except ValueError:
        return "external-manifest.json"
    return relative.as_posix()


def run_conformance(
    *,
    manifest_path: Path = DEFAULT_MANIFEST,
    discover_tools: bool = False,
) -> dict[str, Any]:
    """Run the offline contract suite and return a versioned result object."""

    started = _utc_now()
    manifest, manifest_raw = load_manifest(manifest_path)
    report_path = str(manifest["report_path"])
    identity_results = _owner_identity_results()
    order_result = _registry_order_result()
    owner_cases = _run_owner_cases(manifest["cases"], report_path)
    registry_cases = _run_registry_cases(manifest["registry_cases"], report_path)
    statuses = [
        *(item["status"] for item in identity_results),
        order_result["status"],
        *(item["status"] for item in owner_cases),
        *(item["status"] for item in registry_cases),
    ]
    failed = statuses.count("fail")
    passed = statuses.count("pass")
    status = "pass" if failed == 0 else "fail"
    discovery: dict[str, Any] = (
        discover_tool_versions(float(manifest["discovery_timeout_seconds"]))
        if discover_tools
        else {
            "requested": False,
            "non_gating": True,
            "proves_runner_execution": False,
            "tools": [],
        }
    )
    reproduce_argv = [
        "python",
        "tools/conformance/run_runner_conformance.py",
        "--manifest",
        _manifest_label(manifest_path),
        "--output",
        "<create-only-result.json>",
    ]
    if discover_tools:
        reproduce_argv.append("--discover-tools")
    source = _source_inventory()
    finished = _utc_now()
    return {
        "$schema": RESULT_SCHEMA_LABEL,
        "schema_version": RESULT_SCHEMA_VERSION,
        "suite_id": manifest["suite_id"],
        "run_id": uuid.uuid4().hex,
        "started_at_utc": started,
        "finished_at_utc": finished,
        "status": status,
        "status_basis": "offline_adapter_contract_only",
        "claims": {
            "offline_adapter_contract_executed": True,
            "external_runner_suites_executed": False,
            "multi_os_real_runner_matrix_published": False,
        },
        "manifest": {
            "path": _manifest_label(manifest_path),
            "sha256": _sha256(manifest_raw),
            "bytes": len(manifest_raw),
        },
        "source": source,
        "reproduce": {"argv": reproduce_argv},
        "owners": identity_results,
        "registry": {
            "order": order_result,
            "cases": registry_cases,
        },
        "cases": owner_cases,
        "live_tool_discovery": discovery,
        "summary": {
            "offline_checks": len(statuses),
            "passed": passed,
            "failed": failed,
            "tool_versions_observed": sum(
                item["status"] == "observed" for item in discovery["tools"]
            ),
            "tool_versions_unsupported": sum(
                item["status"] == "unsupported" for item in discovery["tools"]
            ),
        },
    }


def write_result_create_only(result: Mapping[str, Any], path: Path) -> None:
    """Write one JSON result without ever replacing an existing path."""

    encoded = (json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    write_create_only_bytes(path, encoded)


def load_result(path: Path) -> dict[str, Any]:
    """Load one bounded, stable, non-link runner result."""

    try:
        raw = read_stable_regular_file(path, label="runner result")
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ResultVerificationError(f"cannot load runner result: {exc}") from exc
    if not isinstance(value, dict):
        raise ResultVerificationError("runner result root must be an object")
    return value


def _verification_keys(
    value: Mapping[str, Any],
    required: set[str],
    context: str,
) -> None:
    missing = sorted(required - value.keys())
    extra = sorted(value.keys() - required)
    if missing or extra:
        raise ResultVerificationError(
            f"{context} keys differ: missing={missing}, extra={extra}"
        )


def _verify_source_inventory(source: object) -> None:
    if not isinstance(source, dict):
        raise ResultVerificationError("source must be an object")
    current = _source_inventory()
    _verification_keys(source, set(current), "source")
    for key in (
        "tool_version",
        "kit_version",
        "git_commit",
        "git_dirty",
        "files",
        "aggregate_sha256",
    ):
        if source.get(key) != current[key]:
            raise ResultVerificationError(f"source.{key} does not match trusted source")
    for key in ("python", "platform"):
        nested = source.get(key)
        if not isinstance(nested, dict):
            raise ResultVerificationError(f"source.{key} must be an object")
        expected_keys = (
            {"implementation", "version"}
            if key == "python"
            else {"system", "release", "machine"}
        )
        _verification_keys(nested, expected_keys, f"source.{key}")


def _verify_discovery(discovery: object) -> tuple[int, int]:
    if not isinstance(discovery, dict):
        raise ResultVerificationError("live_tool_discovery must be an object")
    _verification_keys(
        discovery,
        {"requested", "non_gating", "proves_runner_execution", "tools"},
        "live_tool_discovery",
    )
    if discovery["non_gating"] is not True or discovery["proves_runner_execution"] is not False:
        raise ResultVerificationError("tool discovery claim boundary is invalid")
    requested = discovery["requested"]
    tools = discovery["tools"]
    if type(requested) is not bool or not isinstance(tools, list):
        raise ResultVerificationError("tool discovery types are invalid")
    if not requested and tools:
        raise ResultVerificationError("unrequested tool discovery must be empty")
    if requested:
        if len(tools) != len(OWNER_SPECS):
            raise ResultVerificationError("requested discovery must cover all owners")
        for spec, item in zip(OWNER_SPECS, tools, strict=True):
            if not isinstance(item, dict):
                raise ResultVerificationError("tool discovery entry must be an object")
            if item.get("owner") != spec.owner_id or item.get("argv") != list(
                spec.discovery_argv
            ):
                raise ResultVerificationError("tool discovery owner/argv mismatch")
            status = item.get("status")
            expected_keys = (
                {"owner", "argv", "status", "version"}
                if status == "observed"
                else {"owner", "argv", "status", "reason"}
            )
            _verification_keys(item, expected_keys, f"tool discovery {spec.owner_id}")
            if status == "observed":
                version = item.get("version")
                if not isinstance(version, str) or _VERSION_PATTERN.fullmatch(version) is None:
                    raise ResultVerificationError("invalid observed tool version")
            elif status == "unsupported":
                if item.get("reason") not in {
                    "not_found",
                    "timeout",
                    "output_limit",
                    "process_error",
                    "nonzero",
                    "version_unparseable",
                }:
                    raise ResultVerificationError("invalid unsupported discovery reason")
            else:
                raise ResultVerificationError("tool discovery status is invalid")
    observed = sum(item.get("status") == "observed" for item in tools if isinstance(item, dict))
    unsupported = sum(
        item.get("status") == "unsupported" for item in tools if isinstance(item, dict)
    )
    return observed, unsupported


def verify_result(
    result: Mapping[str, Any],
    *,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> None:
    """Verify unsigned self-consistency against the trusted manifest and source tree."""

    top_keys = {
        "$schema",
        "schema_version",
        "suite_id",
        "run_id",
        "started_at_utc",
        "finished_at_utc",
        "status",
        "status_basis",
        "claims",
        "manifest",
        "source",
        "reproduce",
        "owners",
        "registry",
        "cases",
        "live_tool_discovery",
        "summary",
    }
    _verification_keys(result, top_keys, "result")
    manifest, manifest_raw = load_manifest(manifest_path)
    if (
        result.get("$schema") != RESULT_SCHEMA_LABEL
        or result.get("schema_version") != RESULT_SCHEMA_VERSION
        or result.get("suite_id") != manifest["suite_id"]
        or result.get("status_basis") != "offline_adapter_contract_only"
    ):
        raise ResultVerificationError("runner result identity/claim basis mismatch")
    if result.get("claims") != {
        "offline_adapter_contract_executed": True,
        "external_runner_suites_executed": False,
        "multi_os_real_runner_matrix_published": False,
    }:
        raise ResultVerificationError("runner result claims are invalid")
    expected_manifest = {
        "path": _manifest_label(manifest_path),
        "sha256": _sha256(manifest_raw),
        "bytes": len(manifest_raw),
    }
    if result.get("manifest") != expected_manifest:
        raise ResultVerificationError("runner result is not bound to the trusted manifest")
    _verify_source_inventory(result.get("source"))

    owners = _owner_identity_results()
    order = _registry_order_result()
    cases = _run_owner_cases(manifest["cases"], str(manifest["report_path"]))
    registry_cases = _run_registry_cases(
        manifest["registry_cases"],
        str(manifest["report_path"]),
    )
    if result.get("owners") != owners:
        raise ResultVerificationError("runner owner identity results are inconsistent")
    registry_result = result.get("registry")
    if registry_result != {"order": order, "cases": registry_cases}:
        raise ResultVerificationError("runner registry results are inconsistent")
    if result.get("cases") != cases:
        raise ResultVerificationError("runner case results are inconsistent")

    statuses = [
        *(item["status"] for item in owners),
        order["status"],
        *(item["status"] for item in cases),
        *(item["status"] for item in registry_cases),
    ]
    failed = statuses.count("fail")
    status = "pass" if failed == 0 else "fail"
    observed, unsupported = _verify_discovery(result.get("live_tool_discovery"))
    reproduce = result.get("reproduce")
    if not isinstance(reproduce, dict):
        raise ResultVerificationError("reproduce must be an object")
    _verification_keys(reproduce, {"argv"}, "reproduce")
    expected_argv = [
        "python",
        "tools/conformance/run_runner_conformance.py",
        "--manifest",
        _manifest_label(manifest_path),
        "--output",
        "<create-only-result.json>",
    ]
    discovery = result["live_tool_discovery"]
    if isinstance(discovery, dict) and discovery.get("requested") is True:
        expected_argv.append("--discover-tools")
    if reproduce.get("argv") != expected_argv:
        raise ResultVerificationError("runner reproduce argv is inconsistent")
    expected_summary = {
        "offline_checks": len(statuses),
        "passed": statuses.count("pass"),
        "failed": failed,
        "tool_versions_observed": observed,
        "tool_versions_unsupported": unsupported,
    }
    if result.get("status") != status or result.get("summary") != expected_summary:
        raise ResultVerificationError("runner aggregate status/summary is inconsistent")


def exit_code(status: str) -> int:
    return 0 if status == "pass" else 1


__all__ = [
    "CANONICAL_INNER_ORDER",
    "CANONICAL_REGISTRY_ORDER",
    "DEFAULT_MANIFEST",
    "KIT_VERSION",
    "MANIFEST_SCHEMA_VERSION",
    "ManifestError",
    "OWNER_SPECS",
    "RESULT_SCHEMA_VERSION",
    "ResultVerificationError",
    "discover_tool_versions",
    "exit_code",
    "load_manifest",
    "load_result",
    "run_conformance",
    "validate_manifest",
    "verify_result",
    "write_result_create_only",
]
