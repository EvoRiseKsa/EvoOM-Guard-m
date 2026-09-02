"""Strict evidence record for the GitHub-hosted live runner matrix."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from tools.conformance.secure_io import read_stable_regular_file, write_create_only_bytes

SCHEMA_VERSION = "evoguard-live-runner-conformance-v1"
RESULT_SCHEMA = "tools/conformance/live-runner-result.schema.json"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MAX_JUNIT_BYTES = 2 * 1024 * 1024
MAX_RESULT_BYTES = 2 * 1024 * 1024
_SHA_RE = re.compile(r"[0-9a-f]{40}")
_DIGITS_RE = re.compile(r"[1-9][0-9]*")
_NODE_22_RE = re.compile(r"v22\.[0-9]+\.[0-9]+")
_PULL_REF_RE = re.compile(r"refs/pull/[1-9][0-9]*/merge")
_VITEST_4_1_10_RE = re.compile(r"vitest/4\.1\.10(?:\s.*)?")
_WORKFLOW_REF_PREFIX = (
    "EvoRiseKsa/EvoOM-Guard-m/.github/workflows/"
    "runner-live-conformance.yml@"
)
_EXPECTED_TESTS = frozenset(
    {
        "test_pytest_honest_fix_is_pass_with_junit_source",
        "test_pytest_broken_fix_is_fail_with_real_counts",
        "test_pytest_protected_test_rewrite_is_rejected_before_execution",
        "test_parse_node_toplevel_cases_no_suite_wrapper",
        "test_parse_node_mixed_suite_and_toplevel_counts_all_cases",
        "test_parse_node_skipped_excluded_from_total",
        "test_pytest_suite_attribute_fallback_still_works",
        "test_node_test_honest_fix_is_pass_with_junit_source",
        "test_node_test_broken_fix_is_fail_with_real_counts",
        "test_parse_vitest_junit_counts",
        "test_vitest_honest_fix_is_pass_with_junit_source",
        "test_vitest_broken_fix_is_fail_with_real_counts",
        "test_vitest_baseline_and_candidate_resolve_the_same_runner",
    }
)
_SOURCE_PATHS = (
    ".github/workflows/runner-live-conformance.yml",
    "evoom_guard/runners/node_test.py",
    "evoom_guard/runners/pytest.py",
    "evoom_guard/runners/vitest.py",
    "evoom_guard/verifiers/repo_verifier.py",
    "tests/test_node_oracle.py",
    "tests/test_pytest_oracle.py",
    "tests/test_vitest_oracle.py",
    "requirements/ci.lock",
    "tools/ci-vitest/package-lock.json",
    "tools/ci-vitest/package.json",
    "tools/conformance/secure_io.py",
    "tools/conformance/live_runner_result.py",
    "tools/conformance/run_live_runner_conformance.py",
    "pyproject.toml",
    RESULT_SCHEMA,
)


class LiveRunnerResultError(ValueError):
    """The live-runner result or its exact execution evidence is invalid."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _reject_constant(value: str) -> None:
    raise LiveRunnerResultError(f"non-finite JSON constant is forbidden: {value}")


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LiveRunnerResultError(f"duplicate JSON key is forbidden: {key}")
        result[key] = value
    return result


def _require_keys(
    value: Mapping[str, Any],
    required: set[str],
    context: str,
) -> None:
    missing = sorted(required - value.keys())
    extra = sorted(value.keys() - required)
    if missing or extra:
        raise LiveRunnerResultError(
            f"{context} has invalid keys: missing={missing}, extra={extra}"
        )


def _require_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise LiveRunnerResultError(f"{context} must be a non-empty string")
    return value


def _require_nonnegative_int(value: Any, context: str) -> int:
    if type(value) is not int or value < 0:
        raise LiveRunnerResultError(f"{context} must be a nonnegative integer")
    return value


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise LiveRunnerResultError(f"required environment value is absent: {name}")
    return value


def _bounded_version(argv: Sequence[str], *, label: str) -> str:
    environment = {
        "COMSPEC": os.environ.get("COMSPEC", ""),
        "PATH": os.environ.get("PATH", ""),
        "PATHEXT": os.environ.get("PATHEXT", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "WINDIR": os.environ.get("WINDIR", ""),
    }
    resolved = shutil.which(argv[0], path=environment["PATH"])
    if resolved is None:
        raise LiveRunnerResultError(f"cannot resolve the {label} executable")
    command = [resolved, *argv[1:]]
    if os.name == "nt" and Path(resolved).suffix.casefold() in {".bat", ".cmd"}:
        command = [
            environment["COMSPEC"],
            "/d",
            "/s",
            "/c",
            subprocess.list2cmdline([resolved, *argv[1:]]),
        ]
    try:
        completed = subprocess.run(
            command,
            cwd=REPOSITORY_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise LiveRunnerResultError(f"cannot observe {label} version: {exc}") from exc
    output = (completed.stdout + completed.stderr).strip()
    if completed.returncode != 0:
        raise LiveRunnerResultError(
            f"{label} version command returned {completed.returncode}"
        )
    if not output or len(output.encode("utf-8")) > 4096:
        raise LiveRunnerResultError(f"{label} version output is absent or oversized")
    return output


def parse_exact_junit(raw: bytes) -> dict[str, Any]:
    """Require the exact no-skip live oracle set from a bounded pytest JUnit file."""

    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise LiveRunnerResultError("JUnit DTD/entity declarations are forbidden")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise LiveRunnerResultError(f"JUnit is not well-formed XML: {exc}") from exc
    if root.tag != "testsuites":
        raise LiveRunnerResultError("JUnit root must be testsuites")
    cases = list(root.iter("testcase"))
    names = [case.attrib.get("name", "") for case in cases]
    if any(not name for name in names):
        raise LiveRunnerResultError("every JUnit testcase must have a name")
    if len(names) != len(set(names)):
        raise LiveRunnerResultError("JUnit testcase names must be unique")
    observed = frozenset(names)
    if observed != _EXPECTED_TESTS:
        raise LiveRunnerResultError(
            "live oracle set differs from the reviewed contract: "
            f"missing={sorted(_EXPECTED_TESTS - observed)}, "
            f"extra={sorted(observed - _EXPECTED_TESTS)}"
        )
    failures = sum(case.find("failure") is not None for case in cases)
    errors = sum(case.find("error") is not None for case in cases)
    skipped = sum(case.find("skipped") is not None for case in cases)
    if failures or errors or skipped:
        raise LiveRunnerResultError(
            "live oracle result is not clean: "
            f"failures={failures}, errors={errors}, skipped={skipped}"
        )
    return {
        "errors": errors,
        "failures": failures,
        "skipped": skipped,
        "test_names": sorted(names),
        "tests": len(cases),
    }


def _source_inventory() -> tuple[dict[str, dict[str, Any]], str]:
    inventory: dict[str, dict[str, Any]] = {}
    aggregate = hashlib.sha256()
    for relative in _SOURCE_PATHS:
        raw = read_stable_regular_file(
            REPOSITORY_ROOT / relative,
            label=f"live runner source {relative}",
        )
        digest = _sha256(raw)
        inventory[relative] = {"sha256": digest, "size": len(raw)}
        encoded = relative.encode("utf-8")
        aggregate.update(len(encoded).to_bytes(8, "big"))
        aggregate.update(encoded)
        aggregate.update(len(raw).to_bytes(8, "big"))
        aggregate.update(raw)
    return inventory, aggregate.hexdigest()


def _execution_identity() -> dict[str, str]:
    repository = _required_environment("GITHUB_REPOSITORY")
    event_name = _required_environment("GITHUB_EVENT_NAME")
    ref = _required_environment("GITHUB_REF")
    sha = _required_environment("GITHUB_SHA")
    run_id = _required_environment("GITHUB_RUN_ID")
    run_attempt = _required_environment("GITHUB_RUN_ATTEMPT")
    workflow_ref = _required_environment("GITHUB_WORKFLOW_REF")
    workflow_sha = _required_environment("GITHUB_WORKFLOW_SHA")
    if repository != "EvoRiseKsa/EvoOM-Guard-m":
        raise LiveRunnerResultError("unexpected repository identity")
    if event_name not in {"pull_request", "push"}:
        raise LiveRunnerResultError("unexpected workflow event")
    if event_name == "push" and ref != "refs/heads/main":
        raise LiveRunnerResultError("the push matrix must run on refs/heads/main")
    if event_name == "pull_request" and _PULL_REF_RE.fullmatch(ref) is None:
        raise LiveRunnerResultError("the pull-request matrix ref is invalid")
    if _SHA_RE.fullmatch(sha) is None:
        raise LiveRunnerResultError("GITHUB_SHA must be lowercase 40-hex")
    if _SHA_RE.fullmatch(workflow_sha) is None:
        raise LiveRunnerResultError("GITHUB_WORKFLOW_SHA must be lowercase 40-hex")
    if _DIGITS_RE.fullmatch(run_id) is None or _DIGITS_RE.fullmatch(run_attempt) is None:
        raise LiveRunnerResultError("run identity must contain positive decimal integers")
    if not workflow_ref.startswith(_WORKFLOW_REF_PREFIX):
        raise LiveRunnerResultError("GITHUB_WORKFLOW_REF names an unexpected workflow")
    if workflow_ref.removeprefix(_WORKFLOW_REF_PREFIX) != ref:
        raise LiveRunnerResultError("workflow ref and execution ref disagree")
    git_commit, git_tree, tracked_dirty = _git_state()
    if git_commit != sha:
        raise LiveRunnerResultError("checked-out Git commit differs from GITHUB_SHA")
    if tracked_dirty:
        raise LiveRunnerResultError("tracked source changed during live conformance")
    return {
        "event_name": event_name,
        "git_commit": git_commit,
        "git_tree": git_tree,
        "repository": repository,
        "ref": ref,
        "run_attempt": run_attempt,
        "run_id": run_id,
        "sha": sha,
        "workflow_ref": workflow_ref,
        "workflow_sha": workflow_sha,
    }


def _git_state() -> tuple[str, str, bool]:
    environment = {
        "COMSPEC": os.environ.get("COMSPEC", ""),
        "PATH": os.environ.get("PATH", ""),
        "PATHEXT": os.environ.get("PATHEXT", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "WINDIR": os.environ.get("WINDIR", ""),
    }
    resolved = shutil.which("git", path=environment["PATH"])
    if resolved is None:
        raise LiveRunnerResultError("cannot resolve the Git executable")

    def run(*arguments: str) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                [resolved, *arguments],
                cwd=REPOSITORY_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
            raise LiveRunnerResultError(f"cannot observe Git state: {exc}") from exc

    head = run("rev-parse", "--verify", "HEAD")
    if head.returncode != 0 or _SHA_RE.fullmatch(head.stdout.strip()) is None:
        raise LiveRunnerResultError("cannot resolve the checked-out Git commit")
    tree = run("rev-parse", "--verify", "HEAD^{tree}")
    if tree.returncode != 0 or _SHA_RE.fullmatch(tree.stdout.strip()) is None:
        raise LiveRunnerResultError("cannot resolve the checked-out Git tree")
    dirty = run("diff", "--quiet", "--no-ext-diff", "--ignore-submodules", "HEAD", "--")
    if dirty.returncode not in {0, 1}:
        raise LiveRunnerResultError("cannot determine tracked Git state")
    return head.stdout.strip(), tree.stdout.strip(), dirty.returncode == 1


def _python_packages_identity() -> tuple[int, str]:
    packages: dict[str, str] = {}
    for distribution in importlib.metadata.distributions():
        name = (distribution.metadata["Name"] or "").strip()
        version = distribution.version.strip()
        normalized = re.sub(r"[-_.]+", "-", name).casefold()
        if not normalized or not version:
            raise LiveRunnerResultError("installed Python package identity is incomplete")
        previous = packages.setdefault(normalized, version)
        if previous != version:
            raise LiveRunnerResultError(
                f"installed Python package identity is ambiguous: {normalized}"
            )
    if not packages:
        raise LiveRunnerResultError("installed Python package inventory is empty")
    payload = _canonical_bytes({"packages": sorted(packages.items())})
    return len(packages), _sha256(payload)


def _environment_identity() -> dict[str, Any]:
    runner_os = _required_environment("RUNNER_OS")
    runner_arch = _required_environment("RUNNER_ARCH")
    runner_environment = _required_environment("RUNNER_ENVIRONMENT")
    matrix_os = _required_environment("EVOGUARD_MATRIX_OS")
    matrix_python = _required_environment("EVOGUARD_MATRIX_PYTHON")
    if runner_os not in {"Linux", "Windows"}:
        raise LiveRunnerResultError("runner OS is outside the live matrix")
    if runner_arch != "X64":
        raise LiveRunnerResultError("the reviewed live matrix requires X64 runners")
    if runner_environment != "github-hosted":
        raise LiveRunnerResultError("the reviewed live matrix requires GitHub-hosted runners")
    if matrix_os not in {"ubuntu-latest", "windows-latest"}:
        raise LiveRunnerResultError("matrix OS is outside the reviewed contract")
    expected_runner = "Linux" if matrix_os == "ubuntu-latest" else "Windows"
    if runner_os != expected_runner:
        raise LiveRunnerResultError("matrix OS and delivered runner OS disagree")
    if matrix_python not in {"3.10", "3.11", "3.12"}:
        raise LiveRunnerResultError("matrix Python is outside the reviewed contract")
    if runner_os == "Windows" and matrix_python != "3.12":
        raise LiveRunnerResultError("the reviewed Windows cell requires Python 3.12")
    if not platform.python_version().startswith(matrix_python + "."):
        raise LiveRunnerResultError("declared and delivered Python versions disagree")
    node = _bounded_version(("node", "--version"), label="Node")
    vitest = _bounded_version(("vitest", "--version"), label="Vitest")
    if _NODE_22_RE.fullmatch(node) is None:
        raise LiveRunnerResultError("the delivered Node version is not Node 22")
    if _VITEST_4_1_10_RE.fullmatch(vitest) is None:
        raise LiveRunnerResultError("the delivered Vitest version is not 4.1.10")
    if os.environ.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD") != "1":
        raise LiveRunnerResultError("pytest plugin autoload must be disabled")
    package_count, package_digest = _python_packages_identity()
    return {
        "matrix_os": matrix_os,
        "matrix_python": matrix_python,
        "node": node,
        "python": platform.python_version(),
        "python_packages_count": package_count,
        "python_packages_sha256": package_digest,
        "pytest_plugin_autoload_disabled": True,
        "runner_arch": runner_arch,
        "runner_environment": runner_environment,
        "runner_image": _required_environment("ImageOS"),
        "runner_image_version": _required_environment("ImageVersion"),
        "runner_os": runner_os,
        "vitest": vitest,
    }


def build_result(junit_path: Path) -> dict[str, Any]:
    raw_junit = read_stable_regular_file(
        junit_path,
        label="live runner JUnit",
        max_bytes=MAX_JUNIT_BYTES,
    )
    suite = parse_exact_junit(raw_junit)
    suite["junit_sha256"] = _sha256(raw_junit)
    suite["junit_size"] = len(raw_junit)
    inventory, aggregate = _source_inventory()
    return {
        "$schema": RESULT_SCHEMA,
        "claims": {
            "external_runner_suites_executed": True,
            "hostile_code_production": False,
            "independent_evaluation": False,
            "matrix_cell_only": True,
        },
        "environment": _environment_identity(),
        "execution": _execution_identity(),
        "schema_version": SCHEMA_VERSION,
        "source": {"aggregate_sha256": aggregate, "reviewed_files": inventory},
        "status": "pass",
        "status_basis": "real_guard_oracle_tests_only",
        "suite": suite,
    }


def validate_result(value: Mapping[str, Any]) -> None:
    _require_keys(
        value,
        {
            "$schema",
            "claims",
            "environment",
            "execution",
            "schema_version",
            "source",
            "status",
            "status_basis",
            "suite",
        },
        "result",
    )
    if value["$schema"] != RESULT_SCHEMA or value["schema_version"] != SCHEMA_VERSION:
        raise LiveRunnerResultError("result schema identity is invalid")
    if value["status"] != "pass" or value["status_basis"] != "real_guard_oracle_tests_only":
        raise LiveRunnerResultError("result status is invalid")
    claims = value["claims"]
    if not isinstance(claims, dict):
        raise LiveRunnerResultError("claims must be an object")
    _require_keys(
        claims,
        {
            "external_runner_suites_executed",
            "hostile_code_production",
            "independent_evaluation",
            "matrix_cell_only",
        },
        "claims",
    )
    expected_claims = {
        "external_runner_suites_executed": True,
        "hostile_code_production": False,
        "independent_evaluation": False,
        "matrix_cell_only": True,
    }
    for key, expected in expected_claims.items():
        actual = claims[key]
        if type(actual) is not bool or actual is not expected:
            raise LiveRunnerResultError("claim boundary is invalid")
    for key in ("environment", "execution", "source", "suite"):
        if not isinstance(value[key], dict):
            raise LiveRunnerResultError(f"{key} must be an object")
    environment = value["environment"]
    _require_keys(
        environment,
        {
            "matrix_os",
            "matrix_python",
            "node",
            "python",
            "python_packages_count",
            "python_packages_sha256",
            "pytest_plugin_autoload_disabled",
            "runner_arch",
            "runner_environment",
            "runner_image",
            "runner_image_version",
            "runner_os",
            "vitest",
        },
        "environment",
    )
    matrix_os = _require_string(environment["matrix_os"], "environment.matrix_os")
    matrix_python = _require_string(
        environment["matrix_python"], "environment.matrix_python"
    )
    runner_os = _require_string(environment["runner_os"], "environment.runner_os")
    if matrix_os not in {"ubuntu-latest", "windows-latest"}:
        raise LiveRunnerResultError("environment.matrix_os is unsupported")
    if matrix_python not in {"3.10", "3.11", "3.12"}:
        raise LiveRunnerResultError("environment.matrix_python is unsupported")
    expected_runner = "Linux" if matrix_os == "ubuntu-latest" else "Windows"
    if runner_os != expected_runner:
        raise LiveRunnerResultError("environment OS identities disagree")
    if environment["runner_arch"] != "X64":
        raise LiveRunnerResultError("environment.runner_arch is invalid")
    if environment["runner_environment"] != "github-hosted":
        raise LiveRunnerResultError("environment.runner_environment is invalid")
    if runner_os == "Windows" and matrix_python != "3.12":
        raise LiveRunnerResultError("the Windows matrix cell must use Python 3.12")
    for key in (
        "node",
        "python",
        "python_packages_sha256",
        "runner_image",
        "runner_image_version",
        "vitest",
    ):
        _require_string(environment[key], f"environment.{key}")
    if _NODE_22_RE.fullmatch(environment["node"]) is None:
        raise LiveRunnerResultError("environment.node is not Node 22")
    if len(environment["node"]) > 4096:
        raise LiveRunnerResultError("environment.node is oversized")
    if _VITEST_4_1_10_RE.fullmatch(environment["vitest"]) is None:
        raise LiveRunnerResultError("environment.vitest is not Vitest 4.1.10")
    if len(environment["vitest"]) > 4096:
        raise LiveRunnerResultError("environment.vitest is oversized")
    if (
        re.fullmatch(r"[0-9a-f]{64}", environment["python_packages_sha256"])
        is None
    ):
        raise LiveRunnerResultError(
            "environment.python_packages_sha256 must be lowercase 64-hex"
        )
    if _require_nonnegative_int(
        environment["python_packages_count"], "environment.python_packages_count"
    ) == 0:
        raise LiveRunnerResultError("environment.python_packages_count must be positive")
    if type(environment["pytest_plugin_autoload_disabled"]) is not bool or not environment[
        "pytest_plugin_autoload_disabled"
    ]:
        raise LiveRunnerResultError(
            "environment.pytest_plugin_autoload_disabled must be true"
        )

    execution = value["execution"]
    _require_keys(
        execution,
        {
            "event_name",
            "git_commit",
            "git_tree",
            "repository",
            "ref",
            "run_attempt",
            "run_id",
            "sha",
            "workflow_ref",
            "workflow_sha",
        },
        "execution",
    )
    if execution["repository"] != "EvoRiseKsa/EvoOM-Guard-m":
        raise LiveRunnerResultError("execution.repository is invalid")
    sha = _require_string(execution["sha"], "execution.sha")
    if _SHA_RE.fullmatch(sha) is None:
        raise LiveRunnerResultError("execution.sha must be lowercase 40-hex")
    if execution["git_commit"] != sha:
        raise LiveRunnerResultError("execution.git_commit differs from execution.sha")
    for key in ("git_tree", "workflow_sha"):
        if _SHA_RE.fullmatch(
            _require_string(execution[key], f"execution.{key}")
        ) is None:
            raise LiveRunnerResultError(f"execution.{key} must be lowercase 40-hex")
    event_name = _require_string(execution["event_name"], "execution.event_name")
    ref = _require_string(execution["ref"], "execution.ref")
    if event_name == "push":
        if ref != "refs/heads/main":
            raise LiveRunnerResultError("execution push ref is invalid")
    elif event_name == "pull_request":
        if _PULL_REF_RE.fullmatch(ref) is None:
            raise LiveRunnerResultError("execution pull-request ref is invalid")
    else:
        raise LiveRunnerResultError("execution.event_name is invalid")
    for key in ("run_attempt", "run_id"):
        if _DIGITS_RE.fullmatch(
            _require_string(execution[key], f"execution.{key}")
        ) is None:
            raise LiveRunnerResultError(f"execution.{key} must be a positive integer")
    workflow_ref = _require_string(execution["workflow_ref"], "execution.workflow_ref")
    if workflow_ref != _WORKFLOW_REF_PREFIX + ref:
        raise LiveRunnerResultError("execution.workflow_ref is invalid")

    source = value["source"]
    _require_keys(source, {"aggregate_sha256", "reviewed_files"}, "source")
    aggregate = _require_string(source["aggregate_sha256"], "source.aggregate_sha256")
    if re.fullmatch(r"[0-9a-f]{64}", aggregate) is None:
        raise LiveRunnerResultError("source.aggregate_sha256 must be lowercase 64-hex")
    files = source["reviewed_files"]
    if not isinstance(files, dict):
        raise LiveRunnerResultError("source.reviewed_files must be an object")
    if set(files) != set(_SOURCE_PATHS):
        raise LiveRunnerResultError(
            "source.reviewed_files differs from the reviewed inventory"
        )
    for relative, entry in files.items():
        if not isinstance(entry, dict):
            raise LiveRunnerResultError(
                f"source.reviewed_files.{relative} must be an object"
            )
        _require_keys(entry, {"sha256", "size"}, f"source.reviewed_files.{relative}")
        digest = _require_string(
            entry["sha256"], f"source.reviewed_files.{relative}.sha256"
        )
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise LiveRunnerResultError(
                f"source.reviewed_files.{relative}.sha256 must be lowercase 64-hex"
            )
        if (
            _require_nonnegative_int(
                entry["size"], f"source.reviewed_files.{relative}.size"
            )
            == 0
        ):
            raise LiveRunnerResultError(
                f"source.reviewed_files.{relative}.size must be positive"
            )

    suite = value["suite"]
    _require_keys(
        suite,
        {
            "errors",
            "failures",
            "junit_sha256",
            "junit_size",
            "skipped",
            "test_names",
            "tests",
        },
        "suite",
    )
    for key in ("errors", "failures", "skipped"):
        if _require_nonnegative_int(suite[key], f"suite.{key}") != 0:
            raise LiveRunnerResultError(f"suite.{key} must be zero")
    if _require_nonnegative_int(suite["tests"], "suite.tests") != len(_EXPECTED_TESTS):
        raise LiveRunnerResultError("suite.tests is invalid")
    junit_size = _require_nonnegative_int(suite["junit_size"], "suite.junit_size")
    if junit_size == 0:
        raise LiveRunnerResultError("suite.junit_size must be positive")
    if junit_size > MAX_JUNIT_BYTES:
        raise LiveRunnerResultError("suite.junit_size exceeds the JUnit byte limit")
    junit_digest = _require_string(suite["junit_sha256"], "suite.junit_sha256")
    if re.fullmatch(r"[0-9a-f]{64}", junit_digest) is None:
        raise LiveRunnerResultError("suite.junit_sha256 must be lowercase 64-hex")
    names = suite["test_names"]
    if not isinstance(names, list) or names != sorted(_EXPECTED_TESTS):
        raise LiveRunnerResultError("suite.test_names differs from the reviewed oracle set")


def load_result(path: Path) -> dict[str, Any]:
    raw = read_stable_regular_file(
        path,
        label="live runner result",
        max_bytes=MAX_RESULT_BYTES,
    )
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_closed_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LiveRunnerResultError(f"result is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise LiveRunnerResultError("result root must be an object")
    validate_result(value)
    if raw != _canonical_bytes(value):
        raise LiveRunnerResultError("result JSON is not canonical")
    return value


def verify_result(result: Mapping[str, Any], junit_path: Path) -> None:
    validate_result(result)
    expected = build_result(junit_path)
    if dict(result) != expected:
        raise LiveRunnerResultError("result differs from current exact evidence")


def write_result(result: Mapping[str, Any], path: Path) -> None:
    validate_result(result)
    write_create_only_bytes(path, _canonical_bytes(result))


__all__ = [
    "LiveRunnerResultError",
    "build_result",
    "load_result",
    "parse_exact_junit",
    "validate_result",
    "verify_result",
    "write_result",
]
