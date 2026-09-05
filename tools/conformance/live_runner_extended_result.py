"""Strict evidence for one cell of the extended GitHub-hosted runner matrix."""

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

SCHEMA_VERSION = "evoguard-live-runner-extended-conformance-v1"
RESULT_SCHEMA = "tools/conformance/live-runner-extended-result.schema.json"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
NODE_PROJECT = REPOSITORY_ROOT / "tools" / "ci-live-runners" / "node"
RUBY_PROJECT = REPOSITORY_ROOT / "tools" / "ci-live-runners" / "ruby"
MAX_JUNIT_BYTES = 2 * 1024 * 1024
MAX_RESULT_BYTES = 2 * 1024 * 1024

_SHA_RE = re.compile(r"[0-9a-f]{40}")
_DIGITS_RE = re.compile(r"[1-9][0-9]*")
_BASH_VERSION_RE = re.compile(
    r"GNU bash, version [0-9]+\.[0-9]+\.[0-9]+\([0-9]+\)-release \(.+\)"
)
_PULL_REF_RE = re.compile(r"refs/pull/[1-9][0-9]*/merge")
_WORKFLOW_REF_PREFIX = (
    "EvoRiseKsa/EvoOM-Guard-m/.github/workflows/"
    "runner-live-conformance.yml@"
)
_EXPECTED_TOOLS = {
    "bundler": "4.0.20",
    "go": "1.27.1",
    "gotestsum": "1.13.0",
    "java": "21.0.9",
    "jest_cli": "30.5.0",
    "jest_junit": "17.0.0",
    "jest_package": "30.5.1",
    "maven": "3.9.16",
    "mocha": "12.0.0",
    "node": "22.23.2",
    "rspec": "3.13.2",
    "rspec_junit_formatter": "0.6.0",
    "ruby": "3.4.10",
}
_EXPECTED_TESTS = frozenset(
    {
        "test_extended_parse_jest_junit_counts",
        "test_extended_jest_honest_fix_is_pass",
        "test_extended_jest_broken_fix_is_fail",
        "test_extended_jest_protected_test_rewrite_is_rejected",
        "test_extended_parse_gotestsum_junit_counts",
        "test_extended_gotestsum_honest_fix_is_pass",
        "test_extended_gotestsum_broken_fix_is_fail",
        "test_extended_parse_rspec_junit_counts",
        "test_extended_rspec_honest_fix_is_pass",
        "test_extended_rspec_broken_fix_is_fail",
        "test_extended_parse_mocha_junit_counts",
        "test_extended_mocha_honest_fix_is_pass",
        "test_extended_mocha_broken_fix_is_fail",
        "test_extended_parse_maven_junit_counts",
        "test_extended_maven_honest_fix_is_pass",
        "test_extended_maven_broken_fix_is_fail",
        "test_extended_shell_honest_fix_is_pass",
        "test_extended_shell_broken_fix_is_fail",
    }
)
_SOURCE_PATHS = (
    ".github/workflows/runner-live-conformance.yml",
    "evoom_guard/adapters.py",
    "evoom_guard/guard.py",
    "evoom_guard/runners/__init__.py",
    "evoom_guard/runners/_command.py",
    "evoom_guard/runners/adapters.py",
    "evoom_guard/runners/gotestsum.py",
    "evoom_guard/runners/jest.py",
    "evoom_guard/runners/maven.py",
    "evoom_guard/runners/mocha.py",
    "evoom_guard/runners/node_test.py",
    "evoom_guard/runners/protocol.py",
    "evoom_guard/runners/registry.py",
    "evoom_guard/runners/rspec.py",
    "evoom_guard/runners/shell.py",
    "evoom_guard/verifiers/junit_oracle.py",
    "evoom_guard/verifiers/repo_verifier.py",
    "tests/live_runner_extended_helpers.py",
    "tests/test_gotestsum_live_oracle.py",
    "tests/test_jest_live_oracle.py",
    "tests/test_live_runner_maven_cache.py",
    "tests/test_maven_live_oracle.py",
    "tests/test_mocha_live_oracle.py",
    "tests/test_rspec_live_oracle.py",
    "tests/test_shell_live_oracle.py",
    "requirements/ci.in",
    "requirements/ci.lock",
    "requirements/docker-pytest.in",
    "requirements/docker-pytest.lock",
    "requirements/python310-compat.in",
    "requirements/python310-compat.lock",
    "tools/ci-live-runners/go/go.mod",
    "tools/ci-live-runners/go/go.sum",
    "tools/ci-live-runners/maven/pom.xml",
    "tools/ci-live-runners/maven/artifacts.sha256",
    "tools/ci-live-runners/maven/src/main/java/io/github/evoriseksa/Calc.java",
    "tools/ci-live-runners/maven/src/test/java/io/github/evoriseksa/CalcTest.java",
    "tools/ci-live-runners/node/package-lock.json",
    "tools/ci-live-runners/node/package.json",
    "tools/ci-live-runners/ruby/Gemfile",
    "tools/ci-live-runners/ruby/Gemfile.lock",
    "tools/conformance/secure_io.py",
    "tools/conformance/fetch_live_runner_maven_cache.py",
    "tools/conformance/live_runner_extended_result.py",
    "tools/conformance/run_live_runner_extended_conformance.py",
    "tools/conformance/verify_live_runner_maven_cache.py",
    "pyproject.toml",
    RESULT_SCHEMA,
)


class LiveRunnerExtendedResultError(ValueError):
    """The extended result or the exact evidence behind it is invalid."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _reject_constant(value: str) -> None:
    raise LiveRunnerExtendedResultError(
        f"non-finite JSON constant is forbidden: {value}"
    )


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LiveRunnerExtendedResultError(
                f"duplicate JSON key is forbidden: {key}"
            )
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
        raise LiveRunnerExtendedResultError(
            f"{context} has invalid keys: missing={missing}, extra={extra}"
        )


def _require_string(value: Any, context: str, *, max_length: int = 4096) -> str:
    if not isinstance(value, str) or not value:
        raise LiveRunnerExtendedResultError(f"{context} must be a non-empty string")
    if len(value) > max_length:
        raise LiveRunnerExtendedResultError(f"{context} is oversized")
    return value


def _require_nonnegative_int(value: Any, context: str) -> int:
    if type(value) is not int or value < 0:
        raise LiveRunnerExtendedResultError(
            f"{context} must be a nonnegative integer"
        )
    return value


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise LiveRunnerExtendedResultError(
            f"required environment value is absent: {name}"
        )
    return value


def _command_environment() -> dict[str, str]:
    allowed = (
        "BUNDLE_GEMFILE",
        "BUNDLE_PATH",
        "COMSPEC",
        "GEM_HOME",
        "GEM_PATH",
        "GOROOT",
        "HOME",
        "JAVA_HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PATHEXT",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    )
    return {name: os.environ[name] for name in allowed if os.environ.get(name)}


def _bounded_version(
    argv: Sequence[str],
    *,
    label: str,
    cwd: Path = REPOSITORY_ROOT,
) -> str:
    environment = _command_environment()
    resolved = shutil.which(argv[0], path=environment.get("PATH", ""))
    if resolved is None:
        raise LiveRunnerExtendedResultError(f"cannot resolve the {label} executable")
    command = [resolved, *argv[1:]]
    if os.name == "nt" and Path(resolved).suffix.casefold() in {".bat", ".cmd"}:
        comspec = environment.get("COMSPEC")
        if not comspec:
            raise LiveRunnerExtendedResultError("COMSPEC is required for a batch tool")
        command = [
            comspec,
            "/d",
            "/s",
            "/c",
            subprocess.list2cmdline([resolved, *argv[1:]]),
        ]
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise LiveRunnerExtendedResultError(
            f"cannot observe {label} version: {exc}"
        ) from exc
    output = "\n".join(
        part.strip() for part in (completed.stdout, completed.stderr) if part.strip()
    )
    if completed.returncode != 0:
        raise LiveRunnerExtendedResultError(
            f"{label} version command returned {completed.returncode}"
        )
    if not output or len(output.encode("utf-8")) > 4096:
        raise LiveRunnerExtendedResultError(
            f"{label} version output is absent or oversized"
        )
    return output


def _exact_output(output: str, expected: str, label: str) -> str:
    if output != expected:
        raise LiveRunnerExtendedResultError(
            f"the delivered {label} version is not {expected}"
        )
    return expected


def _node_package_version(package: str) -> str:
    expression = f"process.stdout.write(require('{package}/package.json').version)"
    return _bounded_version(
        ("node", "-e", expression),
        label=f"{package} package",
        cwd=NODE_PROJECT,
    )


def _ruby_package_version(package: str) -> str:
    expression = (
        "puts Gem::Specification.find_by_name(" + repr(package) + ").version.to_s"
    )
    return _bounded_version(
        ("bundle", "exec", "ruby", "-e", expression),
        label=f"{package} package",
        cwd=RUBY_PROJECT,
    )


def _exact_local_node_tool(name: str) -> str:
    suffix = ".cmd" if os.name == "nt" else ""
    target = NODE_PROJECT / "node_modules" / ".bin" / f"{name}{suffix}"
    try:
        resolved = target.resolve(strict=True)
    except OSError as exc:
        raise LiveRunnerExtendedResultError(
            f"the locked {name} executable is absent"
        ) from exc
    return str(resolved)


def _bash_identity(runner_os: str) -> tuple[str, str]:
    if runner_os == "Linux":
        expected_path = "/usr/bin/bash"
    elif runner_os == "Windows":
        expected_path = r"C:\Program Files\Git\bin\bash.exe"
    else:
        raise LiveRunnerExtendedResultError("the Bash runner OS is invalid")
    declared = _required_environment("EVOGUARD_EXTENDED_BASH")
    try:
        resolved = str(Path(declared).resolve(strict=True))
    except OSError as exc:
        raise LiveRunnerExtendedResultError("the exact Bash executable is absent") from exc
    if os.path.normcase(resolved) != os.path.normcase(expected_path):
        raise LiveRunnerExtendedResultError("the Bash executable path is outside the contract")
    output = _bounded_version((resolved, "--version"), label="Bash")
    first_line = output.splitlines()[0]
    if _BASH_VERSION_RE.fullmatch(first_line) is None:
        raise LiveRunnerExtendedResultError("the delivered Bash version is invalid")
    return expected_path, first_line


def _tool_identity(runner_os: str) -> dict[str, str]:
    node = _bounded_version(("node", "--version"), label="Node")
    if node != "v22.23.2":
        raise LiveRunnerExtendedResultError("the delivered Node version is not 22.23.2")

    jest_cli = _bounded_version(
        (_exact_local_node_tool("jest"), "--version"), label="Jest CLI"
    )
    mocha_path = _required_environment("EVOGUARD_EXTENDED_MOCHA")
    expected_mocha = _exact_local_node_tool("mocha")
    try:
        actual_mocha = str(Path(mocha_path).resolve(strict=True))
    except OSError as exc:
        raise LiveRunnerExtendedResultError(
            "the locked Mocha executable is absent"
        ) from exc
    if os.path.normcase(actual_mocha) != os.path.normcase(expected_mocha):
        raise LiveRunnerExtendedResultError(
            "the Mocha executable does not belong to the locked tool project"
        )

    go_output = _bounded_version(("go", "version"), label="Go")
    expected_go = (
        "go version go1.27.1 linux/amd64"
        if runner_os == "Linux"
        else "go version go1.27.1 windows/amd64"
    )
    _exact_output(go_output, expected_go, "Go")
    gotestsum_output = _bounded_version(
        ("gotestsum", "--version"), label="gotestsum"
    )

    ruby_output = _bounded_version(("ruby", "--version"), label="Ruby")
    if re.match(r"ruby 3\.4\.10(?:p[0-9]+)?(?:\s|$)", ruby_output) is None:
        raise LiveRunnerExtendedResultError("the delivered Ruby version is not 3.4.10")
    bundler_output = _bounded_version(("bundle", "--version"), label="Bundler")

    java_output = _bounded_version(("java", "-version"), label="Java")
    java_first = java_output.splitlines()[0]
    if re.search(r'\bversion "21\.0\.9"', java_first) is None:
        raise LiveRunnerExtendedResultError("the delivered Java version is not 21.0.9")
    if (
        re.search(r"\bTemurin-21\.0\.9\+10\b", java_output) is None
        or re.search(r"\bbuild 21\.0\.9\+10(?:-LTS)?\b", java_output) is None
    ):
        raise LiveRunnerExtendedResultError(
            "the delivered Java build is not Temurin 21.0.9+10"
        )
    maven_output = _bounded_version(("mvn", "-o", "--version"), label="Maven")
    maven_first = maven_output.splitlines()[0]
    _exact_output(
        maven_first,
        "Apache Maven 3.9.16 (2bdd9fddda4b155ebf8000e807eb73fd829a51d5)",
        "Maven",
    )

    bash_path, bash_version = _bash_identity(runner_os)
    tools = {
        "bash_path": bash_path,
        "bash_version": bash_version,
        "bundler": _exact_output(
            bundler_output, "Bundler version 4.0.20", "Bundler"
        ).removeprefix("Bundler version "),
        "go": "1.27.1",
        "gotestsum": _exact_output(
            gotestsum_output, "gotestsum version v1.13.0", "gotestsum"
        ).removeprefix("gotestsum version v"),
        "java": "21.0.9",
        "jest_cli": _exact_output(jest_cli, "30.5.0", "Jest CLI"),
        "jest_junit": _exact_output(
            _node_package_version("jest-junit"), "17.0.0", "jest-junit"
        ),
        "jest_package": _exact_output(
            _node_package_version("jest"), "30.5.1", "Jest package"
        ),
        "maven": "3.9.16",
        "mocha": _exact_output(
            _bounded_version((actual_mocha, "--version"), label="Mocha"),
            "12.0.0",
            "Mocha",
        ),
        "node": node.removeprefix("v"),
        "rspec": _exact_output(
            _ruby_package_version("rspec"), "3.13.2", "RSpec"
        ),
        "rspec_junit_formatter": _exact_output(
            _ruby_package_version("rspec_junit_formatter"),
            "0.6.0",
            "RSpec JUnit formatter",
        ),
        "ruby": "3.4.10",
    }
    if {key: tools[key] for key in _EXPECTED_TOOLS} != _EXPECTED_TOOLS:
        raise LiveRunnerExtendedResultError("the delivered tool set is outside the contract")
    return tools


def parse_exact_junit(raw: bytes) -> dict[str, Any]:
    """Require all 18 reviewed extended oracles with no non-pass outcome."""

    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise LiveRunnerExtendedResultError(
            "JUnit DTD/entity declarations are forbidden"
        )
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise LiveRunnerExtendedResultError(
            f"JUnit is not well-formed XML: {exc}"
        ) from exc
    if root.tag != "testsuites":
        raise LiveRunnerExtendedResultError("JUnit root must be testsuites")
    suites = list(root.findall("testsuite"))
    if len(suites) != 1 or list(suites[0].findall(".//testsuite")):
        raise LiveRunnerExtendedResultError(
            "JUnit must contain exactly one non-nested testsuite"
        )
    suite = suites[0]
    declared = {
        "errors": 0,
        "failures": 0,
        "skipped": 0,
        "tests": len(_EXPECTED_TESTS),
    }
    for name, expected in declared.items():
        raw_count = suite.attrib.get(name, "")
        if not raw_count.isascii() or not raw_count.isdecimal():
            raise LiveRunnerExtendedResultError(
                f"JUnit testsuite.{name} must be a declared decimal count"
            )
        if int(raw_count) != expected:
            raise LiveRunnerExtendedResultError(
                f"JUnit testsuite.{name} differs from the exact contract"
            )
    cases = list(suite.iter("testcase"))
    names = [case.attrib.get("name", "") for case in cases]
    if any(not name for name in names):
        raise LiveRunnerExtendedResultError("every JUnit testcase must have a name")
    if len(names) != len(set(names)):
        raise LiveRunnerExtendedResultError("JUnit testcase names must be unique")
    observed = frozenset(names)
    if observed != _EXPECTED_TESTS:
        raise LiveRunnerExtendedResultError(
            "extended live oracle set differs from the reviewed contract: "
            f"missing={sorted(_EXPECTED_TESTS - observed)}, "
            f"extra={sorted(observed - _EXPECTED_TESTS)}"
        )
    failures = sum(case.find("failure") is not None for case in cases)
    errors = sum(case.find("error") is not None for case in cases)
    skipped = sum(case.find("skipped") is not None for case in cases)
    if failures or errors or skipped:
        raise LiveRunnerExtendedResultError(
            "extended live oracle result is not clean: "
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
            label=f"extended live runner source {relative}",
        )
        digest = _sha256(raw)
        inventory[relative] = {"sha256": digest, "size": len(raw)}
        encoded = relative.encode("utf-8")
        aggregate.update(len(encoded).to_bytes(8, "big"))
        aggregate.update(encoded)
        aggregate.update(len(raw).to_bytes(8, "big"))
        aggregate.update(raw)
    return inventory, aggregate.hexdigest()


def _git_state() -> tuple[str, str, bool]:
    environment = _command_environment()
    resolved = shutil.which("git", path=environment.get("PATH", ""))
    if resolved is None:
        raise LiveRunnerExtendedResultError("cannot resolve the Git executable")

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
            raise LiveRunnerExtendedResultError(
                f"cannot observe Git state: {exc}"
            ) from exc

    head = run("rev-parse", "--verify", "HEAD")
    if head.returncode != 0 or _SHA_RE.fullmatch(head.stdout.strip()) is None:
        raise LiveRunnerExtendedResultError(
            "cannot resolve the checked-out Git commit"
        )
    tree = run("rev-parse", "--verify", "HEAD^{tree}")
    if tree.returncode != 0 or _SHA_RE.fullmatch(tree.stdout.strip()) is None:
        raise LiveRunnerExtendedResultError("cannot resolve the checked-out Git tree")
    dirty = run("diff", "--quiet", "--no-ext-diff", "--ignore-submodules", "HEAD", "--")
    if dirty.returncode not in {0, 1}:
        raise LiveRunnerExtendedResultError("cannot determine tracked Git state")
    return head.stdout.strip(), tree.stdout.strip(), dirty.returncode == 1


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
        raise LiveRunnerExtendedResultError("unexpected repository identity")
    if event_name not in {"pull_request", "push"}:
        raise LiveRunnerExtendedResultError("unexpected workflow event")
    if event_name == "push" and ref != "refs/heads/main":
        raise LiveRunnerExtendedResultError(
            "the push matrix must run on refs/heads/main"
        )
    if event_name == "pull_request" and _PULL_REF_RE.fullmatch(ref) is None:
        raise LiveRunnerExtendedResultError(
            "the pull-request matrix ref is invalid"
        )
    if _SHA_RE.fullmatch(sha) is None:
        raise LiveRunnerExtendedResultError("GITHUB_SHA must be lowercase 40-hex")
    if _SHA_RE.fullmatch(workflow_sha) is None:
        raise LiveRunnerExtendedResultError(
            "GITHUB_WORKFLOW_SHA must be lowercase 40-hex"
        )
    if _DIGITS_RE.fullmatch(run_id) is None or _DIGITS_RE.fullmatch(run_attempt) is None:
        raise LiveRunnerExtendedResultError(
            "run identity must contain positive decimal integers"
        )
    if workflow_ref != _WORKFLOW_REF_PREFIX + ref:
        raise LiveRunnerExtendedResultError(
            "workflow ref and execution ref disagree"
        )
    git_commit, git_tree, tracked_dirty = _git_state()
    if git_commit != sha:
        raise LiveRunnerExtendedResultError(
            "checked-out Git commit differs from GITHUB_SHA"
        )
    if tracked_dirty:
        raise LiveRunnerExtendedResultError(
            "tracked source changed during extended live conformance"
        )
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


def _python_packages_identity() -> tuple[int, str]:
    packages: dict[str, str] = {}
    for distribution in importlib.metadata.distributions():
        name = (distribution.metadata["Name"] or "").strip()
        version = distribution.version.strip()
        normalized = re.sub(r"[-_.]+", "-", name).casefold()
        if not normalized or not version:
            raise LiveRunnerExtendedResultError(
                "installed Python package identity is incomplete"
            )
        previous = packages.setdefault(normalized, version)
        if previous != version:
            raise LiveRunnerExtendedResultError(
                f"installed Python package identity is ambiguous: {normalized}"
            )
    if not packages:
        raise LiveRunnerExtendedResultError(
            "installed Python package inventory is empty"
        )
    payload = _canonical_bytes({"packages": sorted(packages.items())})
    return len(packages), _sha256(payload)


def _environment_identity() -> dict[str, Any]:
    runner_os = _required_environment("RUNNER_OS")
    runner_arch = _required_environment("RUNNER_ARCH")
    runner_environment = _required_environment("RUNNER_ENVIRONMENT")
    matrix_os = _required_environment("EVOGUARD_MATRIX_OS")
    matrix_python = _required_environment("EVOGUARD_MATRIX_PYTHON")
    if runner_os not in {"Linux", "Windows"}:
        raise LiveRunnerExtendedResultError(
            "runner OS is outside the extended live matrix"
        )
    if runner_arch != "X64":
        raise LiveRunnerExtendedResultError(
            "the extended live matrix requires X64 runners"
        )
    if runner_environment != "github-hosted":
        raise LiveRunnerExtendedResultError(
            "the extended live matrix requires GitHub-hosted runners"
        )
    expected_runner = {
        "ubuntu-latest": "Linux",
        "windows-latest": "Windows",
    }.get(matrix_os)
    if expected_runner is None or runner_os != expected_runner:
        raise LiveRunnerExtendedResultError(
            "matrix OS and delivered runner OS disagree"
        )
    if matrix_python != "3.12.10" or platform.python_version() != "3.12.10":
        raise LiveRunnerExtendedResultError(
            "the extended live matrix requires exact Python 3.12.10"
        )
    if os.environ.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD") != "1":
        raise LiveRunnerExtendedResultError(
            "pytest plugin autoload must be disabled"
        )
    package_count, package_digest = _python_packages_identity()
    return {
        "matrix_os": matrix_os,
        "matrix_python": matrix_python,
        "python": platform.python_version(),
        "python_packages_count": package_count,
        "python_packages_sha256": package_digest,
        "pytest_plugin_autoload_disabled": True,
        "runner_arch": runner_arch,
        "runner_environment": runner_environment,
        "runner_image": _required_environment("ImageOS"),
        "runner_image_version": _required_environment("ImageVersion"),
        "runner_os": runner_os,
        "tools": _tool_identity(runner_os),
    }


def build_result(junit_path: Path) -> dict[str, Any]:
    raw_junit = read_stable_regular_file(
        junit_path,
        label="extended live runner JUnit",
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
        "status_basis": "real_extended_guard_oracle_tests_only",
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
        raise LiveRunnerExtendedResultError("result schema identity is invalid")
    if (
        value["status"] != "pass"
        or value["status_basis"] != "real_extended_guard_oracle_tests_only"
    ):
        raise LiveRunnerExtendedResultError("result status is invalid")

    claims = value["claims"]
    if not isinstance(claims, dict):
        raise LiveRunnerExtendedResultError("claims must be an object")
    expected_claims = {
        "external_runner_suites_executed": True,
        "hostile_code_production": False,
        "independent_evaluation": False,
        "matrix_cell_only": True,
    }
    _require_keys(claims, set(expected_claims), "claims")
    for key, expected in expected_claims.items():
        actual = claims[key]
        if type(actual) is not bool or actual is not expected:
            raise LiveRunnerExtendedResultError("claim boundary is invalid")

    for key in ("environment", "execution", "source", "suite"):
        if not isinstance(value[key], dict):
            raise LiveRunnerExtendedResultError(f"{key} must be an object")

    environment = value["environment"]
    _require_keys(
        environment,
        {
            "matrix_os",
            "matrix_python",
            "python",
            "python_packages_count",
            "python_packages_sha256",
            "pytest_plugin_autoload_disabled",
            "runner_arch",
            "runner_environment",
            "runner_image",
            "runner_image_version",
            "runner_os",
            "tools",
        },
        "environment",
    )
    matrix_os = _require_string(environment["matrix_os"], "environment.matrix_os")
    runner_os = _require_string(environment["runner_os"], "environment.runner_os")
    expected_runner = {
        "ubuntu-latest": "Linux",
        "windows-latest": "Windows",
    }.get(matrix_os)
    if expected_runner is None or runner_os != expected_runner:
        raise LiveRunnerExtendedResultError("environment OS identities disagree")
    if environment["matrix_python"] != "3.12.10" or environment["python"] != "3.12.10":
        raise LiveRunnerExtendedResultError("environment Python identity is invalid")
    if environment["runner_arch"] != "X64":
        raise LiveRunnerExtendedResultError("environment.runner_arch is invalid")
    if environment["runner_environment"] != "github-hosted":
        raise LiveRunnerExtendedResultError(
            "environment.runner_environment is invalid"
        )
    for key in (
        "python_packages_sha256",
        "runner_image",
        "runner_image_version",
    ):
        _require_string(environment[key], f"environment.{key}")
    if re.fullmatch(r"[0-9a-f]{64}", environment["python_packages_sha256"]) is None:
        raise LiveRunnerExtendedResultError(
            "environment.python_packages_sha256 must be lowercase 64-hex"
        )
    if _require_nonnegative_int(
        environment["python_packages_count"], "environment.python_packages_count"
    ) == 0:
        raise LiveRunnerExtendedResultError(
            "environment.python_packages_count must be positive"
        )
    if (
        type(environment["pytest_plugin_autoload_disabled"]) is not bool
        or not environment["pytest_plugin_autoload_disabled"]
    ):
        raise LiveRunnerExtendedResultError(
            "environment.pytest_plugin_autoload_disabled must be true"
        )
    tools = environment["tools"]
    if not isinstance(tools, dict):
        raise LiveRunnerExtendedResultError("environment.tools must be an object")
    _require_keys(
        tools,
        {*_EXPECTED_TOOLS, "bash_path", "bash_version"},
        "environment.tools",
    )
    for name, expected in _EXPECTED_TOOLS.items():
        if tools[name] != expected:
            raise LiveRunnerExtendedResultError(
                f"environment.tools.{name} is outside the pinned contract"
            )
    expected_bash = (
        "/usr/bin/bash"
        if runner_os == "Linux"
        else r"C:\Program Files\Git\bin\bash.exe"
    )
    if tools["bash_path"] != expected_bash:
        raise LiveRunnerExtendedResultError(
            "environment.tools.bash_path is outside the pinned contract"
        )
    bash_version = _require_string(
        tools["bash_version"], "environment.tools.bash_version"
    )
    if _BASH_VERSION_RE.fullmatch(bash_version) is None:
        raise LiveRunnerExtendedResultError(
            "environment.tools.bash_version is invalid"
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
        raise LiveRunnerExtendedResultError("execution.repository is invalid")
    sha = _require_string(execution["sha"], "execution.sha")
    if _SHA_RE.fullmatch(sha) is None:
        raise LiveRunnerExtendedResultError(
            "execution.sha must be lowercase 40-hex"
        )
    if execution["git_commit"] != sha:
        raise LiveRunnerExtendedResultError(
            "execution.git_commit differs from execution.sha"
        )
    for key in ("git_tree", "workflow_sha"):
        if _SHA_RE.fullmatch(
            _require_string(execution[key], f"execution.{key}")
        ) is None:
            raise LiveRunnerExtendedResultError(
                f"execution.{key} must be lowercase 40-hex"
            )
    event_name = _require_string(execution["event_name"], "execution.event_name")
    ref = _require_string(execution["ref"], "execution.ref")
    if event_name == "push":
        if ref != "refs/heads/main":
            raise LiveRunnerExtendedResultError("execution push ref is invalid")
    elif event_name == "pull_request":
        if _PULL_REF_RE.fullmatch(ref) is None:
            raise LiveRunnerExtendedResultError(
                "execution pull-request ref is invalid"
            )
    else:
        raise LiveRunnerExtendedResultError("execution.event_name is invalid")
    for key in ("run_attempt", "run_id"):
        if _DIGITS_RE.fullmatch(
            _require_string(execution[key], f"execution.{key}")
        ) is None:
            raise LiveRunnerExtendedResultError(
                f"execution.{key} must be a positive integer"
            )
    if execution["workflow_ref"] != _WORKFLOW_REF_PREFIX + ref:
        raise LiveRunnerExtendedResultError("execution.workflow_ref is invalid")

    source = value["source"]
    _require_keys(source, {"aggregate_sha256", "reviewed_files"}, "source")
    aggregate = _require_string(
        source["aggregate_sha256"], "source.aggregate_sha256"
    )
    if re.fullmatch(r"[0-9a-f]{64}", aggregate) is None:
        raise LiveRunnerExtendedResultError(
            "source.aggregate_sha256 must be lowercase 64-hex"
        )
    files = source["reviewed_files"]
    if not isinstance(files, dict):
        raise LiveRunnerExtendedResultError(
            "source.reviewed_files must be an object"
        )
    if set(files) != set(_SOURCE_PATHS):
        raise LiveRunnerExtendedResultError(
            "source.reviewed_files differs from the reviewed inventory"
        )
    for relative, entry in files.items():
        if not isinstance(entry, dict):
            raise LiveRunnerExtendedResultError(
                f"source.reviewed_files.{relative} must be an object"
            )
        _require_keys(entry, {"sha256", "size"}, f"source.reviewed_files.{relative}")
        digest = _require_string(
            entry["sha256"], f"source.reviewed_files.{relative}.sha256"
        )
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise LiveRunnerExtendedResultError(
                f"source.reviewed_files.{relative}.sha256 must be lowercase 64-hex"
            )
        if _require_nonnegative_int(
            entry["size"], f"source.reviewed_files.{relative}.size"
        ) == 0:
            raise LiveRunnerExtendedResultError(
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
            raise LiveRunnerExtendedResultError(f"suite.{key} must be zero")
    if _require_nonnegative_int(suite["tests"], "suite.tests") != len(_EXPECTED_TESTS):
        raise LiveRunnerExtendedResultError("suite.tests is invalid")
    junit_size = _require_nonnegative_int(suite["junit_size"], "suite.junit_size")
    if junit_size == 0 or junit_size > MAX_JUNIT_BYTES:
        raise LiveRunnerExtendedResultError("suite.junit_size is outside its byte limit")
    junit_digest = _require_string(suite["junit_sha256"], "suite.junit_sha256")
    if re.fullmatch(r"[0-9a-f]{64}", junit_digest) is None:
        raise LiveRunnerExtendedResultError(
            "suite.junit_sha256 must be lowercase 64-hex"
        )
    names = suite["test_names"]
    if not isinstance(names, list) or names != sorted(_EXPECTED_TESTS):
        raise LiveRunnerExtendedResultError(
            "suite.test_names differs from the reviewed oracle set"
        )


def load_result(path: Path) -> dict[str, Any]:
    raw = read_stable_regular_file(
        path,
        label="extended live runner result",
        max_bytes=MAX_RESULT_BYTES,
    )
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_closed_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LiveRunnerExtendedResultError(
            f"result is not strict UTF-8 JSON: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise LiveRunnerExtendedResultError("result root must be an object")
    validate_result(value)
    if raw != _canonical_bytes(value):
        raise LiveRunnerExtendedResultError("result JSON is not canonical")
    return value


def verify_result(result: Mapping[str, Any], junit_path: Path) -> None:
    validate_result(result)
    expected = build_result(junit_path)
    if dict(result) != expected:
        raise LiveRunnerExtendedResultError(
            "result differs from current exact extended evidence"
        )


def write_result(result: Mapping[str, Any], path: Path) -> None:
    validate_result(result)
    write_create_only_bytes(path, _canonical_bytes(result))


__all__ = [
    "LiveRunnerExtendedResultError",
    "build_result",
    "load_result",
    "parse_exact_junit",
    "validate_result",
    "verify_result",
    "write_result",
]
