# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Static, non-executing policy readiness analysis for one Guard command.

The analyzer deliberately never launches the configured test command.  It is
safe to run before an admission attempt and reports only facts that can be
derived from trusted policy, the host tool search path, and a small documented
set of runner behaviours.  Runtime continuity remains fail closed: a warning
from this module never exempts a path from the exact candidate-tree identity.

``doctor`` has a frozen host-environment contract.  This module is kept
independent so a repository-aware ``preflight`` CLI can be added without
changing that contract.
"""

from __future__ import annotations

import ntpath
import os
import shutil
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Literal

from evoom_guard.domain import unsupported_policy_requirements

CheckStatus = Literal["pass", "info", "warning", "error"]

_SHELL_OPERATORS = ("&&", "||", ";", "|", ">", "<", "$(", "`")
_WINDOWS_EXECUTABLE_SUFFIXES = frozenset((".bat", ".cmd", ".com", ".exe"))
_PYTHON_EXECUTABLES = frozenset(("python", "python2", "python3", "py"))
_OPAQUE_SCRIPT_LAUNCHERS = frozenset(("npm", "pnpm", "yarn", "yarnpkg"))
_PROJECT_OUTPUT_RUNNERS = {
    "cargo": "target/",
    "gradle": "build/",
    "gradlew": "build/",
    "mvn": "target/",
    "mvnw": "target/",
}


@dataclass(frozen=True, slots=True)
class PreflightCheck:
    """One deterministic repository-readiness finding."""

    code: str
    status: CheckStatus
    message: str
    remediation: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "status": self.status,
            "message": self.message,
            "remediation": self.remediation,
        }


@dataclass(frozen=True, slots=True)
class PreflightReport:
    """Typed, JSON-ready result of one static preflight analysis."""

    repository: str
    platform: str
    isolation: str
    blackbox: bool
    blackbox_only: bool
    docker_image: str | None
    test_command: tuple[str, ...]
    setup_command: tuple[str, ...] | None
    operating_profile: str | None
    verifier_pack_path: str | None
    expect_verifier_pack_sha256: str | None
    verifier_pack_configured: bool
    repo_suite_enabled: bool
    runtime_continuity_required: bool
    checks: tuple[PreflightCheck, ...]

    @property
    def ready(self) -> bool:
        """Whether no deterministic pre-execution blocker was found."""

        return not any(check.status == "error" for check in self.checks)

    def to_dict(self) -> dict[str, object]:
        counts = {
            status: sum(check.status == status for check in self.checks)
            for status in ("pass", "info", "warning", "error")
        }
        return {
            "schema_version": "evoguard/preflight/v1",
            "repository": self.repository,
            "platform": self.platform,
            "isolation": self.isolation,
            "blackbox": self.blackbox,
            "blackbox_only": self.blackbox_only,
            "docker_image": self.docker_image,
            "test_command": list(self.test_command),
            "setup_command": (
                list(self.setup_command) if self.setup_command is not None else None
            ),
            "operating_profile": self.operating_profile,
            "verifier_pack_path": self.verifier_pack_path,
            "expect_verifier_pack_sha256": self.expect_verifier_pack_sha256,
            "verifier_pack_configured": self.verifier_pack_configured,
            "repo_suite_enabled": self.repo_suite_enabled,
            "runtime_continuity_required": self.runtime_continuity_required,
            "ready": self.ready,
            "summary": counts,
            "checks": [check.to_dict() for check in self.checks],
        }


def normalize_test_command(
    value: str | Sequence[str] | None,
    *,
    default_python: str | None = None,
) -> tuple[str, ...]:
    """Mirror Guard's current trusted-policy command normalization.

    This intentionally preserves the existing whitespace split for plain
    strings.  The analyzer can therefore report quoted strings whose intended
    argv would not survive that compatibility behaviour.  Shell operators keep
    the current explicit ``sh -c`` wrapper.
    """

    if isinstance(value, str):
        if any(operator in value for operator in _SHELL_OPERATORS):
            return ("sh", "-c", value)
        normalized = tuple(value.split())
        if normalized:
            return normalized
    if value is not None:
        normalized = tuple(str(token) for token in value)
        if normalized:
            return normalized
    python = sys.executable if default_python is None else default_python
    return (
        python,
        "-m",
        "pytest",
        "-q",
        "--color=no",
        "-p",
        "no:cacheprovider",
    )


def _executable_name(token: object) -> str:
    name = ntpath.basename(str(token).rstrip("/\\")).casefold()
    stem, suffix = ntpath.splitext(name)
    return stem if suffix in _WINDOWS_EXECUTABLE_SUFFIXES else name


def _is_windows(platform_name: str) -> bool:
    return platform_name.casefold().startswith(("win", "cygwin", "msys"))


def _is_explicit_executable(token: str) -> bool:
    return os.path.isabs(token) or "/" in token or "\\" in token


def _path_is_within(root: str, path: str) -> bool:
    """Return whether one resolved executable is inside the candidate root."""

    try:
        normalized_root = os.path.normcase(os.path.realpath(root))
        normalized_path = os.path.normcase(os.path.realpath(path))
        return os.path.commonpath((normalized_root, normalized_path)) == normalized_root
    except ValueError:
        return False


def _container_image_is_digest_pinned(image: str) -> bool:
    name, separator, digest = image.rpartition("@sha256:")
    return bool(
        name.strip()
        and separator
        and len(digest) == 64
        and all(character in "0123456789abcdefABCDEF" for character in digest)
    )


def _container_image_has_reference_name(image: str) -> bool:
    name, separator, _digest = image.rpartition("@sha256:")
    return bool((name if separator else image).strip())


def _command_after_known_launcher(command: Sequence[str]) -> tuple[str, ...]:
    """Expose a direct runner behind a small set of argv-safe launchers."""

    tokens = tuple(str(token) for token in command)
    if not tokens:
        return ()
    launcher = _executable_name(tokens[0])
    if launcher in {"poetry", "pipenv", "uv"} and len(tokens) >= 3:
        if tokens[1] == "run":
            return tokens[2:]
    if launcher == "bundle" and len(tokens) >= 3 and tokens[1] == "exec":
        return tokens[2:]
    if launcher == "pnpm" and len(tokens) >= 3 and tokens[1] in {"exec", "dlx"}:
        return tokens[2:]
    if launcher == "npm" and len(tokens) >= 3 and tokens[1] in {"exec", "x"}:
        return tokens[2:]
    if launcher in {"npx", "bunx"} and len(tokens) >= 2:
        index = 1
        while index < len(tokens) and tokens[index].startswith("-"):
            # Options such as --package=value are safe to skip. Options whose
            # value is a separate token remain deliberately opaque.
            if "=" not in tokens[index]:
                return tokens
            index += 1
        return tokens[index:]
    return tokens


def _python_option_present(command: Sequence[str], option: str) -> bool:
    """Recognise an exact or combined Python interpreter option."""

    invocation = _parse_python_invocation(command)
    return invocation is not None and option in invocation[0]


def _is_py_launcher_selector(token: str) -> bool:
    """Recognise the version selectors consumed by the Windows ``py`` launcher."""

    if token.startswith("-V:") and len(token) > 3:
        return True
    if not token.startswith("-") or len(token) < 2 or token[1] not in "23":
        return False
    suffix = token[2:]
    return not suffix or all(character.isdigit() or character in ".-" for character in suffix)


def _parse_python_invocation(
    command: Sequence[str],
) -> tuple[frozenset[str], str | None] | None:
    """Parse interpreter flags and return the selected ``-m`` module, if any.

    Only interpreter options are parsed; target-program arguments remain opaque.
    Value-taking ``-X``/``-W`` options and Windows ``py -3.x`` selectors are
    consumed so later isolation/bytecode flags cannot be mistaken for values.
    """

    tokens = _command_after_known_launcher(command)
    if not tokens:
        return None
    executable = _executable_name(tokens[0])
    if executable not in _PYTHON_EXECUTABLES and not executable.startswith("python"):
        return None

    index = 1
    if executable == "py":
        while index < len(tokens) and _is_py_launcher_selector(tokens[index]):
            index += 1

    flags: set[str] = set()
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            break
        if token == "-m":
            module = tokens[index + 1] if index + 1 < len(tokens) else None
            return frozenset(flags), module
        if token == "-c":
            break
        next_index = _consume_python_interpreter_option(tokens, index, flags)
        if next_index is None:
            break
        index = next_index
    return frozenset(flags), None


def _consume_python_interpreter_option(
    tokens: Sequence[str],
    index: int,
    flags: set[str],
) -> int | None:
    """Consume one option before Python's script/module boundary."""

    token = tokens[index]
    if token in {"-X", "-W", "--check-hash-based-pycs"}:
        return index + 2
    if token.startswith(("-X", "-W")) and len(token) > 2:
        return index + 1
    if token.startswith("--check-hash-based-pycs="):
        return index + 1
    no_value_flags = frozenset("bBdEhiIOPqRsSuvVx")
    if token.startswith("-") and not token.startswith("--") and len(token) > 1:
        characters = token[1:]
        if all(character in no_value_flags for character in characters):
            flags.update(f"-{character}" for character in characters)
            return index + 1
    return None


def _invokes_pytest(command: Sequence[str]) -> bool:
    tokens = _command_after_known_launcher(command)
    if not tokens:
        return False
    executable = _executable_name(tokens[0])
    if executable == "pytest":
        return True
    invocation = _parse_python_invocation(tokens)
    return invocation is not None and invocation[1] == "pytest"


def _pytest_cache_disabled(command: Sequence[str]) -> bool:
    tokens = tuple(str(token) for token in command)
    for index, token in enumerate(tokens):
        if token in {"-p", "--plugin"} and index + 1 < len(tokens):
            if tokens[index + 1] == "no:cacheprovider":
                return True
        if token in {"-p=no:cacheprovider", "--plugin=no:cacheprovider"}:
            return True
    return False


def _python_command(command: Sequence[str]) -> tuple[str, ...] | None:
    tokens = _command_after_known_launcher(command)
    if not tokens:
        return None
    executable = _executable_name(tokens[0])
    if executable in _PYTHON_EXECUTABLES or executable.startswith("python"):
        return tokens
    return None


def _runtime_write_checks(command: Sequence[str]) -> list[PreflightCheck]:
    checks: list[PreflightCheck] = []
    effective = _command_after_known_launcher(command)
    executable = _executable_name(effective[0]) if effective else ""
    python_command = _python_command(command)

    if python_command is not None:
        ignores_environment = _python_option_present(
            python_command, "-I"
        ) or _python_option_present(python_command, "-E")
        bytecode_disabled = _python_option_present(python_command, "-B")
        if ignores_environment and not bytecode_disabled:
            checks.append(
                PreflightCheck(
                    code="runtime_write.python_environment_ignored",
                    status="error",
                    message=(
                        "the Python command ignores Guard's "
                        "PYTHONDONTWRITEBYTECODE environment and can create "
                        "__pycache__ inside the exact runtime tree"
                    ),
                    remediation=(
                        "add the explicit -B interpreter option (for example "
                        "`python -I -B ...`) or remove -I/-E when isolation "
                        "policy permits"
                    ),
                )
            )
        else:
            checks.append(
                PreflightCheck(
                    code="runtime_write.python_bytecode",
                    status="pass",
                    message=(
                        "Python bytecode writes are suppressed by -B or by "
                        "Guard's judge environment"
                    ),
                )
            )

    if _invokes_pytest(command):
        if _pytest_cache_disabled(command):
            checks.append(
                PreflightCheck(
                    code="runtime_write.pytest_cache",
                    status="pass",
                    message="the pytest cache provider is explicitly disabled",
                )
            )
        else:
            checks.append(
                PreflightCheck(
                    code="runtime_write.pytest_cache",
                    status="error",
                    message=(
                        "pytest can create .pytest_cache inside the exact "
                        "runtime tree before verifier-pack execution"
                    ),
                    remediation=(
                        "append `-p no:cacheprovider` to the trusted test_command"
                    ),
                )
            )

    if executable in _PROJECT_OUTPUT_RUNNERS:
        output = _PROJECT_OUTPUT_RUNNERS[executable]
        checks.append(
            PreflightCheck(
                code="runtime_write.project_output",
                status="error",
                message=(
                    f"{executable} normally writes {output} inside the project "
                    "tree, which violates exact runtime continuity"
                ),
                remediation=(
                    "redirect build/test outputs to a judge-owned temporary "
                    "directory, or use blackbox-only when the repository suite "
                    "is intentionally not part of the judgment"
                ),
            )
        )

    if executable in {"jest", "vitest"}:
        cache_disabled = any(
            token in {"--no-cache", "--cache=false"}
            for token in effective[1:]
        )
        checks.append(
            PreflightCheck(
                code="runtime_write.javascript_cache",
                status="pass" if cache_disabled else "warning",
                message=(
                    "the JavaScript runner cache is explicitly disabled"
                    if cache_disabled
                    else (
                        f"{executable} may create a project-local cache during "
                        "the repository suite"
                    )
                ),
                remediation=(
                    None
                    if cache_disabled
                    else "disable the runner cache or redirect it outside the candidate tree"
                ),
            )
        )

    top_level = _executable_name(command[0]) if command else ""
    if top_level in _OPAQUE_SCRIPT_LAUNCHERS and effective == tuple(command):
        checks.append(
            PreflightCheck(
                code="runtime_write.opaque_package_script",
                status="warning",
                message=(
                    "the package-manager script hides the concrete runner and "
                    "its project-local output behaviour from static preflight"
                ),
                remediation=(
                    "use an explicit cache-safe runner argv where practical and "
                    "start with the non-required workflow from "
                    "`evo-guard init --preset advisory`"
                ),
            )
        )

    if not checks:
        checks.append(
            PreflightCheck(
                code="runtime_write.unclassified_command",
                status="warning",
                message=(
                    "static preflight has no cache/write model for this test command"
                ),
                remediation=(
                    "use a non-required advisory workflow first and inspect any "
                    "candidate_tree_changed_during_run paths before promotion"
                ),
            )
        )

    checks.append(
        PreflightCheck(
            code="runtime_write.static_scope",
            status="info",
            message=(
                "preflight does not execute candidate code and cannot prove that "
                "tests will make no other persistent writes"
            ),
            remediation=(
                "treat Guard's runtime identity check as authoritative; preflight "
                "findings never weaken fail-closed tamper detection"
            ),
        )
    )
    return checks


def _policy_checks(
    *,
    isolation: str,
    blackbox: bool,
    blackbox_only: bool,
    docker_image: str | None,
    verifier_pack_configured: bool,
    setup_command_present: bool,
    trust_setup_on_host: bool,
    require_demonstrated_fix: bool,
    min_diff_coverage: float | None,
    strict_harness: bool,
    operating_profile: str | None,
    profile_violations: Sequence[str],
    windows: bool,
) -> list[PreflightCheck]:
    checks: list[PreflightCheck] = []
    for requirement in unsupported_policy_requirements(
        require_demonstrated_fix=require_demonstrated_fix,
        min_diff_coverage=min_diff_coverage,
        blackbox=blackbox,
        isolation=isolation,
        setup_command_present=setup_command_present,
    ):
        mode = "the black-box judge" if blackbox else f"isolation {isolation!r}"
        checks.append(
            PreflightCheck(
                code="policy.requirement_unsupported",
                status="error",
                message=(
                    f"policy requirement {requirement!r} cannot be enforced under {mode}"
                ),
                remediation="select a compatible judge path or remove the requirement",
            )
        )
    for violation in profile_violations:
        checks.append(
            PreflightCheck(
                code="policy.operating_profile_violation",
                status="error",
                message=(
                    f"operating profile {operating_profile!r} is not satisfied: "
                    f"{violation}"
                ),
                remediation="restore the complete reviewed operating-profile policy",
            )
        )
    if blackbox_only and not blackbox:
        checks.append(
            PreflightCheck(
                code="policy.blackbox_only_requires_blackbox",
                status="error",
                message="blackbox_only requires blackbox=true",
                remediation="enable blackbox or disable blackbox_only",
            )
        )
    if blackbox and not verifier_pack_configured:
        checks.append(
            PreflightCheck(
                code="policy.blackbox_requires_verifier_pack",
                status="error",
                message="blackbox mode requires a verifier pack",
                remediation="configure a digest-pinned verifier_pack",
            )
        )
    if blackbox and windows:
        checks.append(
            PreflightCheck(
                code="policy.blackbox_posix_host_required",
                status="error",
                message=(
                    "black-box candidate launching currently requires a POSIX host"
                ),
                remediation="use GitHub Actions/Linux or WSL on Windows",
            )
        )
    if isolation in {"docker", "gvisor"}:
        checks.extend(_container_policy_checks(isolation, docker_image))
    host_strict_harness = isolation == "subprocess" or (
        setup_command_present and trust_setup_on_host
    )
    if strict_harness and windows and host_strict_harness:
        checks.append(
            PreflightCheck(
                code="policy.strict_harness_process_group_unavailable",
                status="error",
                message=(
                    "strict_harness requires POSIX process-group cleanup proof for "
                    "host execution, which this Windows host cannot provide"
                ),
                remediation=(
                    "use container-isolated execution without host setup, or run the "
                    "strict harness on a POSIX judge"
                ),
            )
        )
    return checks


def _container_policy_checks(
    isolation: str,
    docker_image: str | None,
) -> list[PreflightCheck]:
    if not docker_image:
        return [
            PreflightCheck(
                code="policy.container_requires_image",
                status="error",
                message=f"{isolation} isolation requires a configured container image",
                remediation="configure docker_image before requesting container isolation",
            )
        ]
    checks = [
        PreflightCheck(
            code="policy.container_image_configured",
            status="pass",
            message="container isolation has a configured image reference",
        )
    ]
    if not _container_image_has_reference_name(docker_image):
        checks.append(
            PreflightCheck(
                code="policy.container_image_invalid_reference",
                status="error",
                message="container image reference has no image name",
                remediation="use <registry>/<image>@sha256:<64-hex-digest>",
            )
        )
        return checks
    if not _container_image_is_digest_pinned(docker_image):
        checks.append(
            PreflightCheck(
                code="policy.container_image_mutable_reference",
                status="warning",
                message=(
                    "Guard resolves the image to an immutable ID for each run, "
                    "but this configured reference may drift between runs"
                ),
                remediation=(
                    "prefer an image reference ending in @sha256:<64-hex-digest> "
                    "for reproducible policy"
                ),
            )
        )
    return checks


def _raw_command_checks(raw_command: str | Sequence[str] | None) -> list[PreflightCheck]:
    if not isinstance(raw_command, str):
        return []
    checks: list[PreflightCheck] = []
    has_quotes = any(character in raw_command for character in ("'", '"'))
    has_shell_operator = any(operator in raw_command for operator in _SHELL_OPERATORS)
    if has_quotes and not has_shell_operator:
        checks.append(
            PreflightCheck(
                code="test_command.lossy_string_split",
                status="warning",
                message=(
                    "a quoted string test_command is normalized by whitespace, "
                    "so quoting is not preserved"
                ),
                remediation=(
                    "store test_command as a JSON string array so each argv token "
                    "is explicit"
                ),
            )
        )
    if has_shell_operator:
        checks.append(
            PreflightCheck(
                code="test_command.shell_dependency",
                status="warning",
                message="shell operators require the configured command to run through `sh -c`",
                remediation=(
                    "prefer a shell-free argv or ensure the selected judge image/host "
                    "intentionally supplies POSIX sh"
                ),
            )
        )
    return checks


def _platform_launcher_checks(executable: str, *, windows: bool) -> list[PreflightCheck]:
    name = _executable_name(executable)
    checks: list[PreflightCheck] = []
    if name == "py" and not windows:
        checks.append(
            PreflightCheck(
                code="test_command.platform_launcher",
                status="error",
                message="the `py` launcher is Windows-specific",
                remediation="use `python`/`python3` or an image-local interpreter",
            )
        )
    if name in {"cmd", "cmd.exe", "powershell"} and not windows:
        checks.append(
            PreflightCheck(
                code="test_command.platform_launcher",
                status="error",
                message=f"{name} is not portable to this platform",
                remediation="use a shell-free cross-platform argv",
            )
        )
    if name == "sh" and windows:
        checks.append(
            PreflightCheck(
                code="test_command.platform_launcher",
                status="warning",
                message="POSIX sh is not supplied by standard Windows installations",
                remediation="use a list-form shell-free command on Windows",
            )
        )
    return checks


def _candidate_executable_check(
    *,
    code: str,
    repository: str,
    configured: str,
    resolved: str | None,
) -> PreflightCheck | None:
    candidate_controlled = (
        _is_explicit_executable(configured) and not os.path.isabs(configured)
    ) or (resolved is not None and _path_is_within(repository, resolved))
    if not candidate_controlled:
        return None
    return PreflightCheck(
        code=code,
        status="warning",
        message="the executable resolves from inside the repository candidate tree",
        remediation=(
            "use an absolute trusted launcher outside the candidate tree or remove "
            "repository-relative PATH entries"
        ),
    )


def _host_command_checks(
    *,
    repository: str,
    executable: str,
    locate: Callable[[str], str | None],
    code_prefix: str,
) -> list[PreflightCheck]:
    resolved = locate(executable)
    checks: list[PreflightCheck] = []
    candidate_check = _candidate_executable_check(
        code=f"{code_prefix}.candidate_relative_executable",
        repository=repository,
        configured=executable,
        resolved=resolved,
    )
    if candidate_check is not None:
        checks.append(candidate_check)
    checks.append(
        PreflightCheck(
            code=f"{code_prefix}.executable_available",
            status="pass" if resolved else "error",
            message=(
                f"{code_prefix.replace('_', ' ')} executable resolved to {resolved}"
                if resolved
                else f"{code_prefix.replace('_', ' ')} executable is unavailable: {executable}"
            ),
            remediation=(
                None
                if resolved
                else "install the trusted runner or select a container image that supplies it"
            ),
        )
    )
    return checks


def _container_command_checks(
    *,
    repository: str,
    executable: str,
    locate: Callable[[str], str | None],
) -> list[PreflightCheck]:
    docker = locate("docker")
    checks: list[PreflightCheck] = []
    candidate_check = _candidate_executable_check(
        code="container_runtime.candidate_relative_executable",
        repository=repository,
        configured="docker",
        resolved=docker,
    )
    if candidate_check is not None:
        checks.append(candidate_check)
    checks.extend(
        (
            PreflightCheck(
                code="container_runtime.available",
                status="pass" if docker else "error",
                message=(
                    f"container client resolved to {docker}"
                    if docker
                    else "docker client is unavailable for the requested isolation"
                ),
                remediation=(
                    None
                    if docker
                    else "install Docker and make its trusted client available on PATH"
                ),
            ),
            PreflightCheck(
                code="test_command.container_executable",
                status="info",
                message=(
                    f"availability of {executable!r} inside the selected image cannot "
                    "be proven without starting the container"
                ),
                remediation="pin an image that contains the configured runner/interpreter",
            ),
        )
    )
    return checks


def _setup_command_checks(
    *,
    repository: str,
    setup_command: tuple[str, ...] | None,
    isolation: str,
    trust_setup_on_host: bool,
    locate: Callable[[str], str | None],
) -> list[PreflightCheck]:
    if not setup_command:
        return []
    executable = setup_command[0]
    if isolation == "subprocess" or trust_setup_on_host:
        return _host_command_checks(
            repository=repository,
            executable=executable,
            locate=locate,
            code_prefix="setup_command",
        )
    return [
        PreflightCheck(
            code="setup_command.container_executable",
            status="info",
            message=(
                f"availability of setup executable {executable!r} inside the "
                "selected image cannot be proven without starting it"
            ),
            remediation="pin an image that contains the configured setup runner",
        )
    ]


def _runtime_continuity_checks(
    *,
    command: tuple[str, ...],
    isolation: str,
    blackbox_only: bool,
    verifier_pack_configured: bool,
) -> list[PreflightCheck]:
    required = verifier_pack_configured and not blackbox_only
    if required and command and isolation == "subprocess":
        return _runtime_write_checks(command)
    if required and command:
        return [
            PreflightCheck(
                code="runtime_write.read_only_container",
                status="pass",
                message=(
                    "container suite and verifier-pack phases mount the candidate "
                    "tree read-only, preventing persistent runtime-tree writes"
                ),
            )
        ]
    reason = (
        "blackbox-only skips the repository suite"
        if blackbox_only
        else "no verifier pack requires exact suite-to-pack runtime continuity"
    )
    return [
        PreflightCheck(
            code="runtime_write.continuity_not_required",
            status="pass",
            message=reason,
        )
    ]


def analyze_preflight(
    *,
    repository: str,
    command: Sequence[str],
    raw_command: str | Sequence[str] | None = None,
    isolation: str = "subprocess",
    blackbox: bool = False,
    docker_image: str | None = None,
    verifier_pack_path: str | None = None,
    expect_verifier_pack_sha256: str | None = None,
    verifier_pack_configured: bool = False,
    blackbox_only: bool = False,
    setup_command: Sequence[str] | None = None,
    trust_setup_on_host: bool = False,
    require_demonstrated_fix: bool = False,
    min_diff_coverage: float | None = None,
    strict_harness: bool = False,
    operating_profile: str | None = None,
    profile_violations: Sequence[str] = (),
    platform_name: str | None = None,
    blackbox_launcher_env_executable: str = "/usr/bin/env",
    blackbox_launcher_python_executable: str = "python3",
    which: Callable[[str], str | None] | None = None,
    is_directory: Callable[[str], bool] | None = None,
) -> PreflightReport:
    """Analyze one already-resolved Guard policy without running candidate code.

    Effects are injectable so callers can apply the same trusted PATH policy as
    execution and tests can characterize every branch without touching the real
    host.  ``raw_command`` should be the original config/CLI value when available;
    it is used only to diagnose lossy string normalization.
    """

    active_platform = sys.platform if platform_name is None else platform_name
    locate = shutil.which if which is None else which
    directory_exists = os.path.isdir if is_directory is None else is_directory
    repository_available = directory_exists(repository)
    normalized = tuple(str(token) for token in command)
    normalized_setup = (
        tuple(str(token) for token in setup_command) if setup_command is not None else None
    )
    windows = _is_windows(active_platform)
    checks = _policy_checks(
        isolation=isolation,
        blackbox=blackbox,
        blackbox_only=blackbox_only,
        docker_image=docker_image,
        verifier_pack_configured=verifier_pack_configured,
        setup_command_present=bool(normalized_setup),
        trust_setup_on_host=trust_setup_on_host,
        require_demonstrated_fix=require_demonstrated_fix,
        min_diff_coverage=min_diff_coverage,
        strict_harness=strict_harness,
        operating_profile=operating_profile,
        profile_violations=profile_violations,
        windows=windows,
    )
    checks.append(
        PreflightCheck(
            code="repository.available",
            status="pass" if repository_available else "error",
            message=(
                "repository root is an available directory"
                if repository_available
                else f"repository root is not an available directory: {repository}"
            ),
            remediation=(
                None
                if repository_available
                else "select an existing trusted base repository"
            ),
        )
    )
    repo_suite_enabled = not blackbox_only
    if repo_suite_enabled:
        checks.append(
            PreflightCheck(
                code="test_command.nonempty",
                status="pass" if normalized else "error",
                message=(
                    "the effective test command is non-empty"
                    if normalized
                    else "the effective test command is empty"
                ),
                remediation=(
                    None if normalized else "configure a non-empty argv test_command"
                ),
            )
        )
        checks.extend(_raw_command_checks(raw_command))
        if normalized:
            executable = normalized[0]
            if isolation == "subprocess":
                checks.extend(_platform_launcher_checks(executable, windows=windows))
                checks.extend(
                    _host_command_checks(
                        repository=repository,
                        executable=executable,
                        locate=locate,
                        code_prefix="test_command",
                    )
                )
            else:
                checks.extend(
                    _container_command_checks(
                        repository=repository,
                        executable=executable,
                        locate=locate,
                    )
                )
    else:
        checks.append(
            PreflightCheck(
                code="test_command.not_used_blackbox_only",
                status="info",
                message=(
                    "blackbox-only skips the repository suite, so its test_command "
                    "is not analyzed"
                ),
            )
        )
    if blackbox and not windows:
        for executable, code_prefix in (
            (blackbox_launcher_env_executable, "blackbox_launcher_env"),
            (blackbox_launcher_python_executable, "blackbox_launcher_python"),
        ):
            checks.extend(
                _host_command_checks(
                    repository=repository,
                    executable=executable,
                    locate=locate,
                    code_prefix=code_prefix,
                )
            )
    checks.extend(
        _setup_command_checks(
            repository=repository,
            setup_command=normalized_setup,
            isolation=isolation,
            trust_setup_on_host=trust_setup_on_host,
            locate=locate,
        )
    )
    runtime_continuity_required = verifier_pack_configured and repo_suite_enabled
    checks.extend(
        _runtime_continuity_checks(
            command=normalized,
            isolation=isolation,
            blackbox_only=blackbox_only,
            verifier_pack_configured=verifier_pack_configured,
        )
    )

    return PreflightReport(
        repository=repository,
        platform=active_platform,
        isolation=isolation,
        blackbox=blackbox,
        blackbox_only=blackbox_only,
        docker_image=docker_image,
        test_command=normalized,
        setup_command=normalized_setup,
        operating_profile=operating_profile,
        verifier_pack_path=verifier_pack_path,
        expect_verifier_pack_sha256=expect_verifier_pack_sha256,
        verifier_pack_configured=verifier_pack_configured,
        repo_suite_enabled=repo_suite_enabled,
        runtime_continuity_required=runtime_continuity_required,
        checks=tuple(checks),
    )


__all__ = [
    "PreflightCheck",
    "PreflightReport",
    "analyze_preflight",
    "normalize_test_command",
]
