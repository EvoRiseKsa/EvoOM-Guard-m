# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Protected-harness path policy for the repository verifier.

The functions in this module are deliberately deterministic and side-effect
free.  The legacy names remain re-exported by
:mod:`evoom_guard.verifiers.repo_verifier`.
"""

from __future__ import annotations

import json
import os
import re
from fnmatch import fnmatch

from evoom_guard.contracts import VerdictResult

# Test-file basenames the candidate may not touch.
_PROTECTED_BASENAMES = (
    # Python
    "test_*.py", "*_test.py", "conftest.py",
    # JavaScript / TypeScript colocated test files (vitest / jest pattern).
    "*.test.ts", "*.test.tsx", "*.test.js", "*.test.jsx",
    "*.spec.ts", "*.spec.tsx", "*.spec.js", "*.spec.jsx",
    # Cypress convention, including colocated TypeScript/JavaScript specs.
    "*.cy.*",
    # Go and RSpec convention.
    "*_test.go", "*_spec.rb",
    "*.snap",
)

# Test-runner/build configuration and dependency locks are judge-owned evidence:
# candidates may not touch them, and ``allow`` cannot waive them.
_PROTECTED_CONFIG = (
    ".evoguard.json",
    "pytest.ini", ".pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml",
    "vitest.config.*", "vite.config.*", "jest.config.*", "jest.setup.*",
    ".mocharc.*", "karma.conf.*", "cypress.config.*", "playwright.config.*",
    "ava.config.*", ".nycrc", ".nycrc.*",
    ".rspec",
    "pom.xml",
    "foundry.toml", "echidna.yaml", "slither.config.json",
    "Makefile", "GNUmakefile", "noxfile.py", "Justfile", "Rakefile", "rakefile",
    "pnpm-lock.yaml", "package-lock.json", "yarn.lock",
    "Cargo.lock", "Gemfile.lock", "poetry.lock", "go.sum",
)

# ``strict_harness`` is intentionally a separate, opt-in profile rather than a
# silent expansion of the default protected set.  These project/dependency and
# compiler inputs can change what code a test command resolves, installs, or
# transpiles even when the test file itself is untouched.  The trade-off is
# real: routine dependency/toolchain upgrades must use a trusted maintenance
# lane instead of an untrusted-patch verification lane.
_STRICT_HARNESS_BASENAMES = (
    # Python environment resolvers / installers.
    "requirements*.txt", "constraints*.txt", "pipfile", "pipfile.lock",
    "uv.lock", "pdm.lock", "pixi.lock", "setup.py",
    # JavaScript/TypeScript project and compiler inputs.  In strict mode the
    # complete package manifest is judge-owned; restoring just test scripts is
    # insufficient because dependencies and lifecycle hooks affect execution.
    "package.json", "npm-shrinkwrap.json", "bun.lock", "bun.lockb",
    "pnpm-workspace.yaml", "tsconfig*.json", "babel.config.*", ".babelrc",
    ".babelrc.*", ".swcrc",
    # Native-language project manifests and their dependency resolution.
    "go.mod", "go.work", "cargo.toml", "gemfile", "composer.json",
    "composer.lock", "build.gradle", "build.gradle.kts", "settings.gradle",
    "settings.gradle.kts", "gradle.properties",
)
_STRICT_HARNESS_EXACT_PATHS = (".cargo/config", ".cargo/config.toml")

# Files Python auto-executes in the judge process.
_PROTECTED_AUTOEXEC = ("sitecustomize.py", "usercustomize.py", "*.pth")

# CI definitions that control the gate itself. GitHub permits a local Action at
# the repository root (``uses: ./``) or at an arbitrary checked-in directory,
# so action manifests must be protected even outside ``.github/actions/``.
_PROTECTED_CI_PREFIXES = (".github/workflows/", ".github/actions/")
_PROTECTED_CI_MANIFESTS = ("action.yml", "action.yaml")

# Literal local Action references in a base-owned GitHub workflow.  The narrow
# parser intentionally recognizes only the YAML scalar shapes GitHub accepts
# for a relative local-action reference; candidates never supply this policy.
_LOCAL_ACTION_USES = re.compile(
    r"^\s*(?:-\s*)?uses\s*:\s*(?:[\"'](?P<quoted>\./[^\"']+)[\"']|"
    r"(?P<bare>\./[^\s#]+))\s*(?:#.*)?$",
    re.IGNORECASE,
)

# Directory segments that conventionally contain the complete judge suite.  The
# match is deliberately segment-based: ``testing`` and ``specification`` are
# application directories, while ``__tests__`` and ``spec`` are test roots.
_PROTECTED_TEST_DIR_SEGMENTS = ("tests", "test", "__tests__", "spec")

# Test-like basenames auto-applied to the whole suite.
_AUTOEXEC_TESTLIKE = ("conftest.py",)

# ``package.json`` keys/scripts that configure the JS test harness.
_PKG_RUNNER_KEYS = ("jest", "vitest", "mocha", "ava", "c8", "nyc")


def is_safe_relpath(path: str) -> bool:
    """Is the path safe? Relative, normalized, and unable to escape the repo root."""
    if not path or os.path.isabs(path) or "\\" in path:
        return False
    parts = path.split("/")
    return all(part not in ("", ".", "..") for part in parts)


def is_protected(path: str, extra_globs: tuple[str, ...] = ()) -> bool:
    """Is this one of the files that judge the candidate?"""
    parts = path.split("/")
    directories = tuple(part.lower() for part in parts[:-1])
    if any(part in _PROTECTED_TEST_DIR_SEGMENTS for part in directories):
        return True
    if any(
        first == "cypress" and second == "e2e"
        for first, second in zip(directories, directories[1:], strict=False)
    ):
        return True
    base = parts[-1]
    if any(fnmatch(base.lower(), pattern.lower()) for pattern in _PROTECTED_BASENAMES):
        return True
    return any(fnmatch(path.lower(), glob.lower()) for glob in extra_globs)


def is_strict_harness_manifest(path: str) -> bool:
    """Is ``path`` an opt-in immutable execution-environment input?

    This deliberately matches a conservative cross-language set.  It is
    called only when a trusted policy selected ``strict_harness``; callers must
    not let a candidate-provided allowlist bypass it.
    """
    normalized = path.lower()
    base = normalized.rsplit("/", 1)[-1]
    return (
        normalized in _STRICT_HARNESS_EXACT_PATHS
        or any(
            fnmatch(base, pattern.lower())
            for pattern in _STRICT_HARNESS_BASENAMES
        )
    )


def is_protected_config(path: str, *, strict_harness: bool = False) -> bool:
    """Is this judge-owned config, lock, or strict-profile project manifest?"""
    base = path.split("/")[-1].lower()
    return (
        any(fnmatch(base, pattern.lower()) for pattern in _PROTECTED_CONFIG)
        or (strict_harness and is_strict_harness_manifest(path))
    )


def is_judge_autoexec(path: str) -> bool:
    """Is this a file Python auto-executes inside the judge process?"""
    base = path.split("/")[-1].lower()
    return any(fnmatch(base, pattern.lower()) for pattern in _PROTECTED_AUTOEXEC)


def is_allowlist_exemptible(
    path: str,
    *,
    local_action_dirs: tuple[str, ...] = (),
    strict_harness: bool = False,
) -> bool:
    """May an adopter allowlist exempt this path?

    The answer is deliberately false for every built-in judge-owned path. A
    workflow can be part of a pull-request candidate, so treating its inputs as
    an authority to exempt tests/config/CI would let the candidate rewrite the
    evidence that decides its own verdict. ``allow`` remains available only for
    adopter-defined extra protected globs.
    """
    return not (
        is_protected(path, ())
        or is_protected_config(path, strict_harness=strict_harness)
        or is_protected_ci(path, local_action_dirs=local_action_dirs)
        or is_judge_autoexec(path)
    )


def discover_local_action_dirs(repo_path: str) -> tuple[str, ...]:
    """Return non-root local Action directories used by base workflows.

    A local action can use arbitrary helper files beside its manifest.  Scan
    only the trusted base ``.github/workflows`` files for literal ``uses:
    ./path`` references, require an action manifest at that path, and protect
    that complete non-root directory.  Merely having an ``action.yml`` anywhere
    does not make a directory judge-owned.  A root ``uses: ./`` remains covered
    by its protected manifest only: treating the repository root as a local
    Action directory would forbid every source patch.
    """
    workflow_root = os.path.join(repo_path, ".github", "workflows")
    if not os.path.isdir(workflow_root):
        return ()

    action_dirs: set[str] = set()
    for current, dirs, files in os.walk(workflow_root, followlinks=False):
        # Never recurse through a workflow-directory symlink.  It can escape
        # the repository, and GitHub does not use it as a normal workflow file.
        dirs[:] = [
            name for name in dirs
            if not os.path.islink(os.path.join(current, name))
        ]
        for filename in files:
            if not filename.lower().endswith((".yml", ".yaml")):
                continue
            workflow_path = os.path.join(current, filename)
            try:
                with open(workflow_path, encoding="utf-8") as workflow_file:
                    lines = workflow_file.readlines()
            except OSError:
                continue
            for line in lines:
                match = _LOCAL_ACTION_USES.match(line)
                if match is None:
                    continue
                raw_path = match.group("quoted") or match.group("bare")
                relative = raw_path[2:].strip("/")
                # The root local Action has no safely separable helper directory.
                if not relative or not is_safe_relpath(relative):
                    continue
                action_dir = os.path.join(repo_path, *relative.split("/"))
                if not os.path.isdir(action_dir):
                    continue
                if any(
                    os.path.isfile(os.path.join(action_dir, manifest))
                    for manifest in _PROTECTED_CI_MANIFESTS
                ):
                    action_dirs.add(relative)

    return tuple(sorted(action_dirs, key=str.lower))


def _is_inside_local_action_dir(path: str, local_action_dirs: tuple[str, ...]) -> bool:
    """Does ``path`` belong to a base-owned local Action directory?"""
    normalized = path.lower()
    for directory in local_action_dirs:
        action_dir = directory.strip("/").lower()
        if not action_dir:
            continue
        if normalized == action_dir or normalized.startswith(action_dir + "/"):
            return True
    return False


def is_protected_ci(
    path: str,
    *,
    local_action_dirs: tuple[str, ...] = (),
) -> bool:
    """Is this a CI workflow/local action file that defines how the gate runs?"""
    normalized = path.lower()
    return (
        any(normalized.startswith(prefix) for prefix in _PROTECTED_CI_PREFIXES)
        or normalized in _PROTECTED_CI_MANIFESTS
        or any(normalized.endswith(f"/{name}") for name in _PROTECTED_CI_MANIFESTS)
        or _is_inside_local_action_dir(path, local_action_dirs)
    )


def matches_globs(path: str, globs: tuple[str, ...]) -> bool:
    """Does ``path`` match any of ``globs`` (case-insensitive)?"""
    return any(fnmatch(path.lower(), glob.lower()) for glob in globs)


_matches_globs = matches_globs


def is_addable_new_test(
    path: str,
    extra: tuple[str, ...],
    *,
    is_new: bool,
    local_action_dirs: tuple[str, ...] = (),
    strict_harness: bool = False,
) -> bool:
    """May feature mode allow this net-new, plain test file?"""
    return (
        is_new
        and is_protected(path, ())
        and path.split("/")[-1].lower() not in _AUTOEXEC_TESTLIKE
        and not _matches_globs(path, extra)
        and not is_protected_config(path, strict_harness=strict_harness)
        and not is_judge_autoexec(path)
        and not is_protected_ci(path, local_action_dirs=local_action_dirs)
    )


def _is_judge_script(name: str) -> bool:
    """A ``scripts`` entry that runs/wraps the test suite."""
    return name == "test" or name.startswith("test:") or name in ("pretest", "posttest")


def restore_judge_package_json(original_text: str | None, candidate_text: str) -> str:
    """Return candidate ``package.json`` with test-harness fields restored."""
    try:
        candidate = json.loads(candidate_text)
    except (ValueError, TypeError):
        return candidate_text
    if not isinstance(candidate, dict):
        return candidate_text
    try:
        original = json.loads(original_text) if original_text else {}
    except (ValueError, TypeError):
        original = {}
    if not isinstance(original, dict):
        original = {}

    changed = False
    for key in _PKG_RUNNER_KEYS:
        if key in original:
            if candidate.get(key) != original[key]:
                candidate[key] = original[key]
                changed = True
        elif key in candidate:
            del candidate[key]
            changed = True

    orig_scripts = original.get("scripts")
    orig_scripts = orig_scripts if isinstance(orig_scripts, dict) else {}
    cand_scripts_raw = candidate.get("scripts")
    cand_scripts = dict(cand_scripts_raw) if isinstance(cand_scripts_raw, dict) else {}
    scripts_changed = False
    for name in {
        item
        for item in (set(cand_scripts) | set(orig_scripts))
        if _is_judge_script(item)
    }:
        if name in orig_scripts:
            if cand_scripts.get(name) != orig_scripts[name]:
                cand_scripts[name] = orig_scripts[name]
                scripts_changed = True
        elif name in cand_scripts:
            del cand_scripts[name]
            scripts_changed = True
    if scripts_changed:
        changed = True
        candidate["scripts"] = cand_scripts

    if not changed:
        return candidate_text
    return json.dumps(candidate, indent=2, ensure_ascii=False) + "\n"


def reject_unsafe_or_protected(
    paths: list[str],
    extra: tuple[str, ...],
    *,
    allow_new_tests: bool = False,
    new_paths: frozenset[str] = frozenset(),
    allow: tuple[str, ...] = (),
    local_action_dirs: tuple[str, ...] = (),
    strict_harness: bool = False,
) -> VerdictResult | None:
    """Reject the first unsafe or judge-owned path."""
    for path in paths:
        if not is_safe_relpath(path):
            return VerdictResult(
                passed=False,
                score=0.05,
                diagnostics=f"unsafe path rejected: {path}",
                artifact={"files_changed": []},
            )
        # Check immutable configuration before adopter-defined extra globs:
        # otherwise an ``allow`` pattern could accidentally exempt a strict
        # project manifest that also happens to be listed in ``protected``.
        if is_protected_config(path, strict_harness=strict_harness):
            return VerdictResult(
                passed=False,
                score=0.05,
                diagnostics=(
                    f"modifying the test/build configuration is forbidden: {path} — "
                    "fix the source under test, not the harness that judges it"
                ),
                artifact={"files_changed": []},
            )
        if is_protected(path, extra):
            if allow_new_tests and is_addable_new_test(
                path,
                extra,
                is_new=path in new_paths,
                local_action_dirs=local_action_dirs,
                strict_harness=strict_harness,
            ):
                continue
            if is_allowlist_exemptible(
                path,
                local_action_dirs=local_action_dirs,
                strict_harness=strict_harness,
            ) and _matches_globs(path, allow):
                continue
            return VerdictResult(
                passed=False,
                score=0.05,
                diagnostics=f"modifying the judging tests is forbidden: {path}",
                artifact={"files_changed": []},
            )
        if is_protected_ci(path, local_action_dirs=local_action_dirs):
            return VerdictResult(
                passed=False,
                score=0.05,
                diagnostics=(
                    "modifying the CI workflow / local action that runs the gate is "
                    f"forbidden: {path} — fix the source under test, not the gate "
                    "that judges it"
                ),
                artifact={"files_changed": []},
            )
        if is_judge_autoexec(path):
            return VerdictResult(
                passed=False,
                score=0.05,
                diagnostics=(
                    f"writing an auto-executed judge file is forbidden: {path} — it "
                    "would run code inside the judge process itself (not the program "
                    "under test); fix the source instead"
                ),
                artifact={"files_changed": []},
            )
    return None
