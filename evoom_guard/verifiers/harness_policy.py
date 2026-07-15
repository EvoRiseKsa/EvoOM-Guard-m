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
from fnmatch import fnmatch

from evoom_guard.contracts import VerdictResult

# Test-file basenames the candidate may not touch.
_PROTECTED_BASENAMES = (
    # Python
    "test_*.py", "*_test.py", "conftest.py",
    # JavaScript / TypeScript colocated test files (vitest / jest pattern).
    "*.test.ts", "*.test.tsx", "*.test.js", "*.test.jsx",
    "*.spec.ts", "*.spec.tsx", "*.spec.js", "*.spec.jsx",
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

# Files Python auto-executes in the judge process.
_PROTECTED_AUTOEXEC = ("sitecustomize.py", "usercustomize.py", "*.pth")

# CI definitions that control the gate itself. GitHub permits a local Action at
# the repository root (``uses: ./``) or at an arbitrary checked-in directory,
# so action manifests must be protected even outside ``.github/actions/``.
_PROTECTED_CI_PREFIXES = (".github/workflows/", ".github/actions/")
_PROTECTED_CI_MANIFESTS = ("action.yml", "action.yaml")

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
    if any(part.lower() in ("tests", "test") for part in parts[:-1]):
        return True
    base = parts[-1]
    if any(fnmatch(base.lower(), pattern.lower()) for pattern in _PROTECTED_BASENAMES):
        return True
    return any(fnmatch(path.lower(), glob.lower()) for glob in extra_globs)


def is_protected_config(path: str) -> bool:
    """Is this test-runner/build config or dependency lock protected?"""
    base = path.split("/")[-1].lower()
    return any(fnmatch(base, pattern.lower()) for pattern in _PROTECTED_CONFIG)


def is_judge_autoexec(path: str) -> bool:
    """Is this a file Python auto-executes inside the judge process?"""
    base = path.split("/")[-1].lower()
    return any(fnmatch(base, pattern.lower()) for pattern in _PROTECTED_AUTOEXEC)


def is_allowlist_exemptible(path: str) -> bool:
    """May an adopter allowlist exempt this path?

    The answer is deliberately false for every built-in judge-owned path. A
    workflow can be part of a pull-request candidate, so treating its inputs as
    an authority to exempt tests/config/CI would let the candidate rewrite the
    evidence that decides its own verdict. ``allow`` remains available only for
    adopter-defined extra protected globs.
    """
    return not (
        is_protected(path, ())
        or is_protected_config(path)
        or is_protected_ci(path)
        or is_judge_autoexec(path)
    )


def is_protected_ci(path: str) -> bool:
    """Is this a CI workflow/local action file that defines how the gate runs?"""
    normalized = path.lower()
    return (
        any(normalized.startswith(prefix) for prefix in _PROTECTED_CI_PREFIXES)
        or normalized in _PROTECTED_CI_MANIFESTS
        or any(normalized.endswith(f"/{name}") for name in _PROTECTED_CI_MANIFESTS)
    )


def _matches_globs(path: str, globs: tuple[str, ...]) -> bool:
    """Does ``path`` match any of ``globs`` (case-insensitive)?"""
    return any(fnmatch(path.lower(), glob.lower()) for glob in globs)


def is_addable_new_test(path: str, extra: tuple[str, ...], *, is_new: bool) -> bool:
    """May feature mode allow this net-new, plain test file?"""
    return (
        is_new
        and is_protected(path, ())
        and path.split("/")[-1].lower() not in _AUTOEXEC_TESTLIKE
        and not _matches_globs(path, extra)
        and not is_protected_config(path)
        and not is_judge_autoexec(path)
        and not is_protected_ci(path)
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
        if is_protected(path, extra):
            if allow_new_tests and is_addable_new_test(
                path, extra, is_new=path in new_paths
            ):
                continue
            if is_allowlist_exemptible(path) and _matches_globs(path, allow):
                continue
            return VerdictResult(
                passed=False,
                score=0.05,
                diagnostics=f"modifying the judging tests is forbidden: {path}",
                artifact={"files_changed": []},
            )
        if is_protected_config(path):
            return VerdictResult(
                passed=False,
                score=0.05,
                diagnostics=(
                    f"modifying the test/build configuration is forbidden: {path} — "
                    "fix the source under test, not the harness that judges it"
                ),
                artifact={"files_changed": []},
            )
        if is_protected_ci(path):
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
