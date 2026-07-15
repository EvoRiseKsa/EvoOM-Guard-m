# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Characterize the legacy ``repo_verifier`` import surface.

The implementation may be split into focused modules, but existing in-package
consumers and tests still import these names from ``repo_verifier``.  These tests
pin that compatibility seam without requiring each implementation to remain in
the original file.
"""

from __future__ import annotations

import inspect
import subprocess
import sys
from unittest.mock import Mock

import evoom_guard.verifiers as verifiers
import evoom_guard.verifiers.candidate_edits as candidate_edits
import evoom_guard.verifiers.diagnostics as diagnostics
import evoom_guard.verifiers.fidelity as fidelity
import evoom_guard.verifiers.harness_policy as harness_policy
import evoom_guard.verifiers.junit_oracle as junit_oracle
import evoom_guard.verifiers.repo_verifier as repo_verifier

# Union of the names imported by guard.py, blackbox.py, evidence.py, the
# verifiers package, and the test suite.  Private helpers are included only when
# a current runtime consumer imports them directly.
IMPORTED_SURFACE = {
    "COPY_IGNORE",
    "RepoVerifier",
    "SetupFidelityError",
    "_matches_globs",
    "_resolve_host_command",
    "_setup_fidelity_changes",
    "_setup_fidelity_snapshot",
    "apply_blocks_to_copy",
    "copy_repo_tree",
    "detect_tamper",
    "distill_diagnostics",
    "grade_repo_run",
    "is_addable_new_test",
    "is_judge_autoexec",
    "is_protected",
    "is_protected_ci",
    "is_protected_config",
    "is_safe_relpath",
    "judge_subprocess_env",
    "parse_blocks_lenient",
    "parse_file_blocks",
    "parse_junit_dir",
    "parse_junit_xml",
    "parse_patch_blocks",
    "parse_pytest_counts",
    "reject_unsafe_or_protected",
    "restore_judge_package_json",
}

# Tests address these attributes through the module rather than importing them.
MODULE_ATTRIBUTE_SURFACE = {"_docker_container_name", "verify_pack_snapshot"}


def test_current_import_surface_remains_available() -> None:
    required = IMPORTED_SURFACE | MODULE_ATTRIBUTE_SURFACE
    missing = sorted(name for name in required if not hasattr(repo_verifier, name))
    assert not missing, f"repo_verifier compatibility exports disappeared: {missing}"

    assert inspect.isclass(repo_verifier.RepoVerifier)
    assert issubclass(repo_verifier.SetupFidelityError, RuntimeError)
    assert isinstance(repo_verifier.COPY_IGNORE, tuple)
    assert verifiers.RepoVerifier is repo_verifier.RepoVerifier


def test_split_helpers_are_legacy_reexports() -> None:
    module_names = {
        candidate_edits: (
            "PatchBlock",
            "parse_blocks_lenient",
            "parse_file_blocks",
            "parse_patch_blocks",
        ),
        diagnostics: ("distill_diagnostics",),
        fidelity: (
            "_DEFAULT_SETUP_OUTPUT_DIRS",
            "SetupFidelityError",
            "_is_default_setup_output",
            "_fidelity_entry_state",
            "_setup_fidelity_snapshot",
            "_setup_fidelity_changes",
        ),
        harness_policy: (
            "_matches_globs",
            "is_addable_new_test",
            "is_allowlist_exemptible",
            "is_judge_autoexec",
            "is_protected",
            "is_protected_ci",
            "is_protected_config",
            "is_safe_relpath",
            "reject_unsafe_or_protected",
            "restore_judge_package_json",
        ),
        junit_oracle: (
            "JUnitCounts",
            "detect_tamper",
            "grade_repo_run",
            "parse_junit_dir",
            "parse_junit_xml",
            "parse_pytest_counts",
        ),
    }
    for module, names in module_names.items():
        for name in names:
            assert getattr(repo_verifier, name) is getattr(module, name)


def test_fidelity_import_order_has_no_cycle() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import evoom_guard.verifiers.fidelity; "
                "import evoom_guard.verifiers.repo_verifier; "
                "import evoom_guard.guard"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr


def test_important_call_shapes_remain_compatible() -> None:
    """Bind representative current calls while allowing new optional parameters."""

    calls = {
        "RepoVerifier": ((), {"timeout": 30, "isolation": "subprocess"}),
        "_matches_globs": (("src/app.py", ("src/*",)), {}),
        "_setup_fidelity_changes": (({}, {}), {}),
        "_setup_fidelity_snapshot": (("repo", ()), {"baseline": None}),
        "apply_blocks_to_copy": (("repo", {}, []), {}),
        "copy_repo_tree": (("source", "destination"), {}),
        "detect_tamper": ((0, None), {"report_expected": False}),
        "distill_diagnostics": (("output",), {"max_chars": 100}),
        "grade_repo_run": ((0, None), {"report_expected": False}),
        "is_addable_new_test": (("tests/test_x.py", ()), {"is_new": True}),
        "is_protected": (("src/app.py", ()), {}),
        "judge_subprocess_env": (("workdir",), {}),
        "parse_blocks_lenient": (("candidate",), {"default_path": None}),
        "parse_junit_dir": (("reports",), {}),
        "reject_unsafe_or_protected": ((["src/app.py"], ()), {"allow": ()}),
        "restore_judge_package_json": ((None, "{}"), {}),
        "verify_pack_snapshot": (("snapshot", ("digest", None)), {}),
    }

    for name, (args, kwargs) in calls.items():
        inspect.signature(getattr(repo_verifier, name)).bind(*args, **kwargs)


def test_windows_host_command_resolves_pathex_shim(monkeypatch) -> None:
    concrete = r"C:\tools\node_modules\.bin\vitest.CMD"
    isfile = Mock(side_effect=lambda path: path == concrete)
    monkeypatch.setattr(repo_verifier.os.path, "isfile", isfile)

    resolved = repo_verifier._resolve_host_command(
        ["vitest", "run"],
        cwd=r"C:\candidate",
        env={"PATH": r"C:\tools\node_modules\.bin", "PATHEXT": ".CMD;.EXE"},
        platform="nt",
    )

    assert resolved == [concrete, "run"]
    assert concrete in {call.args[0] for call in isfile.call_args_list}


def test_windows_host_command_does_not_search_relative_path_entries(monkeypatch) -> None:
    checked: list[str] = []

    def record_candidate(path: str) -> bool:
        checked.append(path)
        return False

    monkeypatch.setattr(repo_verifier.os.path, "isfile", record_candidate)

    resolved = repo_verifier._resolve_host_command(
        ["python", "-m", "pytest"],
        cwd=r"C:\candidate",
        env={
            "PATH": r".;candidate-tools;C:\trusted-tools",
            "PATHEXT": ".CMD;.EXE",
        },
        platform="nt",
    )

    assert resolved == ["python", "-m", "pytest"]
    assert checked
    assert all(path.startswith("C:\\trusted-tools\\") for path in checked)


def test_non_windows_host_command_keeps_token_and_skips_resolution(monkeypatch) -> None:
    isfile = Mock(side_effect=AssertionError("POSIX commands must not be rewritten"))
    monkeypatch.setattr(repo_verifier.os.path, "isfile", isfile)

    assert repo_verifier._resolve_host_command(
        ["vitest", "run"], platform="posix"
    ) == ["vitest", "run"]
    isfile.assert_not_called()


def test_lightweight_parsers_and_graders_keep_their_behavior() -> None:
    assert repo_verifier.parse_file_blocks("plain text") == {}
    assert repo_verifier.parse_patch_blocks("plain text") == []
    assert repo_verifier.parse_pytest_counts("2 passed, 1 failed in 0.1s") == (2, 3)
    assert repo_verifier.is_safe_relpath("src/app.py")
    assert not repo_verifier.is_safe_relpath("../outside.py")

    junit = repo_verifier.parse_junit_xml(
        '<testsuite tests="1" failures="0" errors="0" skipped="0">'
        '<testcase name="ok"/></testsuite>'
    )
    assert junit is not None
    assert (junit.passed, junit.total, junit.failures, junit.errors) == (1, 1, 0, 0)
    assert repo_verifier.grade_repo_run(0, junit, report_expected=True) == (True, 1.0, 1, 1)
    assert not repo_verifier.detect_tamper(0, junit, report_expected=True)


def test_fidelity_baseline_controls_new_default_outputs(tmp_path) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    before = fidelity._setup_fidelity_snapshot(str(tmp_path))

    generated = tmp_path / "node_modules" / "pkg"
    generated.mkdir(parents=True)
    (generated / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")

    unfiltered = fidelity._setup_fidelity_snapshot(str(tmp_path), baseline=None)
    filtered = fidelity._setup_fidelity_snapshot(str(tmp_path), baseline=before)
    filtered_from_empty = fidelity._setup_fidelity_snapshot(str(tmp_path), baseline={})

    assert "node_modules/pkg/index.js" in unfiltered
    assert all(not path.startswith("node_modules") for path in filtered)
    assert all(not path.startswith("node_modules") for path in filtered_from_empty)
    assert filtered["app.py"] == before["app.py"]


def test_fidelity_binds_preexisting_default_output_content(tmp_path) -> None:
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    tracked = vendor / "tracked.py"
    tracked.write_text("SAFE = True\n", encoding="utf-8")
    before = fidelity._setup_fidelity_snapshot(str(tmp_path))

    tracked.write_text("SAFE = False\n", encoding="utf-8")
    after = fidelity._setup_fidelity_snapshot(str(tmp_path), baseline=before)

    assert fidelity._setup_fidelity_changes(before, after) == ["vendor/tracked.py"]


def test_fidelity_changes_are_sorted() -> None:
    state = ("file", 0o644, "digest")
    assert fidelity._setup_fidelity_changes(
        {"z.py": state, "a.py": state},
        {"m.py": state},
    ) == ["a.py", "m.py", "z.py"]
