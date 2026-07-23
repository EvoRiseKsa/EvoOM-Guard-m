"""Deterministic pre-extraction characterization for candidate preflight.

The harness exercises Guard's public API and projects only the static path
classification contract.  A tiny trusted command is allowed to run for
admitted candidates so the vector also freezes the pre-execution/no-execution
boundary without depending on a repository test framework.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from evoom_guard.guard import guard

SCHEMA_VERSION = "candidate-preflight-characterization-v1"
NORMALIZED_FIELDS: tuple[str, ...] = ()

CASE_NAMES = (
    "adopter_allowlist_exemption",
    "empty_change",
    "local_action_helper",
    "mixed_deletions",
    "new_test_default",
    "new_test_feature_mode",
    "protected_autoexec",
    "protected_existing_test",
    "reserved_pack_namespace",
    "safe_deletion",
    "safe_existing_edit",
    "strict_dependency_manifest",
    "unsafe_parent_path",
)


def _block(path: str, body: str) -> str:
    return f"<<<FILE: {path}>>>\n{body}\n<<<END FILE>>>"


def _make_repo(root: Path) -> None:
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".ci" / "guard").mkdir(parents=True)
    (root / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "src" / "old.py").write_text("OLD = True\n", encoding="utf-8")
    (root / "tests" / "test_base.py").write_text(
        "def test_base():\n    assert True\n",
        encoding="utf-8",
    )
    (root / ".ci" / "guard" / "action.yml").write_text(
        "runs:\n  using: composite\n  steps: []\n",
        encoding="utf-8",
    )
    (root / ".ci" / "guard" / "check.py").write_text(
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    (root / ".github" / "workflows" / "guard.yml").write_text(
        "jobs:\n"
        "  guard:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: ./.ci/guard\n",
        encoding="utf-8",
    )


def _case_spec(case_name: str) -> dict[str, Any]:
    specs: dict[str, dict[str, Any]] = {
        "adopter_allowlist_exemption": {
            "candidate": _block("src/secret.py", "VALUE = 2\n"),
            "protected": ("src/*",),
            "allow": ("src/secret.py",),
        },
        "empty_change": {"candidate": ""},
        "local_action_helper": {
            "candidate": _block(".ci/guard/check.py", "raise SystemExit(1)\n"),
        },
        "mixed_deletions": {
            "candidate": _block("src/app.py", "VALUE = 2\n"),
            "deleted": ("src/old.py", "tests/test_base.py", "../escape.py"),
        },
        "new_test_default": {
            "candidate": _block(
                "tests/test_new.py",
                "def test_new():\n    assert True\n",
            ),
        },
        "new_test_feature_mode": {
            "candidate": _block(
                "tests/test_new.py",
                "def test_new():\n    assert True\n",
            ),
            "allow_new_tests": True,
        },
        "protected_autoexec": {
            "candidate": _block("sitecustomize.py", "raise SystemExit(0)\n"),
        },
        "protected_existing_test": {
            "candidate": _block(
                "tests/test_base.py",
                "def test_base():\n    assert False\n",
            ),
        },
        "reserved_pack_namespace": {
            "candidate": _block(
                "evoguard_verifier_pack/conftest.py",
                "VALUE = 1\n",
            ),
        },
        "safe_deletion": {
            "candidate": _block("src/app.py", "VALUE = 2\n"),
            "deleted": ("src/old.py",),
        },
        "safe_existing_edit": {
            "candidate": _block("src/app.py", "VALUE = 2\n"),
        },
        "strict_dependency_manifest": {
            "candidate": _block("requirements-dev.txt", "pytest==9\n"),
            "strict_harness": True,
        },
        "unsafe_parent_path": {
            "candidate": _block("../escape.py", "VALUE = 1\n"),
        },
    }
    return specs[case_name]


def capture_case(case_name: str, root: Path) -> dict[str, Any]:
    repo = root / case_name
    repo.mkdir(parents=True)
    _make_repo(repo)
    spec = _case_spec(case_name)
    result = guard(
        str(repo),
        spec["candidate"],
        deleted=spec.get("deleted", ()),
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        protected=spec.get("protected", ()),
        allow=spec.get("allow", ()),
        allow_new_tests=spec.get("allow_new_tests", False),
        strict_harness=spec.get("strict_harness", False),
    )
    attestation = result.attestation or {}
    return {
        "files_changed": result.files_changed,
        "protected_violations": result.protected_violations,
        "verdict": result.verdict,
        "reason_code": result.reason_code,
        "test_command_ran": result.test_command_ran,
        "execution_state": result.execution_state,
        "execution_phase": result.execution_phase,
        "deleted_paths": attestation.get("deleted_paths"),
        "deleted_paths_applied": attestation.get("deleted_paths_applied"),
    }


def capture_all(root: Path) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "normalization": list(NORMALIZED_FIELDS),
        "cases": {
            case_name: capture_case(case_name, root)
            for case_name in CASE_NAMES
        },
    }


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
