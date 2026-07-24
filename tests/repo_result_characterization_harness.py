"""Pre-extraction characterization harness for repository result projection.

The vector captures the complete public ``VerdictResult`` plus the artifact's
insertion order and present-null key set.  Only elapsed measurements and
workspace-specific paths are normalized.  It intentionally exercises the
existing ``RepoVerifier`` facade rather than duplicating projection logic.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from evoom_guard.verifiers import repo_verifier
from evoom_guard.verifiers.repo_verifier import RepoVerifier

SCHEMA_VERSION = "repo-result-projection-characterization-v1"
CASE_NAMES = (
    "no_pack_completed",
    "pack_command_unavailable",
    "pack_completed",
    "pack_invalid_present_file",
    "pack_missing_path",
)

_APP_EDIT = "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"
_PASS_XML = (
    '<testsuite tests="1" failures="0" errors="0" skipped="0">'
    '<testcase name="pass"/></testsuite>'
)


def _report_path(command: list[str]) -> Path | None:
    for token in command:
        if token.startswith("--junitxml="):
            return Path(token.split("=", 1)[1])
    return None


def _normalize_text(
    value: str,
    *,
    source: Path,
    pack: Path,
    missing_pack: Path,
) -> str:
    normalized = value
    for path, token in (
        (source, "<SOURCE>"),
        (pack, "<PACK>"),
        (missing_pack, "<MISSING_PACK>"),
    ):
        normalized = normalized.replace(str(path), token)
    return normalized


def _normalize_value(
    value: object,
    *,
    source: Path,
    pack: Path,
    missing_pack: Path,
) -> object:
    if isinstance(value, dict):
        return {
            key: _normalize_value(
                item,
                source=source,
                pack=pack,
                missing_pack=missing_pack,
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _normalize_value(
                item,
                source=source,
                pack=pack,
                missing_pack=missing_pack,
            )
            for item in value
        ]
    if isinstance(value, str):
        return _normalize_text(
            value,
            source=source,
            pack=pack,
            missing_pack=missing_pack,
        )
    return value


def capture_case(case_name: str, workspace: Path) -> dict[str, Any]:
    """Capture one reviewed facade outcome with only timing/path normalization."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown characterization case: {case_name}")

    source = workspace / f"source-{case_name}"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    pack = workspace / f"pack-{case_name}"
    missing_pack = workspace / f"missing-pack-{case_name}"
    if case_name == "pack_invalid_present_file":
        pack.write_text("not a directory\n", encoding="utf-8")
    elif case_name != "no_pack_completed":
        pack.mkdir()
        (pack / "test_contract.py").write_text(
            "def test_contract():\n    assert True\n",
            encoding="utf-8",
        )

    calls = 0

    def fake_run(
        command: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if case_name == "pack_command_unavailable" and calls == 2:
            raise FileNotFoundError("controlled verifier-pack command unavailable")
        report = _report_path(command)
        if report is not None:
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(_PASS_XML, encoding="utf-8")
        return subprocess.CompletedProcess(
            command,
            0,
            f"phase:{calls}",
            "",
        )

    problem: dict[str, Any] = {"repo_path": str(source)}
    if case_name == "pack_missing_path":
        problem["verifier_pack"] = str(missing_pack)
    elif case_name != "no_pack_completed":
        problem["verifier_pack"] = str(pack)

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            repo_verifier,
            "_run_bounded_subprocess",
            fake_run,
        )
        result = RepoVerifier(
            test_command=[sys.executable, "-m", "pytest"],
            mem_limit_mb=0,
        ).verify(_APP_EDIT, problem)

    artifact = copy.deepcopy(result.artifact)
    artifact_keys = list(artifact)
    present_null_keys = [
        key for key, value in artifact.items() if value is None
    ]
    if "elapsed" in artifact:
        artifact["elapsed"] = "<ELAPSED>"
    if "runtime_identity_elapsed_ms" in artifact:
        artifact["runtime_identity_elapsed_ms"] = "<RUNTIME_ELAPSED_MS>"
    normalized_artifact = _normalize_value(
        artifact,
        source=source,
        pack=pack,
        missing_pack=missing_pack,
    )
    assert isinstance(normalized_artifact, dict)
    return {
        "passed": result.passed,
        "score": result.score,
        "diagnostics": _normalize_text(
            result.diagnostics,
            source=source,
            pack=pack,
            missing_pack=missing_pack,
        ),
        "artifact_keys": artifact_keys,
        "present_null_keys": present_null_keys,
        "artifact": normalized_artifact,
    }


def capture_all(workspace: Path) -> dict[str, Any]:
    """Capture all cases in a versioned, deterministic envelope."""

    for name in CASE_NAMES:
        (workspace / name).mkdir(parents=True, exist_ok=True)
    return {
        "schema_version": SCHEMA_VERSION,
        "cases": {
            name: capture_case(name, workspace / name)
            for name in CASE_NAMES
        },
    }


def canonical_json(payload: object) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
