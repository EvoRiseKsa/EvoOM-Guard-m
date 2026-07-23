# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Compatibility and integration gates for the typed Guard request."""

from __future__ import annotations

import importlib
import os
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import evoom_guard.domain as domain
from evoom_guard.domain.request import (
    CandidateInput,
    GuardRequest,
    RepositoryInput,
    SourceIdentity,
)
from evoom_guard.policy import build_effective_policy, effective_policy_payload


def _policy() -> domain.EffectivePolicy:
    return build_effective_policy(
        mode="repo",
        isolation="subprocess",
        docker_image=None,
        docker_network="none",
        test_command=None,
        setup_command=None,
        trust_setup_on_host=False,
        setup_output_globs=(),
        protected=(),
        allow=(),
        allow_new_tests=False,
        timeout=120,
        mem_limit_mb=1024,
        verifier_pack=None,
        expect_verifier_pack_sha256=None,
        blackbox=False,
        blackbox_only=False,
        require_report_integrity=None,
        require_candidate_isolation=None,
        min_diff_coverage=None,
        baseline_evidence=False,
        require_demonstrated_fix=False,
        strict_harness=False,
        policy_id=None,
        policy_version=None,
    )


def _capture_requests(
    monkeypatch: pytest.MonkeyPatch,
    guard_module: object,
) -> list[GuardRequest]:
    captured: list[GuardRequest] = []

    def capture_request(**values: object) -> GuardRequest:
        request = GuardRequest(**values)  # type: ignore[arg-type]
        captured.append(request)
        return request

    monkeypatch.setattr(guard_module, "GuardRequest", capture_request)
    return captured


def test_domain_public_api_reexports_exact_request_types() -> None:
    assert domain.RepositoryInput is RepositoryInput
    assert domain.CandidateInput is CandidateInput
    assert domain.SourceIdentity is SourceIdentity
    assert domain.GuardRequest is GuardRequest


def test_guard_request_is_a_frozen_typed_composition() -> None:
    file_blocks = {"app.py": "x = 1\n"}
    deleted_paths = ["old.py"]
    request = GuardRequest(
        repository=RepositoryInput(path="/trusted/base"),
        candidate=CandidateInput(
            text="candidate",
            deleted_paths=deleted_paths,  # type: ignore[arg-type]
            file_blocks=file_blocks,
        ),
        source=SourceIdentity(
            base_sha="a" * 40,
            head_sha="b" * 40,
            base_tree_sha="c" * 40,
            head_tree_sha="d" * 40,
        ),
        policy=_policy(),
        verifier_pack_path="packs/core",
        collect_diff_coverage=True,
    )

    assert request.repository.path == "/trusted/base"
    assert request.candidate.file_blocks == file_blocks
    assert request.candidate.file_blocks is not file_blocks
    file_blocks["app.py"] = "externally mutated\n"
    deleted_paths.append("late.py")
    assert request.candidate.file_blocks == {"app.py": "x = 1\n"}
    assert request.candidate.deleted_paths == ("old.py",)
    assert request.candidate.file_blocks is not None
    with pytest.raises(TypeError):
        request.candidate.file_blocks["late.py"] = "blocked\n"  # type: ignore[index]
    assert request.source.head_tree_sha == "d" * 40
    assert request.policy.mode == "repo"
    with pytest.raises(FrozenInstanceError):
        request.collect_diff_coverage = False  # type: ignore[misc]


def test_guard_builds_one_request_after_validation_and_uses_its_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_module = importlib.import_module("evoom_guard.guard")
    captured = _capture_requests(monkeypatch, guard_module)
    result = guard_module.guard(
        "not-read-for-preflight",
        "opaque candidate",
        file_blocks={"app.py": "x = 1\n"},
        deleted=("old.py",),
        isolation="docker",
        min_diff_coverage=80.0,
        base_sha="a" * 40,
        head_sha="b" * 40,
        base_tree_sha="c" * 40,
        head_tree_sha="d" * 40,
        policy_id="org/prod",
        policy_version="4",
    )

    assert result.verdict == "ERROR"
    assert result.reason_code == "policy_requirement_unsupported"
    assert len(captured) == 1
    request = captured[0]
    assert request.repository.path == "not-read-for-preflight"
    assert request.candidate.text == "opaque candidate"
    assert request.candidate.deleted_paths == ("old.py",)
    assert request.candidate.file_blocks == {"app.py": "x = 1\n"}
    assert request.source == SourceIdentity(
        base_sha="a" * 40,
        head_sha="b" * 40,
        base_tree_sha="c" * 40,
        head_tree_sha="d" * 40,
    )
    assert request.collect_diff_coverage is True
    assert request.policy.policy_id == "org/prod"
    assert request.policy.policy_version == "4"
    assert result.attestation is not None
    assert result.attestation["effective_policy"] == effective_policy_payload(
        request.policy
    )


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        (
            {"blackbox": True, "file_blocks": {"app.py": "x = 1\n"}},
            ("ERROR", "verifier_pack_required"),
        ),
        (
            {"file_blocks": {"tests/test_app.py": "def test_x(): pass\n"}},
            ("REJECTED", "protected_harness_edit"),
        ),
        (
            {
                "file_blocks": {"app.py": "x = 1\n"},
                "test_command": [sys.executable, "-c", "print('ok')"],
            },
            ("PASS", "tests_passed"),
        ),
    ],
    ids=("blackbox-missing-pack", "static-rejection", "repo-pass"),
)
def test_each_guard_flow_constructs_one_request_and_uses_its_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kwargs: dict[str, object],
    expected: tuple[str, str],
) -> None:
    guard_module = importlib.import_module("evoom_guard.guard")
    captured = _capture_requests(monkeypatch, guard_module)
    (tmp_path / "app.py").write_text("x = 0\n", encoding="utf-8")

    result = guard_module.guard(
        str(tmp_path),
        "opaque candidate",
        **kwargs,  # type: ignore[arg-type]
    )

    assert (result.verdict, result.reason_code) == expected
    assert len(captured) == 1
    assert result.attestation is not None
    assert result.attestation["effective_policy"] == effective_policy_payload(
        captured[0].policy
    )


@pytest.mark.skipif(os.name == "nt", reason="black-box candidate launcher requires POSIX")
def test_successful_blackbox_flow_uses_one_owned_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_module = importlib.import_module("evoom_guard.guard")
    captured = _capture_requests(monkeypatch, guard_module)
    (tmp_path / "app.py").write_text("x = 0\n", encoding="utf-8")
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "test_protocol.py").write_text(
        "import os\n"
        "import subprocess\n"
        "import sys\n\n"
        "def test_protocol():\n"
        "    result = subprocess.run(\n"
        "        [os.environ['EVOGUARD_EXEC'], sys.executable, '-c', "
        "'import app; assert app.x == 1'],\n"
        "        capture_output=True, text=True, check=False,\n"
        "    )\n"
        "    assert result.returncode == 0, result.stderr\n",
        encoding="utf-8",
    )

    result = guard_module.guard(
        str(tmp_path),
        "opaque candidate",
        file_blocks={"app.py": "x = 1\n"},
        blackbox=True,
        blackbox_only=True,
        verifier_pack=str(pack),
        timeout=60,
    )

    assert result.verdict == "PASS"
    assert len(captured) == 1
    assert result.attestation is not None
    assert result.attestation["effective_policy"] == effective_policy_payload(
        captured[0].policy
    )


def test_guard_runs_from_owned_snapshots_after_request_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_module = importlib.import_module("evoom_guard.guard")
    original_payload = guard_module._effective_policy_payload
    file_blocks = {"app.py": "x = 1\n"}
    test_command = ["python", "-m", "pytest"]

    def mutate_caller_inputs(policy: domain.EffectivePolicy) -> dict[str, object]:
        payload = original_payload(policy)
        file_blocks["late.py"] = "late mutation\n"
        test_command.append("--late-mutation")
        return payload

    monkeypatch.setattr(
        guard_module,
        "_effective_policy_payload",
        mutate_caller_inputs,
    )
    result = guard_module.guard(
        "not-read-for-preflight",
        "opaque candidate",
        file_blocks=file_blocks,
        test_command=test_command,
        isolation="docker",
        min_diff_coverage=80.0,
    )

    assert result.verdict == "ERROR"
    assert result.files_changed == ["app.py"]
    assert result.attestation is not None
    assert result.attestation["effective_policy"]["test_command"] == [
        "python",
        "-m",
        "pytest",
    ]


def test_invalid_public_inputs_fail_before_request_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_module = importlib.import_module("evoom_guard.guard")

    def unexpected_request(**_values: object) -> GuardRequest:
        raise AssertionError("GuardRequest must not be built before validation")

    monkeypatch.setattr(guard_module, "GuardRequest", unexpected_request)
    with pytest.raises(ValueError, match="timeout must be a positive integer"):
        guard_module.guard(".", "", timeout=0)
