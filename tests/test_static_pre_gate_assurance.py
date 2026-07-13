# -----------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Regression contract for assurance metadata on static pre-gate outcomes.

A protected-harness edit is decided from the candidate diff before any repo or
black-box judge runs.  Requested execution policy remains useful attestation
context, but it is not evidence that a runtime boundary, report channel, or
verifier-pack snapshot was actually delivered.
"""

from __future__ import annotations

import pytest

import evoom_guard.blackbox as blackbox_module
from evoom_guard.guard import (
    ERROR,
    REASON_NO_PARSEABLE_EDITS,
    REASON_PROTECTED_HARNESS_EDIT,
    REASON_UNSAFE_PATH,
    REJECTED,
    guard,
    to_sarif,
)
from evoom_guard.verifiers.repo_verifier import RepoVerifier


def _repo(tmp_path):
    repo = tmp_path / "repo"
    tests = repo / "tests"
    tests.mkdir(parents=True)
    (repo / "calc.py").write_text(
        "def add(a, b):\n    return a + b\n", encoding="utf-8"
    )
    (tests / "test_calc.py").write_text(
        "from calc import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n",
        encoding="utf-8",
    )
    return repo


def _protected_edit() -> str:
    return (
        "<<<FILE: tests/test_calc.py>>>\n"
        "def test_add():\n    assert True\n"
        "<<<END FILE>>>"
    )


def _forbid_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected(*_args, **_kwargs):
        raise AssertionError("a static pre-gate decision must not start a judge")

    monkeypatch.setattr(RepoVerifier, "verify", unexpected)
    monkeypatch.setattr(blackbox_module, "run_blackbox", unexpected)


@pytest.mark.parametrize("requested_isolation", ["subprocess", "docker", "gvisor"])
def test_static_rejection_reports_no_delivered_runtime_boundary(
    tmp_path, monkeypatch: pytest.MonkeyPatch, requested_isolation: str
) -> None:
    _forbid_execution(monkeypatch)
    result = guard(
        str(_repo(tmp_path)),
        _protected_edit(),
        isolation=requested_isolation,
        docker_image="python:3.12" if requested_isolation != "subprocess" else None,
    )

    assert result.verdict == REJECTED
    assert result.to_dict()["test_command_ran"] is False
    assert result.isolation == "not_run"
    assert result.assurance is not None
    assert result.assurance["overall_profile"] == "static_gate"
    assert result.assurance["candidate_isolation"] == "not_run"
    assert result.assurance["suite_isolation"] == "not_run"
    assert result.assurance["report_integrity"] == "not_applicable_static_gate"
    assert result.assurance["setup_isolation"] is None
    assert result.assurance["runtime_continuity"] == "not_applicable"
    assert result.assurance["verifier_pack"] is None

    # The requested policy is retained as context, not promoted to delivered
    # assurance merely because the caller selected it.
    assert result.attestation is not None
    assert result.attestation["effective_policy"]["isolation"] == requested_isolation
    assert result.attestation["isolation_evidence"] is None


def test_static_blackbox_rejection_preserves_mode_without_claiming_pack_evidence(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_execution(monkeypatch)
    requested_pack = tmp_path / "judge-owned-pack-not-opened"
    result = guard(
        str(_repo(tmp_path)),
        _protected_edit(),
        blackbox=True,
        blackbox_only=True,
        verifier_pack=str(requested_pack),
        isolation="docker",
        docker_image="python:3.12",
    )

    assert result.verdict == REJECTED
    assert result.to_dict()["test_command_ran"] is False
    assert result.attestation is not None
    assert result.attestation["mode"] == "blackbox"
    policy = result.attestation["effective_policy"]
    assert policy["mode"] == "blackbox"
    assert policy["blackbox"] is True
    assert policy["verifier_pack_required"] is True
    assert result.attestation["verifier_pack_sha256"] is None
    assert result.attestation["verifier_pack_manifest"] is None

    assert result.assurance is not None
    assert result.assurance["overall_profile"] == "static_gate"
    pack = result.assurance["verifier_pack"]
    assert pack is not None and pack["configured"] is True
    assert pack["present"] is None
    assert pack["integrity"] == "not_evaluated_static_gate"
    assert pack["secrecy"] == "not_evaluated_static_gate"


@pytest.mark.parametrize(
    ("case", "expected_verdict", "expected_reason"),
    [
        ("no_parseable_edits", ERROR, REASON_NO_PARSEABLE_EDITS),
        ("unsafe_path", ERROR, REASON_UNSAFE_PATH),
        ("protected_deletion", REJECTED, REASON_PROTECTED_HARNESS_EDIT),
    ],
)
def test_all_diff_decided_pre_gate_shapes_report_no_execution(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    expected_verdict: str,
    expected_reason: str,
) -> None:
    _forbid_execution(monkeypatch)
    repo = _repo(tmp_path)
    candidate = "just prose"
    deleted: tuple[str, ...] = ()
    if case == "unsafe_path":
        candidate = "<<<FILE: ../escape.py>>>\nx = 1\n<<<END FILE>>>"
    elif case == "protected_deletion":
        candidate = ""
        deleted = ("tests/test_calc.py",)

    result = guard(str(repo), candidate, deleted=deleted, isolation="docker")

    assert result.verdict == expected_verdict
    assert result.reason_code == expected_reason
    assert result.to_dict()["test_command_ran"] is False
    assert result.isolation == "not_run"
    assert result.assurance is not None
    assert result.assurance["overall_profile"] == "static_gate"
    assert result.assurance["candidate_isolation"] == "not_run"
    assert result.assurance["suite_isolation"] == "not_run"


@pytest.mark.parametrize(
    "floor",
    [
        {"require_candidate_isolation": "docker"},
        {"require_report_integrity": "external_process_isolated"},
    ],
)
def test_runtime_assurance_floors_do_not_override_static_rejection(
    tmp_path, monkeypatch: pytest.MonkeyPatch, floor: dict[str, str]
) -> None:
    _forbid_execution(monkeypatch)
    result = guard(str(_repo(tmp_path)), _protected_edit(), **floor)

    assert result.verdict == REJECTED
    assert result.reason_code == "protected_harness_edit"
    assert result.to_dict()["test_command_ran"] is False
    assert result.assurance is not None
    assert result.assurance["overall_profile"] == "static_gate"


def test_sarif_static_rejection_says_execution_was_not_run(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_execution(monkeypatch)
    result = guard(
        str(_repo(tmp_path)),
        _protected_edit(),
        isolation="docker",
        docker_image="python:3.12",
    )

    (finding,) = to_sarif(result)["runs"][0]["results"]
    assert finding["properties"]["verdict"] == REJECTED
    assert finding["properties"]["isolation"] == "not_run"
