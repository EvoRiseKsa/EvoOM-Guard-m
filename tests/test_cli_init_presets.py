"""Focused safety tests for the ``evo-guard init`` onboarding presets."""

from __future__ import annotations

from pathlib import Path

import pytest

from evoom_guard import cli
from evoom_guard.cli.init_command import (
    render_advisory_workflow,
    render_public_workflow,
)

REF = "v9.9.9"
UPLOAD_ARTIFACT_PIN = (
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
)


def test_init_blocking_preset_is_byte_identical_to_the_default(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["init", "--stdout", "--ref", REF]) == 0
    default = capsys.readouterr().out

    assert cli.main(
        ["init", "--stdout", "--preset", "blocking", "--ref", REF]
    ) == 0
    explicit = capsys.readouterr().out

    assert default == explicit == render_public_workflow(REF) + "\n"


def test_advisory_preset_is_read_only_fail_closed_and_evidence_preserving() -> None:
    workflow = render_advisory_workflow(REF)

    assert f"uses: EvoRiseKsa/EvoOM-Guard-m@{REF}" in workflow
    assert 'fail-on: "any-non-pass"' in workflow
    assert "continue-on-error: true" in workflow
    assert f"uses: {UPLOAD_ARTIFACT_PIN} # v7.0.1" in workflow
    assert "if: ${{ always() }}" in workflow
    assert "${{ steps.guard.outputs.json-path }}" in workflow
    assert "${{ steps.guard.outputs.report-path }}" in workflow
    assert "if-no-files-found: error" in workflow
    evidence_gate = workflow.index(
        "- name: Require complete EvoGuard observation evidence"
    )
    upload = workflow.index("- name: Upload EvoGuard observation evidence")
    assert evidence_gate < upload
    assert "EVOGUARD_JSON_PATH: ${{ steps.guard.outputs.json-path }}" in workflow
    assert "EVOGUARD_REPORT_PATH: ${{ steps.guard.outputs.report-path }}" in workflow
    assert (
        'if [ -z "$EVOGUARD_JSON_PATH" ] || [ ! -f "$EVOGUARD_JSON_PATH" ] || [ ! -s "$EVOGUARD_JSON_PATH" ]; then'
        in workflow
    )
    assert (
        'if [ -z "$EVOGUARD_REPORT_PATH" ] || [ ! -f "$EVOGUARD_REPORT_PATH" ] || [ ! -s "$EVOGUARD_REPORT_PATH" ]; then'
        in workflow
    )
    assert '[ "$evidence_complete" = "true" ]' in workflow

    assert "permissions: {}" in workflow
    assert "contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert 'comment: "false"' in workflow
    assert "pull-requests: write" not in workflow
    assert "persist-credentials: true" not in workflow
    assert "secrets." not in workflow
    assert "github.token" not in workflow
    assert "--advisory" not in workflow


def test_init_advisory_writes_workflow_and_trusted_policy(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workflow_path = tmp_path / ".github" / "workflows" / "evoguard.yml"

    assert cli.main(
        [
            "init",
            "--path",
            str(workflow_path),
            "--preset",
            "advisory",
            "--test-command",
            "python -I -B -m pytest -q -p no:cacheprovider",
            "--ref",
            REF,
        ]
    ) == 0

    assert workflow_path.read_text(encoding="utf-8") == render_advisory_workflow(REF)
    assert (tmp_path / ".evoguard.json").read_text(encoding="utf-8") == (
        '{\n  "test_command": "python -I -B -m pytest -q -p no:cacheprovider"\n}\n'
    )
    message = capsys.readouterr().out
    assert "uploaded evidence" in message
    assert "completed non-PASS verdicts" in message
    assert "either missing/empty JSON/Markdown evidence file still fails" in message
    assert "--preset blocking --force" in message
    assert f"ref=[{REF}]" in message
    assert f"workflow path=[{workflow_path}]" in message
    assert f"trusted policy path=[{tmp_path / '.evoguard.json'}]" in message


def test_init_advisory_rejects_tags_without_evidence_outputs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workflow_path = tmp_path / "evoguard.yml"

    assert cli.main(
        [
            "init",
            "--path",
            str(workflow_path),
            "--preset",
            "advisory",
            "--ref",
            "v4.5.0",
        ]
    ) == 2

    assert not workflow_path.exists()
    assert "supports EvoGuard v4.6.0 or later tags" in capsys.readouterr().out


def test_init_advisory_handles_unbounded_numeric_semver_without_traceback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    huge_ref = "v" + "9" * 5000 + ".0.0"

    assert cli.main(
        ["init", "--stdout", "--preset", "advisory", "--ref", huge_ref]
    ) == 0
    assert f"EvoRiseKsa/EvoOM-Guard-m@{huge_ref}" in capsys.readouterr().out


def test_advisory_promotion_message_preserves_custom_policy_path(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workflow_path = tmp_path / "custom workflows" / "observe.yml"
    policy_path = tmp_path / "trusted policy" / "guard.json"

    assert cli.main(
        [
            "init",
            "--path",
            str(workflow_path),
            "--policy-path",
            str(policy_path),
            "--preset",
            "advisory",
            "--ref",
            REF,
        ]
    ) == 0

    message = capsys.readouterr().out
    assert f"workflow path=[{workflow_path}]" in message
    assert f"trusted policy path=[{policy_path}]" in message


def test_init_rejects_unknown_preset_before_writing(tmp_path: Path) -> None:
    workflow_path = tmp_path / "evoguard.yml"

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "init",
                "--path",
                str(workflow_path),
                "--preset",
                "observe-ish",
                "--ref",
                REF,
            ]
        )

    assert exc_info.value.code == 2
    assert not workflow_path.exists()
