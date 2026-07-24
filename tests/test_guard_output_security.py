# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available - see LICENSE for permitted use.
# Original creator: Mana Alharbi.
# -----------------------------------------------------------------------------
"""Adversarial publication contracts for Guard output."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, TextIO

import pytest

from evoom_guard import cli
from evoom_guard import guard as guard_module
from evoom_guard.guard import ERROR, GuardResult
from evoom_guard.integrations import guard_output


def _error_result(
    *,
    reason: str = "controlled failure",
    files_changed: list[str] | None = None,
    diagnostics: str = "",
    source: str | None = None,
) -> GuardResult:
    return GuardResult(
        verdict=ERROR,
        passed=False,
        reason=reason,
        files_changed=files_changed or ["src/app.py"],
        protected_violations=[],
        risk_level="low",
        risk_score=0.1,
        diagnostics=diagnostics,
        source=source,
        reason_code="controlled_error",
    )


def _atomic_temps(directory: Path) -> list[Path]:
    return list(directory.glob(".evoguard-output-*.tmp"))


def test_markdown_projection_neutralizes_untrusted_structure() -> None:
    result = _error_result(
        reason="failed\n\n## Forged PASS\n<script>",
        files_changed=["src/`</code><h2>FORGED</h2>.py"],
        diagnostics="before\n```\n## forged diagnostics\n```\nafter",
        source="diff|forged\u202e",
    )

    report = guard_module.render_report(
        result,
        deleted=["gone`\n## forged deletion"],
        title="Trusted\n## forged title",
    )

    assert report.startswith("## Trusted\\n## forged title —")
    assert "\n## Forged PASS" not in report
    assert (
        "**failed\\n\\n## Forged PASS\\n&lt;script&gt;**"
        in report
    )
    assert "| Input | diff\\|forged\\u202e |" in report
    assert "`` src/`</code><h2>FORGED</h2>.py ``" in report
    assert "`` gone`\\n## forged deletion ``" in report
    assert (
        "````\nbefore\n```\n## forged diagnostics\n```\nafter\n````"
        in report
    )
    assert "\u202e" not in report


@pytest.mark.parametrize("writer_name", ("json", "sarif"))
def test_atomic_machine_writer_rolls_back_partial_serialization(
    writer_name: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / f"verdict.{writer_name}"
    prior = b'{"prior":"complete"}'
    destination.write_bytes(prior)

    def broken_dump(
        _value: object,
        stream: TextIO,
        *,
        indent: int,
    ) -> None:
        assert indent == 2
        stream.write('{"partial":')
        raise OSError("simulated serializer failure")

    monkeypatch.setattr(guard_module.json, "dump", broken_dump)
    with pytest.raises(OSError, match="simulated serializer failure"):
        if writer_name == "json":
            guard_module.write_json(_error_result(), str(destination))
        else:
            guard_module.write_sarif(_error_result(), str(destination))

    assert destination.read_bytes() == prior
    assert _atomic_temps(tmp_path) == []


def test_sarif_conversion_failure_does_not_touch_the_destination(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "verdict.sarif"
    prior = b'{"prior":"complete"}'
    destination.write_bytes(prior)

    def reject_conversion(_result: object) -> dict[str, Any]:
        raise ValueError("simulated conversion failure")

    with pytest.raises(ValueError, match="simulated conversion failure"):
        guard_output.write_sarif(
            _error_result(),
            str(destination),
            converter=reject_conversion,
        )

    assert destination.read_bytes() == prior
    assert _atomic_temps(tmp_path) == []


@pytest.mark.parametrize("failure_point", ("fsync", "replace"))
def test_atomic_markdown_writer_rolls_back_commit_failures(
    failure_point: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "report.md"
    destination.write_text("prior complete report", encoding="utf-8")

    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError(f"simulated {failure_point} failure")

    monkeypatch.setattr(guard_output.os, failure_point, fail)
    with pytest.raises(OSError, match=f"simulated {failure_point} failure"):
        guard_output.write_markdown("new report", str(destination))

    assert destination.read_text(encoding="utf-8") == "prior complete report"
    assert _atomic_temps(tmp_path) == []


def test_atomic_writer_fsyncs_before_same_directory_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "report.md"
    events: list[str] = []
    real_mkstemp = guard_output.tempfile.mkstemp
    real_fsync = guard_output.os.fsync
    real_replace = guard_output.os.replace

    def observed_mkstemp(*args: Any, **kwargs: Any) -> tuple[int, str]:
        assert Path(kwargs["dir"]) == tmp_path
        events.append("mkstemp")
        return real_mkstemp(*args, **kwargs)

    def observed_fsync(descriptor: int) -> None:
        events.append("fsync")
        real_fsync(descriptor)

    def observed_replace(source: str, target: str) -> None:
        assert Path(source).parent == tmp_path
        assert Path(target) == destination
        events.append("replace")
        real_replace(source, target)

    monkeypatch.setattr(guard_output.tempfile, "mkstemp", observed_mkstemp)
    monkeypatch.setattr(guard_output.os, "fsync", observed_fsync)
    monkeypatch.setattr(guard_output.os, "replace", observed_replace)

    guard_output.write_markdown("complete", str(destination))

    assert events == ["mkstemp", "fsync", "replace"]
    assert destination.read_text(encoding="utf-8") == "complete"
    assert _atomic_temps(tmp_path) == []


def test_atomic_cleanup_failure_never_masks_the_primary_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_unlink = guard_output.os.unlink

    def reject_cleanup(_path: str) -> None:
        raise OSError("simulated cleanup failure")

    def reject_write(_stream: TextIO) -> None:
        raise RuntimeError("primary serialization failure")

    monkeypatch.setattr(guard_output.os, "unlink", reject_cleanup)
    with pytest.raises(
        RuntimeError,
        match="primary serialization failure",
    ) as captured:
        guard_output._atomic_write(str(tmp_path / "report.md"), reject_write)

    notes = getattr(captured.value, "__notes__", [])
    if notes:
        assert any("atomic output cleanup failed" in note for note in notes)

    monkeypatch.setattr(guard_output.os, "unlink", real_unlink)
    for temp_path in _atomic_temps(tmp_path):
        temp_path.unlink()


def test_atomic_writer_replaces_leaf_symlink_without_following_it(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.md"
    target.write_text("do not overwrite", encoding="utf-8")
    destination = tmp_path / "report.md"
    try:
        os.symlink(target, destination)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    guard_output.write_markdown("trusted report", str(destination))

    assert target.read_text(encoding="utf-8") == "do not overwrite"
    assert not destination.is_symlink()
    assert destination.read_text(encoding="utf-8") == "trusted report"


def test_cli_report_path_uses_the_shared_atomic_writer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[str, str]] = []
    monkeypatch.setattr(
        guard_output,
        "write_markdown",
        lambda report, path: observed.append((report, path)),
    )

    services = cli._guard_command_services()
    services.write_report("report.md", "complete")

    assert observed == [("complete\n", "report.md")]


def test_sarif_artifact_uri_is_normalized_and_percent_encoded() -> None:
    result = _error_result(
        files_changed=["src\\space name-µ.py"],
    )

    finding = guard_module.to_sarif(result)["runs"][0]["results"][0]

    assert finding["locations"] == [
        {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": "src/space%20name-%C2%B5.py"
                }
            }
        }
    ]


@pytest.mark.parametrize(
    "path",
    (
        "src/control\nname.py",
        "src/nul\x00name.py",
        "src/bidi\u202ename.py",
        "/absolute.py",
        "../escape.py",
        "src/../escape.py",
        "src//ambiguous.py",
        "C:\\absolute.py",
    ),
)
def test_sarif_rejects_control_or_non_repository_artifact_paths(
    path: str,
) -> None:
    with pytest.raises(ValueError, match="SARIF artifact path"):
        guard_module.to_sarif(_error_result(files_changed=[path]))


def test_successful_atomic_json_preserves_the_public_wire_payload(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "verdict.json"
    result = _error_result()

    guard_module.write_json(result, str(destination), deleted=["gone.py"])

    assert json.loads(destination.read_text(encoding="utf-8")) == {
        **result.to_dict(),
        "deleted": ["gone.py"],
    }
    assert _atomic_temps(tmp_path) == []
