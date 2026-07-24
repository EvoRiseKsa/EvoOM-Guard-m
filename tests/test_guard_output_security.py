# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available - see LICENSE for permitted use.
# Original creator: Mana Alharbi.
# -----------------------------------------------------------------------------
"""Adversarial publication contracts for Guard output."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace
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
        source="diff|forged\u202e&NewLine;&#10;&#x202E;",
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
    assert (
        "| Input | diff\\|forged\\u202e"
        "&amp;NewLine;&amp;#10;&amp;#x202E; |"
        in report
    )
    assert "`` src/`</code><h2>FORGED</h2>.py ``" in report
    assert "`` gone`\\n## forged deletion ``" in report
    assert (
        "````\nbefore\n```\n## forged diagnostics\n```\nafter\n````"
        in report
    )
    assert "\u202e" not in report


class _ExplosiveText:
    def __str__(self) -> str:
        raise AssertionError("unvalidated evidence reached string projection")


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("executed", "1"),
        ("total", True),
        ("percent", float("nan")),
        ("percent", _ExplosiveText()),
    ),
)
def test_diff_coverage_numeric_evidence_fails_closed(
    field: str,
    value: object,
) -> None:
    result = _error_result()
    result.diff_coverage = {
        "measured": True,
        "executed": 1,
        "total": 2,
        "percent": 50.0,
        "files": {},
    }
    result.diff_coverage[field] = value

    with pytest.raises(ValueError, match=f"diff_coverage.{field}"):
        guard_module.render_report(result)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("tests_passed", "1"),
        ("tests_total", False),
        ("tests_passed", _ExplosiveText()),
    ),
)
def test_baseline_numeric_evidence_fails_closed(
    field: str,
    value: object,
) -> None:
    result = _error_result()
    result.baseline = {
        "verdict": "FAIL",
        "repair_effect": "demonstrated",
        "tests_passed": 1,
        "tests_total": 2,
    }
    result.baseline[field] = value

    with pytest.raises(ValueError, match=f"baseline.{field}"):
        guard_module.render_report(result)


@pytest.mark.parametrize("line", ("7", True, 0, -1, _ExplosiveText()))
def test_missed_line_evidence_fails_closed(line: object) -> None:
    result = _error_result()
    result.diff_coverage = {
        "measured": True,
        "executed": 1,
        "total": 2,
        "percent": 50.0,
        "files": {"src/app.py": {"missed": [line]}},
    }

    with pytest.raises(ValueError, match="missed"):
        guard_module.render_report(result)


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


@pytest.mark.parametrize("primary_point", ("writer", "fsync"))
def test_atomic_writer_preserves_primary_when_close_also_fails(
    primary_point: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_fdopen = guard_output.os.fdopen

    class CloseFailureStream:
        def __init__(self, descriptor: int) -> None:
            self._stream = real_fdopen(
                descriptor,
                "w",
                encoding="utf-8",
                newline=None,
            )

        def write(self, value: str) -> int:
            return self._stream.write(value)

        def flush(self) -> None:
            self._stream.flush()

        def fileno(self) -> int:
            return self._stream.fileno()

        def close(self) -> None:
            self._stream.close()
            raise OSError("secondary close failure")

    monkeypatch.setattr(
        guard_output.os,
        "fdopen",
        lambda descriptor, *_args, **_kwargs: CloseFailureStream(descriptor),
    )
    if primary_point == "fsync":
        def reject_fsync(_descriptor: int) -> None:
            raise RuntimeError("primary fsync failure")

        monkeypatch.setattr(guard_output.os, "fsync", reject_fsync)

    def writer(stream: TextIO) -> None:
        if primary_point == "writer":
            raise RuntimeError("primary writer failure")
        stream.write("complete")

    with pytest.raises(
        RuntimeError,
        match=f"primary {primary_point} failure",
    ) as captured:
        guard_output._atomic_write(str(tmp_path / "report.md"), writer)

    notes = getattr(captured.value, "__notes__", [])
    if notes:
        assert any("atomic output close failed" in note for note in notes)
    assert _atomic_temps(tmp_path) == []


def test_atomic_writer_rejects_leaf_symlink_without_following_it(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.md"
    target.write_text("do not overwrite", encoding="utf-8")
    destination = tmp_path / "report.md"
    try:
        os.symlink(target, destination)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(guard_output.OutputDestinationError) as captured:
        guard_output.write_markdown("trusted report", str(destination))

    assert captured.value.code == "non_regular"
    assert target.read_text(encoding="utf-8") == "do not overwrite"
    assert destination.is_symlink()
    assert _atomic_temps(tmp_path) == []


def test_atomic_writer_rejects_directory_destination(tmp_path: Path) -> None:
    destination = tmp_path / "report.md"
    destination.mkdir()

    with pytest.raises(guard_output.OutputDestinationError) as captured:
        guard_output.write_markdown("trusted report", str(destination))

    assert captured.value.code == "non_regular"
    assert _atomic_temps(tmp_path) == []


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
def test_atomic_writer_rejects_fifo_destination(tmp_path: Path) -> None:
    destination = tmp_path / "report.md"
    os.mkfifo(destination)

    with pytest.raises(guard_output.OutputDestinationError) as captured:
        guard_output.write_markdown("trusted report", str(destination))

    assert captured.value.code == "non_regular"
    assert _atomic_temps(tmp_path) == []


def test_destination_validator_rejects_device_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        guard_output.os,
        "lstat",
        lambda _path: SimpleNamespace(st_mode=stat.S_IFCHR | 0o660),
    )

    with pytest.raises(guard_output.OutputDestinationError) as captured:
        guard_output._validate_output_destination("report.md")

    assert captured.value.code == "non_regular"


def test_destination_validator_rejects_simulated_read_only_regular_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        guard_output.os,
        "lstat",
        lambda _path: SimpleNamespace(st_mode=stat.S_IFREG | 0o444),
    )

    with pytest.raises(guard_output.OutputDestinationError) as captured:
        guard_output._validate_output_destination("report.md")

    assert captured.value.code == "read_only"


@pytest.mark.parametrize(
    "path",
    (
        "NUL",
        "NUL.",
        "NUL ",
        "reports/CON.txt",
        "reports/PRN",
        "reports/AUX.json",
        "reports/COM",
        "reports/COM1.log",
        "reports/LPT9",
        r"\\?\C:\reports\verdict.json",
        r"\\.\NUL",
        r"\??\C:\reports\verdict.json",
        "reports/verdict.json:stream",
    ),
)
def test_destination_validator_rejects_windows_devices_and_namespaces(
    path: str,
) -> None:
    with pytest.raises(guard_output.OutputDestinationError) as captured:
        guard_output._validate_output_destination(path, platform_name="nt")

    assert captured.value.code in {
        "windows_namespace",
        "windows_reserved_name",
    }


def test_atomic_writer_revalidates_leaf_immediately_before_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "report.md"
    calls = 0

    def changing_destination(_path: str) -> int | None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise guard_output.OutputDestinationError(
                "non_regular",
                "simulated leaf replacement",
            )
        return None

    monkeypatch.setattr(
        guard_output,
        "_validate_output_destination",
        changing_destination,
    )

    with pytest.raises(guard_output.OutputDestinationError) as captured:
        guard_output.write_markdown("trusted report", str(destination))

    assert captured.value.code == "non_regular"
    assert calls == 2
    assert not destination.exists()
    assert _atomic_temps(tmp_path) == []


def test_atomic_writer_applies_existing_mode_before_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "report.md"
    observed_modes: list[int] = []
    real_chmod = guard_output.os.chmod

    monkeypatch.setattr(
        guard_output,
        "_validate_output_destination",
        lambda _path: 0o640,
    )

    def observed_chmod(path: str, mode: int) -> None:
        observed_modes.append(mode)
        real_chmod(path, mode)

    monkeypatch.setattr(guard_output.os, "chmod", observed_chmod)

    guard_output.write_markdown("trusted report", str(destination))

    assert observed_modes == [0o640]
    assert destination.read_text(encoding="utf-8") == "trusted report"


@pytest.mark.skipif(os.name == "nt", reason="portable POSIX mode assertion")
def test_atomic_writer_preserves_existing_regular_mode(tmp_path: Path) -> None:
    destination = tmp_path / "report.md"
    destination.write_text("prior", encoding="utf-8")
    destination.chmod(0o640)

    guard_output.write_markdown("trusted report", str(destination))

    assert stat.S_IMODE(destination.stat().st_mode) == 0o640
    assert destination.read_text(encoding="utf-8") == "trusted report"


@pytest.mark.skipif(os.name == "nt", reason="portable POSIX mode assertion")
def test_atomic_writer_refuses_existing_read_only_regular_file(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "report.md"
    destination.write_text("prior", encoding="utf-8")
    destination.chmod(0o444)
    try:
        with pytest.raises(guard_output.OutputDestinationError) as captured:
            guard_output.write_markdown("trusted report", str(destination))

        assert captured.value.code == "read_only"
        assert destination.read_text(encoding="utf-8") == "prior"
        assert _atomic_temps(tmp_path) == []
    finally:
        destination.chmod(0o600)


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
        files_changed=["src/space name-\u00b5.py"],
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
        "C:relative.py",
        "src\\relative.py",
        "src/surrogate\ud800.py",
    ),
)
def test_sarif_rejects_control_or_non_repository_artifact_paths(
    path: str,
) -> None:
    with pytest.raises(ValueError, match="SARIF artifact path"):
        guard_module.to_sarif(_error_result(files_changed=[path]))


@pytest.mark.parametrize(
    ("path", "code"),
    (
        ("src\\relative.py", "backslash"),
        ("C:relative.py", "drive_prefix"),
        ("src/surrogate\ud800.py", "surrogate"),
    ),
)
def test_sarif_path_errors_are_structured(path: str, code: str) -> None:
    with pytest.raises(guard_output.SarifArtifactPathError) as captured:
        guard_module.to_sarif(_error_result(files_changed=[path]))

    assert captured.value.code == code


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
