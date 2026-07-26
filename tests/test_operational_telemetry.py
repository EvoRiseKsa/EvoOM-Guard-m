import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import tools.telemetry.aggregate_verdicts as telemetry
from evoom_guard.domain.verdict import (
    REASON_CODES as CONTRACT_REASON_CODES,
)
from evoom_guard.domain.verdict import (
    VERDICTS as CONTRACT_VERDICTS,
)
from tools.telemetry.aggregate_verdicts import (
    ISOLATIONS,
    REASON_CODES,
    VERDICTS,
    TelemetryInputError,
    aggregate_paths,
    aggregate_records,
)

ROOT = Path(__file__).parents[1]
TOOL = ROOT / "tools" / "telemetry" / "aggregate_verdicts.py"


def _record(
    *,
    verdict: str = "PASS",
    reason_code: str = "tests_passed",
    isolation: str = "subprocess",
    profile: str | None = "local",
    policy_version: str | None = None,
    latency_ms: float | None = None,
) -> dict[str, object]:
    policy: dict[str, object] = {"policy_version": policy_version}
    if profile is not None:
        policy["operating_profile"] = profile
    attestation: dict[str, object] = {
        "effective_policy": policy,
        "policy_version": policy_version,
    }
    if latency_ms is not None:
        attestation["runtime_identity_elapsed_ms"] = latency_ms
    return {
        "schema_version": "1.12" if profile is not None else "1.11",
        "tool": "evoguard",
        "verdict": verdict,
        "reason_code": reason_code,
        "isolation": isolation,
        "attestation": attestation,
    }


def _changed_stat(
    metadata: os.stat_result,
    **changes: int,
) -> SimpleNamespace:
    values = {
        "st_mode": int(metadata.st_mode),
        "st_dev": int(metadata.st_dev),
        "st_ino": int(metadata.st_ino),
        "st_size": int(metadata.st_size),
        "st_mtime_ns": int(metadata.st_mtime_ns),
        "st_ctime_ns": int(metadata.st_ctime_ns),
        "st_file_attributes": int(getattr(metadata, "st_file_attributes", 0) or 0),
    }
    values.update(changes)
    return SimpleNamespace(**values)


def test_aggregates_only_fixed_dimensions_and_numeric_latency() -> None:
    records = [
        _record(policy_version="2026.07", latency_ms=10),
        _record(
            verdict="FAIL",
            reason_code="tests_failed",
            isolation="docker",
            profile="protected",
            policy_version="2026.07",
            latency_ms=30,
        ),
        _record(
            verdict="ERROR",
            reason_code="test_timeout",
            isolation="gvisor",
            profile="hostile",
            policy_version="private-version",
        ),
        _record(
            verdict="REJECTED",
            reason_code="protected_harness_edit",
            isolation="not_run",
            profile=None,
        ),
    ]

    result = aggregate_records(
        records,
        allowed_policy_versions=("2026.07",),
    )

    assert result["records_total"] == 4
    counts = result["counts"]
    assert isinstance(counts, dict)
    assert counts["verdict"] == {
        "PASS": 1,
        "REJECTED": 1,
        "FAIL": 1,
        "ERROR": 1,
        "TAMPERED": 0,
    }
    assert counts["isolation"] == {
        "not_run": 1,
        "subprocess": 1,
        "docker": 1,
        "gvisor": 1,
    }
    assert counts["operating_profile"] == {
        "local": 1,
        "protected": 1,
        "hostile": 1,
        "unspecified": 1,
    }
    assert counts["policy_version"] == {
        "2026.07": 2,
        "other": 1,
        "unspecified": 1,
    }
    assert result["error_abstentions"] == {"count": 1, "rate": 0.25}
    latency = result["latency"]
    assert isinstance(latency, dict)
    assert latency["runtime_identity_elapsed_ms"] == {
        "samples": 2,
        "min": 10.0,
        "mean": 20.0,
        "p50": 20.0,
        "p95": 30.0,
        "max": 30.0,
    }
    assert latency["records_without_measurement"] == 2


def test_arbitrary_record_evidence_and_unapproved_policy_labels_never_escape() -> None:
    secret = "TOP-SECRET-s3cr3t"
    source_path = "/home/customer/private/repository.py"
    record = _record(policy_version=secret, latency_ms=4)
    record.update(
        {
            "source": source_path,
            "reason": secret,
            "diagnostics": f"trace {secret} {source_path}",
            "files_changed": [source_path],
            "protected_violations": [source_path],
            "evidence": {"api_token": secret},
            "api_key": secret,
        }
    )
    attestation = record["attestation"]
    assert isinstance(attestation, dict)
    attestation.update(
        {
            "candidate_sha256": secret,
            "policy_sha256": secret,
            "test_command": ["python", source_path, secret],
            "evidence": {"secret": secret},
        }
    )

    serialized = json.dumps(aggregate_records([record]), sort_keys=True)

    assert secret not in serialized
    assert source_path not in serialized
    assert "diagnostics" not in serialized
    assert "files_changed" not in serialized
    assert "evidence" not in serialized
    assert '"other": 1' in serialized


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("verdict", "PASS-/private/path"),
        ("reason_code", "token-TOP-SECRET"),
        ("isolation", "tenant-A"),
    ],
)
def test_free_form_categorical_values_are_rejected(
    field: str,
    value: str,
) -> None:
    record = _record()
    record[field] = value
    with pytest.raises(TelemetryInputError):
        aggregate_records([record])


def test_schema_1_11_cannot_carry_an_operating_profile() -> None:
    record = _record(profile="local")
    record["schema_version"] = "1.11"

    with pytest.raises(
        TelemetryInputError,
        match="operating profile requires verdict-record schema 1.12",
    ):
        aggregate_records([record])


def test_cli_failure_does_not_echo_path_or_secret_record_content(
    tmp_path: Path,
) -> None:
    secret = "DO-NOT-PRINT-ME"
    sensitive_name = tmp_path / "customer-private-path.json"
    sensitive_name.write_text(
        json.dumps(
            {
                **_record(),
                "reason_code": secret,
                "diagnostics": secret,
                "source": str(sensitive_name),
            }
        ),
        encoding="utf-8",
    )

    completed = subprocess.run(
        [sys.executable, str(TOOL), str(sensitive_name)],
        check=False,
        capture_output=True,
        encoding="utf-8",
    )

    combined = completed.stdout + completed.stderr
    assert completed.returncode == 2
    assert completed.stdout == ""
    assert secret not in combined
    assert str(sensitive_name) not in combined


def test_strict_json_rejects_duplicate_keys_and_nonfinite_latency(
    tmp_path: Path,
) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":"1.11","schema_version":"1.11"}',
        encoding="utf-8",
    )
    with pytest.raises(TelemetryInputError, match="duplicate JSON key"):
        aggregate_paths([duplicate])

    record = _record()
    attestation = record["attestation"]
    assert isinstance(attestation, dict)
    attestation["runtime_identity_elapsed_ms"] = float("nan")
    with pytest.raises(TelemetryInputError, match="invalid latency"):
        aggregate_records([record])


def test_aggregate_paths_reads_a_valid_record_without_path_read_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record_path = tmp_path / "record.json"
    record_path.write_text(json.dumps(_record()), encoding="utf-8")

    def forbidden_read_text(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("record bytes must come from the stable descriptor")

    monkeypatch.setattr(Path, "read_text", forbidden_read_text)

    result = aggregate_paths([record_path])

    assert result["records_total"] == 1


def test_load_record_rejects_oversized_input_without_disclosing_its_path(
    tmp_path: Path,
) -> None:
    oversized = tmp_path / "customer-secret-oversized.json"
    oversized.write_bytes(b"x" * (telemetry.MAX_RECORD_BYTES + 1))

    with pytest.raises(TelemetryInputError, match="record size limit") as caught:
        telemetry._load_record(oversized, 7)

    message = str(caught.value)
    assert "input 7" in message
    assert str(oversized) not in message
    assert "customer-secret" not in message


def test_bounded_descriptor_loop_rejects_growth_beyond_the_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record_path = tmp_path / "record.json"
    record_path.write_text(json.dumps(_record()), encoding="utf-8")
    remaining = telemetry.MAX_RECORD_BYTES + 1
    requested_sizes: list[int] = []

    def oversized_read(_descriptor: int, requested: int) -> bytes:
        nonlocal remaining
        requested_sizes.append(requested)
        emitted = min(requested, remaining)
        remaining -= emitted
        return b"x" * emitted

    monkeypatch.setattr(telemetry.os, "read", oversized_read)

    with pytest.raises(TelemetryInputError, match="record size limit"):
        telemetry._load_record(record_path, 1)

    assert remaining == 0
    assert requested_sizes
    assert max(requested_sizes) <= telemetry._READ_CHUNK_BYTES


def test_load_record_rejects_lstat_to_descriptor_identity_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record_path = tmp_path / "identity-secret.json"
    record_path.write_text(json.dumps(_record()), encoding="utf-8")
    real_fstat = telemetry.os.fstat

    def mismatched_fstat(descriptor: int) -> SimpleNamespace:
        metadata = real_fstat(descriptor)
        return _changed_stat(metadata, st_ino=int(metadata.st_ino) + 1)

    monkeypatch.setattr(telemetry.os, "fstat", mismatched_fstat)

    with pytest.raises(TelemetryInputError, match="changed while it was opened") as caught:
        telemetry._load_record(record_path, 3)

    assert str(record_path) not in str(caught.value)
    assert "identity-secret" not in str(caught.value)


def test_load_record_rejects_descriptor_metadata_change_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record_path = tmp_path / "record.json"
    record_path.write_text(json.dumps(_record()), encoding="utf-8")
    real_fstat = telemetry.os.fstat
    calls = 0

    def changing_fstat(descriptor: int) -> os.stat_result | SimpleNamespace:
        nonlocal calls
        calls += 1
        metadata = real_fstat(descriptor)
        if calls == 2:
            return _changed_stat(metadata, st_size=int(metadata.st_size) + 1)
        return metadata

    monkeypatch.setattr(telemetry.os, "fstat", changing_fstat)

    with pytest.raises(TelemetryInputError, match="changed while it was read"):
        telemetry._load_record(record_path, 1)

    assert calls == 2


def test_load_record_rejects_symlink_swap_between_lstat_and_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record_path = tmp_path / "record.json"
    original_path = tmp_path / "original.json"
    target_path = tmp_path / "customer-secret-target.json"
    record_path.write_text(json.dumps(_record()), encoding="utf-8")
    target_path.write_text(json.dumps(_record(policy_version="private-secret")), encoding="utf-8")
    real_open = telemetry.os.open
    swapped = False

    def swapping_open(path: os.PathLike[str] | str, flags: int, mode: int = 0o777) -> int:
        nonlocal swapped
        if not swapped and Path(path) == record_path:
            swapped = True
            record_path.replace(original_path)
            try:
                os.symlink(target_path, record_path)
            except (NotImplementedError, OSError) as exc:
                pytest.skip(f"symlink creation is unavailable: {exc}")
        return real_open(path, flags, mode)

    monkeypatch.setattr(telemetry.os, "open", swapping_open)

    with pytest.raises(TelemetryInputError) as caught:
        telemetry._load_record(record_path, 4)

    message = str(caught.value)
    assert swapped is True
    assert str(record_path) not in message
    assert str(target_path) not in message
    assert "private-secret" not in message


def test_directory_discovery_rejects_nested_symbolic_file_without_omission(
    tmp_path: Path,
) -> None:
    records = tmp_path / "records"
    records.mkdir()
    (records / "valid.json").write_text(json.dumps(_record()), encoding="utf-8")
    external = tmp_path / "error-record.json"
    external.write_text(
        json.dumps(
            _record(
                verdict="ERROR",
                reason_code="test_timeout",
            )
        ),
        encoding="utf-8",
    )
    linked = records / "hidden-error.json"
    try:
        linked.symlink_to(external)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")

    with pytest.raises(
        TelemetryInputError,
        match="input 1 contains a symbolic or reparse link",
    ) as caught:
        aggregate_paths([records])

    assert str(linked) not in str(caught.value)
    assert "hidden-error" not in str(caught.value)


def test_directory_discovery_rejects_nested_symbolic_directory(
    tmp_path: Path,
) -> None:
    records = tmp_path / "records"
    records.mkdir()
    external = tmp_path / "external-records"
    external.mkdir()
    (external / "error.json").write_text(
        json.dumps(
            _record(
                verdict="ERROR",
                reason_code="test_timeout",
            )
        ),
        encoding="utf-8",
    )
    linked = records / "linked-records"
    try:
        linked.symlink_to(external, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    with pytest.raises(
        TelemetryInputError,
        match="input 1 contains a symbolic or reparse link",
    ):
        aggregate_paths([records])


def test_directory_discovery_rejects_nested_reparse_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = tmp_path / "records"
    records.mkdir()
    record_path = records / "record.json"
    record_path.write_text(json.dumps(_record()), encoding="utf-8")
    real_lstat = telemetry.os.lstat
    reparse_flag = 0x400
    monkeypatch.setattr(
        telemetry.stat,
        "FILE_ATTRIBUTE_REPARSE_POINT",
        reparse_flag,
        raising=False,
    )

    def reparse_lstat(path: os.PathLike[str] | str) -> os.stat_result | SimpleNamespace:
        metadata = real_lstat(path)
        if Path(path) == record_path:
            return _changed_stat(metadata, st_file_attributes=reparse_flag)
        return metadata

    monkeypatch.setattr(telemetry.os, "lstat", reparse_lstat)

    with pytest.raises(
        TelemetryInputError,
        match="input 1 contains a symbolic or reparse link",
    ):
        aggregate_paths([records])


def test_tool_vocabulary_tracks_the_frozen_record_contract() -> None:
    assert frozenset(VERDICTS) == CONTRACT_VERDICTS
    assert frozenset(REASON_CODES) == CONTRACT_REASON_CODES
    assert set(ISOLATIONS) == {"not_run", "subprocess", "docker", "gvisor"}
