#!/usr/bin/env python3
"""Aggregate local EvoGuard verdict records without copying record evidence.

This tool is deliberately stdlib-only.  It emits counts for fixed categorical
dimensions and summary statistics for one numeric latency field.  It never
copies arbitrary strings, paths, diagnostics, evidence, hashes, commands, or
record identifiers into its output.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import stat
import statistics
import sys
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

OUTPUT_SCHEMA = "evoguard-operational-telemetry-1"
RECORD_SCHEMAS = frozenset({"1.11", "1.12"})
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 10_000
_READ_CHUNK_BYTES = 64 * 1024

VERDICTS = ("PASS", "REJECTED", "FAIL", "ERROR", "TAMPERED")
ISOLATIONS = ("not_run", "subprocess", "docker", "gvisor")
OPERATING_PROFILES = ("local", "protected", "hostile")
REASON_CODES = (
    "tests_passed",
    "protected_harness_edit",
    "tests_failed",
    "no_parseable_edits",
    "unsafe_path",
    "patch_apply_failed",
    "no_test_verdict",
    "junit_exit_mismatch",
    "empty_diff",
    "binary_patch",
    "reverse_apply_failed",
    "no_verifiable_changes",
    "diff_coverage_below_threshold",
    "test_timeout",
    "setup_timeout",
    "setup_failed",
    "assurance_requirement_not_met",
    "fix_not_demonstrated",
    "policy_requirement_unsupported",
    "verifier_pack_identity_mismatch",
    "verifier_pack_invalid",
    "verifier_pack_required",
    "verifier_pack_not_found",
    "verifier_pack_snapshot_changed",
    "candidate_not_exercised",
    "candidate_tree_changed_during_run",
    "test_command_unavailable",
    "runtime_cleanup_failed",
)

_POLICY_VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_RESERVED_POLICY_BUCKETS = frozenset({"other", "unspecified"})
_MISSING = object()


class TelemetryInputError(ValueError):
    """A privacy-safe input error whose message contains no record content."""


def _is_reparse_point(metadata: os.stat_result) -> bool:
    """Return whether Windows metadata identifies a link-like reparse point."""

    attributes = int(getattr(metadata, "st_file_attributes", 0) or 0)
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0) or 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _path_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    """Fields that bind one lstat result to the descriptor opened from its path."""

    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
    )


def _descriptor_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Metadata that must remain stable around the bounded descriptor read."""

    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _reject_constant(_value: str) -> None:
    raise TelemetryInputError("record contains a non-finite JSON number")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise TelemetryInputError("record contains a duplicate JSON key")
        value[key] = item
    return value


def _load_record(path: Path, ordinal: int) -> dict[str, object]:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise TelemetryInputError(f"input {ordinal} is unreadable") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or _is_reparse_point(before)
        or not stat.S_ISREG(before.st_mode)
    ):
        raise TelemetryInputError(f"input {ordinal} is not a regular non-link file")
    if before.st_size > MAX_RECORD_BYTES:
        raise TelemetryInputError(f"input {ordinal} exceeds the record size limit")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise TelemetryInputError(f"input {ordinal} is unreadable") from exc

    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _is_reparse_point(opened):
            raise TelemetryInputError(f"input {ordinal} changed to a non-regular or linked file")
        if _path_identity(opened) != _path_identity(before):
            raise TelemetryInputError(f"input {ordinal} changed while it was opened")
        if opened.st_size > MAX_RECORD_BYTES:
            raise TelemetryInputError(f"input {ordinal} exceeds the record size limit")

        chunks: list[bytes] = []
        bytes_read = 0
        while True:
            remaining = MAX_RECORD_BYTES + 1 - bytes_read
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
            if bytes_read > MAX_RECORD_BYTES:
                raise TelemetryInputError(f"input {ordinal} exceeds the record size limit")

        after = os.fstat(descriptor)
        if _descriptor_identity(after) != _descriptor_identity(opened):
            raise TelemetryInputError(f"input {ordinal} changed while it was read")
        if bytes_read != opened.st_size:
            raise TelemetryInputError(f"input {ordinal} changed while it was read")
        payload = b"".join(chunks).decode("utf-8")
    except TelemetryInputError:
        raise
    except OSError as exc:
        raise TelemetryInputError(f"input {ordinal} is unreadable") from exc
    except UnicodeError as exc:
        raise TelemetryInputError(f"input {ordinal} is not valid UTF-8 JSON") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            raise TelemetryInputError(f"input {ordinal} is unreadable") from exc

    try:
        value = json.loads(
            payload,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except TelemetryInputError:
        raise
    except json.JSONDecodeError as exc:
        raise TelemetryInputError(f"input {ordinal} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise TelemetryInputError(f"input {ordinal} is not a verdict record")
    return value


def discover_record_paths(inputs: Sequence[Path]) -> tuple[Path, ...]:
    """Expand explicit files/directories without following symbolic links."""
    discovered: list[Path] = []
    seen: set[Path] = set()
    for input_ordinal, candidate in enumerate(inputs, 1):
        try:
            candidate_metadata = os.lstat(candidate)
        except OSError as exc:
            raise TelemetryInputError(
                f"input {input_ordinal} does not exist"
            ) from exc
        if (
            stat.S_ISLNK(candidate_metadata.st_mode)
            or _is_reparse_point(candidate_metadata)
        ):
            raise TelemetryInputError(
                f"input {input_ordinal} is a symbolic or reparse link"
            )
        candidates: tuple[Path, ...]
        if stat.S_ISREG(candidate_metadata.st_mode):
            candidates = (candidate,)
        elif stat.S_ISDIR(candidate_metadata.st_mode):
            nested: list[Path] = []

            def traversal_error(
                exc: OSError,
                *,
                ordinal: int = input_ordinal,
            ) -> None:
                raise TelemetryInputError(
                    f"input {ordinal} is unreadable during traversal"
                ) from exc

            for directory, directory_names, file_names in os.walk(
                candidate,
                topdown=True,
                onerror=traversal_error,
                followlinks=False,
            ):
                base = Path(directory)
                try:
                    base_metadata = os.lstat(base)
                except OSError as exc:
                    raise TelemetryInputError(
                        f"input {input_ordinal} changed during traversal"
                    ) from exc
                if (
                    stat.S_ISLNK(base_metadata.st_mode)
                    or _is_reparse_point(base_metadata)
                    or not stat.S_ISDIR(base_metadata.st_mode)
                ):
                    raise TelemetryInputError(
                        f"input {input_ordinal} contains a linked or invalid directory"
                    )
                for name in (*directory_names, *file_names):
                    entry = base / name
                    try:
                        entry_metadata = os.lstat(entry)
                    except OSError as exc:
                        raise TelemetryInputError(
                            f"input {input_ordinal} changed during traversal"
                        ) from exc
                    if (
                        stat.S_ISLNK(entry_metadata.st_mode)
                        or _is_reparse_point(entry_metadata)
                    ):
                        raise TelemetryInputError(
                            f"input {input_ordinal} contains a symbolic or reparse link"
                        )
                directory_names[:] = sorted(directory_names)
                nested.extend(
                    base / name
                    for name in sorted(file_names)
                    if name.lower().endswith(".json")
                )
            candidates = tuple(nested)
        else:
            raise TelemetryInputError(
                f"input {input_ordinal} is not a regular file or directory"
            )

        for path in candidates:
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            discovered.append(path)
            if len(discovered) > MAX_RECORDS:
                raise TelemetryInputError("record count exceeds the safety limit")
    if not discovered:
        raise TelemetryInputError("no verdict records were found")
    return tuple(discovered)


def _validated_policy_allowlist(values: Iterable[str]) -> tuple[str, ...]:
    selected: set[str] = set()
    for value in values:
        if not _POLICY_VERSION_PATTERN.fullmatch(value) or value in _RESERVED_POLICY_BUCKETS:
            raise TelemetryInputError("--allow-policy-version value is invalid")
        selected.add(value)
    return tuple(sorted(selected))


def _record_dimensions(
    record: Mapping[str, object],
    *,
    allowed_policy_versions: frozenset[str],
) -> tuple[str, str, str, str, str, float | None]:
    schema_version = record.get("schema_version")
    if schema_version not in RECORD_SCHEMAS or record.get("tool") != "evoguard":
        raise TelemetryInputError("input is not a supported EvoGuard verdict record")

    verdict = record.get("verdict")
    reason_code = record.get("reason_code")
    isolation = record.get("isolation")
    if verdict not in VERDICTS:
        raise TelemetryInputError("verdict record has an unsupported verdict")
    if reason_code not in REASON_CODES:
        raise TelemetryInputError("verdict record has an unsupported reason code")
    if isolation not in ISOLATIONS:
        raise TelemetryInputError("verdict record has an unsupported isolation")
    assert isinstance(verdict, str)
    assert isinstance(reason_code, str)
    assert isinstance(isolation, str)

    attestation = record.get("attestation")
    if attestation is None:
        return verdict, reason_code, isolation, "unspecified", "unspecified", None
    if not isinstance(attestation, dict):
        raise TelemetryInputError("verdict record has an invalid attestation")

    effective_policy = attestation.get("effective_policy")
    if effective_policy is None:
        effective_policy = {}
    if not isinstance(effective_policy, dict):
        raise TelemetryInputError("verdict record has an invalid effective policy")
    if (
        "operating_profile" in effective_policy
        and schema_version != "1.12"
    ):
        raise TelemetryInputError(
            "operating profile requires verdict-record schema 1.12"
        )

    profile = effective_policy.get("operating_profile", "unspecified")
    if profile not in (*OPERATING_PROFILES, "unspecified"):
        raise TelemetryInputError("verdict record has an unsupported operating profile")
    assert isinstance(profile, str)

    effective_version = effective_policy.get("policy_version", _MISSING)
    attested_version = attestation.get("policy_version", _MISSING)
    if (
        effective_version is not _MISSING
        and attested_version is not _MISSING
        and effective_version != attested_version
    ):
        raise TelemetryInputError("verdict record has conflicting policy versions")
    policy_version = effective_version if effective_version is not _MISSING else attested_version
    if policy_version is _MISSING or policy_version is None:
        policy_bucket = "unspecified"
    elif not isinstance(policy_version, str):
        raise TelemetryInputError("verdict record has an invalid policy version")
    elif policy_version in allowed_policy_versions:
        policy_bucket = policy_version
    else:
        # Never echo an unapproved free-form policy label.  It may contain a
        # path, tenant name, ticket, credential, or other sensitive value.
        policy_bucket = "other"

    latency = attestation.get("runtime_identity_elapsed_ms")
    if latency is None:
        latency_ms = None
    elif (
        isinstance(latency, bool)
        or not isinstance(latency, (int, float))
        or not math.isfinite(latency)
        or latency < 0
    ):
        raise TelemetryInputError("verdict record has invalid latency")
    else:
        latency_ms = float(latency)
    return verdict, reason_code, isolation, profile, policy_bucket, latency_ms


def _fixed_counts(counter: Counter[str], labels: Iterable[str]) -> dict[str, int]:
    return {label: counter[label] for label in labels}


def _latency_summary(samples: Sequence[float]) -> dict[str, float | int] | None:
    if not samples:
        return None
    ordered = sorted(samples)
    p95_index = max(0, math.ceil(len(ordered) * 0.95) - 1)
    return {
        "samples": len(ordered),
        "min": round(ordered[0], 3),
        "mean": round(statistics.fmean(ordered), 3),
        "p50": round(statistics.median(ordered), 3),
        "p95": round(ordered[p95_index], 3),
        "max": round(ordered[-1], 3),
    }


def aggregate_records(
    records: Iterable[Mapping[str, object]],
    *,
    allowed_policy_versions: Iterable[str] = (),
) -> dict[str, object]:
    """Return only allowlisted aggregate dimensions from verdict records."""
    policy_allowlist = _validated_policy_allowlist(allowed_policy_versions)
    allowed_policy_set = frozenset(policy_allowlist)
    verdicts: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    isolations: Counter[str] = Counter()
    profiles: Counter[str] = Counter()
    policy_versions: Counter[str] = Counter()
    latency_samples: list[float] = []

    total = 0
    for record in records:
        (
            verdict,
            reason_code,
            isolation,
            profile,
            policy_version,
            latency_ms,
        ) = _record_dimensions(
            record,
            allowed_policy_versions=allowed_policy_set,
        )
        total += 1
        if total > MAX_RECORDS:
            raise TelemetryInputError("record count exceeds the safety limit")
        verdicts[verdict] += 1
        reasons[reason_code] += 1
        isolations[isolation] += 1
        profiles[profile] += 1
        policy_versions[policy_version] += 1
        if latency_ms is not None:
            latency_samples.append(latency_ms)

    if total == 0:
        raise TelemetryInputError("no verdict records were provided")
    error_count = verdicts["ERROR"]
    return {
        "schema_version": OUTPUT_SCHEMA,
        "records_total": total,
        "counts": {
            "verdict": _fixed_counts(verdicts, VERDICTS),
            "reason_code": _fixed_counts(reasons, REASON_CODES),
            "isolation": _fixed_counts(isolations, ISOLATIONS),
            "operating_profile": _fixed_counts(
                profiles,
                (*OPERATING_PROFILES, "unspecified"),
            ),
            "policy_version": _fixed_counts(
                policy_versions,
                (*policy_allowlist, "other", "unspecified"),
            ),
        },
        "error_abstentions": {
            "count": error_count,
            "rate": error_count / total,
        },
        "latency": {
            "runtime_identity_elapsed_ms": _latency_summary(latency_samples),
            "records_without_measurement": total - len(latency_samples),
        },
    }


def aggregate_paths(
    inputs: Sequence[Path],
    *,
    allowed_policy_versions: Iterable[str] = (),
) -> dict[str, object]:
    paths = discover_record_paths(inputs)
    records = (_load_record(path, ordinal) for ordinal, path in enumerate(paths, 1))
    return aggregate_records(
        records,
        allowed_policy_versions=allowed_policy_versions,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="verdict JSON file or directory of verdict JSON files",
    )
    parser.add_argument(
        "--allow-policy-version",
        action="append",
        default=[],
        metavar="LABEL",
        help=(
            "explicitly permit one low-cardinality policy-version label in output; "
            "unapproved values are counted as 'other'"
        ),
    )
    args = parser.parse_args(argv)
    try:
        result = aggregate_paths(
            args.inputs,
            allowed_policy_versions=args.allow_policy_version,
        )
    except TelemetryInputError as exc:
        print(f"telemetry input error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            result,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
