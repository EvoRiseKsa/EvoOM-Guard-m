#!/usr/bin/env python3
"""Commit, freeze, and score a blind EvoOM Guard evaluation.

The label authority signs a commitment to hidden labels before the execution
party sees them. The execution party verifies and binds that exact commitment,
then freezes exact case-bundle, Guard artifact, policy, baseline-declaration,
and raw-verdict digests. Only after that freeze does the label authority reveal
the labels and salt for scoring.

This tool verifies byte and relation integrity.  It cannot prove that the
people named in the metadata are organizationally independent.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from evoom_guard.domain.verdict import REASON_CODES as RECORD_REASON_CODES
from evoom_guard.policy import effective_policy_sha256
from evoom_guard.record_verifier import verify_record
from evoom_guard.signing import (
    load_signing_key_snapshot,
    public_key_id,
    sign_bytes_with_snapshot,
    verify_bytes_with_key_id,
)
from evoom_guard.strict_json import strict_json_loads

MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
CASE_SCHEMA = "evoguard-blind-case-manifest-v1"
COMMITMENT_SCHEMA = "evoguard-blind-label-commitment-v2"
FROZEN_SCHEMA = "evoguard-blind-predictions-v2"
REPORT_SCHEMA = "evoguard-blind-score-report-v2"
BASELINE_RESULT_SCHEMA = "evoguard-ordinary-ci-result-v2"
LABEL_COMMITMENT_DOMAIN = b"EVOGUARD_BLIND_LABEL_COMMITMENT_V2"
VERDICTS = frozenset({"PASS", "FAIL", "REJECTED", "TAMPERED", "ERROR"})
TRUTHS = frozenset({"accept", "block"})
PREDICTIONS = frozenset({"accept", "block", "abstain"})
PROFILES = frozenset({"local", "protected", "hostile"})
EXECUTION_ERROR_CODES = frozenset(
    {
        "infrastructure_unavailable",
        "invalid_verdict",
        "missing_verdict",
        "runner_crash",
        "runner_timeout",
    }
)
HEX_SHA256 = frozenset("0123456789abcdef")
MAX_SIGNATURE_BYTES = 4096
MAX_BASELINE_TIMEOUT_SECONDS = 24 * 60 * 60
EXECUTION_BINDING_STATUS = "declaration_not_runtime_attestation"


class ProtocolError(ValueError):
    """One protocol input is invalid or contradicts another input."""


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _descriptor_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _path_identity(metadata: os.stat_result) -> tuple[int, ...]:
    # Windows can expose different ctime values through path and descriptor
    # APIs, so ctime is used for descriptor stability but not path binding.
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def _read_regular_bytes(path: Path, *, limit: int, label: str) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise ProtocolError(f"{label} is not a readable regular file: {path}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or _is_reparse_point(before)
        or not stat.S_ISREG(before.st_mode)
    ):
        raise ProtocolError(f"{label} must be a regular non-link file: {path}")
    if before.st_size > limit:
        raise ProtocolError(f"{label} exceeds the {limit}-byte limit")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProtocolError(f"{label} is not a readable regular file: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _is_reparse_point(opened):
            raise ProtocolError(f"{label} is not a regular file: {path}")
        if _path_identity(before) != _path_identity(opened):
            raise ProtocolError(f"{label} changed while it was opened: {path}")
        if opened.st_size > limit:
            raise ProtocolError(f"{label} exceeds the {limit}-byte limit")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(1 << 20, limit + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > limit:
                raise ProtocolError(f"{label} exceeds the {limit}-byte limit")
        after_descriptor = os.fstat(descriptor)
        if _descriptor_identity(after_descriptor) != _descriptor_identity(opened):
            raise ProtocolError(f"{label} changed while it was read: {path}")
        if observed != opened.st_size:
            raise ProtocolError(f"{label} size changed while it was read: {path}")
        try:
            after_path = os.lstat(path)
        except OSError as exc:
            raise ProtocolError(f"{label} path changed while it was read: {path}") from exc
        if (
            stat.S_ISLNK(after_path.st_mode)
            or _is_reparse_point(after_path)
            or _path_identity(after_path) != _path_identity(opened)
        ):
            raise ProtocolError(f"{label} path changed while it was read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and set(value) <= HEX_SHA256
    )


def _is_git_oid(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) in {40, 64}
        and set(value) <= HEX_SHA256
    )


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _framed_digest(domain: bytes, *parts: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(len(domain).to_bytes(8, "big"))
    digest.update(domain)
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.hexdigest()


def _load_object(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular_bytes(path, limit=MAX_JSON_BYTES, label=label)
    try:
        decoded = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProtocolError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(decoded, dict):
        raise ProtocolError(f"{label} must be a JSON object")
    return decoded, raw


def _load_jsonl(path: Path, *, label: str) -> tuple[list[dict[str, Any]], bytes]:
    raw = _read_regular_bytes(path, limit=MAX_JSON_BYTES, label=label)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError(f"{label} is not UTF-8") from exc
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            decoded = strict_json_loads(line)
        except ValueError as exc:
            raise ProtocolError(f"{label} row {number} is not strict JSON: {exc}") from exc
        if not isinstance(decoded, dict):
            raise ProtocolError(f"{label} row {number} must be an object")
        rows.append(decoded)
    if not rows:
        raise ProtocolError(f"{label} is empty")
    return rows, raw


def _expect_exact_keys(
    value: dict[str, Any],
    expected: frozenset[str],
    *,
    label: str,
) -> None:
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ProtocolError(f"{label} keys differ: missing={missing}, extra={extra}")


def _safe_bundle_path(root: Path, relative: object, *, label: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ProtocolError(f"{label}.bundle_file must be a POSIX relative path")
    parsed = PurePosixPath(relative)
    if (
        parsed.is_absolute()
        or not parsed.parts
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        raise ProtocolError(f"{label}.bundle_file is unsafe")
    root_resolved = root.resolve()
    candidate = root.joinpath(*parsed.parts)
    try:
        candidate.resolve().relative_to(root_resolved)
    except ValueError as exc:
        raise ProtocolError(f"{label}.bundle_file escapes the case root") from exc
    return candidate


def _validate_case_manifest(value: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    _expect_exact_keys(
        value,
        frozenset({"schema_version", "evaluation_id", "cases"}),
        label="case manifest",
    )
    if value["schema_version"] != CASE_SCHEMA:
        raise ProtocolError(f"case manifest schema_version must be {CASE_SCHEMA!r}")
    evaluation_id = value["evaluation_id"]
    if not isinstance(evaluation_id, str) or not evaluation_id.strip():
        raise ProtocolError("case manifest evaluation_id must be non-empty")
    cases = value["cases"]
    if not isinstance(cases, list) or not cases:
        raise ProtocolError("case manifest cases must be a non-empty array")
    seen: set[str] = set()
    validated: list[dict[str, Any]] = []
    required = frozenset(
        {
            "id",
            "ecosystem",
            "source_repository",
            "base_commit",
            "head_commit",
            "candidate_sha256",
            "bundle_file",
            "bundle_sha256",
        }
    )
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ProtocolError(f"case manifest cases[{index}] must be an object")
        _expect_exact_keys(case, required, label=f"case manifest cases[{index}]")
        case_id = case["id"]
        if not isinstance(case_id, str) or not case_id.strip():
            raise ProtocolError(f"case manifest cases[{index}].id must be non-empty")
        if case_id in seen:
            raise ProtocolError(f"duplicate case id: {case_id!r}")
        seen.add(case_id)
        for field in ("ecosystem", "source_repository"):
            if not isinstance(case[field], str) or not case[field].strip():
                raise ProtocolError(f"case {case_id!r}.{field} must be non-empty")
        if not _is_git_oid(case["base_commit"]):
            raise ProtocolError(
                f"case {case_id!r}.base_commit must be a lowercase Git object id"
            )
        if case["head_commit"] is not None and not _is_git_oid(case["head_commit"]):
            raise ProtocolError(
                f"case {case_id!r}.head_commit must be a lowercase Git object id or null"
            )
        if not _is_sha256(case["candidate_sha256"]):
            raise ProtocolError(f"case {case_id!r}.candidate_sha256 is invalid")
        if not _is_sha256(case["bundle_sha256"]):
            raise ProtocolError(f"case {case_id!r}.bundle_sha256 is invalid")
        validated.append(case)
    return evaluation_id, validated


def _validate_labels(
    rows: list[dict[str, Any]],
    *,
    case_ids: set[str],
) -> list[dict[str, str]]:
    labels: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, row in enumerate(rows):
        _expect_exact_keys(row, frozenset({"id", "truth"}), label=f"labels row {index + 1}")
        case_id = row["id"]
        truth = row["truth"]
        if not isinstance(case_id, str) or case_id not in case_ids:
            raise ProtocolError(f"labels row {index + 1} has unknown id")
        if case_id in seen:
            raise ProtocolError(f"duplicate label id: {case_id!r}")
        if not isinstance(truth, str) or truth not in TRUTHS:
            raise ProtocolError(f"label {case_id!r} truth must be accept or block")
        seen.add(case_id)
        labels.append({"id": case_id, "truth": truth})
    if seen != case_ids:
        raise ProtocolError(f"labels do not cover every case; missing={sorted(case_ids - seen)}")
    return sorted(labels, key=lambda item: item["id"])


def _render_json(value: object) -> bytes:
    return json.dumps(
        value,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8") + b"\n"


@dataclass
class _ReservedOutput:
    path: Path
    descriptor: int | None


def _reserve_output(path: Path) -> _ReservedOutput:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise ProtocolError(f"refusing to overwrite existing output: {path}") from exc
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or _is_reparse_point(metadata):
        os.close(descriptor)
        raise ProtocolError(f"new output is not a regular file: {path}")
    return _ReservedOutput(path=path, descriptor=descriptor)


def _close_reserved(output: _ReservedOutput) -> None:
    if output.descriptor is None:
        return
    descriptor = output.descriptor
    output.descriptor = None
    os.close(descriptor)


def _write_reserved(output: _ReservedOutput, payload: bytes) -> None:
    if output.descriptor is None:
        raise AssertionError("reserved output is already closed")
    descriptor = output.descriptor
    opened = os.fstat(descriptor)
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]
    os.fsync(descriptor)
    written_metadata = os.fstat(descriptor)
    try:
        at_path = os.lstat(output.path)
    except OSError as exc:
        raise ProtocolError(
            f"output path changed while it was written: {output.path}"
        ) from exc
    if (
        not stat.S_ISREG(written_metadata.st_mode)
        or _is_reparse_point(written_metadata)
        or stat.S_ISLNK(at_path.st_mode)
        or _is_reparse_point(at_path)
        or _path_identity(at_path) != _path_identity(written_metadata)
        or (opened.st_dev, opened.st_ino)
        != (written_metadata.st_dev, written_metadata.st_ino)
    ):
        raise ProtocolError(f"output path changed while it was written: {output.path}")


def _publish_pair(
    payload_path: Path,
    payload: bytes,
    signature_path: Path,
    signature: bytes,
) -> None:
    if payload_path.resolve(strict=False) == signature_path.resolve(strict=False):
        raise ProtocolError("payload and signature outputs must be different paths")
    reserved: list[_ReservedOutput] = []
    try:
        reserved.append(_reserve_output(payload_path))
        reserved.append(_reserve_output(signature_path))
        _write_reserved(reserved[0], payload)
        _write_reserved(reserved[1], signature)
    finally:
        for output in reserved:
            try:
                _close_reserved(output)
            except OSError:
                pass


def _write_new_json(path: Path, value: object) -> None:
    output = _reserve_output(path)
    try:
        _write_reserved(output, _render_json(value))
    finally:
        _close_reserved(output)


def _read_signature(path: Path, *, label: str) -> bytes:
    encoded = _read_regular_bytes(
        path,
        limit=MAX_SIGNATURE_BYTES,
        label=label,
    ).strip()
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ProtocolError(f"{label} is not valid base64") from exc
    if len(signature) != 64:
        raise ProtocolError(f"{label} must decode to a 64-byte Ed25519 signature")
    return signature


def commit_labels(
    case_manifest_path: Path,
    labels_path: Path,
    salt_path: Path,
    output_path: Path,
    *,
    label_authority: str,
    conflict_disclosure: str,
    label_private_key_path: Path,
    signature_output_path: Path,
) -> dict[str, Any]:
    """Create the pre-run public commitment while the salt remains private."""

    manifest, manifest_raw = _load_object(case_manifest_path, label="case manifest")
    evaluation_id, cases = _validate_case_manifest(manifest)
    label_rows, _ = _load_jsonl(labels_path, label="labels")
    labels = _validate_labels(label_rows, case_ids={str(case["id"]) for case in cases})
    salt = _read_regular_bytes(salt_path, limit=4096, label="label salt")
    if len(salt) < 32:
        raise ProtocolError("label salt must contain at least 32 random bytes")
    if not label_authority.strip():
        raise ProtocolError("label_authority must be non-empty")
    if not conflict_disclosure.strip():
        raise ProtocolError("conflict_disclosure must be non-empty")
    manifest_sha256 = _sha256(manifest_raw)
    try:
        signing_key = load_signing_key_snapshot(str(label_private_key_path))
    except (OSError, TypeError, ValueError) as exc:
        raise ProtocolError("the label-authority signing key is unusable") from exc
    commitment = {
        "schema_version": COMMITMENT_SCHEMA,
        "evaluation_id": evaluation_id,
        "case_manifest_sha256": manifest_sha256,
        "case_count": len(cases),
        "labels_commitment_sha256": _framed_digest(
            LABEL_COMMITMENT_DOMAIN,
            bytes.fromhex(manifest_sha256),
            salt,
            _canonical_bytes(labels),
        ),
        "salt_sha256": _sha256(salt),
        "label_authority": label_authority,
        "conflict_disclosure": conflict_disclosure,
        "label_signing_key_id": signing_key.key_id,
    }
    commitment_bytes = _render_json(commitment)
    commitment_signature, _key_id = sign_bytes_with_snapshot(
        commitment_bytes,
        signing_key,
    )
    _publish_pair(
        output_path,
        commitment_bytes,
        signature_output_path,
        base64.b64encode(commitment_signature) + b"\n",
    )
    return commitment


def _validate_commitment(
    commitment: dict[str, Any],
    *,
    evaluation_id: str,
    manifest_sha256: str,
    case_count: int,
) -> str:
    _expect_exact_keys(
        commitment,
        frozenset(
            {
                "schema_version",
                "evaluation_id",
                "case_manifest_sha256",
                "case_count",
                "labels_commitment_sha256",
                "salt_sha256",
                "label_authority",
                "conflict_disclosure",
                "label_signing_key_id",
            }
        ),
        label="label commitment",
    )
    if commitment["schema_version"] != COMMITMENT_SCHEMA:
        raise ProtocolError("unsupported label commitment schema")
    for field in ("label_authority", "conflict_disclosure"):
        if not isinstance(commitment[field], str) or not commitment[field].strip():
            raise ProtocolError(f"label commitment {field} must be non-empty")
    for field in (
        "case_manifest_sha256",
        "labels_commitment_sha256",
        "salt_sha256",
    ):
        if not _is_sha256(commitment[field]):
            raise ProtocolError(f"label commitment {field} is invalid")
    if commitment["evaluation_id"] != evaluation_id:
        raise ProtocolError("label commitment evaluation_id does not match case manifest")
    if commitment["case_manifest_sha256"] != manifest_sha256:
        raise ProtocolError(
            "label commitment does not match exact case manifest bytes"
        )
    if type(commitment["case_count"]) is not int or commitment["case_count"] != case_count:
        raise ProtocolError("label commitment case_count does not match case manifest")
    key_id = commitment["label_signing_key_id"]
    if (
        not isinstance(key_id, str)
        or not key_id.startswith("sha256:")
        or not _is_sha256(key_id.removeprefix("sha256:"))
    ):
        raise ProtocolError("label commitment signing key id is invalid")
    return str(key_id)


def _verify_commitment_signature(
    commitment_raw: bytes,
    signature_path: Path,
    public_key_path: Path,
    *,
    expected_key_id: str,
) -> str:
    signature = _read_signature(signature_path, label="label commitment signature")
    try:
        valid, observed_key_id = verify_bytes_with_key_id(
            commitment_raw,
            signature,
            str(public_key_path),
        )
    except (OSError, TypeError, ValueError) as exc:
        raise ProtocolError(
            "the externally trusted label-authority public key is unusable"
        ) from exc
    if not valid:
        raise ProtocolError("label commitment signature is invalid")
    if observed_key_id != expected_key_id:
        raise ProtocolError(
            "label commitment signing key differs from the externally trusted key"
        )
    return str(observed_key_id)


def _prediction_from_verdict(verdict: str) -> str:
    if verdict == "PASS":
        return "accept"
    if verdict == "ERROR":
        return "abstain"
    return "block"


def _validate_prediction_rows(
    rows: list[dict[str, Any]],
    *,
    case_ids: set[str],
) -> dict[str, dict[str, Any]]:
    expected = frozenset(
        {
            "id",
            "verdict_file",
            "verdict_signature_file",
            "execution_error_code",
            "baseline_result_file",
        }
    )
    validated: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(rows):
        _expect_exact_keys(row, expected, label=f"predictions row {index + 1}")
        case_id = row["id"]
        if not isinstance(case_id, str) or case_id not in case_ids:
            raise ProtocolError(f"predictions row {index + 1} has unknown id")
        if case_id in validated:
            raise ProtocolError(f"duplicate prediction id: {case_id!r}")
        verdict_file = row["verdict_file"]
        verdict_signature_file = row["verdict_signature_file"]
        error_code = row["execution_error_code"]
        if (verdict_file is None) == (error_code is None):
            raise ProtocolError(
                f"prediction {case_id!r} needs exactly one of verdict_file "
                "or execution_error_code"
            )
        if verdict_file is not None and (
            not isinstance(verdict_file, str) or not verdict_file
        ):
            raise ProtocolError(f"prediction {case_id!r}.verdict_file is invalid")
        if verdict_file is None:
            if verdict_signature_file is not None:
                raise ProtocolError(
                    f"prediction {case_id!r}.verdict_signature_file must be null "
                    "when no verdict exists"
                )
        elif not isinstance(verdict_signature_file, str) or not verdict_signature_file:
            raise ProtocolError(
                f"prediction {case_id!r}.verdict_signature_file is required"
            )
        if error_code is not None and error_code not in EXECUTION_ERROR_CODES:
            raise ProtocolError(
                f"prediction {case_id!r}.execution_error_code must be one of "
                f"{sorted(EXECUTION_ERROR_CODES)}"
            )
        baseline_result_file = row["baseline_result_file"]
        if not isinstance(baseline_result_file, str) or not baseline_result_file:
            raise ProtocolError(
                f"prediction {case_id!r}.baseline_result_file is invalid"
            )
        validated[case_id] = row
    if set(validated) != case_ids:
        raise ProtocolError(
            f"predictions do not cover every case; missing={sorted(case_ids - set(validated))}"
        )
    return validated


def _validate_baseline_result(
    value: dict[str, Any],
    *,
    case_id: str,
    case_bundle_sha256: str,
) -> tuple[str, dict[str, Any]]:
    _expect_exact_keys(
        value,
        frozenset(
            {
                "schema_version",
                "case_id",
                "case_bundle_sha256",
                "command_sha256",
                "environment_sha256",
                "toolchain_sha256",
                "timeout_seconds",
                "execution_binding_status",
                "exit_code",
                "execution_error_code",
            }
        ),
        label=f"case {case_id!r} baseline result",
    )
    if value["schema_version"] != BASELINE_RESULT_SCHEMA:
        raise ProtocolError(f"case {case_id!r} baseline result schema is invalid")
    if value["case_id"] != case_id:
        raise ProtocolError(f"case {case_id!r} baseline case_id is inconsistent")
    if value["case_bundle_sha256"] != case_bundle_sha256:
        raise ProtocolError(
            f"case {case_id!r} baseline case bundle digest is inconsistent"
        )
    for field in ("command_sha256", "environment_sha256", "toolchain_sha256"):
        if not _is_sha256(value[field]):
            raise ProtocolError(f"case {case_id!r} baseline {field} is invalid")
    timeout_seconds = value["timeout_seconds"]
    if (
        type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= MAX_BASELINE_TIMEOUT_SECONDS
    ):
        raise ProtocolError(f"case {case_id!r} baseline timeout_seconds is invalid")
    if value["execution_binding_status"] != EXECUTION_BINDING_STATUS:
        raise ProtocolError(
            f"case {case_id!r} baseline execution_binding_status is invalid"
        )
    exit_code = value["exit_code"]
    error_code = value["execution_error_code"]
    if (exit_code is None) == (error_code is None):
        raise ProtocolError(
            f"case {case_id!r} baseline result needs exactly one of exit_code "
            "or execution_error_code"
        )
    if exit_code is not None and (
        type(exit_code) is not int or not 0 <= exit_code <= 255
    ):
        raise ProtocolError(f"case {case_id!r} baseline exit_code is invalid")
    if error_code is not None and error_code not in EXECUTION_ERROR_CODES:
        raise ProtocolError(
            f"case {case_id!r} baseline execution_error_code is invalid"
        )
    prediction = (
        "abstain"
        if error_code is not None
        else "accept"
        if exit_code == 0
        else "block"
    )
    evidence = {
        "case_id": case_id,
        "case_bundle_sha256": case_bundle_sha256,
        "command_sha256": value["command_sha256"],
        "environment_sha256": value["environment_sha256"],
        "toolchain_sha256": value["toolchain_sha256"],
        "timeout_seconds": timeout_seconds,
        "execution_binding_status": EXECUTION_BINDING_STATUS,
        "exit_code": exit_code,
        "execution_error_code": error_code,
    }
    return prediction, evidence


def freeze_predictions(
    case_manifest_path: Path,
    commitment_path: Path,
    commitment_signature_path: Path,
    predictions_path: Path,
    case_root: Path,
    guard_artifact_path: Path,
    policy_path: Path,
    output_path: Path,
    *,
    profile: str,
    baseline_id: str,
    execution_authority: str,
    label_public_key_path: Path,
    verdict_public_key_path: Path,
    execution_private_key_path: Path,
    signature_output_path: Path,
) -> dict[str, Any]:
    """Freeze case inputs and predictions before labels are revealed."""

    manifest, manifest_raw = _load_object(case_manifest_path, label="case manifest")
    evaluation_id, cases = _validate_case_manifest(manifest)
    manifest_sha256 = _sha256(manifest_raw)
    commitment, commitment_raw = _load_object(
        commitment_path,
        label="label commitment",
    )
    label_signing_key_id = _validate_commitment(
        commitment,
        evaluation_id=evaluation_id,
        manifest_sha256=manifest_sha256,
        case_count=len(cases),
    )
    _verify_commitment_signature(
        commitment_raw,
        commitment_signature_path,
        label_public_key_path,
        expected_key_id=label_signing_key_id,
    )
    if profile not in PROFILES:
        raise ProtocolError(f"profile must be one of {sorted(PROFILES)}")
    if baseline_id != "ordinary-ci-exit-v1":
        raise ProtocolError("baseline_id must be 'ordinary-ci-exit-v1'")
    if not execution_authority.strip():
        raise ProtocolError("baseline_id and execution_authority must be non-empty")
    prediction_rows, _ = _load_jsonl(predictions_path, label="predictions")
    predictions = _validate_prediction_rows(
        prediction_rows,
        case_ids={str(case["id"]) for case in cases},
    )
    policy_object, policy_raw = _load_object(policy_path, label="effective policy")
    policy_digest = effective_policy_sha256(policy_object)

    verified_cases: list[dict[str, Any]] = []
    frozen_predictions: list[dict[str, Any]] = []
    verdict_signing_key_id: str | None = None
    guard_version: str | None = None
    for case in sorted(cases, key=lambda item: str(item["id"])):
        case_id = str(case["id"])
        bundle_path = _safe_bundle_path(case_root, case["bundle_file"], label=case_id)
        bundle = _read_regular_bytes(
            bundle_path,
            limit=MAX_ARTIFACT_BYTES,
            label=f"case {case_id!r} bundle",
        )
        observed_bundle_sha = _sha256(bundle)
        if observed_bundle_sha != case["bundle_sha256"]:
            raise ProtocolError(
                f"case {case_id!r} bundle digest mismatch: {observed_bundle_sha}"
            )
        verified_cases.append(
            {
                "id": case_id,
                "bundle_sha256": observed_bundle_sha,
                "bundle_size": len(bundle),
            }
        )

        row = predictions[case_id]
        verdict_file = row["verdict_file"]
        if verdict_file is None:
            verdict = "ERROR"
            reason_code = str(row["execution_error_code"])
            verdict_sha256: str | None = None
            verdict_size: int | None = None
        else:
            verdict_path = Path(verdict_file)
            verdict_object, verdict_raw = _load_object(
                verdict_path, label=f"case {case_id!r} verdict"
            )
            semantic_report = verify_record(verdict_object)
            if semantic_report.get("ok") is not True:
                raise ProtocolError(
                    f"case {case_id!r} verdict fails verify-record semantics"
                )
            signature_path = Path(str(row["verdict_signature_file"]))
            signature = _read_signature(
                signature_path,
                label=f"case {case_id!r} verdict signature",
            )
            try:
                signature_valid, observed_key_id = verify_bytes_with_key_id(
                    verdict_raw,
                    signature,
                    str(verdict_public_key_path),
                )
            except (OSError, TypeError, ValueError) as exc:
                raise ProtocolError(
                    "the externally trusted verdict public key is unusable"
                ) from exc
            if not signature_valid:
                raise ProtocolError(
                    f"case {case_id!r} verdict signature is invalid"
                )
            if verdict_signing_key_id is None:
                verdict_signing_key_id = observed_key_id
            elif verdict_signing_key_id != observed_key_id:
                raise ProtocolError("verdict signing key changed during freeze")

            attestation = verdict_object.get("attestation")
            if not isinstance(attestation, dict):
                raise ProtocolError(f"case {case_id!r} attestation is missing")
            if attestation.get("effective_policy") != policy_object:
                raise ProtocolError(
                    f"case {case_id!r} effective policy differs from --policy"
                )
            if attestation.get("policy_sha256") != policy_digest:
                raise ProtocolError(
                    f"case {case_id!r} policy digest differs from --policy"
                )
            if policy_object.get("operating_profile") != profile:
                raise ProtocolError(
                    f"case {case_id!r} operating profile differs from --profile"
                )
            for field, expected in (
                ("base_sha", case["base_commit"]),
                ("head_sha", case["head_commit"]),
                ("candidate_sha256", case["candidate_sha256"]),
            ):
                if attestation.get(field) != expected:
                    raise ProtocolError(
                        f"case {case_id!r} attestation {field} differs from "
                        "the case manifest"
                    )
            record_guard_version = verdict_object.get("tool_version")
            if not isinstance(record_guard_version, str) or not record_guard_version:
                raise ProtocolError(f"case {case_id!r} Guard version is invalid")
            if guard_version is None:
                guard_version = record_guard_version
            elif guard_version != record_guard_version:
                raise ProtocolError("Guard version changed between case verdicts")
            verdict_value = verdict_object.get("verdict")
            reason_code_value = verdict_object.get("reason_code")
            if not isinstance(verdict_value, str) or verdict_value not in VERDICTS:
                raise ProtocolError(f"case {case_id!r} verdict is invalid")
            if not isinstance(reason_code_value, str) or not reason_code_value:
                raise ProtocolError(f"case {case_id!r} reason_code is invalid")
            if reason_code_value not in RECORD_REASON_CODES:
                raise ProtocolError(
                    f"case {case_id!r} reason_code is outside the record contract"
                )
            verdict = verdict_value
            reason_code = reason_code_value
            verdict_sha256 = _sha256(verdict_raw)
            verdict_size = len(verdict_raw)

        baseline_object, baseline_raw = _load_object(
            Path(str(row["baseline_result_file"])),
            label=f"case {case_id!r} baseline result",
        )
        baseline_prediction, baseline_evidence = (
            _validate_baseline_result(
                baseline_object,
                case_id=case_id,
                case_bundle_sha256=observed_bundle_sha,
            )
        )
        frozen_predictions.append(
            {
                "id": case_id,
                "verdict": verdict,
                "reason_code": reason_code,
                "prediction": _prediction_from_verdict(verdict),
                "baseline_prediction": baseline_prediction,
                "baseline_evidence": baseline_evidence,
                "baseline_result_sha256": _sha256(baseline_raw),
                "baseline_result_size": len(baseline_raw),
                "verdict_sha256": verdict_sha256,
                "verdict_size": verdict_size,
            }
        )

    if verdict_signing_key_id is None:
        raise ProtocolError(
            "at least one signed verdict is required to establish the verdict trust root"
        )
    if guard_version is None:
        raise AssertionError("a signed verdict did not establish Guard version")
    if label_signing_key_id == verdict_signing_key_id:
        raise ProtocolError(
            "label-authority and verdict-finalizer keys must be distinct"
        )
    guard_artifact = _read_regular_bytes(
        guard_artifact_path,
        limit=MAX_ARTIFACT_BYTES,
        label="Guard artifact",
    )
    frozen = {
        "schema_version": FROZEN_SCHEMA,
        "evaluation_id": evaluation_id,
        "created_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        ),
        "case_manifest_sha256": manifest_sha256,
        "label_commitment": {
            "sha256": _sha256(commitment_raw),
            "size": len(commitment_raw),
            "signing_key_id": label_signing_key_id,
        },
        "profile": profile,
        "baseline_id": baseline_id,
        "execution_authority": execution_authority,
        "guard_version": guard_version,
        "verdict_signing_key_id": verdict_signing_key_id,
        "guard_artifact": {
            "sha256": _sha256(guard_artifact),
            "size": len(guard_artifact),
        },
        "policy": {
            "sha256": _sha256(policy_raw),
            "effective_policy_sha256": policy_digest,
            "size": len(policy_raw),
        },
        "verified_cases": verified_cases,
        "predictions": frozen_predictions,
    }
    frozen_bytes = _render_json(frozen)
    try:
        signing_key = load_signing_key_snapshot(str(execution_private_key_path))
        frozen_signature, execution_key_id = sign_bytes_with_snapshot(
            frozen_bytes,
            signing_key,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise ProtocolError("the execution signing key is unusable") from exc
    if execution_key_id in {label_signing_key_id, verdict_signing_key_id}:
        raise ProtocolError(
            "label-authority, verdict-finalizer, and execution-freeze keys "
            "must be distinct"
        )
    _publish_pair(
        output_path,
        frozen_bytes,
        signature_output_path,
        base64.b64encode(frozen_signature) + b"\n",
    )
    return frozen


def _wilson(successes: int, total: int) -> tuple[float, float]:
    if total <= 0:
        return 0.0, 0.0
    z = 1.959963984540054
    proportion = successes / total
    denominator = 1.0 + z * z / total
    centre = (proportion + z * z / (2.0 * total)) / denominator
    margin = (
        z
        * math.sqrt(
            proportion * (1.0 - proportion) / total
            + z * z / (4.0 * total * total)
        )
        / denominator
    )
    return max(0.0, centre - margin), min(1.0, centre + margin)


def _metrics(rows: list[tuple[str, str]]) -> dict[str, int | float]:
    counts = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    abstain_accept = 0
    abstain_block = 0
    for truth, prediction in rows:
        if prediction == "abstain":
            if truth == "block":
                abstain_block += 1
            else:
                abstain_accept += 1
            continue
        predicted_block = prediction == "block"
        key = (
            "tp"
            if truth == "block" and predicted_block
            else "fn"
            if truth == "block"
            else "fp"
            if predicted_block
            else "tn"
        )
        counts[key] += 1
    classified = sum(counts.values())
    abstain = abstain_accept + abstain_block
    total = classified + abstain
    positives = counts["tp"] + counts["fn"]
    negatives = counts["tn"] + counts["fp"]
    accuracy_low, accuracy_high = _wilson(counts["tp"] + counts["tn"], classified)
    fnr_low, fnr_high = _wilson(counts["fn"], positives)
    fpr_low, fpr_high = _wilson(counts["fp"], negatives)
    operational_total = positives + abstain_block
    operational_blocked = counts["tp"] + abstain_block
    return {
        **counts,
        "abstain": abstain,
        "abstain_accept": abstain_accept,
        "abstain_block": abstain_block,
        "classified": classified,
        "total": total,
        "coverage": classified / total,
        "accuracy": (counts["tp"] + counts["tn"]) / classified if classified else 0.0,
        "accuracy_ci95_low": accuracy_low,
        "accuracy_ci95_high": accuracy_high,
        "false_negative_rate": counts["fn"] / positives if positives else 0.0,
        "false_negative_rate_ci95_low": fnr_low,
        "false_negative_rate_ci95_high": fnr_high,
        "false_positive_rate": counts["fp"] / negatives if negatives else 0.0,
        "false_positive_rate_ci95_low": fpr_low,
        "false_positive_rate_ci95_high": fpr_high,
        "operational_block_rate": (
            operational_blocked / operational_total if operational_total else 0.0
        ),
    }


def score_reveal(
    case_manifest_path: Path,
    commitment_path: Path,
    commitment_signature_path: Path,
    frozen_path: Path,
    frozen_signature_path: Path,
    execution_public_key_path: Path,
    label_public_key_path: Path,
    verdict_public_key_path: Path,
    labels_path: Path,
    salt_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Verify the reveal and score Guard and its predeclared baseline."""

    manifest, manifest_raw = _load_object(case_manifest_path, label="case manifest")
    evaluation_id, cases = _validate_case_manifest(manifest)
    commitment, commitment_raw = _load_object(
        commitment_path,
        label="label commitment",
    )
    frozen, frozen_raw = _load_object(frozen_path, label="frozen predictions")
    frozen_signature = _read_signature(
        frozen_signature_path,
        label="frozen predictions signature",
    )
    try:
        frozen_signature_valid, execution_key_id = verify_bytes_with_key_id(
            frozen_raw,
            frozen_signature,
            str(execution_public_key_path),
        )
    except (OSError, TypeError, ValueError) as exc:
        raise ProtocolError(
            "the externally trusted execution public key is unusable"
        ) from exc
    if not frozen_signature_valid:
        raise ProtocolError("frozen predictions signature is invalid")
    try:
        trusted_verdict_key_id = public_key_id(str(verdict_public_key_path))
    except (OSError, TypeError, ValueError) as exc:
        raise ProtocolError(
            "the externally trusted verdict-finalizer public key is unusable"
        ) from exc
    manifest_sha = _sha256(manifest_raw)
    label_signing_key_id = _validate_commitment(
        commitment,
        evaluation_id=evaluation_id,
        manifest_sha256=manifest_sha,
        case_count=len(cases),
    )
    _verify_commitment_signature(
        commitment_raw,
        commitment_signature_path,
        label_public_key_path,
        expected_key_id=label_signing_key_id,
    )

    frozen_keys = frozenset(
        {
            "schema_version",
            "evaluation_id",
            "created_utc",
            "case_manifest_sha256",
            "label_commitment",
            "profile",
            "baseline_id",
            "execution_authority",
            "guard_version",
            "verdict_signing_key_id",
            "guard_artifact",
            "policy",
            "verified_cases",
            "predictions",
        }
    )
    _expect_exact_keys(frozen, frozen_keys, label="frozen predictions")
    if frozen["schema_version"] != FROZEN_SCHEMA:
        raise ProtocolError("unsupported frozen prediction schema")
    if frozen["profile"] not in PROFILES:
        raise ProtocolError("frozen profile is invalid")
    if frozen["baseline_id"] != "ordinary-ci-exit-v1":
        raise ProtocolError("frozen baseline_id is unsupported")
    verdict_signing_key_id = frozen["verdict_signing_key_id"]
    if (
        not isinstance(verdict_signing_key_id, str)
        or not verdict_signing_key_id.startswith("sha256:")
        or not _is_sha256(verdict_signing_key_id.removeprefix("sha256:"))
    ):
        raise ProtocolError("frozen verdict_signing_key_id is invalid")
    if verdict_signing_key_id != trusted_verdict_key_id:
        raise ProtocolError(
            "frozen verdict signing key differs from the externally trusted key"
        )
    if len(
        {label_signing_key_id, trusted_verdict_key_id, execution_key_id}
    ) != 3:
        raise ProtocolError(
            "label-authority, verdict-finalizer, and execution-freeze keys "
            "are not distinct"
        )
    label_commitment_descriptor = frozen["label_commitment"]
    if not isinstance(label_commitment_descriptor, dict):
        raise ProtocolError("frozen label_commitment must be an object")
    _expect_exact_keys(
        label_commitment_descriptor,
        frozenset({"sha256", "size", "signing_key_id"}),
        label="frozen label_commitment",
    )
    if (
        label_commitment_descriptor["sha256"] != _sha256(commitment_raw)
        or label_commitment_descriptor["size"] != len(commitment_raw)
        or label_commitment_descriptor["signing_key_id"] != label_signing_key_id
    ):
        raise ProtocolError(
            "frozen label commitment descriptor does not match the signed commitment"
        )
    for field in (
        "created_utc",
        "baseline_id",
        "execution_authority",
        "guard_version",
    ):
        if not isinstance(frozen[field], str) or not frozen[field].strip():
            raise ProtocolError(f"frozen {field} must be non-empty")
    for field in ("guard_artifact", "policy"):
        descriptor = frozen[field]
        if not isinstance(descriptor, dict):
            raise ProtocolError(f"frozen {field} must be an object")
        expected_descriptor_keys = (
            frozenset({"sha256", "size"})
            if field == "guard_artifact"
            else frozenset({"sha256", "effective_policy_sha256", "size"})
        )
        _expect_exact_keys(
            descriptor,
            expected_descriptor_keys,
            label=f"frozen {field}",
        )
        if not _is_sha256(descriptor["sha256"]):
            raise ProtocolError(f"frozen {field}.sha256 is invalid")
        if field == "policy" and not _is_sha256(
            descriptor["effective_policy_sha256"]
        ):
            raise ProtocolError("frozen policy.effective_policy_sha256 is invalid")
        if type(descriptor["size"]) is not int or descriptor["size"] < 0:
            raise ProtocolError(f"frozen {field}.size is invalid")
    if frozen.get("evaluation_id") != evaluation_id:
        raise ProtocolError("frozen evaluation_id does not match case manifest")
    if frozen.get("case_manifest_sha256") != manifest_sha:
        raise ProtocolError(
            "frozen case_manifest_sha256 does not match exact case manifest bytes"
        )

    label_rows, _ = _load_jsonl(labels_path, label="revealed labels")
    labels = _validate_labels(label_rows, case_ids={str(case["id"]) for case in cases})
    salt = _read_regular_bytes(salt_path, limit=4096, label="revealed label salt")
    if _sha256(salt) != commitment.get("salt_sha256"):
        raise ProtocolError("revealed salt does not match salt_sha256")
    observed_commitment = _framed_digest(
        LABEL_COMMITMENT_DOMAIN,
        bytes.fromhex(manifest_sha),
        salt,
        _canonical_bytes(labels),
    )
    if observed_commitment != commitment.get("labels_commitment_sha256"):
        raise ProtocolError("revealed labels do not match the pre-run commitment")

    verified_cases = frozen["verified_cases"]
    if not isinstance(verified_cases, list):
        raise ProtocolError("frozen verified_cases must be an array")
    manifest_bundle_by_id = {
        str(case["id"]): str(case["bundle_sha256"]) for case in cases
    }
    verified_ids: set[str] = set()
    for index, verified in enumerate(verified_cases):
        if not isinstance(verified, dict):
            raise ProtocolError(f"frozen verified_cases[{index}] must be an object")
        _expect_exact_keys(
            verified,
            frozenset({"id", "bundle_sha256", "bundle_size"}),
            label=f"frozen verified_cases[{index}]",
        )
        case_id = verified["id"]
        if (
            not isinstance(case_id, str)
            or case_id not in manifest_bundle_by_id
            or case_id in verified_ids
        ):
            raise ProtocolError("frozen verified case ids are invalid or duplicated")
        if verified["bundle_sha256"] != manifest_bundle_by_id[case_id]:
            raise ProtocolError(f"frozen case {case_id!r} bundle digest is inconsistent")
        if type(verified["bundle_size"]) is not int or verified["bundle_size"] < 0:
            raise ProtocolError(f"frozen case {case_id!r} bundle size is invalid")
        verified_ids.add(case_id)
    if verified_ids != set(manifest_bundle_by_id):
        raise ProtocolError("frozen verified_cases do not cover the case manifest")

    predictions = frozen["predictions"]
    if not isinstance(predictions, list):
        raise ProtocolError("frozen predictions must be an array")
    prediction_by_id: dict[str, dict[str, Any]] = {}
    prediction_keys = frozenset(
        {
            "id",
            "verdict",
            "reason_code",
            "prediction",
            "baseline_prediction",
            "baseline_evidence",
            "baseline_result_sha256",
            "baseline_result_size",
            "verdict_sha256",
            "verdict_size",
        }
    )
    for index, row in enumerate(predictions):
        if not isinstance(row, dict):
            raise ProtocolError(f"frozen predictions[{index}] must be an object")
        _expect_exact_keys(row, prediction_keys, label=f"frozen predictions[{index}]")
        case_id = row["id"]
        if not isinstance(case_id, str) or case_id in prediction_by_id:
            raise ProtocolError("frozen prediction ids must be unique strings")
        if row["prediction"] not in PREDICTIONS:
            raise ProtocolError(f"frozen prediction {case_id!r} is invalid")
        if row["baseline_prediction"] not in PREDICTIONS:
            raise ProtocolError(f"frozen baseline prediction {case_id!r} is invalid")
        baseline_evidence = row["baseline_evidence"]
        if not isinstance(baseline_evidence, dict):
            raise ProtocolError(
                f"frozen baseline evidence {case_id!r} must be an object"
            )
        baseline_prediction, _validated_baseline = _validate_baseline_result(
            {"schema_version": BASELINE_RESULT_SCHEMA, **baseline_evidence},
            case_id=case_id,
            case_bundle_sha256=manifest_bundle_by_id.get(case_id, ""),
        )
        if row["baseline_prediction"] != baseline_prediction:
            raise ProtocolError(
                f"frozen baseline evidence and prediction contradict for {case_id!r}"
            )
        if (
            not _is_sha256(row["baseline_result_sha256"])
            or type(row["baseline_result_size"]) is not int
            or row["baseline_result_size"] < 0
        ):
            raise ProtocolError(
                f"frozen baseline result descriptor {case_id!r} is invalid"
            )
        verdict = row["verdict"]
        reason_code = row["reason_code"]
        if not isinstance(verdict, str) or verdict not in VERDICTS:
            raise ProtocolError(f"frozen verdict {case_id!r} is invalid")
        if row["prediction"] != _prediction_from_verdict(verdict):
            raise ProtocolError(
                f"frozen verdict and prediction contradict for {case_id!r}"
            )
        if not isinstance(reason_code, str) or (
            reason_code not in RECORD_REASON_CODES
            and reason_code not in EXECUTION_ERROR_CODES
        ):
            raise ProtocolError(f"frozen reason_code {case_id!r} is invalid")
        verdict_sha = row["verdict_sha256"]
        verdict_size = row["verdict_size"]
        if (verdict_sha is None) != (verdict_size is None):
            raise ProtocolError(f"frozen verdict descriptor {case_id!r} is incomplete")
        if verdict_sha is None:
            if verdict != "ERROR" or reason_code not in EXECUTION_ERROR_CODES:
                raise ProtocolError(
                    f"frozen result {case_id!r} without raw bytes must be an "
                    "allowlisted execution error"
                )
        elif (
            not _is_sha256(verdict_sha)
            or type(verdict_size) is not int
            or verdict_size < 0
            or reason_code not in RECORD_REASON_CODES
        ):
            raise ProtocolError(f"frozen verdict descriptor {case_id!r} is invalid")
        prediction_by_id[case_id] = row
    label_by_id = {row["id"]: row["truth"] for row in labels}
    if set(prediction_by_id) != set(label_by_id):
        raise ProtocolError("frozen predictions and revealed labels have different ids")

    scored_cases: list[dict[str, Any]] = []
    guard_rows: list[tuple[str, str]] = []
    baseline_rows: list[tuple[str, str]] = []
    for case_id in sorted(label_by_id):
        truth = label_by_id[case_id]
        prediction = str(prediction_by_id[case_id]["prediction"])
        baseline = str(prediction_by_id[case_id]["baseline_prediction"])
        guard_rows.append((truth, prediction))
        baseline_rows.append((truth, baseline))
        scored_cases.append(
            {
                "id": case_id,
                "truth": truth,
                "guard_prediction": prediction,
                "baseline_prediction": baseline,
                "verdict": prediction_by_id[case_id]["verdict"],
                "reason_code": prediction_by_id[case_id]["reason_code"],
                "verdict_sha256": prediction_by_id[case_id]["verdict_sha256"],
            }
        )
    report = {
        "schema_version": REPORT_SCHEMA,
        "evaluation_id": evaluation_id,
        "case_manifest_sha256": manifest_sha,
        "label_commitment": label_commitment_descriptor,
        "labels_commitment_sha256": commitment["labels_commitment_sha256"],
        "frozen_predictions_sha256": _sha256(frozen_raw),
        "guard_artifact": frozen.get("guard_artifact"),
        "guard_version": frozen.get("guard_version"),
        "policy": frozen.get("policy"),
        "profile": frozen.get("profile"),
        "baseline_id": frozen.get("baseline_id"),
        "label_authority": commitment["label_authority"],
        "execution_authority": frozen.get("execution_authority"),
        "execution_signing_key_id": execution_key_id,
        "label_signing_key_id": label_signing_key_id,
        "verdict_signing_key_id": verdict_signing_key_id,
        "execution_binding_status": (
            "signed_execution_authority_declaration_not_runtime_attestation"
        ),
        "conflict_disclosure": commitment["conflict_disclosure"],
        "independence_status": "externally_declared_not_verified_by_tool",
        "key_separation_status": (
            "distinct_keys_verified_organizational_separation_unverified"
        ),
        "guard_metrics": _metrics(guard_rows),
        "baseline_metrics": _metrics(baseline_rows),
        "cases": scored_cases,
    }
    _write_new_json(output_path, report)
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    commit = subparsers.add_parser("commit-labels")
    commit.add_argument("--cases", required=True, type=Path)
    commit.add_argument("--labels", required=True, type=Path)
    commit.add_argument("--salt", required=True, type=Path)
    commit.add_argument("--out", required=True, type=Path)
    commit.add_argument("--signature-out", required=True, type=Path)
    commit.add_argument("--label-sign-key", required=True, type=Path)
    commit.add_argument("--label-authority", required=True)
    commit.add_argument("--conflict-disclosure", required=True)

    freeze = subparsers.add_parser("freeze-predictions")
    freeze.add_argument("--cases", required=True, type=Path)
    freeze.add_argument("--commitment", required=True, type=Path)
    freeze.add_argument("--commitment-sig", required=True, type=Path)
    freeze.add_argument("--label-pub", required=True, type=Path)
    freeze.add_argument("--predictions", required=True, type=Path)
    freeze.add_argument("--case-root", required=True, type=Path)
    freeze.add_argument("--guard-artifact", required=True, type=Path)
    freeze.add_argument("--policy", required=True, type=Path)
    freeze.add_argument("--profile", required=True, choices=sorted(PROFILES))
    freeze.add_argument("--baseline-id", required=True)
    freeze.add_argument("--execution-authority", required=True)
    freeze.add_argument(
        "--verdict-pub",
        required=True,
        type=Path,
        help="externally trusted verdict-finalizer Ed25519 public key",
    )
    freeze.add_argument(
        "--execution-sign-key",
        required=True,
        type=Path,
        help="execution authority Ed25519 key used only after candidate execution",
    )
    freeze.add_argument("--out", required=True, type=Path)
    freeze.add_argument("--signature-out", required=True, type=Path)

    score = subparsers.add_parser("score-reveal")
    score.add_argument("--cases", required=True, type=Path)
    score.add_argument("--commitment", required=True, type=Path)
    score.add_argument("--commitment-sig", required=True, type=Path)
    score.add_argument("--label-pub", required=True, type=Path)
    score.add_argument(
        "--verdict-pub",
        required=True,
        type=Path,
        help="externally trusted verdict-finalizer Ed25519 public key",
    )
    score.add_argument("--frozen", required=True, type=Path)
    score.add_argument("--frozen-sig", required=True, type=Path)
    score.add_argument("--execution-pub", required=True, type=Path)
    score.add_argument("--labels", required=True, type=Path)
    score.add_argument("--salt", required=True, type=Path)
    score.add_argument("--out", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "commit-labels":
            commit_labels(
                args.cases,
                args.labels,
                args.salt,
                args.out,
                label_authority=args.label_authority,
                conflict_disclosure=args.conflict_disclosure,
                label_private_key_path=args.label_sign_key,
                signature_output_path=args.signature_out,
            )
        elif args.command == "freeze-predictions":
            freeze_predictions(
                args.cases,
                args.commitment,
                args.commitment_sig,
                args.predictions,
                args.case_root,
                args.guard_artifact,
                args.policy,
                args.out,
                profile=args.profile,
                baseline_id=args.baseline_id,
                execution_authority=args.execution_authority,
                label_public_key_path=args.label_pub,
                verdict_public_key_path=args.verdict_pub,
                execution_private_key_path=args.execution_sign_key,
                signature_output_path=args.signature_out,
            )
        else:
            score_reveal(
                args.cases,
                args.commitment,
                args.commitment_sig,
                args.frozen,
                args.frozen_sig,
                args.execution_pub,
                args.label_pub,
                args.verdict_pub,
                args.labels,
                args.salt,
                args.out,
            )
    except (OSError, ProtocolError) as exc:
        print(f"blind evaluation error: {exc}", file=sys.stderr)
        return 2
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
