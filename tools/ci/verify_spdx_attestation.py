# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Validate one pinned ``gh attestation verify`` SPDX result and write a receipt.

This is a bounded semantic adapter for the no-secret F verification job.  The
caller performs the cryptographic provider verification with a pinned GitHub
CLI.  This tool then rejects any successful output that does not bind the exact
pyz subject, retained SPDX predicate, protected E workflow/run, repository
identity, source digest, and GitHub-hosted runner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn

PREDICATE_TYPE = "https://spdx.dev/Document/v2.3"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
FORMAT = "EVOGUARD_GITHUB_SPDX_ATTESTATION_RECEIPT_V1"
MAX_JSON_BYTES = 16 * 1024 * 1024


class VerificationError(ValueError):
    """The retained output does not prove the required SPDX relation."""


def _fail(message: str) -> NoReturn:
    raise VerificationError(message)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _canonical(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _read_regular(path: Path, *, limit: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise VerificationError(f"cannot inspect {label}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > limit
    ):
        _fail(f"{label} is not a bounded single-link regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ):
            _fail(f"{label} changed before reading")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(data) > limit or after.st_size != len(data):
        _fail(f"{label} exceeds its byte limit or changed while reading")
    return data


def _load(data: bytes, *, label: str) -> Any:
    try:
        text = data.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=lambda value: _fail(f"invalid JSON constant: {value}"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"{label} is not strict UTF-8 JSON") from exc


def _exact(value: Mapping[str, Any], keys: set[str], *, label: str) -> None:
    if set(value) != keys:
        _fail(f"{label} keys are not exact")


def _required(value: Mapping[str, Any], keys: set[str], *, label: str) -> None:
    if missing := keys - set(value):
        _fail(f"{label} is missing required keys: {sorted(missing)}")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(
    raw_data: bytes,
    artifact_data: bytes,
    spdx_data: bytes,
    *,
    artifact_name: str,
    spdx_name: str,
    repository: str,
    repository_id: str,
    repository_owner_id: str,
    workflow_path: str,
    source_digest: str,
    run_id: int,
    run_attempt: int,
    event: str,
) -> dict[str, Any]:
    raw = _load(raw_data, label="GitHub SPDX attestation output")
    spdx = _load(spdx_data, label="retained SPDX predicate")
    if not isinstance(spdx, dict) or _canonical(spdx) != spdx_data:
        _fail("retained SPDX predicate must be one canonical JSON object")
    if (
        not isinstance(raw, list)
        or len(raw) != 1
        or not isinstance(raw[0], dict)
    ):
        _fail("GitHub SPDX output must contain exactly one attestation")
    entry = raw[0]
    _exact(entry, {"attestation", "verificationResult"}, label="attestation entry")
    result = entry["verificationResult"]
    if not isinstance(result, dict):
        _fail("verificationResult must be an object")
    _required(
        result,
        {"signature", "verifiedIdentity", "statement"},
        label="verificationResult",
    )
    signature = result["signature"]
    identity = result["verifiedIdentity"]
    statement = result["statement"]
    if not all(isinstance(item, dict) for item in (signature, identity, statement)):
        _fail("signature, verifiedIdentity, and statement must be objects")
    certificate = signature.get("certificate")
    if not isinstance(certificate, dict):
        _fail("signature certificate must be an object")
    signer_base = f"https://github.com/{repository}/{workflow_path}@"
    signer_uri = certificate.get("buildSignerURI")
    if signer_uri not in {signer_base + source_digest, signer_base + "refs/heads/main"}:
        _fail("certificate signer URI is not exact")
    run_uri = (
        f"https://github.com/{repository}/actions/runs/{run_id}/"
        f"attempts/{run_attempt}"
    )
    owner = repository.split("/", 1)[0]
    expected_certificate = {
        "subjectAlternativeName": signer_uri,
        "issuer": OIDC_ISSUER,
        "githubWorkflowTrigger": event,
        "githubWorkflowRepository": repository,
        "githubWorkflowSHA": source_digest,
        "githubWorkflowRef": "refs/heads/main",
        "buildSignerURI": signer_uri,
        "buildSignerDigest": source_digest,
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": f"https://github.com/{repository}",
        "sourceRepositoryDigest": source_digest,
        "sourceRepositoryRef": "refs/heads/main",
        "sourceRepositoryIdentifier": repository_id,
        "sourceRepositoryOwnerURI": f"https://github.com/{owner}",
        "sourceRepositoryOwnerIdentifier": repository_owner_id,
        "sourceRepositoryVisibilityAtSigning": "public",
        "buildConfigURI": signer_uri,
        "buildConfigDigest": source_digest,
        "buildTrigger": event,
        "runInvocationURI": run_uri,
    }
    _required(certificate, set(expected_certificate), label="certificate")
    if any(certificate.get(key) != value for key, value in expected_certificate.items()):
        _fail("certificate does not bind the exact E workflow run")
    _required(
        identity,
        {"subjectAlternativeName", "issuer", "runnerEnvironment"},
        label="verifiedIdentity",
    )
    identity_san = identity["subjectAlternativeName"]
    identity_issuer = identity["issuer"]
    if not isinstance(identity_san, dict) or not isinstance(identity_issuer, dict):
        _fail("verified identity constraints must be objects")
    _exact(
        identity_san,
        {"subjectAlternativeName", "regexp"},
        label="verified identity subject alternative name",
    )
    _exact(
        identity_issuer,
        {"issuer", "regexp"},
        label="verified identity issuer",
    )
    san_pattern = identity_san.get("regexp")
    issuer_pattern = identity_issuer.get("regexp")
    try:
        san_matches = (
            identity_san.get("subjectAlternativeName") == ""
            and isinstance(san_pattern, str)
            and re.fullmatch(san_pattern, signer_uri) is not None
        )
        issuer_matches = (
            identity_issuer.get("issuer") == ""
            and isinstance(issuer_pattern, str)
            and re.fullmatch(issuer_pattern, OIDC_ISSUER) is not None
        )
    except re.error as exc:
        raise VerificationError("verified identity contains an invalid regexp") from exc
    if (
        identity.get("runnerEnvironment") != "github-hosted"
        or not san_matches
        or not issuer_matches
    ):
        _fail("verified identity is not GitHub-hosted")
    _exact(
        statement,
        {"_type", "subject", "predicateType", "predicate"},
        label="statement",
    )
    subject = statement.get("subject")
    expected_subject = {
        "name": artifact_name,
        "digest": {"sha256": _sha(artifact_data)},
    }
    if subject != [expected_subject]:
        _fail("SPDX attestation subject does not bind the exact pyz")
    if (
        statement.get("_type") != "https://in-toto.io/Statement/v1"
        or statement.get("predicateType") != PREDICATE_TYPE
        or statement.get("predicate") != spdx
    ):
        _fail("SPDX attestation predicate does not equal the retained SPDX bytes")
    return {
        "format": FORMAT,
        "artifact": {
            "name": artifact_name,
            "sha256": _sha(artifact_data),
            "size": len(artifact_data),
        },
        "predicate": {
            "name": spdx_name,
            "sha256": _sha(spdx_data),
            "size": len(spdx_data),
            "type": PREDICATE_TYPE,
        },
        "verification_policy": {
            "repository": repository,
            "repository_id": repository_id,
            "repository_owner_id": repository_owner_id,
            "signer_workflow": f"{repository}/{workflow_path}",
            "signer_digest": source_digest,
            "source_ref": "refs/heads/main",
            "source_digest": source_digest,
            "cert_oidc_issuer": OIDC_ISSUER,
            "predicate_type": PREDICATE_TYPE,
            "deny_self_hosted_runners": True,
            "attestation_limit": 1,
        },
        "workflow_run": {
            "id": run_id,
            "attempt": run_attempt,
            "event": event,
        },
        "verification_output": {
            "sha256": _sha(raw_data),
            "size": len(raw_data),
            "verified_attestation_count": 1,
        },
    }


def _write_new(path: Path, data: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written < 1:
                _fail("receipt write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw_output", type=Path)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("spdx", type=Path)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--repository-owner-id", required=True)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--source-digest", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--event", choices=("workflow_dispatch",), required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        raw = _read_regular(
            args.raw_output,
            limit=MAX_JSON_BYTES,
            label="GitHub SPDX attestation output",
        )
        artifact = _read_regular(
            args.artifact,
            limit=64 * 1024 * 1024,
            label="pyz subject",
        )
        spdx = _read_regular(
            args.spdx,
            limit=MAX_JSON_BYTES,
            label="SPDX predicate",
        )
        receipt = verify(
            raw,
            artifact,
            spdx,
            artifact_name=args.artifact.name,
            spdx_name=args.spdx.name,
            repository=args.repository,
            repository_id=args.repository_id,
            repository_owner_id=args.repository_owner_id,
            workflow_path=args.workflow_path,
            source_digest=args.source_digest,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            event=args.event,
        )
        _write_new(args.receipt, _canonical(receipt))
    except (OSError, VerificationError) as exc:
        print(f"spdx-attestation: INVALID: {exc}", file=sys.stderr)
        return 1
    print("spdx-attestation: VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
