# ------------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available - see LICENSE for permitted use.
# Original creator: Mana Alharbi.
# ------------------------------------------------------------------------------
"""Typed application adapters for the Trusted Finalizer CLI command family.

The :mod:`evoom_guard.cli` facade keeps public names, domain imports, and the
historical dependency lookup timing.  This module owns only deterministic
command orchestration and report projection; every effect enters through one
frozen service value.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

_Output = Callable[[str], None]
_ExpectedErrors = tuple[type[Exception], ...]
_Report = dict[str, object]


class _ReadRegularFile(Protocol):
    def __call__(self, path: str, *, limit: int, label: str) -> bytes: ...


class _ReadExternalObject(Protocol):
    def __call__(self, path: str, *, label: str) -> dict[str, Any]: ...


class _BindingsValue(Protocol):
    @property
    def payload(self) -> Mapping[str, Any]: ...


class _DerivedBindingsValue(Protocol):
    @property
    def candidate_sha256(self) -> str: ...

    @property
    def policy_sha256(self) -> str: ...

    @property
    def verifier_pack_sha256(self) -> str | None: ...


class _DeriveBindings(Protocol):
    def __call__(
        self,
        *,
        base_repo: str,
        head_repo: str,
        base_sha: str,
        head_sha: str,
        base_tree_sha: str,
        head_tree_sha: str,
        source: Mapping[str, Any],
        repository: str,
        repository_id: str,
        guard_artifact_sha256: str,
        base_is_bare: bool,
        head_is_bare: bool,
    ) -> _DerivedBindingsValue: ...


class _WriteBindings(Protocol):
    def __call__(
        self,
        bindings: Any,
        *,
        bindings_path: str,
        force: bool,
    ) -> str: ...


class _ReadBindings(Protocol):
    def __call__(self, path: str) -> _BindingsValue: ...


class _ContextFromBindings(Protocol):
    def __call__(
        self,
        bindings: Any,
        record: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]: ...


class _WriteVerifiedContext(Protocol):
    def __call__(
        self,
        bindings: Any,
        record: Mapping[str, Any],
        *,
        source_path: str,
        context_path: str,
        force: bool,
    ) -> tuple[str, str]: ...


class _CreateHandoff(Protocol):
    def __call__(
        self,
        verdict_path: str,
        output_path: str,
        *,
        source: Mapping[str, Any],
        context: Mapping[str, Any],
        force: bool,
    ) -> Mapping[str, Any]: ...


class _FinalizedBundle(Protocol):
    @property
    def bundle_path(self) -> str: ...

    @property
    def manifest(self) -> Mapping[str, Any]: ...


class _SealedFinalizer(Protocol):
    @property
    def decision(self) -> str: ...

    @property
    def finalized(self) -> _FinalizedBundle: ...


class _SealFinalizer(Protocol):
    def __call__(
        self,
        handoff_path: str,
        verdict_path: str,
        output_path: str,
        *,
        expected_source: Mapping[str, Any],
        expected_context: Mapping[str, Any],
        private_key_path: str,
        expected_derivation: Mapping[str, Any] | None,
        materials: Sequence[Any],
        force: bool,
    ) -> _SealedFinalizer: ...


class _VerifiedBundlePayload(Protocol):
    @property
    def manifest(self) -> Mapping[str, Any]: ...

    @property
    def record_report(self) -> Mapping[str, Any]: ...


class _VerifiedFinalizer(Protocol):
    @property
    def decision(self) -> str: ...

    @property
    def bundle(self) -> _VerifiedBundlePayload: ...


class _VerifyFinalized(Protocol):
    def __call__(
        self,
        bundle_path: str,
        *,
        trusted_public_key_path: str,
        expected_source: Mapping[str, Any],
        expected_context: Mapping[str, Any],
    ) -> _VerifiedFinalizer: ...


@dataclass(frozen=True, slots=True)
class SemanticRecordServices:
    """Entry-snapshotted semantic-record dependencies."""

    max_verdict_bytes: int
    read_regular_file: _ReadRegularFile
    load_json_object: Callable[[bytes, str], dict[str, Any]]
    verify_record: Callable[[Mapping[str, Any]], Mapping[str, Any]]


@dataclass(frozen=True, slots=True)
class DeriveBindingsServices:
    """Entry-snapshotted derivation operations and live facade reporting."""

    derivation_format: str
    expected_errors: _ExpectedErrors
    derive_bindings: _DeriveBindings
    write_bindings: _WriteBindings
    machine_report: Callable[[_Output, _Report], None]


@dataclass(frozen=True, slots=True)
class VerifyBindingsServices:
    """Dependencies for binding verification and canonical context output."""

    derivation_format: str
    expected_errors: _ExpectedErrors
    read_bindings: Callable[[str], Any]
    read_semantic_record: Callable[[str], dict[str, Any]]
    context_from_bindings: _ContextFromBindings
    write_verified_context: _WriteVerifiedContext
    machine_report: Callable[[_Output, _Report], None]


@dataclass(frozen=True, slots=True)
class FinalizerHandoffServices:
    """Dependencies for constructing an unsigned trusted handoff."""

    metadata_errors: _ExpectedErrors
    invalid_input_errors: _ExpectedErrors
    operational_errors: _ExpectedErrors
    read_external_object: _ReadExternalObject
    create_handoff: _CreateHandoff
    absolute_path: Callable[[str], str]
    machine_report: Callable[[_Output, _Report], None]


@dataclass(frozen=True, slots=True)
class SealFinalizerServices:
    """Dependencies for sealing a handoff against trusted external inputs."""

    trusted_input_errors: _ExpectedErrors
    invalid_input_errors: _ExpectedErrors
    operational_errors: _ExpectedErrors
    read_external_object: _ReadExternalObject
    read_bindings: _ReadBindings
    parse_materials: Callable[[list[str]], Sequence[Any]]
    seal_finalizer: _SealFinalizer
    machine_report: Callable[[_Output, _Report], None]


@dataclass(frozen=True, slots=True)
class VerifyFinalizedServices:
    """Dependencies for offline verification of one finalized bundle."""

    external_input_errors: _ExpectedErrors
    signing_unavailable_errors: _ExpectedErrors
    invalid_bundle_errors: _ExpectedErrors
    read_external_object: _ReadExternalObject
    verify_finalized: _VerifyFinalized
    machine_report: Callable[[_Output, _Report], None]


def execute_derive_finalizer_bindings(
    args: argparse.Namespace,
    *,
    services: DeriveBindingsServices,
    out: _Output = print,
) -> int:
    """Derive trusted-finalizer values from raw immutable Git objects."""

    source = {
        "pull_request_number": args.pr_number,
        "workflow_run_id": args.run_id,
        "workflow_run_attempt": args.run_attempt,
        "base_sha": args.base_sha,
        "head_sha": args.head_sha,
    }
    expected_errors = services.expected_errors
    try:
        bindings = services.derive_bindings(
            base_repo=args.base_repo,
            head_repo=args.head_repo,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            base_tree_sha=args.base_tree_sha,
            head_tree_sha=args.head_tree_sha,
            source=source,
            repository=args.repository,
            repository_id=args.repository_id,
            guard_artifact_sha256=args.guard_artifact_sha,
            base_is_bare=args.base_bare,
            head_is_bare=args.head_bare,
        )
        output = services.write_bindings(
            bindings,
            bindings_path=args.out,
            force=args.force,
        )
    except expected_errors as exc:
        services.machine_report(
            out,
            {
                "format": services.derivation_format,
                "ok": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    services.machine_report(
        out,
        {
            "format": services.derivation_format,
            "ok": True,
            "status": "DERIVED",
            "bindings": output,
            "candidate_sha256": bindings.candidate_sha256,
            "policy_sha256": bindings.policy_sha256,
            "verifier_pack_sha256": bindings.verifier_pack_sha256,
        },
    )
    return 0


def execute_read_semantic_finalizer_record(
    path: str,
    *,
    services: SemanticRecordServices,
) -> dict[str, Any]:
    """Read and semantically validate one untrusted verdict record."""

    if path == "-":
        raise ValueError("verdict must be a regular JSON file, not standard input")
    data = services.read_regular_file(
        path,
        limit=services.max_verdict_bytes,
        label="verdict",
    )
    record = services.load_json_object(data, "verdict")
    report = services.verify_record(record)
    if not report["ok"]:
        failed = ", ".join(item["id"] for item in report["checks"] if item.get("status") == "fail")
        raise ValueError("verdict record is semantically invalid: " + failed)
    return record


def execute_verify_finalizer_bindings(
    args: argparse.Namespace,
    *,
    services: VerifyBindingsServices,
    out: _Output = print,
) -> int:
    """Compare a semantic record to independently derived raw-Git bindings."""

    expected_errors = services.expected_errors
    try:
        bindings = services.read_bindings(args.bindings)
        record = services.read_semantic_record(args.verdict)
        source, context = services.context_from_bindings(bindings, record)
        source_out, context_out = services.write_verified_context(
            bindings,
            record,
            source_path=args.source_out,
            context_path=args.context_out,
            force=args.force,
        )
    except expected_errors as exc:
        services.machine_report(
            out,
            {
                "format": services.derivation_format,
                "ok": False,
                "status": "MISMATCH",
                "error": str(exc),
            },
        )
        return 1
    services.machine_report(
        out,
        {
            "format": services.derivation_format,
            "ok": True,
            "status": "VERIFIED",
            "source": source,
            "context": context,
            "source_path": source_out,
            "context_path": context_out,
        },
    )
    return 0


def execute_finalizer_handoff(
    args: argparse.Namespace,
    *,
    services: FinalizerHandoffServices,
    out: _Output = print,
) -> int:
    """Bind a semantic re-verification record to trusted metadata."""

    if args.verdict == "-":
        services.machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZER_HANDOFF_V1",
                "ok": False,
                "status": "ERROR",
                "error": "finalizer-handoff verdict must be a regular file, not standard input",
            },
        )
        return 2
    metadata_errors = services.metadata_errors
    try:
        source = services.read_external_object(args.source, label="source")
        context = services.read_external_object(args.context, label="context")
    except metadata_errors as exc:
        services.machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZER_HANDOFF_V1",
                "ok": False,
                "status": "ERROR",
                "error": f"unusable trusted metadata: {exc}",
            },
        )
        return 2
    invalid_input_errors = services.invalid_input_errors
    operational_errors = services.operational_errors
    try:
        handoff = services.create_handoff(
            args.verdict,
            args.out,
            source=source,
            context=context,
            force=args.force,
        )
    except invalid_input_errors as exc:
        services.machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZER_HANDOFF_V1",
                "ok": False,
                "status": "INVALID_INPUT",
                "error": str(exc),
            },
        )
        return 1
    except operational_errors as exc:
        services.machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZER_HANDOFF_V1",
                "ok": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    services.machine_report(
        out,
        {
            "format": "EVOGUARD_TRUSTED_FINALIZER_HANDOFF_V1",
            "ok": True,
            "status": "CREATED",
            "handoff": services.absolute_path(args.out),
            "record_sha256": handoff["record"]["sha256"],
            "source": handoff["source"],
            "context": handoff["context"],
        },
    )
    return 0


def execute_seal_finalizer(
    args: argparse.Namespace,
    *,
    services: SealFinalizerServices,
    out: _Output = print,
) -> int:
    """Seal only a handoff that matches externally re-derived metadata."""

    if args.verdict == "-":
        services.machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": "seal-finalizer verdict must be a regular file, not standard input",
            },
        )
        return 2
    trusted_input_errors = services.trusted_input_errors
    try:
        expected_source = services.read_external_object(
            args.expected_source,
            label="expected source",
        )
        expected_context = services.read_external_object(
            args.expected_context,
            label="expected context",
        )
        expected_derivation = (
            services.read_bindings(args.expected_derivation).payload
            if args.expected_derivation is not None
            else None
        )
        materials = services.parse_materials(args.material)
    except trusted_input_errors as exc:
        services.machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": f"unusable trusted input: {exc}",
            },
        )
        return 2
    invalid_input_errors = services.invalid_input_errors
    operational_errors = services.operational_errors
    try:
        sealed = services.seal_finalizer(
            args.handoff,
            args.verdict,
            args.out,
            expected_source=expected_source,
            expected_context=expected_context,
            private_key_path=args.sign_key,
            expected_derivation=expected_derivation,
            materials=materials,
            force=args.force,
        )
    except invalid_input_errors as exc:
        services.machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
                "ok": False,
                "sealed": False,
                "status": "INVALID_INPUT",
                "error": str(exc),
            },
        )
        return 1
    except operational_errors as exc:
        services.machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    allowed = sealed.decision == "ALLOW"
    services.machine_report(
        out,
        {
            "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
            "ok": allowed,
            "sealed": True,
            "status": "FINALIZED" if allowed else "DENIED",
            "decision": sealed.decision,
            "bundle": sealed.finalized.bundle_path,
            "record_sha256": sealed.finalized.manifest["record"]["sha256"],
            "key_id": sealed.finalized.manifest["authentication"]["key_id"],
        },
    )
    return 0 if allowed or not args.require_pass else 1


def execute_verify_finalized(
    args: argparse.Namespace,
    *,
    services: VerifyFinalizedServices,
    out: _Output = print,
) -> int:
    """Verify one signed finalizer bundle and its anti-replay bindings."""

    external_input_errors = services.external_input_errors
    try:
        expected_source = services.read_external_object(
            args.expected_source,
            label="expected source",
        )
        expected_context = services.read_external_object(
            args.expected_context,
            label="expected context",
        )
    except external_input_errors as exc:
        services.machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZER_VERIFICATION_V1",
                "ok": False,
                "verified": False,
                "status": "INCOMPLETE",
                "error": f"unusable external trust input: {exc}",
            },
        )
        return 2
    signing_unavailable_errors = services.signing_unavailable_errors
    invalid_bundle_errors = services.invalid_bundle_errors
    try:
        verified = services.verify_finalized(
            args.bundle,
            trusted_public_key_path=args.trusted_pub,
            expected_source=expected_source,
            expected_context=expected_context,
        )
    except signing_unavailable_errors as exc:
        services.machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZER_VERIFICATION_V1",
                "ok": False,
                "verified": False,
                "status": "INCOMPLETE",
                "error": str(exc),
            },
        )
        return 2
    except invalid_bundle_errors as exc:
        services.machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZER_VERIFICATION_V1",
                "ok": False,
                "verified": False,
                "status": "INVALID",
                "error": str(exc),
            },
        )
        return 1
    allowed = verified.decision == "ALLOW"
    ok = allowed or not args.require_pass
    services.machine_report(
        out,
        {
            "format": "EVOGUARD_TRUSTED_FINALIZER_VERIFICATION_V1",
            "ok": ok,
            "verified": True,
            "status": "VERIFIED" if ok else "DENIED",
            "decision": verified.decision,
            "key_id": verified.bundle.manifest["authentication"]["key_id"],
            "record": verified.bundle.record_report,
        },
    )
    return 0 if ok else 1
