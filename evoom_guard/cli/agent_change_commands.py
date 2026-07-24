# ------------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# ------------------------------------------------------------------------------
"""Typed application adapters for the five Agent Change CLI commands.

The package facade owns imports and compatibility lookup timing.  This module
owns only command orchestration and projection, and receives every domain,
filesystem, and reporting effect through explicit services.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

_Output = Callable[[str], None]
_ExpectedErrors = tuple[type[Exception], ...]


class _PayloadValue(Protocol):
    @property
    def payload(self) -> Mapping[str, Any]: ...


class _BindingsValue(Protocol):
    @property
    def candidate_sha256(self) -> str: ...

    @property
    def touched_paths(self) -> Iterable[str]: ...

    @property
    def policy_sha256(self) -> str: ...

    @property
    def verifier_pack_sha256(self) -> str | None: ...


class _GitExecutablePin(Protocol):
    def __call__(self, path: str, expected_sha256: str, /) -> Any: ...


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
        base_is_bare: bool,
        head_is_bare: bool,
        git_executable: Any,
    ) -> _BindingsValue: ...


class _WriteBindings(Protocol):
    def __call__(
        self,
        bindings: Any,
        *,
        bindings_path: str,
        force: bool,
    ) -> str: ...


class _ReadExternalObject(Protocol):
    def __call__(self, path: str, *, label: str) -> dict[str, Any]: ...


class _SealAuthorization(Protocol):
    def __call__(
        self,
        output_path: str,
        *,
        source: Mapping[str, Any],
        scope: Mapping[str, Any],
        required: Mapping[str, Any],
        private_key_path: str,
        force: bool,
    ) -> _PayloadValue: ...


class _FinalizerBindingsValue(Protocol):
    @property
    def payload(self) -> Mapping[str, Any]: ...


class _FinalizedPathValue(Protocol):
    @property
    def bundle_path(self) -> str: ...


class _FinalizedValue(Protocol):
    @property
    def finalized(self) -> _FinalizedPathValue: ...


class _ProposalContract(Protocol):
    @property
    def bindings(self) -> _BindingsValue: ...

    @property
    def proposal(self) -> _PayloadValue: ...


class _SealedFinalizedValue(Protocol):
    @property
    def decision(self) -> str: ...

    @property
    def finalized(self) -> _FinalizedValue: ...

    @property
    def contract(self) -> _ProposalContract: ...


class _SealFinalized(Protocol):
    def __call__(
        self,
        proposal_path: str,
        authorization_path: str,
        handoff_path: str,
        verdict_path: str,
        output_path: str,
        *,
        base_repo: str,
        head_repo: str,
        git_executable: Any,
        base_is_bare: bool,
        head_is_bare: bool,
        expected_authorization_source: Mapping[str, Any],
        authorization_public_key_path: str,
        expected_finalizer_source: Mapping[str, Any],
        expected_context: Mapping[str, Any],
        finalizer_private_key_path: str,
        finalizer_public_key_path: str,
        expected_derivation: Mapping[str, Any],
        force: bool,
    ) -> _SealedFinalizedValue: ...


class _VerifiedFinalizedValue(Protocol):
    @property
    def decision(self) -> str: ...

    @property
    def contract(self) -> _ProposalContract: ...


class _VerifyFinalized(Protocol):
    def __call__(
        self,
        bundle_path: str,
        *,
        trusted_finalizer_public_key_path: str,
        authorization_public_key_path: str,
        expected_authorization_source: Mapping[str, Any],
        expected_finalizer_source: Mapping[str, Any],
        expected_context: Mapping[str, Any],
        expected_bindings: Any,
    ) -> _VerifiedFinalizedValue: ...


@dataclass(frozen=True, slots=True)
class ValidateProposalServices:
    """Entry-snapshotted domain operations and live facade reporting."""

    proposal_format: str
    expected_errors: _ExpectedErrors
    inspect_proposal: Callable[[str], _PayloadValue]
    machine_report: Callable[[_Output, dict[str, object]], None]


@dataclass(frozen=True, slots=True)
class DeriveBindingsServices:
    """Dependencies for deterministic raw-Git binding derivation."""

    bindings_format: str
    expected_errors: _ExpectedErrors
    git_executable_pin: _GitExecutablePin
    derive_bindings: _DeriveBindings
    write_bindings: _WriteBindings
    machine_report: Callable[[_Output, dict[str, object]], None]


@dataclass(frozen=True, slots=True)
class SealAuthorizationServices:
    """Dependencies for authorization input loading and sealing."""

    authorization_format: str
    expected_errors: _ExpectedErrors
    read_external_object: _ReadExternalObject
    seal_authorization: _SealAuthorization
    absolute_path: Callable[[str], str]
    machine_report: Callable[[_Output, dict[str, object]], None]


@dataclass(frozen=True, slots=True)
class SealFinalizedServices:
    """Dependencies for trusted finalizer bundle construction."""

    proposal_format: str
    expected_errors: _ExpectedErrors
    git_executable_pin: _GitExecutablePin
    read_finalizer_bindings: Callable[[str], _FinalizerBindingsValue]
    read_external_object: _ReadExternalObject
    seal_finalized: _SealFinalized
    machine_report: Callable[[_Output, dict[str, object]], None]


@dataclass(frozen=True, slots=True)
class VerifyFinalizedServices:
    """Dependencies for offline finalized-bundle verification."""

    proposal_format: str
    expected_errors: _ExpectedErrors
    read_agent_bindings: Callable[[str], object]
    read_external_object: _ReadExternalObject
    verify_finalized: _VerifyFinalized
    machine_report: Callable[[_Output, dict[str, object]], None]


def execute_validate_agent_change_proposal(
    args: argparse.Namespace,
    *,
    services: ValidateProposalServices,
    out: _Output = print,
) -> int:
    """Validate and project one Agent Change proposal."""

    expected_errors = services.expected_errors
    try:
        proposal = services.inspect_proposal(args.proposal)
    except expected_errors as exc:
        services.machine_report(
            out,
            {
                "format": services.proposal_format,
                "ok": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    services.machine_report(
        out,
        {
            "format": services.proposal_format,
            "ok": True,
            "status": "VALID",
            "source": proposal.payload["source"],
            "producer": proposal.payload["producer"],
            "candidate_sha256": proposal.payload["change"]["candidate_sha256"],
            "touched_paths": proposal.payload["change"]["touched_paths"],
        },
    )
    return 0


def execute_derive_agent_change_bindings(
    args: argparse.Namespace,
    *,
    services: DeriveBindingsServices,
    out: _Output = print,
) -> int:
    """Derive and publish Agent Change raw-Git bindings."""

    expected_errors = services.expected_errors
    try:
        git_executable = services.git_executable_pin(
            args.git_executable,
            args.git_executable_sha256,
        )
        bindings = services.derive_bindings(
            base_repo=args.base_repo,
            head_repo=args.head_repo,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            base_tree_sha=args.base_tree_sha,
            head_tree_sha=args.head_tree_sha,
            base_is_bare=args.base_bare,
            head_is_bare=args.head_bare,
            git_executable=git_executable,
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
                "format": services.bindings_format,
                "ok": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    services.machine_report(
        out,
        {
            "format": services.bindings_format,
            "ok": True,
            "status": "DERIVED",
            "bindings": output,
            "candidate_sha256": bindings.candidate_sha256,
            "touched_paths": list(bindings.touched_paths),
            "policy_sha256": bindings.policy_sha256,
            "verifier_pack_sha256": bindings.verifier_pack_sha256,
        },
    )
    return 0


def execute_seal_agent_change_authorization(
    args: argparse.Namespace,
    *,
    services: SealAuthorizationServices,
    out: _Output = print,
) -> int:
    """Load trusted authorization inputs and seal their exact relation."""

    expected_errors = services.expected_errors
    try:
        source = services.read_external_object(
            args.source,
            label="authorization source",
        )
        scope = services.read_external_object(
            args.scope,
            label="authorization scope",
        )
        required = services.read_external_object(
            args.required,
            label="authorization requirements",
        )
        sealed = services.seal_authorization(
            args.out,
            source=source,
            scope=scope,
            required=required,
            private_key_path=args.sign_key,
            force=args.force,
        )
    except expected_errors as exc:
        services.machine_report(
            out,
            {
                "format": services.authorization_format,
                "ok": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    services.machine_report(
        out,
        {
            "format": services.authorization_format,
            "ok": True,
            "status": "SEALED",
            "authorization": services.absolute_path(args.out),
            "key_id": sealed.payload["authentication"]["key_id"],
            "source": sealed.payload["source"],
            "scope": sealed.payload["scope"],
        },
    )
    return 0


def execute_seal_agent_change_finalized(
    args: argparse.Namespace,
    *,
    services: SealFinalizedServices,
    out: _Output = print,
) -> int:
    """Seal a final Agent Change decision from trusted external bindings."""

    expected_errors = services.expected_errors
    try:
        git_executable = services.git_executable_pin(
            args.git_executable,
            args.git_executable_sha256,
        )
        finalizer_bindings = services.read_finalizer_bindings(args.finalizer_bindings)
        authorization_source = services.read_external_object(
            args.authorization_source,
            label="authorization source",
        )
        expected_source = services.read_external_object(
            args.expected_source,
            label="expected source",
        )
        expected_context = services.read_external_object(
            args.expected_context,
            label="expected context",
        )
        sealed = services.seal_finalized(
            args.proposal,
            args.authorization,
            args.handoff,
            args.verdict,
            args.out,
            base_repo=args.base_repo,
            head_repo=args.head_repo,
            git_executable=git_executable,
            base_is_bare=args.base_bare,
            head_is_bare=args.head_bare,
            expected_authorization_source=authorization_source,
            authorization_public_key_path=args.authorization_pub,
            expected_finalizer_source=expected_source,
            expected_context=expected_context,
            finalizer_private_key_path=args.sign_key,
            finalizer_public_key_path=args.trusted_pub,
            expected_derivation=finalizer_bindings.payload,
            force=args.force,
        )
    except expected_errors as exc:
        services.machine_report(
            out,
            {
                "format": services.proposal_format,
                "ok": False,
                "status": "DENY",
                "error": str(exc),
            },
        )
        return 1
    services.machine_report(
        out,
        {
            "format": services.proposal_format,
            "ok": True,
            "status": "ALLOW",
            "decision": sealed.decision,
            "bundle": sealed.finalized.finalized.bundle_path,
            "candidate_sha256": sealed.contract.bindings.candidate_sha256,
            "touched_paths": list(sealed.contract.bindings.touched_paths),
        },
    )
    return 0


def execute_verify_agent_change_finalized(
    args: argparse.Namespace,
    *,
    services: VerifyFinalizedServices,
    out: _Output = print,
) -> int:
    """Verify a finalized Agent Change bundle against independent inputs."""

    expected_errors = services.expected_errors
    try:
        bindings = services.read_agent_bindings(args.agent_bindings)
        authorization_source = services.read_external_object(
            args.authorization_source,
            label="authorization source",
        )
        expected_source = services.read_external_object(
            args.expected_source,
            label="expected source",
        )
        expected_context = services.read_external_object(
            args.expected_context,
            label="expected context",
        )
        verified = services.verify_finalized(
            args.bundle,
            trusted_finalizer_public_key_path=args.trusted_pub,
            authorization_public_key_path=args.authorization_pub,
            expected_authorization_source=authorization_source,
            expected_finalizer_source=expected_source,
            expected_context=expected_context,
            expected_bindings=bindings,
        )
    except expected_errors as exc:
        services.machine_report(
            out,
            {
                "format": services.proposal_format,
                "ok": False,
                "status": "DENY",
                "error": str(exc),
            },
        )
        return 1
    services.machine_report(
        out,
        {
            "format": services.proposal_format,
            "ok": True,
            "status": "ALLOW",
            "decision": verified.decision,
            "candidate_sha256": verified.contract.bindings.candidate_sha256,
            "touched_paths": list(verified.contract.bindings.touched_paths),
            "claimed_producer": verified.contract.proposal.payload["producer"],
        },
    )
    return 0
