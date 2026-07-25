"""Deterministic characterization of the GitHub attestation receipt CLI.

This freezes the three public receipt adapters before extraction: entry
snapshots versus live facade helpers, exact argument and provider-isolation
timing, the retained-only offline boundary, exception precedence and identity,
success projection order, partial output residue, reports, and exit codes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from typing import Any

from evoom_guard import cli, github_attestation

BASELINE_COMMIT = "92d92f2afdad27afc35580f035ad393a88d1d610"
SCHEMA_VERSION = "cli-github-attestation-receipt-characterization-v1"
CASE_NAMES = (
    "create_argument_failure_identity",
    "create_domain_error_subclass_precedes_value_error",
    "create_first_path_oserror_is_operational",
    "create_incomplete_isolation_is_rejected",
    "create_isolation_builder_frozen_before_fields",
    "create_isolation_helper_is_live_after_timeout",
    "create_isolation_new_error_falls_to_operational",
    "create_operational_error_preserves_partial_outputs",
    "create_output_failure_identity",
    "create_plain_value_error_is_operational",
    "create_policy_helper_is_live_after_paths",
    "create_policy_helper_value_error_is_operational",
    "create_projection_failure_identity",
    "create_provider_baseexception_identity",
    "create_provider_frozen_before_arguments",
    "create_reporter_frozen_before_projection",
    "create_success_isolated_boundary",
    "create_success_unisolated_boundary",
    "create_timeout_oserror_is_operational",
    "reverify_argument_failure_identity",
    "reverify_domain_error_subclass_precedes_value_error",
    "reverify_first_path_oserror_is_operational",
    "reverify_incomplete_isolation_is_rejected",
    "reverify_isolation_builder_frozen_before_fields",
    "reverify_isolation_helper_is_live_after_timeout",
    "reverify_isolation_new_error_falls_to_operational",
    "reverify_operational_error",
    "reverify_output_failure_identity",
    "reverify_plain_value_error_is_operational",
    "reverify_policy_helper_is_live_after_paths",
    "reverify_policy_helper_value_error_is_operational",
    "reverify_projection_failure_identity",
    "reverify_provider_baseexception_identity",
    "reverify_provider_frozen_before_arguments",
    "reverify_reporter_frozen_before_projection",
    "reverify_success_isolated_boundary",
    "reverify_success_unisolated_boundary",
    "reverify_timeout_oserror_is_operational",
    "verify_argument_failure_identity",
    "verify_domain_error_subclass_precedes_value_error",
    "verify_first_path_oserror_is_operational",
    "verify_operational_error",
    "verify_output_failure_identity",
    "verify_plain_value_error_is_operational",
    "verify_policy_helper_is_live_after_paths",
    "verify_policy_helper_value_error_is_operational",
    "verify_projection_failure_identity",
    "verify_provider_baseexception_identity",
    "verify_provider_frozen_before_arguments",
    "verify_reporter_frozen_before_projection",
    "verify_success_offline_boundary",
)

_POLICY_KWARGS = {
    "repository": "owner/repository",
    "signer_workflow": "owner/repository/.github/workflows/build.yml",
    "signer_digest": "1" * 40,
    "source_ref": "refs/heads/main",
    "source_digest": "2" * 40,
    "cert_oidc_issuer": "https://token.actions.githubusercontent.com",
}
_POLICY_ARGS = {
    "repo": _POLICY_KWARGS["repository"],
    "signer_workflow": _POLICY_KWARGS["signer_workflow"],
    "signer_digest": _POLICY_KWARGS["signer_digest"],
    "source_ref": _POLICY_KWARGS["source_ref"],
    "source_digest": _POLICY_KWARGS["source_digest"],
    "cert_oidc_issuer": _POLICY_KWARGS["cert_oidc_issuer"],
}
_ARTIFACT = {"sha256": "3" * 64, "size": 73}
_POLICY_REPORT = {
    **_POLICY_KWARGS,
    "predicate_type": "https://slsa.dev/provenance/v1",
    "deny_self_hosted_runners": True,
    "attestation_limit": 1,
}
_ONLINE_CONTROL_ARGS = {
    "gh_executable",
    "timeout_seconds",
    "gh_executable_sha256",
    "provider_isolation_uid",
    "provider_isolation_gid",
}
_CREATE_ALLOWED = frozenset(
    {
        "artifact",
        "receipt_out",
        "raw_output_out",
        *tuple(_POLICY_ARGS),
        *_ONLINE_CONTROL_ARGS,
    }
)
_OFFLINE_ALLOWED = frozenset(
    {"receipt", "artifact", "raw_output", *tuple(_POLICY_ARGS)}
)
_REVERIFY_ALLOWED = frozenset(
    {"receipt", "artifact", *tuple(_POLICY_ARGS), *_ONLINE_CONTROL_ARGS}
)


def canonical_json(value: Any) -> str:
    """Return a stable human-readable encoding for failure diffs."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def compact_vector_json(value: dict[str, object]) -> str:
    """Keep fixture metadata readable and each complete case on one line."""

    cases = value["cases"]
    assert isinstance(cases, dict)
    names = sorted(cases)
    lines = [
        "{",
        f'  "baseline_commit": {json.dumps(value["baseline_commit"])},',
        '  "cases": {',
    ]
    for index, name in enumerate(names):
        suffix = "," if index + 1 < len(names) else ""
        encoded = json.dumps(
            cases[name],
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        lines.append(f"    {json.dumps(name)}: {encoded}{suffix}")
    lines.extend(
        [
            "  },",
            f'  "schema_version": {json.dumps(value["schema_version"])}',
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


def _display(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


class _SideEffectNamespace(argparse.Namespace):
    """Log every contract argument read and optionally mutate on one read."""

    def __getattribute__(self, name: str) -> object:
        namespace = object.__getattribute__(self, "__dict__")
        strict_allowed = namespace.get("_strict_allowed")
        if strict_allowed is not None and name not in strict_allowed:
            namespace["_events"].append(f"boundary-violated:{name}")
            raise AssertionError(f"command read unexpected argument attribute {name!r}")
        tracked = namespace.get("_tracked_names", frozenset())
        if name in tracked:
            namespace["_events"].append(f"arg:{name}={_display(namespace[name])}")
            effect = namespace["_property_effects"].pop(name, None)
            if effect is not None:
                effect()
        return super().__getattribute__(name)


class _ForbiddenEnvironment:
    """Fail closed if an adapter consults ambient process environment."""

    def __init__(self, events: list[str]) -> None:
        self._events = events

    def _reject(self, operation: str) -> Any:
        self._events.append(f"environment-boundary-violated:{operation}")
        raise AssertionError(
            f"GitHub receipt CLI adapter read ambient environment via {operation}"
        )

    def __contains__(self, key: object) -> bool:
        return self._reject(f"contains:{key}")

    def __getitem__(self, key: str) -> str:
        return self._reject(f"getitem:{key}")

    def __iter__(self) -> Any:
        return self._reject("iter")

    def __len__(self) -> int:
        return self._reject("len")

    def copy(self) -> dict[str, str]:
        return self._reject("copy")

    def get(self, key: str, default: object = None) -> str | object:
        del default
        return self._reject(f"get:{key}")

    def items(self) -> Any:
        return self._reject("items")

    def keys(self) -> Any:
        return self._reject("keys")


class _AsDictValue:
    def __init__(
        self,
        events: list[str],
        name: str,
        value: dict[str, object],
        *,
        rebind_reporter: Any = None,
        failure: BaseException | None = None,
    ) -> None:
        self._events = events
        self._name = name
        self._value = value
        self._rebind_reporter = rebind_reporter
        self._failure = failure

    def as_dict(self) -> dict[str, object]:
        self._events.append(f"projection:{self._name}.as_dict")
        if self._rebind_reporter is not None:
            self._events.append(f"rebind:reporter-from-{self._name}")
            cli._machine_report = self._rebind_reporter
        if self._failure is not None:
            raise self._failure
        return dict(self._value)


class _CreatedResult:
    def __init__(
        self,
        events: list[str],
        *,
        rebind_reporter: Any = None,
        projection_failure: BaseException | None = None,
    ) -> None:
        self._events = events
        self._rebind_reporter = rebind_reporter
        self._artifact = _AsDictValue(
            events,
            "create.artifact",
            _ARTIFACT,
            failure=projection_failure,
        )
        self._policy = _AsDictValue(events, "create.policy", _POLICY_REPORT)

    @property
    def receipt_path(self) -> str:
        self._events.append("projection:create.receipt_path")
        if self._rebind_reporter is not None:
            self._events.append("rebind:reporter-from-create.receipt_path")
            cli._machine_report = self._rebind_reporter
        return "/outputs/receipt.json"

    @property
    def raw_output_path(self) -> str:
        self._events.append("projection:create.raw_output_path")
        return "/outputs/raw.json"

    @property
    def artifact(self) -> _AsDictValue:
        self._events.append("projection:create.artifact")
        return self._artifact

    @property
    def policy(self) -> _AsDictValue:
        self._events.append("projection:create.policy")
        return self._policy

    @property
    def verified_attestation_count(self) -> int:
        self._events.append("projection:create.verified_attestation_count")
        return 1


class _CheckedResult:
    def __init__(
        self,
        events: list[str],
        name: str,
        *,
        rebind_reporter: Any = None,
        projection_failure: BaseException | None = None,
    ) -> None:
        self._events = events
        self._name = name
        self._artifact = _AsDictValue(
            events,
            f"{name}.artifact",
            _ARTIFACT,
            rebind_reporter=rebind_reporter,
            failure=projection_failure,
        )
        self._policy = _AsDictValue(events, f"{name}.policy", _POLICY_REPORT)

    @property
    def artifact(self) -> _AsDictValue:
        self._events.append(f"projection:{self._name}.artifact")
        return self._artifact

    @property
    def policy(self) -> _AsDictValue:
        self._events.append(f"projection:{self._name}.policy")
        return self._policy

    @property
    def verified_attestation_count(self) -> int:
        self._events.append(
            f"projection:{self._name}.verified_attestation_count"
        )
        return 1


def _args(command_kind: str, events: list[str]) -> _SideEffectNamespace:
    values: dict[str, object] = {
        "artifact": "/inputs/artifact.bin",
        "receipt": "/inputs/receipt.json",
        "receipt_out": "/outputs/receipt.json",
        "raw_output": "/inputs/raw.json",
        "raw_output_out": "/outputs/raw.json",
        **_POLICY_ARGS,
        "gh_executable": "/trusted/bin/gh",
        "timeout_seconds": 47,
        "gh_executable_sha256": None,
        "provider_isolation_uid": None,
        "provider_isolation_gid": None,
        # Sentinels that must never be consulted by these CLI adapters.
        "env": "/forbidden/environment",
        "gh_token": "/forbidden/token",
        "github_token": "/forbidden/token",
        "home": "/forbidden/home",
        "network": "/forbidden/network",
        "xdg_config_home": "/forbidden/config",
    }
    args = _SideEffectNamespace(**values)
    args._events = events
    args._property_effects = {}
    args._strict_allowed = None
    args._tracked_names = frozenset(values)
    return args


def capture_case(case_name: str) -> dict[str, object]:
    """Capture one command through the historical public facade."""

    if case_name not in CASE_NAMES:
        raise ValueError(
            f"unknown GitHub attestation receipt characterization case: {case_name}"
        )

    command_kind = case_name.split("_", 1)[0]
    events: list[str] = []
    calls: list[dict[str, object]] = []
    files: dict[str, str] = {}
    outputs: list[dict[str, object]] = []
    output_sha256: list[str] = []
    args = _args(command_kind, events)

    original_reporter = cli._machine_report
    original_policy_helper = cli._github_attestation_policy_kwargs
    original_isolation_helper = cli._github_attestation_provider_isolation
    original_create = github_attestation.create_github_attestation_receipt
    original_verify = github_attestation.verify_github_attestation_receipt
    original_reverify = github_attestation.reverify_github_attestation_receipt
    original_factory = github_attestation.github_attestation_provider_isolation
    original_error = github_attestation.GitHubAttestationError
    original_format = github_attestation.GITHUB_ATTESTATION_RECEIPT_FORMAT
    original_environment = os.environ

    expected_exception: BaseException | None = None
    output_exception: BaseException | None = None
    projection_exception: BaseException | None = None
    provider_exception: BaseException | None = None
    isolation_objects: list[object] = []

    if case_name.endswith("argument_failure_identity"):
        expected_exception = RuntimeError("argument property failed")
    elif case_name.endswith("provider_baseexception_identity"):
        provider_exception = KeyboardInterrupt("provider interrupted")
        expected_exception = provider_exception
    elif case_name.endswith("projection_failure_identity"):
        projection_exception = RuntimeError("projection failed")
        expected_exception = projection_exception
    elif case_name.endswith("output_failure_identity"):
        output_exception = RuntimeError("output failed")
        expected_exception = output_exception

    def emit(message: str) -> None:
        parsed = json.loads(message)
        assert isinstance(parsed, dict)
        events.append(f"output:{parsed['status']}")
        outputs.append(parsed)
        output_sha256.append(hashlib.sha256(message.encode("utf-8")).hexdigest())
        if output_exception is not None:
            raise output_exception

    def reporter(report_out: Any, value: dict[str, object]) -> None:
        events.append(f"reporter:original:{value['status']}")
        original_reporter(report_out, value)

    def late_reporter(report_out: Any, value: dict[str, object]) -> None:
        events.append(f"reporter:late:{value['status']}")
        original_reporter(report_out, value)

    def fail_argument_property() -> None:
        events.append("argument-property-failure")
        assert expected_exception is not None
        raise expected_exception

    def fail_argument_oserror() -> None:
        events.append("argument-oserror")
        raise OSError("argument I/O failed")

    def rebind_policy_helper() -> None:
        events.append("rebind:policy-helper")
        cli._github_attestation_policy_kwargs = late_policy_helper

    def late_policy_helper(namespace: argparse.Namespace) -> dict[str, str]:
        del namespace
        events.append("policy-helper:late")
        return dict(_POLICY_KWARGS)

    def rebind_failing_policy_helper() -> None:
        events.append("rebind:failing-policy-helper")
        cli._github_attestation_policy_kwargs = failing_policy_helper

    def failing_policy_helper(namespace: argparse.Namespace) -> dict[str, str]:
        del namespace
        events.append("policy-helper:value-error")
        raise ValueError("policy helper failed")

    def rebind_isolation_helper() -> None:
        events.append("rebind:isolation-helper")
        cli._github_attestation_provider_isolation = late_isolation_helper

    def late_isolation_helper(namespace: argparse.Namespace) -> object:
        del namespace
        events.append("isolation-helper:late")
        value = {"isolation": "late-helper"}
        isolation_objects.append(value)
        return value

    def rebind_factory() -> None:
        events.append("rebind:isolation-factory")
        github_attestation.github_attestation_provider_isolation = late_factory

    def late_factory(*factory_args: Any, **factory_kwargs: Any) -> object:
        events.append("isolation-factory:late")
        calls.append(
            {
                "provider": "isolation-late",
                "args": list(factory_args),
                "kwargs": factory_kwargs,
            }
        )
        value = {"isolation": "late-factory"}
        isolation_objects.append(value)
        return value

    class _LateGitHubError(ValueError):
        pass

    class _RebindingGitHubError(original_error):
        def __str__(self) -> str:
            events.append("rebind:reporter-from-error-string")
            cli._machine_report = late_reporter
            return "github attestation rejected"

    def rebind_new_error_before_isolation() -> None:
        events.append("rebind:new-github-error-before-isolation")
        github_attestation.GitHubAttestationError = _LateGitHubError

    def late_create(*provider_args: Any, **provider_kwargs: Any) -> _CreatedResult:
        del provider_args, provider_kwargs
        events.append("provider:create-late")
        return _CreatedResult(events)

    def late_verify(*provider_args: Any, **provider_kwargs: Any) -> _CheckedResult:
        del provider_args, provider_kwargs
        events.append("provider:verify-late")
        return _CheckedResult(events, "verify")

    def late_reverify(*provider_args: Any, **provider_kwargs: Any) -> _CheckedResult:
        del provider_args, provider_kwargs
        events.append("provider:reverify-late")
        return _CheckedResult(events, "reverify")

    def rebind_entry_symbols() -> None:
        events.append(f"rebind:{command_kind}-entry-symbols")
        github_attestation.GITHUB_ATTESTATION_RECEIPT_FORMAT = "LATE_FORMAT"
        github_attestation.GitHubAttestationError = _LateGitHubError
        if command_kind == "create":
            github_attestation.create_github_attestation_receipt = late_create
        elif command_kind == "verify":
            github_attestation.verify_github_attestation_receipt = late_verify
        else:
            github_attestation.reverify_github_attestation_receipt = late_reverify

    if case_name.endswith("argument_failure_identity"):
        first_name = "artifact" if command_kind == "create" else "receipt"
        args._property_effects[first_name] = fail_argument_property
    elif case_name.endswith("first_path_oserror_is_operational"):
        first_name = "artifact" if command_kind == "create" else "receipt"
        args._property_effects[first_name] = fail_argument_oserror
    elif case_name.endswith("provider_frozen_before_arguments"):
        first_name = "artifact" if command_kind == "create" else "receipt"
        args._property_effects[first_name] = rebind_entry_symbols
    elif case_name.endswith("policy_helper_is_live_after_paths"):
        preceding_name = "raw_output_out" if command_kind == "create" else (
            "raw_output" if command_kind == "verify" else "artifact"
        )
        args._property_effects[preceding_name] = rebind_policy_helper
    elif case_name.endswith("policy_helper_value_error_is_operational"):
        preceding_name = "raw_output_out" if command_kind == "create" else (
            "raw_output" if command_kind == "verify" else "artifact"
        )
        args._property_effects[preceding_name] = rebind_failing_policy_helper
    elif case_name.endswith("timeout_oserror_is_operational"):
        args._property_effects["timeout_seconds"] = fail_argument_oserror
    elif case_name.endswith("isolation_helper_is_live_after_timeout"):
        args._property_effects["timeout_seconds"] = rebind_isolation_helper
    elif case_name.endswith("isolation_builder_frozen_before_fields"):
        args.gh_executable_sha256 = "4" * 64
        args.provider_isolation_uid = 2000
        args.provider_isolation_gid = 2001
        args._property_effects["gh_executable_sha256"] = rebind_factory
    elif case_name.endswith("incomplete_isolation_is_rejected"):
        args.gh_executable_sha256 = "4" * 64
    elif case_name.endswith("isolation_new_error_falls_to_operational"):
        args.gh_executable_sha256 = "4" * 64
        args._property_effects["timeout_seconds"] = (
            rebind_new_error_before_isolation
        )
    elif case_name.endswith("success_isolated_boundary"):
        args.gh_executable_sha256 = "4" * 64
        args.provider_isolation_uid = 2000
        args.provider_isolation_gid = 2001

    args._strict_allowed = {
        "create": _CREATE_ALLOWED,
        "verify": _OFFLINE_ALLOWED,
        "reverify": _REVERIFY_ALLOWED,
    }[command_kind]

    def isolation_factory(
        executable_path: str,
        executable_sha256: str,
        *,
        uid: int,
        gid: int,
    ) -> object:
        events.append("isolation-factory:original")
        call = {
            "provider": "isolation",
            "executable_path": executable_path,
            "executable_sha256": executable_sha256,
            "uid": uid,
            "gid": gid,
        }
        calls.append(call)
        value = {
            "executable_path": executable_path,
            "executable_sha256": executable_sha256,
            "uid": uid,
            "gid": gid,
        }
        isolation_objects.append(value)
        return value

    def maybe_raise_provider_error(output_paths: tuple[str, ...] = ()) -> None:
        if case_name.endswith("domain_error_subclass_precedes_value_error"):
            github_attestation.GitHubAttestationError = _LateGitHubError
            github_attestation.GITHUB_ATTESTATION_RECEIPT_FORMAT = "LATE_FORMAT"
            raise _RebindingGitHubError("ignored")
        if case_name.endswith("plain_value_error_is_operational"):
            raise ValueError("plain provider value error")
        if case_name.endswith("operational_error_preserves_partial_outputs"):
            for path in output_paths:
                files[path] = "partial-provider-output"
                events.append(f"io:partial-output:{path}")
            raise OSError("provider I/O failed")
        if case_name.endswith("operational_error"):
            raise OSError("provider I/O failed")
        if provider_exception is not None:
            raise provider_exception

    def create_provider(
        artifact_path: str,
        receipt_path: str,
        raw_output_path: str,
        *,
        repository: str,
        signer_workflow: str,
        signer_digest: str,
        source_ref: str,
        source_digest: str,
        cert_oidc_issuer: str,
        gh_executable: str,
        timeout_seconds: int,
        provider_isolation: object,
    ) -> _CreatedResult:
        events.append("provider:create-original")
        if provider_isolation is not None:
            events.append(
                "provider-isolation:"
                + (
                    "same-identity"
                    if any(provider_isolation is item for item in isolation_objects)
                    else "different-identity"
                )
            )
        calls.append(
            {
                "provider": "create",
                "artifact": artifact_path,
                "receipt_out": receipt_path,
                "raw_output_out": raw_output_path,
                "repository": repository,
                "signer_workflow": signer_workflow,
                "signer_digest": signer_digest,
                "source_ref": source_ref,
                "source_digest": source_digest,
                "cert_oidc_issuer": cert_oidc_issuer,
                "gh_executable": gh_executable,
                "timeout_seconds": timeout_seconds,
                "provider_isolation": provider_isolation,
            }
        )
        maybe_raise_provider_error((raw_output_path, receipt_path))
        files[raw_output_path] = "raw-provider-output"
        events.append(f"io:provider-output:{raw_output_path}")
        files[receipt_path] = "receipt-provider-output"
        events.append(f"io:provider-output:{receipt_path}")
        return _CreatedResult(
            events,
            rebind_reporter=(
                late_reporter
                if case_name == "create_reporter_frozen_before_projection"
                else None
            ),
            projection_failure=projection_exception,
        )

    def verify_provider(
        receipt_path: str,
        artifact_path: str,
        raw_output_path: str,
        *,
        repository: str,
        signer_workflow: str,
        signer_digest: str,
        source_ref: str,
        source_digest: str,
        cert_oidc_issuer: str,
    ) -> _CheckedResult:
        events.append("provider:verify-original")
        calls.append(
            {
                "provider": "verify",
                "receipt": receipt_path,
                "artifact": artifact_path,
                "raw_output": raw_output_path,
                "repository": repository,
                "signer_workflow": signer_workflow,
                "signer_digest": signer_digest,
                "source_ref": source_ref,
                "source_digest": source_digest,
                "cert_oidc_issuer": cert_oidc_issuer,
            }
        )
        maybe_raise_provider_error()
        return _CheckedResult(
            events,
            "verify",
            rebind_reporter=(
                late_reporter
                if case_name == "verify_reporter_frozen_before_projection"
                else None
            ),
            projection_failure=projection_exception,
        )

    def reverify_provider(
        receipt_path: str,
        artifact_path: str,
        *,
        repository: str,
        signer_workflow: str,
        signer_digest: str,
        source_ref: str,
        source_digest: str,
        cert_oidc_issuer: str,
        gh_executable: str,
        timeout_seconds: int,
        provider_isolation: object,
    ) -> _CheckedResult:
        events.append("provider:reverify-original")
        if provider_isolation is not None:
            events.append(
                "provider-isolation:"
                + (
                    "same-identity"
                    if any(provider_isolation is item for item in isolation_objects)
                    else "different-identity"
                )
            )
        calls.append(
            {
                "provider": "reverify",
                "receipt": receipt_path,
                "artifact": artifact_path,
                "repository": repository,
                "signer_workflow": signer_workflow,
                "signer_digest": signer_digest,
                "source_ref": source_ref,
                "source_digest": source_digest,
                "cert_oidc_issuer": cert_oidc_issuer,
                "gh_executable": gh_executable,
                "timeout_seconds": timeout_seconds,
                "provider_isolation": provider_isolation,
            }
        )
        maybe_raise_provider_error()
        return _CheckedResult(
            events,
            "reverify",
            rebind_reporter=(
                late_reporter
                if case_name == "reverify_reporter_frozen_before_projection"
                else None
            ),
            projection_failure=projection_exception,
        )

    cli._machine_report = reporter
    github_attestation.create_github_attestation_receipt = create_provider
    github_attestation.verify_github_attestation_receipt = verify_provider
    github_attestation.reverify_github_attestation_receipt = reverify_provider
    github_attestation.github_attestation_provider_isolation = isolation_factory
    os.environ = _ForbiddenEnvironment(events)  # type: ignore[assignment]  # noqa: B003

    exit_code: int | None = None
    exception: dict[str, object] | None = None
    try:
        command = {
            "create": cli.cmd_github_attestation_receipt,
            "verify": cli.cmd_verify_github_attestation_receipt,
            "reverify": cli.cmd_reverify_github_attestation_receipt,
        }[command_kind]
        exit_code = command(args, out=emit)
    except BaseException as exc:
        exception = {
            "type": type(exc).__name__,
            "message": str(exc),
            "same_identity": exc is expected_exception,
        }
    finally:
        cli._machine_report = original_reporter
        cli._github_attestation_policy_kwargs = original_policy_helper
        cli._github_attestation_provider_isolation = original_isolation_helper
        github_attestation.create_github_attestation_receipt = original_create
        github_attestation.verify_github_attestation_receipt = original_verify
        github_attestation.reverify_github_attestation_receipt = original_reverify
        github_attestation.github_attestation_provider_isolation = original_factory
        github_attestation.GitHubAttestationError = original_error
        github_attestation.GITHUB_ATTESTATION_RECEIPT_FORMAT = original_format
        os.environ = original_environment  # noqa: B003

    return {
        "calls": calls,
        "call_sha256": [
            hashlib.sha256(
                json.dumps(
                    call,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()
            for call in calls
        ],
        "events": events,
        "exception": exception,
        "exit_code": exit_code,
        "files": files,
        "outputs": outputs,
        "output_sha256": output_sha256,
    }


def capture_vector() -> dict[str, object]:
    """Return all cases in stable order."""

    return {
        "baseline_commit": BASELINE_COMMIT,
        "schema_version": SCHEMA_VERSION,
        "cases": {
            case_name: capture_case(case_name)
            for case_name in sorted(CASE_NAMES)
        },
    }


if __name__ == "__main__":
    print(compact_vector_json(capture_vector()), end="")
