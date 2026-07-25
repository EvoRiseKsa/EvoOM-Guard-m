"""Deterministic characterization of GitHub attestation admission CLI adapters.

The harness freezes the two public admission commands before their facade
extraction.  It records entry snapshots versus live helpers, eager regular-path
guards, trusted metadata reads, provider isolation timing, exception
precedence, partial output residue, success projection order, and the offline
closed-world boundary of retained-byte verification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from typing import Any

from evoom_guard import (
    artifact_digest_admission,
    cli,
    github_attestation,
    signing,
)

BASELINE_COMMIT = "28ddb67b52d259458796fd2ac4d47807491365c0"
SCHEMA_VERSION = "cli-github-attestation-admission-characterization-v1"

SEAL_REGULAR_PATH_CASES = {
    "seal_artifact_stdin_short_circuit": "artifact",
    "seal_finalizer_bundle_stdin_short_circuit": "finalizer_bundle",
    "seal_receipt_out_stdin_short_circuit": "receipt_out",
    "seal_raw_output_out_stdin_short_circuit": "raw_output_out",
    "seal_out_stdin_short_circuit": "out",
    "seal_finalizer_pub_stdin_short_circuit": "finalizer_pub",
    "seal_sign_key_stdin_short_circuit": "sign_key",
}
VERIFY_REGULAR_PATH_CASES = {
    "verify_binding_stdin_short_circuit": "binding",
    "verify_artifact_stdin_short_circuit": "artifact",
    "verify_receipt_stdin_short_circuit": "receipt",
    "verify_raw_output_stdin_short_circuit": "raw_output",
    "verify_finalizer_bundle_stdin_short_circuit": "finalizer_bundle",
    "verify_trusted_pub_stdin_short_circuit": "trusted_pub",
    "verify_finalizer_pub_stdin_short_circuit": "finalizer_pub",
}

_SEAL_CASES = (
    *SEAL_REGULAR_PATH_CASES,
    "seal_success_unisolated_boundary",
    "seal_success_isolated_boundary",
    "seal_regular_path_failure_identity",
    "seal_guard_reporter_is_live_after_paths",
    "seal_source_property_rebinds_reader",
    "seal_context_property_rebinds_reader",
    "seal_source_read_error",
    "seal_context_read_error",
    "seal_metadata_value_error_is_metadata_error",
    "seal_provider_frozen_before_arguments",
    "seal_format_frozen_before_arguments",
    "seal_github_error_class_frozen_before_arguments",
    "seal_signing_error_class_frozen_before_arguments",
    "seal_policy_helper_is_live_after_positionals",
    "seal_policy_helper_value_error_is_operational",
    "seal_policy_helper_baseexception_identity",
    "seal_isolation_helper_is_live_after_timeout",
    "seal_isolation_builder_frozen_before_fields",
    "seal_incomplete_isolation_is_rejected",
    "seal_isolation_new_error_falls_to_operational",
    "seal_domain_error_subclass_precedes_value_error",
    "seal_plain_value_error_is_operational",
    "seal_oserror_is_operational",
    "seal_operational_error_preserves_partial_outputs",
    "seal_provider_baseexception_identity",
    "seal_projection_failure_identity",
    "seal_output_failure_identity",
    "seal_reporter_frozen_before_projection",
    "seal_repeated_projection_order",
    "seal_no_force_closed_world",
    "seal_argument_baseexception_identity",
)
_VERIFY_CASES = (
    *VERIFY_REGULAR_PATH_CASES,
    "verify_success_offline_boundary",
    "verify_regular_path_failure_identity",
    "verify_guard_reporter_is_live_after_paths",
    "verify_source_property_rebinds_reader",
    "verify_context_property_rebinds_reader",
    "verify_source_read_error",
    "verify_context_read_error",
    "verify_metadata_value_error_is_metadata_error",
    "verify_provider_frozen_before_arguments",
    "verify_format_frozen_before_arguments",
    "verify_github_error_class_frozen_before_arguments",
    "verify_signing_error_class_frozen_before_arguments",
    "verify_policy_helper_is_live_after_positionals",
    "verify_policy_helper_value_error_is_operational",
    "verify_policy_helper_baseexception_identity",
    "verify_domain_error_subclass_precedes_value_error",
    "verify_plain_value_error_is_operational",
    "verify_oserror_is_operational",
    "verify_provider_baseexception_identity",
    "verify_projection_failure_identity",
    "verify_output_failure_identity",
    "verify_reporter_frozen_before_projection",
    "verify_repeated_projection_order",
    "verify_no_live_provider_or_force_closed_world",
    "verify_argument_baseexception_identity",
)
CASE_NAMES = (*_SEAL_CASES, *_VERIFY_CASES)

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
_SUBJECT = {"name": "artifact.bin", "digest": {"sha256": "3" * 64}}
_PROVENANCE = {"receipt_sha256": "4" * 64, "raw_output_sha256": "5" * 64}
_FINALIZER = {"decision": "ALLOW", "record_sha256": "6" * 64}
_AUTHENTICATION = {"algorithm": "ed25519", "key_id": "key-" + "7" * 16}
_EXPECTED_SOURCE = {"repository": "owner/repository", "commit": "8" * 40}
_EXPECTED_CONTEXT = {"workflow": "trusted-finalizer", "run_id": 73}

_ONLINE_CONTROL_ARGS = {
    "gh_executable",
    "timeout_seconds",
    "gh_executable_sha256",
    "provider_isolation_uid",
    "provider_isolation_gid",
}
SEAL_ALLOWED = frozenset(
    {
        "artifact",
        "finalizer_bundle",
        "receipt_out",
        "raw_output_out",
        "out",
        "finalizer_pub",
        "sign_key",
        "expected_source",
        "expected_context",
        *tuple(_POLICY_ARGS),
        *_ONLINE_CONTROL_ARGS,
    }
)
VERIFY_ALLOWED = frozenset(
    {
        "binding",
        "artifact",
        "receipt",
        "raw_output",
        "finalizer_bundle",
        "trusted_pub",
        "finalizer_pub",
        "expected_source",
        "expected_context",
        *tuple(_POLICY_ARGS),
    }
)


def canonical_json(value: Any) -> str:
    """Return a stable human-readable encoding for assertion diffs."""

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
    """Log contract reads and fail on every undeclared facade dependency."""

    def __getattribute__(self, name: str) -> object:
        namespace = object.__getattribute__(self, "__dict__")
        strict_allowed = namespace.get("_strict_allowed")
        if strict_allowed is not None and name not in strict_allowed:
            namespace["_events"].append(f"boundary-violated:{name}")
            raise AssertionError(f"command read unexpected argument attribute {name!r}")
        tracked = namespace.get("_tracked_names", frozenset())
        if name in tracked:
            namespace["_events"].append(f"arg:{name}={_display(namespace[name])}")
            counts = namespace["_read_counts"]
            counts[name] = counts.get(name, 0) + 1
            effect = namespace["_property_effects"].pop((name, counts[name]), None)
            if effect is None:
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
            f"GitHub admission CLI adapter read ambient environment via {operation}"
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
        failure: BaseException | None = None,
    ) -> None:
        self._events = events
        self._name = name
        self._value = value
        self._failure = failure

    def as_dict(self) -> dict[str, object]:
        self._events.append(f"projection:{self._name}.as_dict")
        if self._failure is not None:
            raise self._failure
        return dict(self._value)


class _ReceiptResult:
    def __init__(
        self,
        events: list[str],
        name: str,
        *,
        projection_failure: BaseException | None = None,
    ) -> None:
        self._events = events
        self._name = name
        self._artifact = _AsDictValue(
            events,
            f"{name}.artifact",
            _ARTIFACT,
            failure=projection_failure,
        )
        self._policy = _AsDictValue(events, f"{name}.policy", _POLICY_REPORT)

    @property
    def receipt_path(self) -> str:
        self._events.append(f"projection:{self._name}.receipt_path")
        return "/outputs/receipt.json"

    @property
    def raw_output_path(self) -> str:
        self._events.append(f"projection:{self._name}.raw_output_path")
        return "/outputs/raw.json"

    @property
    def artifact(self) -> _AsDictValue:
        self._events.append(f"projection:{self._name}.artifact")
        return self._artifact

    @property
    def policy(self) -> _AsDictValue:
        self._events.append(f"projection:{self._name}.policy")
        return self._policy


class _InspectionResult:
    def __init__(self, events: list[str], name: str) -> None:
        self._events = events
        self._name = name

    @property
    def finalizer(self) -> dict[str, object]:
        self._events.append(f"projection:{self._name}.finalizer")
        return dict(_FINALIZER)

    @property
    def payload(self) -> dict[str, object]:
        self._events.append(f"projection:{self._name}.payload")
        return {"authentication": dict(_AUTHENTICATION)}


class _AdmissionResult:
    def __init__(self, events: list[str], name: str) -> None:
        self._events = events
        self._name = name
        self._subject = _AsDictValue(events, f"{name}.subject", _SUBJECT)
        self._provenance = _AsDictValue(
            events,
            f"{name}.provenance_reference",
            _PROVENANCE,
        )
        self._inspection = _InspectionResult(events, f"{name}.inspection")

    @property
    def binding_path(self) -> str:
        self._events.append(f"projection:{self._name}.binding_path")
        return "/outputs/binding.json"

    @property
    def subject(self) -> _AsDictValue:
        self._events.append(f"projection:{self._name}.subject")
        return self._subject

    @property
    def provenance_reference(self) -> _AsDictValue:
        self._events.append(f"projection:{self._name}.provenance_reference")
        return self._provenance

    @property
    def payload(self) -> dict[str, object]:
        self._events.append(f"projection:{self._name}.payload")
        return {
            "finalizer": dict(_FINALIZER),
            "authentication": dict(_AUTHENTICATION),
        }

    @property
    def inspection(self) -> _InspectionResult:
        self._events.append(f"projection:{self._name}.inspection")
        return self._inspection


class _CombinedResult:
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
        self._rebind_reporter = rebind_reporter
        self._receipt = _ReceiptResult(
            events,
            f"{name}.receipt",
            projection_failure=projection_failure,
        )
        self._admission = _AdmissionResult(events, f"{name}.admission")

    @property
    def receipt(self) -> _ReceiptResult:
        self._events.append(f"projection:{self._name}.receipt")
        if self._rebind_reporter is not None:
            self._events.append(f"rebind:reporter-from-{self._name}.receipt")
            cli._machine_report = self._rebind_reporter
        return self._receipt

    @property
    def admission(self) -> _AdmissionResult:
        self._events.append(f"projection:{self._name}.admission")
        return self._admission


def _args(events: list[str]) -> _SideEffectNamespace:
    values: dict[str, object] = {
        "artifact": "/inputs/artifact.bin",
        "finalizer_bundle": "/inputs/finalizer.json",
        "receipt_out": "/outputs/receipt.json",
        "raw_output_out": "/outputs/raw.json",
        "out": "/outputs/binding.json",
        "finalizer_pub": "/trusted/finalizer.pub",
        "sign_key": "/trusted/admission.key",
        "binding": "/inputs/binding.json",
        "receipt": "/inputs/receipt.json",
        "raw_output": "/inputs/raw.json",
        "trusted_pub": "/trusted/admission.pub",
        "expected_source": "/trusted/source.json",
        "expected_context": "/trusted/context.json",
        **_POLICY_ARGS,
        "gh_executable": "/trusted/bin/gh",
        "timeout_seconds": 47,
        "gh_executable_sha256": None,
        "provider_isolation_uid": None,
        "provider_isolation_gid": None,
        # Existing sentinels must remain unreadable from these public adapters.
        "force": True,
        "allow_overwrite": True,
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
    args._read_counts = {}
    args._strict_allowed = None
    args._tracked_names = frozenset(values)
    return args


def capture_case(case_name: str) -> dict[str, object]:
    """Capture one command through the historical public facade."""

    if case_name not in CASE_NAMES:
        raise ValueError(
            f"unknown GitHub attestation admission characterization case: {case_name}"
        )

    command_kind = case_name.split("_", 1)[0]
    events: list[str] = []
    calls: list[dict[str, object]] = []
    files: dict[str, str] = {}
    outputs: list[dict[str, object]] = []
    output_sha256: list[str] = []
    isolation_objects: list[object] = []
    args = _args(events)

    original_reporter = cli._machine_report
    original_reader = cli._read_external_finalizer_object
    original_policy_helper = cli._github_attestation_policy_kwargs
    original_isolation_helper = cli._github_attestation_provider_isolation
    original_seal = github_attestation.seal_github_attestation_admission
    original_verify = github_attestation.verify_github_attestation_admission
    original_factory = github_attestation.github_attestation_provider_isolation
    original_error = github_attestation.GitHubAttestationError
    original_format = artifact_digest_admission.ARTIFACT_DIGEST_BINDING_FORMAT
    original_signing_error = signing.SigningUnavailableError
    original_environment = os.environ

    expected_exception: BaseException | None = None
    output_exception: BaseException | None = None
    projection_exception: BaseException | None = None
    provider_exception: BaseException | None = None

    if case_name.endswith("regular_path_failure_identity"):
        expected_exception = RuntimeError("regular path property failed")
    elif case_name.endswith("argument_baseexception_identity"):
        expected_exception = KeyboardInterrupt("argument property interrupted")
    elif case_name.endswith("policy_helper_baseexception_identity"):
        expected_exception = SystemExit("policy helper interrupted")
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

    def reader(path: str, *, label: str) -> dict[str, object]:
        events.append(f"reader:original:{label}:{path}")
        if case_name.endswith("source_read_error") and label == "expected source":
            raise OSError("source metadata read failed")
        if case_name.endswith("context_read_error") and label == "expected context":
            raise UnicodeError("context metadata decode failed")
        return (
            dict(_EXPECTED_SOURCE)
            if label == "expected source"
            else dict(_EXPECTED_CONTEXT)
        )

    def late_reader(path: str, *, label: str) -> dict[str, object]:
        events.append(f"reader:late:{label}:{path}")
        value = (
            dict(_EXPECTED_SOURCE)
            if label == "expected source"
            else dict(_EXPECTED_CONTEXT)
        )
        value["reader"] = "late"
        return value

    def fail_regular_path() -> None:
        events.append("argument-property-failure")
        assert expected_exception is not None
        raise expected_exception

    def fail_argument_baseexception() -> None:
        events.append("argument-property-baseexception")
        assert expected_exception is not None
        raise expected_exception

    def fail_metadata_value_error() -> None:
        events.append("metadata-property-value-error")
        raise ValueError("metadata path failed")

    def rebind_reporter() -> None:
        events.append("rebind:reporter-from-regular-path")
        cli._machine_report = late_reporter

    def rebind_reader() -> None:
        events.append("rebind:metadata-reader")
        cli._read_external_finalizer_object = late_reader

    def policy_helper(namespace: argparse.Namespace) -> dict[str, str]:
        assert namespace is args
        events.append("policy-helper:original")
        return dict(_POLICY_KWARGS)

    def late_policy_helper(namespace: argparse.Namespace) -> dict[str, str]:
        assert namespace is args
        events.append("policy-helper:late")
        return dict(_POLICY_KWARGS)

    def failing_policy_helper(namespace: argparse.Namespace) -> dict[str, str]:
        assert namespace is args
        events.append("policy-helper:value-error")
        raise ValueError("policy helper failed")

    def interrupted_policy_helper(namespace: argparse.Namespace) -> dict[str, str]:
        assert namespace is args
        events.append("policy-helper:baseexception")
        assert expected_exception is not None
        raise expected_exception

    def rebind_policy_helper() -> None:
        events.append("rebind:policy-helper")
        cli._github_attestation_policy_kwargs = late_policy_helper

    def rebind_failing_policy_helper() -> None:
        events.append("rebind:failing-policy-helper")
        cli._github_attestation_policy_kwargs = failing_policy_helper

    def rebind_interrupted_policy_helper() -> None:
        events.append("rebind:interrupted-policy-helper")
        cli._github_attestation_policy_kwargs = interrupted_policy_helper

    def isolation_helper(namespace: argparse.Namespace) -> object | None:
        events.append("isolation-helper:original")
        return original_isolation_helper(namespace)

    def late_isolation_helper(namespace: argparse.Namespace) -> object:
        assert namespace is args
        events.append("isolation-helper:late")
        value = {"isolation": "late-helper"}
        isolation_objects.append(value)
        return value

    def rebind_isolation_helper() -> None:
        events.append("rebind:isolation-helper")
        cli._github_attestation_provider_isolation = late_isolation_helper

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

    def rebind_factory() -> None:
        events.append("rebind:isolation-factory")
        github_attestation.github_attestation_provider_isolation = late_factory

    class _LateGitHubError(ValueError):
        pass

    class _LateSigningError(RuntimeError):
        pass

    class _RebindingGitHubError(original_error):
        def __str__(self) -> str:
            events.append("rebind:reporter-from-error-string")
            cli._machine_report = late_reporter
            return "github attestation rejected"

    def rebind_new_error_before_isolation() -> None:
        events.append("rebind:new-github-error-before-isolation")
        github_attestation.GitHubAttestationError = _LateGitHubError

    def rebind_entry_provider() -> None:
        events.append(f"rebind:{command_kind}-provider")
        if command_kind == "seal":
            github_attestation.seal_github_attestation_admission = late_seal_provider
        else:
            github_attestation.verify_github_attestation_admission = late_verify_provider

    def rebind_entry_format() -> None:
        events.append("rebind:entry-format")
        artifact_digest_admission.ARTIFACT_DIGEST_BINDING_FORMAT = "LATE_FORMAT"

    def rebind_entry_error() -> None:
        events.append("rebind:entry-github-error")
        github_attestation.GitHubAttestationError = _LateGitHubError

    def rebind_entry_signing_error() -> None:
        events.append("rebind:entry-signing-error")
        signing.SigningUnavailableError = _LateSigningError  # type: ignore[misc]

    def late_seal_provider(*provider_args: Any, **provider_kwargs: Any) -> _CombinedResult:
        del provider_args, provider_kwargs
        events.append("provider:seal-late")
        return _CombinedResult(events, "seal-late")

    def late_verify_provider(
        *provider_args: Any, **provider_kwargs: Any
    ) -> _CombinedResult:
        del provider_args, provider_kwargs
        events.append("provider:verify-late")
        return _CombinedResult(events, "verify-late")

    regular_case = (
        SEAL_REGULAR_PATH_CASES.get(case_name)
        if command_kind == "seal"
        else VERIFY_REGULAR_PATH_CASES.get(case_name)
    )
    if regular_case is not None:
        setattr(args, regular_case, "-")
    elif case_name.endswith("regular_path_failure_identity"):
        args._property_effects[
            "artifact" if command_kind == "seal" else "binding"
        ] = fail_regular_path
    elif case_name.endswith("argument_baseexception_identity"):
        args._property_effects[
            "artifact" if command_kind == "seal" else "binding"
        ] = fail_argument_baseexception
    elif case_name.endswith("guard_reporter_is_live_after_paths"):
        guard_name = "artifact" if command_kind == "seal" else "binding"
        setattr(args, guard_name, "-")
        args._property_effects[guard_name] = rebind_reporter
    elif case_name.endswith("source_property_rebinds_reader"):
        args._property_effects["expected_source"] = rebind_reader
    elif case_name.endswith("context_property_rebinds_reader"):
        args._property_effects["expected_context"] = rebind_reader
    elif case_name.endswith("metadata_value_error_is_metadata_error"):
        args._property_effects["expected_source"] = fail_metadata_value_error
    elif case_name.endswith("provider_frozen_before_arguments"):
        args._property_effects[
            "artifact" if command_kind == "seal" else "binding"
        ] = rebind_entry_provider
    elif case_name.endswith("format_frozen_before_arguments"):
        args._property_effects[
            "artifact" if command_kind == "seal" else "binding"
        ] = rebind_entry_format
    elif case_name.endswith("github_error_class_frozen_before_arguments"):
        args._property_effects[
            "artifact" if command_kind == "seal" else "binding"
        ] = rebind_entry_error
    elif case_name.endswith("signing_error_class_frozen_before_arguments"):
        args._property_effects[
            "artifact" if command_kind == "seal" else "binding"
        ] = rebind_entry_signing_error
    elif case_name.endswith("policy_helper_is_live_after_positionals"):
        preceding = "out" if command_kind == "seal" else "finalizer_bundle"
        args._property_effects[(preceding, 2)] = rebind_policy_helper
    elif case_name.endswith("policy_helper_value_error_is_operational"):
        preceding = "out" if command_kind == "seal" else "finalizer_bundle"
        args._property_effects[(preceding, 2)] = rebind_failing_policy_helper
    elif case_name.endswith("policy_helper_baseexception_identity"):
        preceding = "out" if command_kind == "seal" else "finalizer_bundle"
        args._property_effects[(preceding, 2)] = rebind_interrupted_policy_helper
    elif case_name.endswith("isolation_helper_is_live_after_timeout"):
        args._property_effects["timeout_seconds"] = rebind_isolation_helper
    elif case_name.endswith("isolation_builder_frozen_before_fields"):
        args.gh_executable_sha256 = "9" * 64
        args.provider_isolation_uid = 2000
        args.provider_isolation_gid = 2001
        args._property_effects["gh_executable_sha256"] = rebind_factory
    elif case_name.endswith("incomplete_isolation_is_rejected"):
        args.gh_executable_sha256 = "9" * 64
    elif case_name.endswith("isolation_new_error_falls_to_operational"):
        args.gh_executable_sha256 = "9" * 64
        args._property_effects["timeout_seconds"] = rebind_new_error_before_isolation
    elif case_name.endswith("success_isolated_boundary"):
        args.gh_executable_sha256 = "9" * 64
        args.provider_isolation_uid = 2000
        args.provider_isolation_gid = 2001

    args._strict_allowed = (
        SEAL_ALLOWED if command_kind == "seal" else VERIFY_ALLOWED
    )

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
        value = dict(call)
        isolation_objects.append(value)
        return value

    def maybe_raise_provider_error(output_paths: tuple[str, ...] = ()) -> None:
        if case_name.endswith("domain_error_subclass_precedes_value_error"):
            raise _RebindingGitHubError("ignored")
        if case_name.endswith("plain_value_error_is_operational"):
            raise ValueError("plain provider value error")
        if case_name.endswith("oserror_is_operational"):
            raise OSError("provider I/O failed")
        if case_name.endswith("operational_error_preserves_partial_outputs"):
            for path in output_paths:
                files[path] = "partial-provider-output"
                events.append(f"io:partial-output:{path}")
            raise OSError("provider I/O failed after partial outputs")
        if case_name.endswith("format_frozen_before_arguments"):
            raise OSError("provider I/O failed")
        if case_name.endswith("github_error_class_frozen_before_arguments"):
            raise original_error("entry GitHub error")
        if case_name.endswith("signing_error_class_frozen_before_arguments"):
            raise original_signing_error("entry signing error")
        if provider_exception is not None:
            raise provider_exception

    def seal_provider(
        artifact_path: str,
        receipt_path: str,
        raw_output_path: str,
        finalizer_bundle_path: str,
        binding_path: str,
        *,
        repository: str,
        signer_workflow: str,
        signer_digest: str,
        source_ref: str,
        source_digest: str,
        cert_oidc_issuer: str,
        trusted_finalizer_public_key_path: str,
        expected_finalizer_source: object,
        expected_finalizer_context: object,
        private_key_path: str,
        gh_executable: str,
        timeout_seconds: int,
        provider_isolation: object,
    ) -> _CombinedResult:
        events.append("provider:seal-original")
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
                "provider": "seal",
                "artifact": artifact_path,
                "receipt_out": receipt_path,
                "raw_output_out": raw_output_path,
                "finalizer_bundle": finalizer_bundle_path,
                "binding_out": binding_path,
                "repository": repository,
                "signer_workflow": signer_workflow,
                "signer_digest": signer_digest,
                "source_ref": source_ref,
                "source_digest": source_digest,
                "cert_oidc_issuer": cert_oidc_issuer,
                "finalizer_pub": trusted_finalizer_public_key_path,
                "expected_source": expected_finalizer_source,
                "expected_context": expected_finalizer_context,
                "sign_key": private_key_path,
                "gh_executable": gh_executable,
                "timeout_seconds": timeout_seconds,
                "provider_isolation": provider_isolation,
            }
        )
        maybe_raise_provider_error((receipt_path, raw_output_path, binding_path))
        files[receipt_path] = "sealed-receipt-output"
        events.append(f"io:provider-output:{receipt_path}")
        files[raw_output_path] = "sealed-raw-output"
        events.append(f"io:provider-output:{raw_output_path}")
        files[binding_path] = "sealed-binding-output"
        events.append(f"io:provider-output:{binding_path}")
        return _CombinedResult(
            events,
            "seal",
            rebind_reporter=(
                late_reporter
                if case_name == "seal_reporter_frozen_before_projection"
                else None
            ),
            projection_failure=projection_exception,
        )

    def verify_provider(
        binding_path: str,
        artifact_path: str,
        receipt_path: str,
        raw_output_path: str,
        finalizer_bundle_path: str,
        *,
        repository: str,
        signer_workflow: str,
        signer_digest: str,
        source_ref: str,
        source_digest: str,
        cert_oidc_issuer: str,
        trusted_public_key_path: str,
        trusted_finalizer_public_key_path: str,
        expected_finalizer_source: object,
        expected_finalizer_context: object,
    ) -> _CombinedResult:
        events.append("provider:verify-original")
        calls.append(
            {
                "provider": "verify",
                "binding": binding_path,
                "artifact": artifact_path,
                "receipt": receipt_path,
                "raw_output": raw_output_path,
                "finalizer_bundle": finalizer_bundle_path,
                "repository": repository,
                "signer_workflow": signer_workflow,
                "signer_digest": signer_digest,
                "source_ref": source_ref,
                "source_digest": source_digest,
                "cert_oidc_issuer": cert_oidc_issuer,
                "trusted_pub": trusted_public_key_path,
                "finalizer_pub": trusted_finalizer_public_key_path,
                "expected_source": expected_finalizer_source,
                "expected_context": expected_finalizer_context,
            }
        )
        maybe_raise_provider_error()
        return _CombinedResult(
            events,
            "verify",
            rebind_reporter=(
                late_reporter
                if case_name == "verify_reporter_frozen_before_projection"
                else None
            ),
            projection_failure=projection_exception,
        )

    cli._machine_report = reporter
    cli._read_external_finalizer_object = reader
    cli._github_attestation_policy_kwargs = policy_helper
    cli._github_attestation_provider_isolation = isolation_helper
    github_attestation.seal_github_attestation_admission = seal_provider
    github_attestation.verify_github_attestation_admission = verify_provider
    github_attestation.github_attestation_provider_isolation = isolation_factory
    os.environ = _ForbiddenEnvironment(events)  # type: ignore[assignment]  # noqa: B003

    exit_code: int | None = None
    exception: dict[str, object] | None = None
    try:
        command = (
            cli.cmd_seal_github_attestation_admission
            if command_kind == "seal"
            else cli.cmd_verify_github_attestation_admission
        )
        exit_code = command(args, out=emit)
    except BaseException as exc:
        exception = {
            "type": type(exc).__name__,
            "message": str(exc),
            "same_identity": exc is expected_exception,
        }
    finally:
        cli._machine_report = original_reporter
        cli._read_external_finalizer_object = original_reader
        cli._github_attestation_policy_kwargs = original_policy_helper
        cli._github_attestation_provider_isolation = original_isolation_helper
        github_attestation.seal_github_attestation_admission = original_seal
        github_attestation.verify_github_attestation_admission = original_verify
        github_attestation.github_attestation_provider_isolation = original_factory
        github_attestation.GitHubAttestationError = original_error
        artifact_digest_admission.ARTIFACT_DIGEST_BINDING_FORMAT = original_format
        signing.SigningUnavailableError = original_signing_error  # type: ignore[misc]
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
