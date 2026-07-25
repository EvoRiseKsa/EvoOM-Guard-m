"""Deterministic characterization of the Release Source Admission CLI pair.

This is a refactor-safety harness, not a second implementation.  It freezes
the two public adapters before their production extraction: entry snapshots,
live facade seams, trusted-input read order, protected-runtime/provider
ordering, no-clobber preflight, exception classification, partial evidence,
success projection order, and the offline verifier's closed authority set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from types import SimpleNamespace
from typing import Any

from evoom_guard import (
    cli,
    finalizer_derivation,
    github_attestation,
    release_source_producer_receipt,
    signing,
)
from evoom_guard.admission import release_source as release_source_admission

BASELINE_COMMIT = "b87ae48926a1233e656e38c2ec989a165426c050"
SCHEMA_VERSION = "cli-release-source-admission-characterization-v1"

SEAL_ALLOWED = frozenset(
    {
        "receipt",
        "handoff",
        "verdict",
        "out",
        "source",
        "context",
        "producer",
        "admitter",
        "bootstrap_guard_sha",
        "github_policy",
        "git_repository",
        "git_repository_bare",
        "git_executable",
        "git_executable_sha256",
        "github_receipt_out",
        "github_raw_output_out",
        "gh_executable",
        "gh_executable_sha256",
        "provider_isolation_uid",
        "provider_isolation_gid",
        "timeout_seconds",
        "sign_key",
        "sign_pub",
        "trusted_finalizer_pub",
        "artifact_admission_v1_pub",
        "artifact_digest_admission_v2_pub",
        "release_source_finalizer_v1_pub",
        "force",
    }
)
VERIFY_ALLOWED = frozenset(
    {
        "bundle",
        "trusted_pub",
        "expected_source",
        "expected_context",
        "expected_producer",
        "expected_admitter",
        "expected_bootstrap_guard_sha",
        "expected_github_policy",
        "expected_git_executable_sha256",
        "expected_gh_executable_sha256",
        "expected_provider_isolation_uid",
        "expected_provider_isolation_gid",
        "trusted_finalizer_pub",
        "artifact_admission_v1_pub",
        "artifact_digest_admission_v2_pub",
        "release_source_finalizer_v1_pub",
    }
)

SEAL_STDIN_CASES = {
    "seal_receipt_stdin_short_circuit": "receipt",
    "seal_handoff_stdin_short_circuit": "handoff",
    "seal_verdict_stdin_short_circuit": "verdict",
}

_SEAL_CASES = (
    *SEAL_STDIN_CASES,
    "seal_success",
    "seal_success_closed_world",
    "seal_success_projection_order",
    "seal_receipt_property_failure_identity",
    "seal_producer_helper_is_live",
    "seal_reader_is_live_between_inputs",
    "seal_source_read_error",
    "seal_admitter_read_error",
    "seal_key_helper_is_live",
    "seal_signer_collision",
    "seal_preflight_is_live",
    "seal_preflight_rejects_before_executables",
    "seal_output_alias_rejected",
    "seal_existing_output_rejected",
    "seal_existing_provider_output_rejected",
    "seal_git_provider_frozen_before_arguments",
    "seal_isolation_provider_frozen_before_arguments",
    "seal_workflow_provider_frozen_before_arguments",
    "seal_runtime_provider_frozen_before_arguments",
    "seal_receipt_provider_frozen_before_arguments",
    "seal_sealer_provider_frozen_before_arguments",
    "seal_format_frozen_before_arguments",
    "seal_release_error_class_frozen",
    "seal_producer_error_class_frozen",
    "seal_github_error_class_frozen",
    "seal_finalizer_error_class_frozen",
    "seal_signing_error_class_frozen",
    "seal_event_path_missing",
    "seal_event_reader_error",
    "seal_plain_value_error",
    "seal_oserror",
    "seal_partial_provider_output_preserved",
    "seal_provider_baseexception_identity",
    "seal_projection_failure_identity",
    "seal_output_failure_identity",
    "seal_error_reporter_snapshot",
    "seal_success_reporter_snapshot",
)
_VERIFY_CASES = (
    "verify_bundle_stdin_short_circuit",
    "verify_success_offline_boundary",
    "verify_reader_is_live_between_inputs",
    "verify_source_read_error",
    "verify_key_helper_is_live",
    "verify_provider_frozen_before_arguments",
    "verify_format_frozen_before_arguments",
    "verify_release_error_class_frozen",
    "verify_signing_error_class_frozen",
    "verify_plain_value_error",
    "verify_oserror",
    "verify_provider_baseexception_identity",
    "verify_projection_failure_identity",
    "verify_output_failure_identity",
    "verify_error_reporter_snapshot",
    "verify_success_reporter_snapshot",
)
CASE_NAMES = (*_SEAL_CASES, *_VERIFY_CASES)

_SOURCE = {"repository": "owner/repository", "head_sha": "1" * 40}
_CONTEXT = {"policy_digest": "sha256:" + "2" * 64}
_PRODUCER = {"workflow": "producer.yml", "workflow_sha": "3" * 40}
_ADMITTER = {"workflow": "admitter.yml", "workflow_sha": "4" * 40}
_POLICY = {"repository": "owner/repository", "signer_digest": "5" * 40}
_EVENT = {"workflow_run": {"head_sha": "6" * 40}}
_KEYS = {
    "trusted_finalizer": "kid:trusted-finalizer.pub",
    "artifact_admission_v1": "kid:artifact-v1.pub",
    "artifact_digest_admission_v2": "kid:artifact-v2.pub",
    "release_source_finalizer_v1": "kid:source-finalizer-v1.pub",
}


def canonical_json(value: Any) -> str:
    """Return a stable, reviewable representation."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _display(value: object) -> str:
    return json.dumps(_stable(value), ensure_ascii=True, sort_keys=True)


def _stable(value: object) -> object:
    if isinstance(value, _Token):
        return {"token": value.name}
    if isinstance(value, _Environment):
        return {"token": "environment"}
    if isinstance(value, dict):
        return {str(key): _stable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_stable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return {"type": type(value).__name__}


class _Token:
    def __init__(self, name: str) -> None:
        self.name = name


class _SideEffectNamespace(argparse.Namespace):
    """Record argument reads and reject undeclared authority on request."""

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


class _Environment:
    def __init__(self, events: list[str], event_path: str | None) -> None:
        self._events = events
        self._event_path = event_path

    def get(self, key: str, default: object = None) -> object:
        self._events.append(f"environment:get:{key}")
        if key == "GITHUB_EVENT_PATH":
            return self._event_path
        return default

    def __contains__(self, key: object) -> bool:
        self._events.append(f"environment:contains:{key}")
        raise AssertionError("adapter widened its ambient-environment reads")

    def __getitem__(self, key: str) -> str:
        self._events.append(f"environment:getitem:{key}")
        raise AssertionError("adapter widened its ambient-environment reads")

    def __iter__(self) -> Any:
        self._events.append("environment:iter")
        raise AssertionError("adapter iterated ambient environment")


class _PathFacade:
    def __init__(
        self,
        events: list[str],
        *,
        existing: set[str],
        real_path: Any,
    ) -> None:
        self._events = events
        self._existing = existing
        self._real_path = real_path

    def abspath(self, path: str) -> str:
        return self._real_path.abspath(path)

    def realpath(self, path: str) -> str:
        return self._real_path.realpath(path)

    def normcase(self, path: str) -> str:
        return self._real_path.normcase(path)

    def lexists(self, path: str) -> bool:
        answer = path in self._existing
        self._events.append(f"path:lexists:{path}:{str(answer).lower()}")
        return answer


class _ProjectionMap:
    def __init__(self, events: list[str], name: str, value: dict[str, object]) -> None:
        self._events = events
        self._name = name
        self._value = value

    def __getitem__(self, key: str) -> object:
        self._events.append(f"projection:{self._name}[{key}]")
        value = self._value[key]
        if isinstance(value, dict):
            return _ProjectionMap(self._events, f"{self._name}.{key}", value)
        return value


class _Sealed:
    def __init__(
        self,
        events: list[str],
        *,
        reporter: Any = None,
        failure: BaseException | None = None,
    ) -> None:
        self._events = events
        self._reporter = reporter
        self._failure = failure
        self._manifest = _ProjectionMap(
            events,
            "sealed.manifest",
            {
                "authentication": {"key_id": "kid:source-admission-v2.pub"},
                "record": {"sha256": "7" * 64},
                "producer_receipt": {"sha256": "8" * 64},
            },
        )

    @property
    def bundle_path(self) -> str:
        self._events.append("projection:sealed.bundle_path")
        if self._reporter is not None:
            self._events.append("rebind:reporter-from-sealed")
            cli._machine_report = self._reporter
        if self._failure is not None:
            raise self._failure
        return "/outputs/source-admission.rsae"

    @property
    def manifest(self) -> _ProjectionMap:
        self._events.append("projection:sealed.manifest")
        return self._manifest

    @property
    def decision(self) -> str:
        self._events.append("projection:sealed.decision")
        return "ALLOW"


class _VerifiedBundle:
    def __init__(self, events: list[str]) -> None:
        self._events = events
        self._manifest = _ProjectionMap(
            events,
            "verified.bundle.manifest",
            {
                "authentication": {"key_id": "kid:source-admission-v2.pub"},
                "record": {"sha256": "7" * 64},
                "producer_receipt": {"sha256": "8" * 64},
            },
        )

    @property
    def manifest(self) -> _ProjectionMap:
        self._events.append("projection:verified.bundle.manifest")
        return self._manifest


class _Verified:
    def __init__(
        self,
        events: list[str],
        *,
        reporter: Any = None,
        failure: BaseException | None = None,
    ) -> None:
        self._events = events
        self._reporter = reporter
        self._failure = failure
        self._bundle = _VerifiedBundle(events)

    @property
    def bundle(self) -> _VerifiedBundle:
        self._events.append("projection:verified.bundle")
        if self._reporter is not None:
            self._events.append("rebind:reporter-from-verified")
            cli._machine_report = self._reporter
        if self._failure is not None:
            raise self._failure
        return self._bundle

    @property
    def decision(self) -> str:
        self._events.append("projection:verified.decision")
        return "ALLOW"


def _args(events: list[str]) -> _SideEffectNamespace:
    values: dict[str, object] = {
        "receipt": "/inputs/producer-receipt.json",
        "handoff": "/inputs/handoff.json",
        "verdict": "/inputs/verdict.json",
        "out": "/outputs/source-admission.rsae",
        "source": "/trust/source.json",
        "context": "/trust/context.json",
        "producer": "/trust/producer.json",
        "admitter": "/trust/admitter.json",
        "bootstrap_guard_sha": "9" * 64,
        "github_policy": "/trust/github-policy.json",
        "git_repository": "/trust/repository.git",
        "git_repository_bare": True,
        "git_executable": "/trusted/bin/git",
        "git_executable_sha256": "a" * 64,
        "github_receipt_out": "/outputs/github-receipt.json",
        "github_raw_output_out": "/outputs/github-raw.json",
        "gh_executable": "/trusted/bin/gh",
        "gh_executable_sha256": "b" * 64,
        "provider_isolation_uid": 1729,
        "provider_isolation_gid": 1730,
        "timeout_seconds": 47,
        "sign_key": "/keys/source-admission.key",
        "sign_pub": "/keys/source-admission.pub",
        "trusted_finalizer_pub": "/keys/trusted-finalizer.pub",
        "artifact_admission_v1_pub": "/keys/artifact-v1.pub",
        "artifact_digest_admission_v2_pub": "/keys/artifact-v2.pub",
        "release_source_finalizer_v1_pub": "/keys/source-finalizer-v1.pub",
        "force": False,
        "bundle": "/inputs/source-admission.rsae",
        "trusted_pub": "/keys/source-admission.pub",
        "expected_source": "/trust/source.json",
        "expected_context": "/trust/context.json",
        "expected_producer": "/trust/producer.json",
        "expected_admitter": "/trust/admitter.json",
        "expected_bootstrap_guard_sha": "9" * 64,
        "expected_github_policy": "/trust/github-policy.json",
        "expected_git_executable_sha256": "a" * 64,
        "expected_gh_executable_sha256": "b" * 64,
        "expected_provider_isolation_uid": 1729,
        "expected_provider_isolation_gid": 1730,
        # Authority sentinels for the offline verifier.
        "env": "/forbidden/environment",
        "github_token": "/forbidden/token",
        "network": "/forbidden/network",
        "allow_nonadmitting_evidence": True,
    }
    args = _SideEffectNamespace(**values)
    args._events = events
    args._property_effects = {}
    args._read_counts = {}
    args._strict_allowed = None
    args._tracked_names = frozenset(values)
    return args


def _data_for_label(label: str) -> dict[str, object]:
    if "workflow_run event" in label:
        return dict(_EVENT)
    if "admitter" in label or "protected C workflow identity" in label:
        return dict(_ADMITTER)
    if "producer identity" in label:
        return dict(_PRODUCER)
    if "policy" in label:
        return dict(_POLICY)
    if "context" in label:
        return dict(_CONTEXT)
    if "source" in label:
        return dict(_SOURCE)
    raise AssertionError(f"unmapped trusted-input label: {label}")


def capture_case(case_name: str) -> dict[str, object]:
    """Capture one public command under deterministic boundary doubles."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown release-source admission case: {case_name}")

    is_seal = case_name.startswith("seal_")
    events: list[str] = []
    calls: list[dict[str, object]] = []
    outputs: list[dict[str, object]] = []
    output_sha256: list[str] = []
    files: dict[str, str] = {}
    args = _args(events)

    original_os = cli.os
    original_reader = cli._read_external_finalizer_object
    original_producer_inputs = cli._producer_receipt_external_inputs
    original_key_helper = cli._release_source_key_separation
    original_preflight = cli._preflight_release_source_admission_paths
    original_reporter = cli._machine_report

    original_git_pin = finalizer_derivation.git_executable_pin
    original_finalizer_error = finalizer_derivation.FinalizerDerivationError
    original_isolation = github_attestation.github_attestation_provider_isolation
    original_github_error = github_attestation.GitHubAttestationError
    original_workflow = (
        release_source_producer_receipt.verify_release_source_admitter_workflow_blob
    )
    original_runtime = (
        release_source_producer_receipt.validate_release_source_admitter_runtime_environment
    )
    original_receipt = (
        release_source_producer_receipt.reverify_attested_release_source_producer_receipt
    )
    original_producer_error = (
        release_source_producer_receipt.ReleaseSourceProducerReceiptError
    )
    original_seal = release_source_admission.seal_release_source_admission
    original_verify = release_source_admission.verify_release_source_admission
    original_release_error = release_source_admission.ReleaseSourceAdmissionError
    original_format = release_source_admission.RELEASE_SOURCE_ADMISSION_FORMAT
    original_public_key_id = signing.public_key_id
    original_signing_error = signing.SigningUnavailableError

    event_path: str | None = "/trust/event.json"
    existing: set[str] = set()
    expected_exception: BaseException | None = None
    projection_exception: BaseException | None = None
    output_exception: BaseException | None = None

    if case_name in {
        "seal_receipt_property_failure_identity",
    }:
        expected_exception = RuntimeError("argument property failed")
    elif case_name in {
        "seal_provider_baseexception_identity",
        "verify_provider_baseexception_identity",
    }:
        expected_exception = KeyboardInterrupt("provider interrupted")
    elif case_name in {
        "seal_projection_failure_identity",
        "verify_projection_failure_identity",
    }:
        projection_exception = RuntimeError("projection failed")
        expected_exception = projection_exception
    elif case_name in {
        "seal_output_failure_identity",
        "verify_output_failure_identity",
    }:
        output_exception = RuntimeError("output failed")
        expected_exception = output_exception

    if case_name in SEAL_STDIN_CASES:
        setattr(args, SEAL_STDIN_CASES[case_name], "-")
    elif case_name == "verify_bundle_stdin_short_circuit":
        args.bundle = "-"
    elif case_name == "seal_output_alias_rejected":
        args.out = args.source
    elif case_name == "seal_existing_output_rejected":
        existing.add(str(args.out))
    elif case_name == "seal_existing_provider_output_rejected":
        existing.add(str(args.github_receipt_out))
    elif case_name == "seal_event_path_missing":
        event_path = None

    environment = _Environment(events, event_path)
    path_facade = _PathFacade(events, existing=existing, real_path=os.path)
    cli.os = SimpleNamespace(environ=environment, path=path_facade)

    def emit(message: str) -> None:
        value = json.loads(message)
        outputs.append(value)
        output_sha256.append(hashlib.sha256(message.encode("utf-8")).hexdigest())
        events.append(f"output:{value['status']}")
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
        if case_name in {"seal_source_read_error", "verify_source_read_error"} and (
            "source" in label and "context" not in label
        ):
            raise OSError("source read failed")
        if case_name == "seal_admitter_read_error" and "admitter" in label:
            raise UnicodeError("admitter decode failed")
        if case_name == "seal_event_reader_error" and "workflow_run event" in label:
            raise ValueError("event payload invalid")
        value = _data_for_label(label)
        if case_name in {
            "seal_reader_is_live_between_inputs",
            "verify_reader_is_live_between_inputs",
        } and ("source" in label and "context" not in label):
            events.append("rebind:reader-after-source")
            cli._read_external_finalizer_object = late_reader
        return value

    def late_reader(path: str, *, label: str) -> dict[str, object]:
        events.append(f"reader:late:{label}:{path}")
        return _data_for_label(label)

    def producer_inputs(command_args: argparse.Namespace) -> tuple[object, object, object]:
        events.append("helper:producer-inputs:original")
        return original_producer_inputs(command_args)

    def late_producer_inputs(
        command_args: argparse.Namespace,
    ) -> tuple[object, object, object]:
        del command_args
        events.append("helper:producer-inputs:late")
        return _Token("late-source"), _Token("late-context"), _Token("late-producer")

    def key_helper(command_args: argparse.Namespace) -> dict[str, str]:
        events.append("helper:key-separation:original")
        return original_key_helper(command_args)

    def late_key_helper(command_args: argparse.Namespace) -> dict[str, str]:
        del command_args
        events.append("helper:key-separation:late")
        return {"late-domain": "kid:late"}

    def preflight(command_args: argparse.Namespace) -> None:
        events.append("helper:preflight:original")
        original_preflight(command_args)

    def late_preflight(command_args: argparse.Namespace) -> None:
        del command_args
        events.append("helper:preflight:late")
        if case_name == "seal_preflight_rejects_before_executables":
            raise ValueError("late preflight rejected")

    def public_key_id(path: str) -> str:
        events.append(f"provider:public-key-id:{path}")
        if case_name == "seal_signer_collision" and path == args.sign_pub:
            return _KEYS["trusted_finalizer"]
        return "kid:" + os.path.basename(path)

    def record_call(provider: str, positional: tuple[object, ...], kwargs: dict[str, object]) -> None:
        events.append(f"provider:{provider}:original")
        calls.append(
            {
                "provider": provider,
                "args": _stable(positional),
                "kwargs": _stable(kwargs),
            }
        )

    def late_provider(name: str) -> Any:
        def provider(*positional: object, **kwargs: object) -> _Token:
            del positional, kwargs
            events.append(f"provider:{name}:late")
            return _Token("late-" + name)

        return provider

    class _LateReleaseError(ValueError):
        pass

    class _LateProducerError(ValueError):
        pass

    class _LateGitHubError(ValueError):
        pass

    class _LateFinalizerError(ValueError):
        pass

    class _LateSigningError(ValueError):
        pass

    class _RebindingReleaseError(original_release_error):
        def __str__(self) -> str:
            events.append("rebind:reporter-from-error-string")
            cli._machine_report = late_reporter
            return "release-source admission invalid"

    def git_pin(*positional: object, **kwargs: object) -> _Token:
        record_call("git-pin", positional, kwargs)
        if case_name == "seal_finalizer_error_class_frozen":
            finalizer_derivation.FinalizerDerivationError = _LateFinalizerError
            raise original_finalizer_error("git pin invalid")
        if case_name == "seal_plain_value_error":
            raise ValueError("plain invalid")
        return _Token("git-pin")

    def isolation(*positional: object, **kwargs: object) -> _Token:
        record_call("provider-isolation", positional, kwargs)
        if case_name == "seal_github_error_class_frozen":
            github_attestation.GitHubAttestationError = _LateGitHubError
            raise original_github_error("isolation invalid")
        return _Token("provider-isolation")

    def workflow(*positional: object, **kwargs: object) -> _Token:
        record_call("workflow-verify", positional, kwargs)
        if case_name == "seal_producer_error_class_frozen":
            release_source_producer_receipt.ReleaseSourceProducerReceiptError = (
                _LateProducerError
            )
            raise original_producer_error("workflow invalid")
        return _Token("verified-admitter")

    def runtime(*positional: object, **kwargs: object) -> _Token:
        record_call("runtime-validate", positional, kwargs)
        return _Token("runtime-admitter")

    def receipt(*positional: object, **kwargs: object) -> _Token:
        record_call("producer-receipt-reverify", positional, kwargs)
        if case_name == "seal_partial_provider_output_preserved":
            receipt_path = str(args.github_receipt_out)
            raw_path = str(args.github_raw_output_out)
            files[receipt_path] = "partial-provider-receipt"
            files[raw_path] = "partial-provider-raw-output"
            events.extend(
                (
                    f"io:partial-output:{receipt_path}",
                    f"io:partial-output:{raw_path}",
                )
            )
            raise OSError("provider verification failed after evidence write")
        return _Token("attested-producer-receipt")

    def seal(*positional: object, **kwargs: object) -> _Sealed:
        record_call("seal", positional, kwargs)
        if case_name == "seal_release_error_class_frozen":
            release_source_admission.ReleaseSourceAdmissionError = _LateReleaseError
            raise original_release_error("release admission invalid")
        if case_name == "seal_signing_error_class_frozen":
            signing.SigningUnavailableError = _LateSigningError
            raise original_signing_error("signing unavailable")
        if case_name == "seal_oserror":
            raise OSError("seal I/O failed")
        if case_name == "seal_provider_baseexception_identity":
            assert expected_exception is not None
            raise expected_exception
        if case_name == "seal_error_reporter_snapshot":
            raise _RebindingReleaseError("ignored")
        return _Sealed(
            events,
            reporter=(
                late_reporter
                if case_name == "seal_success_reporter_snapshot"
                else None
            ),
            failure=projection_exception,
        )

    def verify(*positional: object, **kwargs: object) -> _Verified:
        record_call("verify", positional, kwargs)
        if case_name == "verify_release_error_class_frozen":
            release_source_admission.ReleaseSourceAdmissionError = _LateReleaseError
            raise original_release_error("release admission invalid")
        if case_name == "verify_signing_error_class_frozen":
            signing.SigningUnavailableError = _LateSigningError
            raise original_signing_error("signing unavailable")
        if case_name == "verify_plain_value_error":
            raise ValueError("plain invalid")
        if case_name == "verify_oserror":
            raise OSError("verify I/O failed")
        if case_name == "verify_provider_baseexception_identity":
            assert expected_exception is not None
            raise expected_exception
        if case_name == "verify_error_reporter_snapshot":
            raise _RebindingReleaseError("ignored")
        return _Verified(
            events,
            reporter=(
                late_reporter
                if case_name == "verify_success_reporter_snapshot"
                else None
            ),
            failure=projection_exception,
        )

    cli._read_external_finalizer_object = reader
    cli._producer_receipt_external_inputs = producer_inputs
    cli._release_source_key_separation = key_helper
    cli._preflight_release_source_admission_paths = preflight
    cli._machine_report = reporter
    finalizer_derivation.git_executable_pin = git_pin
    github_attestation.github_attestation_provider_isolation = isolation
    release_source_producer_receipt.verify_release_source_admitter_workflow_blob = (
        workflow
    )
    release_source_producer_receipt.validate_release_source_admitter_runtime_environment = (
        runtime
    )
    release_source_producer_receipt.reverify_attested_release_source_producer_receipt = (
        receipt
    )
    release_source_admission.seal_release_source_admission = seal
    release_source_admission.verify_release_source_admission = verify
    signing.public_key_id = public_key_id

    def fail_argument_property() -> None:
        events.append("argument-property-failure")
        assert expected_exception is not None
        raise expected_exception

    def rebind_imported_provider(module: object, attribute: str, label: str) -> None:
        events.append(f"rebind:provider:{label}")
        setattr(module, attribute, late_provider(label))

    if case_name == "seal_receipt_property_failure_identity":
        args._property_effects["receipt"] = fail_argument_property
    elif case_name == "seal_producer_helper_is_live":
        args._property_effects["verdict"] = lambda: setattr(
            cli, "_producer_receipt_external_inputs", late_producer_inputs
        )
    elif case_name == "seal_key_helper_is_live":
        args._property_effects["admitter"] = lambda: setattr(
            cli, "_release_source_key_separation", late_key_helper
        )
    elif case_name in {
        "seal_preflight_is_live",
        "seal_preflight_rejects_before_executables",
    }:
        args._property_effects["sign_pub"] = lambda: setattr(
            cli, "_preflight_release_source_admission_paths", late_preflight
        )
    elif case_name == "seal_git_provider_frozen_before_arguments":
        args._property_effects["receipt"] = lambda: rebind_imported_provider(
            finalizer_derivation, "git_executable_pin", "git-pin"
        )
    elif case_name == "seal_isolation_provider_frozen_before_arguments":
        args._property_effects["receipt"] = lambda: rebind_imported_provider(
            github_attestation,
            "github_attestation_provider_isolation",
            "provider-isolation",
        )
    elif case_name == "seal_workflow_provider_frozen_before_arguments":
        args._property_effects["receipt"] = lambda: rebind_imported_provider(
            release_source_producer_receipt,
            "verify_release_source_admitter_workflow_blob",
            "workflow-verify",
        )
    elif case_name == "seal_runtime_provider_frozen_before_arguments":
        args._property_effects["receipt"] = lambda: rebind_imported_provider(
            release_source_producer_receipt,
            "validate_release_source_admitter_runtime_environment",
            "runtime-validate",
        )
    elif case_name == "seal_receipt_provider_frozen_before_arguments":
        args._property_effects["receipt"] = lambda: rebind_imported_provider(
            release_source_producer_receipt,
            "reverify_attested_release_source_producer_receipt",
            "producer-receipt-reverify",
        )
    elif case_name == "seal_sealer_provider_frozen_before_arguments":
        args._property_effects["receipt"] = lambda: rebind_imported_provider(
            release_source_admission,
            "seal_release_source_admission",
            "seal",
        )
    elif case_name == "verify_provider_frozen_before_arguments":
        args._property_effects["bundle"] = lambda: rebind_imported_provider(
            release_source_admission,
            "verify_release_source_admission",
            "verify",
        )
    elif case_name in {
        "seal_format_frozen_before_arguments",
        "verify_format_frozen_before_arguments",
    }:
        first_argument = "receipt" if is_seal else "bundle"
        args._property_effects[first_argument] = lambda: setattr(
            release_source_admission,
            "RELEASE_SOURCE_ADMISSION_FORMAT",
            "LATE_FORMAT",
        )
    elif case_name == "verify_key_helper_is_live":
        args._property_effects["expected_github_policy"] = lambda: setattr(
            cli, "_release_source_key_separation", late_key_helper
        )

    if case_name == "seal_success_closed_world":
        args._strict_allowed = SEAL_ALLOWED
    elif case_name == "verify_success_offline_boundary":
        args._strict_allowed = VERIFY_ALLOWED

    exit_code: int | None = None
    exception: dict[str, object] | None = None
    try:
        command = (
            cli.cmd_seal_release_source_admission
            if is_seal
            else cli.cmd_verify_release_source_admission
        )
        exit_code = command(args, out=emit)
    except BaseException as exc:
        exception = {
            "type": type(exc).__name__,
            "message": str(exc),
            "same_identity": exc is expected_exception,
        }
    finally:
        cli.os = original_os
        cli._read_external_finalizer_object = original_reader
        cli._producer_receipt_external_inputs = original_producer_inputs
        cli._release_source_key_separation = original_key_helper
        cli._preflight_release_source_admission_paths = original_preflight
        cli._machine_report = original_reporter
        finalizer_derivation.git_executable_pin = original_git_pin
        finalizer_derivation.FinalizerDerivationError = original_finalizer_error
        github_attestation.github_attestation_provider_isolation = original_isolation
        github_attestation.GitHubAttestationError = original_github_error
        release_source_producer_receipt.verify_release_source_admitter_workflow_blob = (
            original_workflow
        )
        release_source_producer_receipt.validate_release_source_admitter_runtime_environment = (
            original_runtime
        )
        release_source_producer_receipt.reverify_attested_release_source_producer_receipt = (
            original_receipt
        )
        release_source_producer_receipt.ReleaseSourceProducerReceiptError = (
            original_producer_error
        )
        release_source_admission.seal_release_source_admission = original_seal
        release_source_admission.verify_release_source_admission = original_verify
        release_source_admission.ReleaseSourceAdmissionError = original_release_error
        release_source_admission.RELEASE_SOURCE_ADMISSION_FORMAT = original_format
        signing.public_key_id = original_public_key_id
        signing.SigningUnavailableError = original_signing_error

    return {
        "calls": calls,
        "events": events,
        "exception": exception,
        "exit_code": exit_code,
        "files": files,
        "output_sha256": output_sha256,
        "outputs": outputs,
    }


def capture_vector() -> dict[str, object]:
    """Capture all cases in stable order."""

    return {
        "baseline_commit": BASELINE_COMMIT,
        "schema_version": SCHEMA_VERSION,
        "cases": {name: capture_case(name) for name in sorted(CASE_NAMES)},
    }


def digest_vector() -> dict[str, object]:
    """Return a compact cryptographic cross-parent vector."""

    cases = capture_vector()["cases"]
    assert isinstance(cases, dict)
    return {
        "baseline_commit": BASELINE_COMMIT,
        "schema_version": SCHEMA_VERSION,
        "cases": {
            name: hashlib.sha256(
                json.dumps(
                    value,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()
            for name, value in cases.items()
        },
    }


if __name__ == "__main__":
    print(canonical_json(digest_vector()), end="")
