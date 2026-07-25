"""Deterministic characterization of Artifact Admission V1 CLI adapters.

The vector freezes the two public seal/verify commands before extraction:
provider snapshots, argument and trusted-input reads, reporter lookup timing,
exit/status mapping, partial-output residue, exception identity, and the
offline verification boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from typing import Any

from evoom_guard import artifact_admission, cli, signing

BASELINE_COMMIT = "5b43a2f7717168e030db209e90dca77430d1cb9a"
SCHEMA_VERSION = "cli-artifact-admission-v1-characterization-v1"
CASE_NAMES = (
    "seal_artifact_property_failure_identity",
    "seal_artifact_stdin_short_circuit",
    "seal_domain_error_class_and_reporter_snapshot",
    "seal_finalizer_stdin_short_circuit",
    "seal_operational_error_preserves_partial_output",
    "seal_output_failure_identity",
    "seal_projection_failure_identity",
    "seal_provider_baseexception_identity",
    "seal_provider_frozen_before_arguments",
    "seal_signing_error_class_snapshot",
    "seal_source_property_rebinds_reader",
    "seal_source_read_error",
    "seal_success",
    "seal_success_reporter_frozen_before_projection",
    "verify_binding_property_failure_identity",
    "verify_binding_stdin_reads_all_paths",
    "verify_context_read_error",
    "verify_domain_error_class_and_reporter_snapshot",
    "verify_operational_error",
    "verify_output_failure_identity",
    "verify_projection_failure_identity",
    "verify_provider_baseexception_identity",
    "verify_provider_frozen_before_arguments",
    "verify_signing_error_class_snapshot",
    "verify_source_property_rebinds_reader",
    "verify_success_offline_boundary",
    "verify_success_reporter_frozen_before_projection",
)

_SOURCE = {
    "repository": "owner/repository",
    "head_sha": "1" * 40,
}
_CONTEXT = {
    "policy_digest": "sha256:" + "2" * 64,
    "verifier_pack_digest": "sha256:" + "3" * 64,
}
_SUBJECT = {
    "kind": "file",
    "sha256": "4" * 64,
    "size": 17,
}
_FINALIZER = {
    "bundle_sha256": "5" * 64,
    "record_sha256": "6" * 64,
    "key_id": "sha256:" + "7" * 64,
}
_AUTHENTICATION = {
    "key_id": "sha256:" + "8" * 64,
}


def canonical_json(value: Any) -> str:
    """Return the stable human-reviewable vector encoding."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _display(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


class _SideEffectNamespace(argparse.Namespace):
    """Namespace that logs and optionally mutates one selected property read."""

    def __getattribute__(self, name: str) -> object:
        namespace = object.__getattribute__(self, "__dict__")
        tracked = namespace.get("_tracked_names", frozenset())
        if name in tracked:
            namespace["_events"].append(
                f"arg:{name}={_display(namespace[name])}"
            )
            effect = namespace["_property_effects"].pop(name, None)
            if effect is not None:
                effect()
        return super().__getattribute__(name)


class _Subject:
    def __init__(
        self,
        events: list[str],
        *,
        rebind_reporter: Any = None,
        failure: BaseException | None = None,
    ) -> None:
        self._events = events
        self._rebind_reporter = rebind_reporter
        self._failure = failure

    def as_dict(self) -> dict[str, object]:
        self._events.append("projection:subject.as_dict")
        if self._rebind_reporter is not None:
            self._events.append("rebind:reporter-from-subject")
            cli._machine_report = self._rebind_reporter
        if self._failure is not None:
            raise self._failure
        return dict(_SUBJECT)


class _SealResult:
    def __init__(
        self,
        events: list[str],
        *,
        rebind_reporter: Any = None,
        failure: BaseException | None = None,
    ) -> None:
        self._events = events
        self._rebind_reporter = rebind_reporter
        self._failure = failure
        self.subject = _Subject(events)
        self.payload = {
            "finalizer": dict(_FINALIZER),
            "authentication": dict(_AUTHENTICATION),
        }

    @property
    def binding_path(self) -> str:
        self._events.append("projection:binding_path")
        if self._rebind_reporter is not None:
            self._events.append("rebind:reporter-from-binding")
            cli._machine_report = self._rebind_reporter
        if self._failure is not None:
            raise self._failure
        return "/produced/binding.eab"


class _Inspection:
    def __init__(self, events: list[str]) -> None:
        self._events = events

    @property
    def finalizer(self) -> dict[str, object]:
        self._events.append("projection:inspection.finalizer")
        return dict(_FINALIZER)

    @property
    def payload(self) -> dict[str, object]:
        self._events.append("projection:inspection.payload")
        return {
            "authentication": dict(_AUTHENTICATION),
        }


class _VerifyResult:
    def __init__(
        self,
        events: list[str],
        *,
        rebind_reporter: Any = None,
        failure: BaseException | None = None,
    ) -> None:
        self.subject = _Subject(
            events,
            rebind_reporter=rebind_reporter,
            failure=failure,
        )
        self.inspection = _Inspection(events)


def _seal_args(events: list[str]) -> _SideEffectNamespace:
    args = _SideEffectNamespace(
        artifact="/inputs/artifact.bin",
        expected_context="/trust/context.json",
        expected_source="/trust/source.json",
        finalizer_bundle="/trust/finalizer.evf",
        finalizer_pub="/trust/finalizer.pub",
        force=False,
        out="/outputs/binding.eab",
        sign_key="/keys/artifact-admission.key",
    )
    args._events = events
    args._property_effects = {}
    args._tracked_names = frozenset(
        {
            "artifact",
            "expected_context",
            "expected_source",
            "finalizer_bundle",
            "finalizer_pub",
            "force",
            "out",
            "sign_key",
        }
    )
    return args


def _verify_args(events: list[str]) -> _SideEffectNamespace:
    args = _SideEffectNamespace(
        artifact="/inputs/artifact.bin",
        binding="/inputs/binding.eab",
        expected_context="/trust/context.json",
        expected_source="/trust/source.json",
        finalizer_bundle="/trust/finalizer.evf",
        finalizer_pub="/trust/finalizer.pub",
        force=True,
        gh_executable="/forbidden/gh",
        out="/forbidden/output.eab",
        sign_key="/forbidden/signing.key",
        trusted_pub="/trust/artifact-admission.pub",
    )
    args._events = events
    args._property_effects = {}
    args._tracked_names = frozenset(
        {
            "artifact",
            "binding",
            "expected_context",
            "expected_source",
            "finalizer_bundle",
            "finalizer_pub",
            "force",
            "gh_executable",
            "out",
            "sign_key",
            "trusted_pub",
        }
    )
    return args


def capture_case(case_name: str) -> dict[str, object]:
    """Capture one command case through the historical public CLI facade."""

    if case_name not in CASE_NAMES:
        raise ValueError(
            f"unknown Artifact Admission V1 characterization case: {case_name}"
        )

    is_seal = case_name.startswith("seal_")
    events: list[str] = []
    calls: list[dict[str, object]] = []
    files: dict[str, str] = {}
    output_sha256: list[str] = []
    args = _seal_args(events) if is_seal else _verify_args(events)

    original_reader = cli._read_external_finalizer_object
    original_reporter = cli._machine_report
    original_seal = artifact_admission.seal_artifact_admission
    original_verify = artifact_admission.verify_artifact_admission
    original_artifact_error = artifact_admission.ArtifactAdmissionError
    original_format = artifact_admission.ARTIFACT_BINDING_FORMAT
    original_signing_error = signing.SigningUnavailableError

    expected_exception: BaseException | None = None
    output_exception: BaseException | None = None
    projection_exception: BaseException | None = None
    provider_exception: BaseException | None = None

    if case_name in {
        "seal_artifact_property_failure_identity",
        "verify_binding_property_failure_identity",
    }:
        expected_exception = RuntimeError("argument property failed")
    elif case_name in {
        "seal_provider_baseexception_identity",
        "verify_provider_baseexception_identity",
    }:
        provider_exception = KeyboardInterrupt("provider interrupted")
        expected_exception = provider_exception
    elif case_name in {
        "seal_output_failure_identity",
        "verify_output_failure_identity",
    }:
        output_exception = RuntimeError("output failed")
        expected_exception = output_exception
    elif case_name in {
        "seal_projection_failure_identity",
        "verify_projection_failure_identity",
    }:
        projection_exception = RuntimeError("projection failed")
        expected_exception = projection_exception

    def emit(message: str) -> None:
        parsed = json.loads(message)
        events.append(f"output:{parsed['status']}")
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
        if case_name == "seal_source_read_error" and label == "expected source":
            raise OSError("source read failed")
        if case_name == "verify_context_read_error" and label == "expected context":
            raise UnicodeError("context decode failed")
        return dict(_SOURCE if label == "expected source" else _CONTEXT)

    def late_reader(path: str, *, label: str) -> dict[str, object]:
        events.append(f"reader:late:{label}:{path}")
        return dict(_SOURCE if label == "expected source" else _CONTEXT)

    def rebind_reader() -> None:
        events.append("rebind:reader")
        cli._read_external_finalizer_object = late_reader

    def fail_argument_property() -> None:
        events.append("argument-property-failure")
        assert expected_exception is not None
        raise expected_exception

    def late_seal(*provider_args: Any, **provider_kwargs: Any) -> _SealResult:
        del provider_args, provider_kwargs
        events.append("provider:seal-late")
        return _SealResult(events)

    def late_verify(*provider_args: Any, **provider_kwargs: Any) -> _VerifyResult:
        del provider_args, provider_kwargs
        events.append("provider:verify-late")
        return _VerifyResult(events)

    def rebind_seal_provider() -> None:
        events.append("rebind:seal-provider-and-format")
        artifact_admission.seal_artifact_admission = late_seal
        artifact_admission.ARTIFACT_BINDING_FORMAT = "LATE_FORMAT"

    def rebind_verify_provider() -> None:
        events.append("rebind:verify-provider-and-format")
        artifact_admission.verify_artifact_admission = late_verify
        artifact_admission.ARTIFACT_BINDING_FORMAT = "LATE_FORMAT"

    def forbid_offline_attribute() -> None:
        events.append("offline-boundary-violated")
        raise AssertionError("offline verify read a sealing/provider-only argument")

    if case_name == "seal_artifact_stdin_short_circuit":
        args.artifact = "-"
    elif case_name == "seal_finalizer_stdin_short_circuit":
        args.finalizer_bundle = "-"
    elif case_name == "verify_binding_stdin_reads_all_paths":
        args.binding = "-"
    elif case_name == "seal_source_property_rebinds_reader":
        args._property_effects["expected_source"] = rebind_reader
    elif case_name == "verify_source_property_rebinds_reader":
        args._property_effects["expected_source"] = rebind_reader
    elif case_name == "seal_provider_frozen_before_arguments":
        args._property_effects["artifact"] = rebind_seal_provider
    elif case_name == "verify_provider_frozen_before_arguments":
        args._property_effects["binding"] = rebind_verify_provider
    elif case_name == "seal_artifact_property_failure_identity":
        args._property_effects["artifact"] = fail_argument_property
    elif case_name == "verify_binding_property_failure_identity":
        args._property_effects["binding"] = fail_argument_property
    elif case_name == "verify_success_offline_boundary":
        for name in ("force", "gh_executable", "out", "sign_key"):
            args._property_effects[name] = forbid_offline_attribute

    class _LateArtifactError(ValueError):
        pass

    class _RebindingArtifactError(original_artifact_error):
        def __str__(self) -> str:
            events.append("rebind:reporter-from-error-string")
            cli._machine_report = late_reporter
            return "artifact admission invalid"

    class _LateSigningError(RuntimeError):
        pass

    def seal_provider(
        artifact: str,
        finalizer_bundle: str,
        output: str,
        *,
        trusted_finalizer_public_key_path: str,
        expected_finalizer_source: dict[str, object],
        expected_finalizer_context: dict[str, object],
        private_key_path: str,
        force: bool,
    ) -> _SealResult:
        events.append("provider:seal-original")
        calls.append(
            {
                "provider": "seal",
                "artifact": artifact,
                "finalizer_bundle": finalizer_bundle,
                "output": output,
                "trusted_finalizer_public_key_path": (
                    trusted_finalizer_public_key_path
                ),
                "expected_finalizer_source": expected_finalizer_source,
                "expected_finalizer_context": expected_finalizer_context,
                "private_key_path": private_key_path,
                "force": force,
            }
        )
        if case_name == "seal_domain_error_class_and_reporter_snapshot":
            artifact_admission.ArtifactAdmissionError = _LateArtifactError
            raise _RebindingArtifactError("ignored")
        if case_name == "seal_signing_error_class_snapshot":
            signing.SigningUnavailableError = _LateSigningError
            raise original_signing_error("signing unavailable")
        if case_name == "seal_operational_error_preserves_partial_output":
            files[output] = "partial-provider-output"
            events.append(f"io:partial-output:{output}")
            raise OSError("seal I/O failed")
        if provider_exception is not None:
            raise provider_exception
        return _SealResult(
            events,
            rebind_reporter=(
                late_reporter
                if case_name == "seal_success_reporter_frozen_before_projection"
                else None
            ),
            failure=projection_exception,
        )

    def verify_provider(
        binding: str,
        artifact: str,
        finalizer_bundle: str,
        *,
        trusted_public_key_path: str,
        trusted_finalizer_public_key_path: str,
        expected_finalizer_source: dict[str, object],
        expected_finalizer_context: dict[str, object],
    ) -> _VerifyResult:
        events.append("provider:verify-original")
        calls.append(
            {
                "provider": "verify",
                "binding": binding,
                "artifact": artifact,
                "finalizer_bundle": finalizer_bundle,
                "trusted_public_key_path": trusted_public_key_path,
                "trusted_finalizer_public_key_path": (
                    trusted_finalizer_public_key_path
                ),
                "expected_finalizer_source": expected_finalizer_source,
                "expected_finalizer_context": expected_finalizer_context,
            }
        )
        if case_name == "verify_domain_error_class_and_reporter_snapshot":
            artifact_admission.ArtifactAdmissionError = _LateArtifactError
            raise _RebindingArtifactError("ignored")
        if case_name == "verify_signing_error_class_snapshot":
            signing.SigningUnavailableError = _LateSigningError
            raise original_signing_error("signing unavailable")
        if case_name == "verify_operational_error":
            raise OSError("verify I/O failed")
        if provider_exception is not None:
            raise provider_exception
        return _VerifyResult(
            events,
            rebind_reporter=(
                late_reporter
                if case_name == "verify_success_reporter_frozen_before_projection"
                else None
            ),
            failure=projection_exception,
        )

    cli._read_external_finalizer_object = reader
    cli._machine_report = reporter
    artifact_admission.seal_artifact_admission = seal_provider
    artifact_admission.verify_artifact_admission = verify_provider

    exit_code: int | None = None
    exception: dict[str, object] | None = None
    try:
        command = (
            cli.cmd_seal_artifact_admission
            if is_seal
            else cli.cmd_verify_artifact_admission
        )
        exit_code = command(args, out=emit)
    except BaseException as exc:
        exception = {
            "type": type(exc).__name__,
            "message": str(exc),
            "same_identity": exc is expected_exception,
        }
    finally:
        cli._read_external_finalizer_object = original_reader
        cli._machine_report = original_reporter
        artifact_admission.seal_artifact_admission = original_seal
        artifact_admission.verify_artifact_admission = original_verify
        artifact_admission.ArtifactAdmissionError = original_artifact_error
        artifact_admission.ARTIFACT_BINDING_FORMAT = original_format
        signing.SigningUnavailableError = original_signing_error

    return {
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
    print(canonical_json(capture_vector()), end="")
