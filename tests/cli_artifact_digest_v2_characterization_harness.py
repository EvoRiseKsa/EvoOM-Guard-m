"""Deterministic characterization of Artifact Digest Admission V2 CLI adapters.

The vector freezes the two public seal/verify commands before extraction:
entry snapshots, live facade lookups, argument and trusted-input reads,
exception classification and identity, projections, partial output, exact
reports and exit codes, and the detached verification boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from typing import Any

from evoom_guard import artifact_digest_admission, cli, signing

BASELINE_COMMIT = "56e1030cdee4183e98c0f4595a457a6555b9d957"
SCHEMA_VERSION = "cli-artifact-digest-v2-characterization-v1"
CASE_NAMES = (
    "seal_context_property_rebinds_reader",
    "seal_context_read_error",
    "seal_domain_error_class_and_reporter_snapshot",
    "seal_expected_source_value_error_is_metadata_error",
    "seal_finalizer_property_failure_identity",
    "seal_finalizer_stdin_reads_provenance",
    "seal_guard_property_rebinds_reporter",
    "seal_metadata_digest_error_is_operational",
    "seal_operational_error_preserves_partial_output",
    "seal_output_failure_identity",
    "seal_plain_value_error_is_operational",
    "seal_projection_failure_identity",
    "seal_provenance_stdin_short_circuit",
    "seal_provider_baseexception_identity",
    "seal_provider_frozen_before_arguments",
    "seal_signing_error_class_snapshot",
    "seal_source_property_rebinds_reader",
    "seal_source_read_error",
    "seal_subject_kind_oserror_is_operational",
    "seal_subject_kind_property_failure_identity",
    "seal_success",
    "seal_success_reporter_frozen_before_projection",
    "verify_binding_property_failure_identity",
    "verify_binding_stdin_reads_all_paths",
    "verify_context_property_rebinds_reader",
    "verify_context_read_error",
    "verify_domain_error_class_and_reporter_snapshot",
    "verify_expected_source_value_error_is_metadata_error",
    "verify_finalizer_stdin_reads_provenance",
    "verify_guard_property_rebinds_reporter",
    "verify_metadata_digest_error_is_operational",
    "verify_operational_error",
    "verify_output_failure_identity",
    "verify_plain_value_error_is_operational",
    "verify_projection_failure_identity",
    "verify_provenance_stdin_short_circuit",
    "verify_provider_baseexception_identity",
    "verify_provider_frozen_before_arguments",
    "verify_signing_error_class_snapshot",
    "verify_source_property_rebinds_reader",
    "verify_source_read_error",
    "verify_subject_kind_oserror_is_operational",
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
    "kind": "artifact-sha256",
    "digest": "sha256:" + "4" * 64,
}
_PROVENANCE_REFERENCE = {
    "format": "EVOGUARD_OPAQUE_PROVENANCE_REFERENCE_V1",
    "identity": "opaque:build-17",
    "sha256": "5" * 64,
    "size": 31,
}
_FINALIZER = {
    "bundle_sha256": "6" * 64,
    "record_sha256": "7" * 64,
    "key_id": "sha256:" + "8" * 64,
}
_AUTHENTICATION = {
    "key_id": "sha256:" + "9" * 64,
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
        strict_allowed = namespace.get("_strict_allowed")
        if strict_allowed is not None and name not in strict_allowed:
            namespace["_events"].append(f"offline-boundary-violated:{name}")
            raise AssertionError(
                f"offline verify read unexpected argument attribute {name!r}"
            )
        tracked = namespace.get("_tracked_names", frozenset())
        if name in tracked:
            namespace["_events"].append(f"arg:{name}={_display(namespace[name])}")
            effect = namespace["_property_effects"].pop(name, None)
            if effect is not None:
                effect()
        return super().__getattribute__(name)


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


class _SealResult:
    def __init__(
        self,
        events: list[str],
        *,
        rebind_reporter: Any = None,
        projection_failure: BaseException | None = None,
    ) -> None:
        self._events = events
        self._rebind_reporter = rebind_reporter
        self._subject = _AsDictValue(events, "seal.subject", _SUBJECT)
        self._provenance_reference = _AsDictValue(
            events,
            "seal.provenance_reference",
            _PROVENANCE_REFERENCE,
            failure=projection_failure,
        )

    @property
    def binding_path(self) -> str:
        self._events.append("projection:seal.binding_path")
        if self._rebind_reporter is not None:
            self._events.append("rebind:reporter-from-seal.binding_path")
            cli._machine_report = self._rebind_reporter
        return "/produced/digest-binding.eab"

    @property
    def subject(self) -> _AsDictValue:
        self._events.append("projection:seal.subject")
        return self._subject

    @property
    def provenance_reference(self) -> _AsDictValue:
        self._events.append("projection:seal.provenance_reference")
        return self._provenance_reference

    @property
    def payload(self) -> dict[str, object]:
        self._events.append("projection:seal.payload")
        return {
            "finalizer": dict(_FINALIZER),
            "authentication": dict(_AUTHENTICATION),
        }


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
        return {"authentication": dict(_AUTHENTICATION)}


class _VerifyResult:
    def __init__(
        self,
        events: list[str],
        *,
        rebind_reporter: Any = None,
        projection_failure: BaseException | None = None,
    ) -> None:
        self._events = events
        self._subject = _AsDictValue(
            events,
            "verify.subject",
            _SUBJECT,
            rebind_reporter=rebind_reporter,
        )
        self._provenance_reference = _AsDictValue(
            events,
            "verify.provenance_reference",
            _PROVENANCE_REFERENCE,
            failure=projection_failure,
        )
        self._inspection = _Inspection(events)

    @property
    def subject(self) -> _AsDictValue:
        self._events.append("projection:verify.subject")
        return self._subject

    @property
    def provenance_reference(self) -> _AsDictValue:
        self._events.append("projection:verify.provenance_reference")
        return self._provenance_reference

    @property
    def inspection(self) -> _Inspection:
        self._events.append("projection:verify.inspection")
        return self._inspection


def _seal_args(events: list[str]) -> _SideEffectNamespace:
    args = _SideEffectNamespace(
        expected_context="/trust/context.json",
        expected_source="/trust/source.json",
        finalizer_bundle="/trust/finalizer.evf",
        finalizer_pub="/trust/finalizer.pub",
        force=False,
        out="/outputs/digest-binding.eab",
        provenance="/inputs/provenance.json",
        provenance_identity="opaque:build-17",
        sign_key="/keys/artifact-digest-admission.key",
        subject_digest="sha256:" + "4" * 64,
        subject_kind="artifact-sha256",
    )
    args._events = events
    args._property_effects = {}
    args._tracked_names = frozenset(
        {
            "expected_context",
            "expected_source",
            "finalizer_bundle",
            "finalizer_pub",
            "force",
            "out",
            "provenance",
            "provenance_identity",
            "sign_key",
            "subject_digest",
            "subject_kind",
        }
    )
    return args


def _verify_args(events: list[str]) -> _SideEffectNamespace:
    args = _SideEffectNamespace(
        artifact="/forbidden/artifact.bin",
        binding="/inputs/digest-binding.eab",
        env="/forbidden/environment",
        expected_context="/trust/context.json",
        expected_source="/trust/source.json",
        finalizer_bundle="/trust/finalizer.evf",
        finalizer_pub="/trust/finalizer.pub",
        force=True,
        gh_executable="/forbidden/gh",
        gh_token="/forbidden/token",
        network="/forbidden/network",
        out="/forbidden/output.eab",
        provenance="/inputs/provenance.json",
        provenance_identity="opaque:build-17",
        provider_isolation_gid=2001,
        provider_isolation_uid=2000,
        registry="/forbidden/registry",
        sign_key="/forbidden/signing.key",
        subject_digest="sha256:" + "4" * 64,
        subject_kind="artifact-sha256",
        trusted_pub="/trust/artifact-digest-admission.pub",
    )
    args._events = events
    args._property_effects = {}
    args._tracked_names = frozenset(
        {
            "artifact",
            "binding",
            "env",
            "expected_context",
            "expected_source",
            "finalizer_bundle",
            "finalizer_pub",
            "force",
            "gh_executable",
            "gh_token",
            "network",
            "out",
            "provenance",
            "provenance_identity",
            "provider_isolation_gid",
            "provider_isolation_uid",
            "registry",
            "sign_key",
            "subject_digest",
            "subject_kind",
            "trusted_pub",
        }
    )
    return args


def capture_case(case_name: str) -> dict[str, object]:
    """Capture one command case through the historical public CLI facade."""

    if case_name not in CASE_NAMES:
        raise ValueError(
            f"unknown Artifact Digest Admission V2 characterization case: {case_name}"
        )

    is_seal = case_name.startswith("seal_")
    events: list[str] = []
    calls: list[dict[str, object]] = []
    files: dict[str, str] = {}
    output_sha256: list[str] = []
    args = _seal_args(events) if is_seal else _verify_args(events)

    original_reader = cli._read_external_finalizer_object
    original_reporter = cli._machine_report
    original_seal = artifact_digest_admission.seal_artifact_digest_admission
    original_verify = artifact_digest_admission.verify_artifact_digest_admission
    original_digest_error = artifact_digest_admission.ArtifactDigestAdmissionError
    original_format = artifact_digest_admission.ARTIFACT_DIGEST_BINDING_FORMAT
    original_signing_error = signing.SigningUnavailableError

    expected_exception: BaseException | None = None
    output_exception: BaseException | None = None
    projection_exception: BaseException | None = None
    provider_exception: BaseException | None = None

    if case_name in {
        "seal_finalizer_property_failure_identity",
        "seal_subject_kind_property_failure_identity",
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

    def rebind_reporter() -> None:
        events.append("rebind:reporter")
        cli._machine_report = late_reporter

    def reader(path: str, *, label: str) -> dict[str, object]:
        events.append(f"reader:original:{label}:{path}")
        if case_name == "seal_source_read_error" and label == "expected source":
            raise OSError("source read failed")
        if case_name == "verify_source_read_error" and label == "expected source":
            raise OSError("source read failed")
        if case_name in {
            "seal_context_read_error",
            "verify_context_read_error",
        } and label == "expected context":
            raise UnicodeError("context decode failed")
        if case_name in {
            "seal_metadata_digest_error_is_operational",
            "verify_metadata_digest_error_is_operational",
        } and label == "expected source":
            raise original_digest_error("digest error from metadata reader")
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

    def fail_argument_value() -> None:
        events.append("argument-value-failure")
        raise ValueError("argument value failed")

    def fail_argument_oserror() -> None:
        events.append("argument-oserror")
        raise OSError("argument I/O failed")

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
        artifact_digest_admission.seal_artifact_digest_admission = late_seal
        artifact_digest_admission.ARTIFACT_DIGEST_BINDING_FORMAT = "LATE_FORMAT"

    def rebind_verify_provider() -> None:
        events.append("rebind:verify-provider-and-format")
        artifact_digest_admission.verify_artifact_digest_admission = late_verify
        artifact_digest_admission.ARTIFACT_DIGEST_BINDING_FORMAT = "LATE_FORMAT"

    if case_name == "seal_finalizer_property_failure_identity":
        args._property_effects["finalizer_bundle"] = fail_argument_property
    elif case_name == "seal_subject_kind_property_failure_identity":
        args._property_effects["subject_kind"] = fail_argument_property
    elif case_name == "verify_binding_property_failure_identity":
        args._property_effects["binding"] = fail_argument_property
    elif case_name == "seal_finalizer_stdin_reads_provenance":
        args.finalizer_bundle = "-"
    elif case_name == "seal_guard_property_rebinds_reporter":
        args.finalizer_bundle = "-"
        args._property_effects["finalizer_bundle"] = rebind_reporter
    elif case_name == "seal_provenance_stdin_short_circuit":
        args.provenance = "-"
    elif case_name == "verify_binding_stdin_reads_all_paths":
        args.binding = "-"
    elif case_name == "verify_provenance_stdin_short_circuit":
        args.provenance = "-"
    elif case_name == "verify_finalizer_stdin_reads_provenance":
        args.finalizer_bundle = "-"
    elif case_name == "verify_guard_property_rebinds_reporter":
        args.binding = "-"
        args._property_effects["binding"] = rebind_reporter
    elif case_name == "seal_expected_source_value_error_is_metadata_error":
        args._property_effects["expected_source"] = fail_argument_value
    elif case_name == "verify_expected_source_value_error_is_metadata_error":
        args._property_effects["expected_source"] = fail_argument_value
    elif case_name == "seal_subject_kind_oserror_is_operational":
        args._property_effects["subject_kind"] = fail_argument_oserror
    elif case_name == "verify_subject_kind_oserror_is_operational":
        args._property_effects["subject_kind"] = fail_argument_oserror
    elif case_name == "seal_source_property_rebinds_reader":
        args._property_effects["expected_source"] = rebind_reader
    elif case_name == "verify_source_property_rebinds_reader":
        args._property_effects["expected_source"] = rebind_reader
    elif case_name == "seal_context_property_rebinds_reader":
        args._property_effects["expected_context"] = rebind_reader
    elif case_name == "verify_context_property_rebinds_reader":
        args._property_effects["expected_context"] = rebind_reader
    elif case_name == "seal_provider_frozen_before_arguments":
        args._property_effects["finalizer_bundle"] = rebind_seal_provider
    elif case_name == "verify_provider_frozen_before_arguments":
        args._property_effects["binding"] = rebind_verify_provider
    elif case_name == "verify_success_offline_boundary":
        args._strict_allowed = frozenset(
            {
                "binding",
                "expected_context",
                "expected_source",
                "finalizer_bundle",
                "finalizer_pub",
                "provenance",
                "provenance_identity",
                "subject_digest",
                "subject_kind",
                "trusted_pub",
            }
        )

    class _LateDigestError(ValueError):
        pass

    class _RebindingDigestError(original_digest_error):
        def __str__(self) -> str:
            events.append("rebind:reporter-from-error-string")
            cli._machine_report = late_reporter
            return "artifact digest admission invalid"

    class _LateSigningError(RuntimeError):
        pass

    def seal_provider(
        subject_kind: str,
        subject_digest: str,
        provenance: str,
        provenance_identity: str,
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
                "subject_kind": subject_kind,
                "subject_digest": subject_digest,
                "provenance": provenance,
                "provenance_identity": provenance_identity,
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
            artifact_digest_admission.ArtifactDigestAdmissionError = _LateDigestError
            raise _RebindingDigestError("ignored")
        if case_name == "seal_signing_error_class_snapshot":
            signing.SigningUnavailableError = _LateSigningError
            raise original_signing_error("signing unavailable")
        if case_name == "seal_plain_value_error_is_operational":
            raise ValueError("plain provider value error")
        if case_name == "seal_operational_error_preserves_partial_output":
            files[output] = "partial-provider-output"
            events.append(f"io:partial-output:{output}")
            raise OSError("seal I/O failed")
        if provider_exception is not None:
            raise provider_exception
        files[output] = "sealed-provider-output"
        events.append(f"io:sealed-output:{output}")
        return _SealResult(
            events,
            rebind_reporter=(
                late_reporter
                if case_name == "seal_success_reporter_frozen_before_projection"
                else None
            ),
            projection_failure=projection_exception,
        )

    def verify_provider(
        binding: str,
        subject_kind: str,
        subject_digest: str,
        provenance: str,
        provenance_identity: str,
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
                "subject_kind": subject_kind,
                "subject_digest": subject_digest,
                "provenance": provenance,
                "provenance_identity": provenance_identity,
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
            artifact_digest_admission.ArtifactDigestAdmissionError = _LateDigestError
            raise _RebindingDigestError("ignored")
        if case_name == "verify_signing_error_class_snapshot":
            signing.SigningUnavailableError = _LateSigningError
            raise original_signing_error("signing unavailable")
        if case_name == "verify_plain_value_error_is_operational":
            raise ValueError("plain provider value error")
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
            projection_failure=projection_exception,
        )

    cli._read_external_finalizer_object = reader
    cli._machine_report = reporter
    artifact_digest_admission.seal_artifact_digest_admission = seal_provider
    artifact_digest_admission.verify_artifact_digest_admission = verify_provider

    exit_code: int | None = None
    exception: dict[str, object] | None = None
    try:
        command = (
            cli.cmd_seal_artifact_digest_admission
            if is_seal
            else cli.cmd_verify_artifact_digest_admission
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
        artifact_digest_admission.seal_artifact_digest_admission = original_seal
        artifact_digest_admission.verify_artifact_digest_admission = original_verify
        artifact_digest_admission.ArtifactDigestAdmissionError = original_digest_error
        artifact_digest_admission.ARTIFACT_DIGEST_BINDING_FORMAT = original_format
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
