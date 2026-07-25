"""Deterministic characterization of the Release Source Finalizer CLI family.

The vector freezes the four public commands before extraction.  It records
function-entry import snapshots, live facade helpers, argument-read order,
exception classification and identity, exact reports and exit codes, repeated
result projections, file residue, and the strictly local/raw-Git boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from typing import Any

from evoom_guard import cli, evidence_bundle, release_source_finalizer, signing

BASELINE_COMMIT = "28ddb67b52d259458796fd2ac4d47807491365c0"
SCHEMA_VERSION = "cli-release-source-finalizer-characterization-v1"
CASE_NAMES = (
    "derive_bindings_projection_failure_identity",
    "derive_context_valueerror",
    "derive_finalizer_error_class_and_reporter_snapshot",
    "derive_output_failure_identity",
    "derive_provider_baseexception_identity",
    "derive_providers_frozen_before_arguments",
    "derive_publish_context_oserror_preserves_source",
    "derive_publish_source_oserror",
    "derive_raw_git_valueerror",
    "derive_record_oserror",
    "derive_record_valueerror",
    "derive_source_out_property_rebinds_abspath",
    "derive_source_property_rebinds_reader",
    "derive_source_read_oserror",
    "derive_source_read_unicodeerror",
    "derive_source_read_valueerror",
    "derive_success_boundary",
    "derive_success_reporter_frozen_before_projection",
    "derive_verdict_property_failure_identity",
    "derive_verdict_property_rebinds_reporter",
    "derive_verdict_stdin",
    "handoff_context_property_rebinds_reader",
    "handoff_context_read_unicodeerror",
    "handoff_out_property_rebinds_abspath",
    "handoff_output_failure_identity",
    "handoff_projection_failure_identity",
    "handoff_provider_baseexception_identity",
    "handoff_provider_finalizer_error_class_and_reporter_snapshot",
    "handoff_provider_frozen_before_arguments",
    "handoff_provider_oserror_preserves_partial_output",
    "handoff_provider_valueerror",
    "handoff_source_property_rebinds_reader",
    "handoff_source_read_oserror",
    "handoff_source_read_valueerror",
    "handoff_success_boundary",
    "handoff_success_reporter_frozen_before_projection",
    "handoff_verdict_property_failure_identity",
    "handoff_verdict_property_rebinds_reporter",
    "handoff_verdict_stdin",
    "seal_allow_flag_failure_after_report",
    "seal_context_property_rebinds_reader",
    "seal_context_read_unicodeerror",
    "seal_output_failure_identity",
    "seal_projection_failure_identity",
    "seal_provider_baseexception_identity",
    "seal_provider_finalizer_error_class_and_reporter_snapshot",
    "seal_provider_frozen_before_arguments",
    "seal_provider_oserror_preserves_partial_output",
    "seal_provider_valueerror",
    "seal_signing_error_class_snapshot",
    "seal_signing_unavailable",
    "seal_source_property_rebinds_reader",
    "seal_source_read_oserror",
    "seal_source_read_valueerror",
    "seal_success_allow_boundary",
    "seal_success_deny_default",
    "seal_success_deny_opt_in",
    "seal_success_reporter_frozen_before_projection",
    "seal_verdict_property_failure_identity",
    "seal_verdict_property_rebinds_reporter",
    "seal_verdict_stdin",
    "verify_allow_flag_failure_after_report",
    "verify_bundle_property_failure_identity",
    "verify_bundle_stdin_is_forwarded",
    "verify_context_property_rebinds_reader",
    "verify_context_read_unicodeerror",
    "verify_output_failure_identity",
    "verify_projection_failure_identity",
    "verify_provider_baseexception_identity",
    "verify_provider_finalizer_error_class_and_reporter_snapshot",
    "verify_provider_frozen_before_arguments",
    "verify_provider_oserror",
    "verify_provider_valueerror",
    "verify_signing_error_class_snapshot",
    "verify_signing_unavailable",
    "verify_source_property_rebinds_reader",
    "verify_source_read_oserror",
    "verify_source_read_valueerror",
    "verify_success_allow_boundary",
    "verify_success_deny_default",
    "verify_success_deny_opt_in",
    "verify_success_reporter_frozen_before_projection",
)

_SOURCE = {
    "format": "EVOGUARD_RELEASE_SOURCE_V1",
    "repository": "EvoRiseKsa/EvoOM-Guard-m",
    "ref": "refs/heads/main",
    "target_commit_sha": "1" * 40,
}
_CONTEXT = {
    "format": "EVOGUARD_RELEASE_SOURCE_CONTEXT_V1",
    "policy_digest": "sha256:" + "2" * 64,
    "verifier_pack_digest": "sha256:" + "3" * 64,
}
_RECORD = {"sha256": "4" * 64}
_AUTHENTICATION = {"key_id": "sha256:" + "5" * 64}
_VERDICT = {
    "format": "EVOGUARD_SEMANTIC_RECORD_V1",
    "outcome": "PASS",
}


def canonical_json(value: Any) -> str:
    """Return the stable, human-reviewable vector encoding."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _display(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


class _SideEffectNamespace(argparse.Namespace):
    """Namespace that logs and can mutate one selected property read."""

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


class _ObservedMapping(dict[str, object]):
    def __init__(
        self,
        events: list[str],
        name: str,
        value: dict[str, object],
        *,
        fail_key: str | None = None,
        failure: BaseException | None = None,
        rebind_reporter_key: str | None = None,
        late_reporter: Any = None,
    ) -> None:
        super().__init__(value)
        self._events = events
        self._name = name
        self._fail_key = fail_key
        self._failure = failure
        self._rebind_reporter_key = rebind_reporter_key
        self._late_reporter = late_reporter

    def __getitem__(self, key: str) -> object:
        self._events.append(f"projection:{self._name}[{key}]")
        if key == self._rebind_reporter_key:
            self._events.append(f"rebind:reporter-from-{self._name}[{key}]")
            cli._machine_report = self._late_reporter
        if key == self._fail_key and self._failure is not None:
            raise self._failure
        return super().__getitem__(key)


class _HandoffResult(_ObservedMapping):
    def __init__(
        self,
        events: list[str],
        *,
        projection_failure: BaseException | None = None,
        late_reporter: Any = None,
    ) -> None:
        super().__init__(
            events,
            "handoff",
            {
                "record": _ObservedMapping(events, "handoff.record", dict(_RECORD)),
                "source": dict(_SOURCE),
                "context": dict(_CONTEXT),
            },
            fail_key="context" if projection_failure is not None else None,
            failure=projection_failure,
            rebind_reporter_key=(
                "record" if late_reporter is not None else None
            ),
            late_reporter=late_reporter,
        )


class _SealResult:
    def __init__(
        self,
        events: list[str],
        decision: str,
        *,
        projection_failure: BaseException | None = None,
        late_reporter: Any = None,
    ) -> None:
        self._events = events
        self._decision = decision
        self._decision_reads = 0
        self._projection_failure = projection_failure
        self._late_reporter = late_reporter
        self._manifest = _ObservedMapping(
            events,
            "seal.manifest",
            {
                "record": _ObservedMapping(events, "seal.record", dict(_RECORD)),
                "authentication": _ObservedMapping(
                    events,
                    "seal.authentication",
                    dict(_AUTHENTICATION),
                ),
            },
        )

    @property
    def decision(self) -> str:
        self._decision_reads += 1
        self._events.append(f"projection:seal.decision:{self._decision_reads}")
        if self._decision_reads == 2 and self._late_reporter is not None:
            self._events.append("rebind:reporter-from-seal.decision")
            cli._machine_report = self._late_reporter
        return self._decision

    @property
    def bundle_path(self) -> str:
        self._events.append("projection:seal.bundle_path")
        if self._projection_failure is not None:
            raise self._projection_failure
        return "/produced/release-source.evs"

    @property
    def manifest(self) -> _ObservedMapping:
        self._events.append("projection:seal.manifest")
        return self._manifest


class _BundleValue:
    def __init__(self, events: list[str]) -> None:
        self._events = events
        self._manifest = _ObservedMapping(
            events,
            "verify.manifest",
            {
                "authentication": _ObservedMapping(
                    events,
                    "verify.authentication",
                    dict(_AUTHENTICATION),
                )
            },
        )

    @property
    def manifest(self) -> _ObservedMapping:
        self._events.append("projection:verify.bundle.manifest")
        return self._manifest


class _VerifyResult:
    def __init__(
        self,
        events: list[str],
        decision: str,
        *,
        projection_failure: BaseException | None = None,
        late_reporter: Any = None,
    ) -> None:
        self._events = events
        self._decision = decision
        self._decision_reads = 0
        self._bundle = _BundleValue(events)
        self._projection_failure = projection_failure
        self._late_reporter = late_reporter

    @property
    def decision(self) -> str:
        self._decision_reads += 1
        self._events.append(f"projection:verify.decision:{self._decision_reads}")
        if self._decision_reads == 2 and self._late_reporter is not None:
            self._events.append("rebind:reporter-from-verify.decision")
            cli._machine_report = self._late_reporter
        return self._decision

    @property
    def bundle(self) -> _BundleValue:
        self._events.append("projection:verify.bundle")
        if self._projection_failure is not None:
            raise self._projection_failure
        return self._bundle

    @property
    def record_report(self) -> dict[str, object]:
        self._events.append("projection:verify.record_report")
        return {"valid": True, "sha256": _RECORD["sha256"]}


class _Bindings:
    def __init__(
        self,
        events: list[str],
        *,
        projection_failure: BaseException | None = None,
    ) -> None:
        self._events = events
        self._projection_failure = projection_failure

    @property
    def source(self) -> dict[str, object]:
        self._events.append("projection:bindings.source")
        if self._projection_failure is not None:
            raise self._projection_failure
        return dict(_SOURCE)


def _configure_args(args: _SideEffectNamespace, events: list[str]) -> _SideEffectNamespace:
    args._events = events
    args._property_effects = {}
    args._tracked_names = frozenset(
        key for key in vars(args) if not key.startswith("_")
    )
    return args


def _handoff_args(events: list[str]) -> _SideEffectNamespace:
    return _configure_args(
        _SideEffectNamespace(
            context="/trust/context.json",
            force=False,
            out="/outputs/release-source-handoff.json",
            source="/trust/source.json",
            verdict="/inputs/verdict.json",
        ),
        events,
    )


def _seal_args(events: list[str]) -> _SideEffectNamespace:
    return _configure_args(
        _SideEffectNamespace(
            allow_deny_evidence=False,
            expected_context="/trust/context.json",
            expected_source="/trust/source.json",
            force=False,
            git_repository="/repo.git",
            git_repository_bare=True,
            handoff="/inputs/release-source-handoff.json",
            must_differ_from_key_id=[
                "sha256:" + "6" * 64,
                "sha256:" + "7" * 64,
            ],
            out="/outputs/release-source.evs",
            sign_key="/keys/release-source.key",
            verdict="/inputs/verdict.json",
        ),
        events,
    )


def _verify_args(events: list[str]) -> _SideEffectNamespace:
    return _configure_args(
        _SideEffectNamespace(
            allow_deny_evidence=False,
            bundle="/inputs/release-source.evs",
            expected_context="/trust/context.json",
            expected_source="/trust/source.json",
            must_differ_from_key_id=[
                "sha256:" + "6" * 64,
                "sha256:" + "7" * 64,
            ],
            trusted_pub="/keys/release-source.pub",
        ),
        events,
    )


def _derive_args(events: list[str]) -> _SideEffectNamespace:
    return _configure_args(
        _SideEffectNamespace(
            context_out="/outputs/release-source-context.json",
            force=False,
            git_repository="/repo.git",
            git_repository_bare=True,
            source="/trust/source.json",
            source_out="/outputs/release-source.json",
            verdict="/inputs/verdict.json",
        ),
        events,
    )


def _command_kind(case_name: str) -> str:
    return case_name.split("_", 1)[0]


def capture_case(case_name: str) -> dict[str, object]:
    """Capture one case through the historical public CLI facade."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown Release Source Finalizer case: {case_name}")

    kind = _command_kind(case_name)
    events: list[str] = []
    calls: list[dict[str, object]] = []
    files: dict[str, str] = {}
    reports: list[dict[str, object]] = []
    output_sha256: list[str] = []
    args = {
        "handoff": _handoff_args,
        "seal": _seal_args,
        "verify": _verify_args,
        "derive": _derive_args,
    }[kind](events)

    original_reader = cli._read_external_finalizer_object
    original_reporter = cli._machine_report
    original_abspath = cli.os.path.abspath
    original_handoff_format = release_source_finalizer.RELEASE_SOURCE_HANDOFF_FORMAT
    original_evidence_format = release_source_finalizer.RELEASE_SOURCE_EVIDENCE_FORMAT
    original_context_format = release_source_finalizer.RELEASE_SOURCE_CONTEXT_FORMAT
    original_finalizer_error = release_source_finalizer.ReleaseSourceFinalizerError
    original_create_handoff = release_source_finalizer.create_release_source_handoff
    original_seal = release_source_finalizer.seal_release_source_bundle
    original_verify = release_source_finalizer.verify_release_source_bundle
    original_record_snapshot = release_source_finalizer._record_snapshot
    original_derive = release_source_finalizer.derive_release_source_bindings
    original_context_from = release_source_finalizer.context_from_release_source_bindings
    original_publish = release_source_finalizer._publish_bytes
    original_canonical = evidence_bundle._canonical_json
    original_signing_error = signing.SigningUnavailableError

    expected_exception: BaseException | None = None
    output_exception: BaseException | None = None
    projection_exception: BaseException | None = None
    provider_exception: BaseException | None = None

    property_failure_cases = {
        "handoff_verdict_property_failure_identity",
        "seal_verdict_property_failure_identity",
        "verify_bundle_property_failure_identity",
        "derive_verdict_property_failure_identity",
    }
    projection_failure_cases = {
        "handoff_projection_failure_identity",
        "seal_projection_failure_identity",
        "verify_projection_failure_identity",
        "derive_bindings_projection_failure_identity",
    }
    baseexception_cases = {
        "handoff_provider_baseexception_identity",
        "seal_provider_baseexception_identity",
        "verify_provider_baseexception_identity",
        "derive_provider_baseexception_identity",
    }
    output_failure_cases = {
        "handoff_output_failure_identity",
        "seal_output_failure_identity",
        "verify_output_failure_identity",
        "derive_output_failure_identity",
    }
    flag_failure_cases = {
        "seal_allow_flag_failure_after_report",
        "verify_allow_flag_failure_after_report",
    }
    if case_name in property_failure_cases | flag_failure_cases:
        expected_exception = RuntimeError("argument property failed")
    elif case_name in projection_failure_cases:
        projection_exception = RuntimeError("projection failed")
        expected_exception = projection_exception
    elif case_name in baseexception_cases:
        provider_exception = KeyboardInterrupt("provider interrupted")
        expected_exception = provider_exception
    elif case_name in output_failure_cases:
        output_exception = RuntimeError("output failed")
        expected_exception = output_exception

    def emit(message: str) -> None:
        parsed = json.loads(message)
        events.append(f"output:{parsed['status']}")
        output_sha256.append(hashlib.sha256(message.encode("utf-8")).hexdigest())
        if output_exception is not None:
            raise output_exception

    def _json_copy(value: dict[str, object]) -> dict[str, object]:
        return json.loads(json.dumps(value, ensure_ascii=True, sort_keys=True))

    def reporter(report_out: Any, value: dict[str, object]) -> None:
        events.append(f"reporter:original:{value['status']}")
        reports.append(_json_copy(value))
        original_reporter(report_out, value)

    def late_reporter(report_out: Any, value: dict[str, object]) -> None:
        events.append(f"reporter:late:{value['status']}")
        reports.append(_json_copy(value))
        original_reporter(report_out, value)

    def rebind_reporter() -> None:
        events.append("rebind:reporter")
        cli._machine_report = late_reporter

    def fake_abspath(path: str) -> str:
        events.append(f"path:abspath-original:{path}")
        return f"/absolute::{path}"

    def late_abspath(path: str) -> str:
        events.append(f"path:abspath-late:{path}")
        return f"/late-absolute::{path}"

    def rebind_abspath() -> None:
        events.append("rebind:abspath")
        cli.os.path.abspath = late_abspath

    def reader(path: str, *, label: str) -> dict[str, object]:
        events.append(f"reader:original:{label}:{path}")
        if case_name.endswith("source_read_oserror") and "source" in label:
            raise OSError("source read failed")
        if case_name.endswith("source_read_unicodeerror") and "source" in label:
            raise UnicodeError("source decode failed")
        if case_name.endswith("source_read_valueerror") and "source" in label:
            raise ValueError("source value failed")
        if case_name.endswith("context_read_unicodeerror") and "context" in label:
            raise UnicodeError("context decode failed")
        return dict(_CONTEXT if "context" in label else _SOURCE)

    def late_reader(path: str, *, label: str) -> dict[str, object]:
        events.append(f"reader:late:{label}:{path}")
        return dict(_CONTEXT if "context" in label else _SOURCE)

    def rebind_reader() -> None:
        events.append("rebind:reader")
        cli._read_external_finalizer_object = late_reader

    def fail_argument_property() -> None:
        events.append("argument-property-failure")
        assert expected_exception is not None
        raise expected_exception

    class _EntryFinalizerError(Exception):
        def __str__(self) -> str:
            events.append("error-string:entry-finalizer")
            rebind_reporter()
            return "entry finalizer error"

    class _LateFinalizerError(Exception):
        pass

    class _EntrySigningError(Exception):
        pass

    class _LateSigningError(Exception):
        pass

    finalizer_snapshot_cases = {
        "handoff_provider_finalizer_error_class_and_reporter_snapshot",
        "seal_provider_finalizer_error_class_and_reporter_snapshot",
        "verify_provider_finalizer_error_class_and_reporter_snapshot",
        "derive_finalizer_error_class_and_reporter_snapshot",
    }
    signing_snapshot_cases = {
        "seal_signing_error_class_snapshot",
        "verify_signing_error_class_snapshot",
    }
    if case_name in finalizer_snapshot_cases:
        release_source_finalizer.ReleaseSourceFinalizerError = _EntryFinalizerError
    if case_name in signing_snapshot_cases:
        signing.SigningUnavailableError = _EntrySigningError

    def handoff_provider(
        verdict: str,
        output: str,
        *,
        source: dict[str, object],
        context: dict[str, object],
        force: bool,
    ) -> _HandoffResult:
        events.append("provider:handoff-original")
        calls.append(
            {
                "provider": "handoff",
                "verdict": verdict,
                "output": output,
                "source": source,
                "context": context,
                "force": force,
            }
        )
        if case_name == "handoff_provider_finalizer_error_class_and_reporter_snapshot":
            release_source_finalizer.ReleaseSourceFinalizerError = _LateFinalizerError
            raise _EntryFinalizerError()
        if case_name == "handoff_provider_oserror_preserves_partial_output":
            files[output] = "partial-handoff"
            events.append(f"io:partial-output:{output}")
            raise OSError("handoff I/O failed")
        if case_name == "handoff_provider_valueerror":
            raise ValueError("handoff value failed")
        if provider_exception is not None:
            raise provider_exception
        files[output] = "handoff"
        events.append(f"io:output:{output}")
        return _HandoffResult(
            events,
            projection_failure=projection_exception,
            late_reporter=(
                late_reporter
                if case_name == "handoff_success_reporter_frozen_before_projection"
                else None
            ),
        )

    def late_handoff_provider(*provider_args: Any, **provider_kwargs: Any) -> Any:
        del provider_args, provider_kwargs
        events.append("provider:handoff-late")
        raise AssertionError("late handoff provider was used")

    def seal_provider(
        handoff: str,
        verdict: str,
        output: str,
        *,
        expected_source: dict[str, object],
        expected_context: dict[str, object],
        git_repository: str,
        git_repository_is_bare: bool,
        private_key_path: str,
        prohibited_key_ids: list[str],
        force: bool,
    ) -> _SealResult:
        events.append("provider:seal-original")
        calls.append(
            {
                "provider": "seal",
                "handoff": handoff,
                "verdict": verdict,
                "output": output,
                "expected_source": expected_source,
                "expected_context": expected_context,
                "git_repository": git_repository,
                "git_repository_is_bare": git_repository_is_bare,
                "private_key_path": private_key_path,
                "prohibited_key_ids": prohibited_key_ids,
                "force": force,
            }
        )
        if case_name == "seal_provider_finalizer_error_class_and_reporter_snapshot":
            release_source_finalizer.ReleaseSourceFinalizerError = _LateFinalizerError
            raise _EntryFinalizerError()
        if case_name == "seal_provider_oserror_preserves_partial_output":
            files[output] = "partial-seal"
            events.append(f"io:partial-output:{output}")
            raise OSError("seal I/O failed")
        if case_name == "seal_provider_valueerror":
            raise ValueError("seal value failed")
        if case_name == "seal_signing_unavailable":
            raise original_signing_error("signing unavailable")
        if case_name == "seal_signing_error_class_snapshot":
            signing.SigningUnavailableError = _LateSigningError
            raise _EntrySigningError("entry signing unavailable")
        if provider_exception is not None:
            raise provider_exception
        files[output] = "sealed"
        events.append(f"io:output:{output}")
        decision = (
            "DENY"
            if case_name
            in {
                "seal_allow_flag_failure_after_report",
                "seal_success_deny_default",
                "seal_success_deny_opt_in",
            }
            else "ALLOW"
        )
        return _SealResult(
            events,
            decision,
            projection_failure=projection_exception,
            late_reporter=(
                late_reporter
                if case_name == "seal_success_reporter_frozen_before_projection"
                else None
            ),
        )

    def late_seal_provider(*provider_args: Any, **provider_kwargs: Any) -> Any:
        del provider_args, provider_kwargs
        events.append("provider:seal-late")
        raise AssertionError("late seal provider was used")

    def verify_provider(
        bundle: str,
        *,
        trusted_public_key_path: str,
        expected_source: dict[str, object],
        expected_context: dict[str, object],
        prohibited_key_ids: list[str],
    ) -> _VerifyResult:
        events.append("provider:verify-original")
        calls.append(
            {
                "provider": "verify",
                "bundle": bundle,
                "trusted_public_key_path": trusted_public_key_path,
                "expected_source": expected_source,
                "expected_context": expected_context,
                "prohibited_key_ids": prohibited_key_ids,
            }
        )
        if case_name == "verify_provider_finalizer_error_class_and_reporter_snapshot":
            release_source_finalizer.ReleaseSourceFinalizerError = _LateFinalizerError
            raise _EntryFinalizerError()
        if case_name == "verify_provider_oserror":
            raise OSError("verify I/O failed")
        if case_name == "verify_provider_valueerror":
            raise ValueError("verify value failed")
        if case_name == "verify_signing_unavailable":
            raise original_signing_error("signing unavailable")
        if case_name == "verify_signing_error_class_snapshot":
            signing.SigningUnavailableError = _LateSigningError
            raise _EntrySigningError("entry signing unavailable")
        if provider_exception is not None:
            raise provider_exception
        decision = (
            "DENY"
            if case_name
            in {
                "verify_allow_flag_failure_after_report",
                "verify_success_deny_default",
                "verify_success_deny_opt_in",
            }
            else "ALLOW"
        )
        return _VerifyResult(
            events,
            decision,
            projection_failure=projection_exception,
            late_reporter=(
                late_reporter
                if case_name == "verify_success_reporter_frozen_before_projection"
                else None
            ),
        )

    def late_verify_provider(*provider_args: Any, **provider_kwargs: Any) -> Any:
        del provider_args, provider_kwargs
        events.append("provider:verify-late")
        raise AssertionError("late verify provider was used")

    def record_snapshot(verdict_path: str) -> tuple[bytes, dict[str, object], dict[str, object]]:
        events.append(f"provider:record-snapshot-original:{verdict_path}")
        calls.append({"provider": "record_snapshot", "verdict": verdict_path})
        if case_name == "derive_record_oserror":
            raise OSError("record I/O failed")
        if case_name == "derive_record_valueerror":
            raise ValueError("record value failed")
        return b"record", dict(_VERDICT), {"valid": True}

    def derive_provider(
        *,
        git_repository: str,
        source: dict[str, object],
        git_repository_is_bare: bool,
    ) -> _Bindings:
        events.append("provider:derive-original")
        calls.append(
            {
                "provider": "derive",
                "git_repository": git_repository,
                "source": source,
                "git_repository_is_bare": git_repository_is_bare,
            }
        )
        if case_name == "derive_finalizer_error_class_and_reporter_snapshot":
            release_source_finalizer.ReleaseSourceFinalizerError = _LateFinalizerError
            raise _EntryFinalizerError()
        if case_name == "derive_raw_git_valueerror":
            raise ValueError("raw Git value failed")
        if provider_exception is not None:
            raise provider_exception
        return _Bindings(events, projection_failure=projection_exception)

    def context_from_provider(
        bindings: _Bindings,
        verdict: dict[str, object],
    ) -> dict[str, object]:
        events.append("provider:context-from-bindings-original")
        calls.append(
            {
                "provider": "context_from_bindings",
                "bindings_identity": type(bindings).__name__,
                "verdict": verdict,
            }
        )
        if case_name == "derive_context_valueerror":
            raise ValueError("context value failed")
        return dict(_CONTEXT)

    def canonical_provider(value: dict[str, object]) -> bytes:
        events.append(f"provider:canonical-json:{value.get('format')}")
        calls.append({"provider": "canonical_json", "value": value})
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    def publish_provider(
        path: str,
        payload: bytes,
        *,
        force: bool,
        prefix: str,
        label: str,
    ) -> None:
        events.append(f"provider:publish:{label}:{path}")
        calls.append(
            {
                "provider": "publish",
                "path": path,
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                "force": force,
                "prefix": prefix,
                "label": label,
            }
        )
        if case_name == "derive_publish_source_oserror" and label == "verified release source":
            raise OSError("source publish failed")
        if (
            case_name == "derive_publish_context_oserror_preserves_source"
            and label == "verified release-source context"
        ):
            raise OSError("context publish failed")
        files[path] = payload.decode("utf-8")
        events.append(f"io:output:{path}")

    def late_derive_provider(*provider_args: Any, **provider_kwargs: Any) -> Any:
        del provider_args, provider_kwargs
        events.append("provider:derive-late")
        raise AssertionError("late derive provider was used")

    def late_record_snapshot(*provider_args: Any, **provider_kwargs: Any) -> Any:
        del provider_args, provider_kwargs
        events.append("provider:record-snapshot-late")
        raise AssertionError("late record snapshot was used")

    def late_context_from(*provider_args: Any, **provider_kwargs: Any) -> Any:
        del provider_args, provider_kwargs
        events.append("provider:context-from-late")
        raise AssertionError("late context provider was used")

    def late_publish(*provider_args: Any, **provider_kwargs: Any) -> Any:
        del provider_args, provider_kwargs
        events.append("provider:publish-late")
        raise AssertionError("late publisher was used")

    def late_canonical(*provider_args: Any, **provider_kwargs: Any) -> Any:
        del provider_args, provider_kwargs
        events.append("provider:canonical-late")
        raise AssertionError("late canonical encoder was used")

    def rebind_handoff_imports() -> None:
        events.append("rebind:handoff-provider-and-format")
        release_source_finalizer.create_release_source_handoff = late_handoff_provider
        release_source_finalizer.RELEASE_SOURCE_HANDOFF_FORMAT = "LATE_HANDOFF_FORMAT"

    def rebind_seal_imports() -> None:
        events.append("rebind:seal-provider-and-format")
        release_source_finalizer.seal_release_source_bundle = late_seal_provider
        release_source_finalizer.RELEASE_SOURCE_EVIDENCE_FORMAT = "LATE_EVIDENCE_FORMAT"

    def rebind_verify_imports() -> None:
        events.append("rebind:verify-provider-and-format")
        release_source_finalizer.verify_release_source_bundle = late_verify_provider
        release_source_finalizer.RELEASE_SOURCE_EVIDENCE_FORMAT = "LATE_EVIDENCE_FORMAT"

    def rebind_derive_imports() -> None:
        events.append("rebind:derive-providers-and-format")
        release_source_finalizer._record_snapshot = late_record_snapshot
        release_source_finalizer.derive_release_source_bindings = late_derive_provider
        release_source_finalizer.context_from_release_source_bindings = late_context_from
        release_source_finalizer._publish_bytes = late_publish
        evidence_bundle._canonical_json = late_canonical
        release_source_finalizer.RELEASE_SOURCE_CONTEXT_FORMAT = "LATE_CONTEXT_FORMAT"

    if case_name == "handoff_verdict_stdin":
        args.verdict = "-"
    elif case_name == "handoff_verdict_property_rebinds_reporter":
        args.verdict = "-"
        args._property_effects["verdict"] = rebind_reporter
    elif case_name == "handoff_verdict_property_failure_identity":
        args._property_effects["verdict"] = fail_argument_property
    elif case_name == "handoff_source_property_rebinds_reader":
        args._property_effects["source"] = rebind_reader
    elif case_name == "handoff_context_property_rebinds_reader":
        args._property_effects["context"] = rebind_reader
    elif case_name == "handoff_provider_frozen_before_arguments":
        args._property_effects["verdict"] = rebind_handoff_imports
    elif case_name == "handoff_out_property_rebinds_abspath":
        args._property_effects["out"] = rebind_abspath
    elif case_name == "seal_verdict_stdin":
        args.verdict = "-"
    elif case_name == "seal_verdict_property_rebinds_reporter":
        args.verdict = "-"
        args._property_effects["verdict"] = rebind_reporter
    elif case_name == "seal_verdict_property_failure_identity":
        args._property_effects["verdict"] = fail_argument_property
    elif case_name == "seal_source_property_rebinds_reader":
        args._property_effects["expected_source"] = rebind_reader
    elif case_name == "seal_context_property_rebinds_reader":
        args._property_effects["expected_context"] = rebind_reader
    elif case_name == "seal_provider_frozen_before_arguments":
        args._property_effects["verdict"] = rebind_seal_imports
    elif case_name == "seal_success_deny_opt_in":
        args.allow_deny_evidence = True
    elif case_name == "seal_allow_flag_failure_after_report":
        args._property_effects["allow_deny_evidence"] = fail_argument_property
    elif case_name == "verify_bundle_property_failure_identity":
        args._property_effects["bundle"] = fail_argument_property
    elif case_name == "verify_bundle_stdin_is_forwarded":
        args.bundle = "-"
    elif case_name == "verify_source_property_rebinds_reader":
        args._property_effects["expected_source"] = rebind_reader
    elif case_name == "verify_context_property_rebinds_reader":
        args._property_effects["expected_context"] = rebind_reader
    elif case_name == "verify_provider_frozen_before_arguments":
        args._property_effects["expected_source"] = rebind_verify_imports
    elif case_name == "verify_success_deny_opt_in":
        args.allow_deny_evidence = True
    elif case_name == "verify_allow_flag_failure_after_report":
        args._property_effects["allow_deny_evidence"] = fail_argument_property
    elif case_name == "derive_verdict_stdin":
        args.verdict = "-"
    elif case_name == "derive_verdict_property_rebinds_reporter":
        args.verdict = "-"
        args._property_effects["verdict"] = rebind_reporter
    elif case_name == "derive_verdict_property_failure_identity":
        args._property_effects["verdict"] = fail_argument_property
    elif case_name == "derive_source_property_rebinds_reader":
        args._property_effects["source"] = rebind_reader
    elif case_name == "derive_providers_frozen_before_arguments":
        args._property_effects["verdict"] = rebind_derive_imports
    elif case_name == "derive_source_out_property_rebinds_abspath":
        args._property_effects["source_out"] = rebind_abspath
    elif case_name == "derive_success_reporter_frozen_before_projection":
        args._property_effects["source_out"] = rebind_reporter

    boundary_cases = {
        "handoff_success_boundary",
        "seal_success_allow_boundary",
        "verify_success_allow_boundary",
        "derive_success_boundary",
    }
    if case_name in boundary_cases:
        args._strict_allowed = frozenset(args._tracked_names)

    cli._read_external_finalizer_object = reader
    cli._machine_report = reporter
    cli.os.path.abspath = fake_abspath
    release_source_finalizer.create_release_source_handoff = handoff_provider
    release_source_finalizer.seal_release_source_bundle = seal_provider
    release_source_finalizer.verify_release_source_bundle = verify_provider
    release_source_finalizer._record_snapshot = record_snapshot
    release_source_finalizer.derive_release_source_bindings = derive_provider
    release_source_finalizer.context_from_release_source_bindings = context_from_provider
    release_source_finalizer._publish_bytes = publish_provider
    evidence_bundle._canonical_json = canonical_provider

    command = {
        "handoff": cli.cmd_release_source_handoff,
        "seal": cli.cmd_seal_release_source_finalizer,
        "verify": cli.cmd_verify_release_source_finalized,
        "derive": cli.cmd_derive_release_source_controls,
    }[kind]
    exit_code: int | None = None
    exception: dict[str, object] | None = None
    try:
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
        cli.os.path.abspath = original_abspath
        release_source_finalizer.RELEASE_SOURCE_HANDOFF_FORMAT = original_handoff_format
        release_source_finalizer.RELEASE_SOURCE_EVIDENCE_FORMAT = original_evidence_format
        release_source_finalizer.RELEASE_SOURCE_CONTEXT_FORMAT = original_context_format
        release_source_finalizer.ReleaseSourceFinalizerError = original_finalizer_error
        release_source_finalizer.create_release_source_handoff = original_create_handoff
        release_source_finalizer.seal_release_source_bundle = original_seal
        release_source_finalizer.verify_release_source_bundle = original_verify
        release_source_finalizer._record_snapshot = original_record_snapshot
        release_source_finalizer.derive_release_source_bindings = original_derive
        release_source_finalizer.context_from_release_source_bindings = original_context_from
        release_source_finalizer._publish_bytes = original_publish
        evidence_bundle._canonical_json = original_canonical
        signing.SigningUnavailableError = original_signing_error

    behavior_bytes = json.dumps(
        {
            "calls": calls,
            "events": events,
            "files": files,
            "output_sha256": output_sha256,
            "reports": reports,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return {
        "activity_counts": [
            len(calls),
            len(events),
            len(files),
            len(output_sha256),
            len(reports),
        ],
        "behavior_sha256": hashlib.sha256(behavior_bytes).hexdigest(),
        "exception": exception,
        "exit_code": exit_code,
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
