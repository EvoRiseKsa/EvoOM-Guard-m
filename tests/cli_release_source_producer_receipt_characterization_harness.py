"""Deterministic characterization of the producer-receipt CLI family.

The vector freezes the three public producer-receipt commands before
extraction.  It records eager stdin reads, import snapshots, live facade
helpers, exact provider calls, exception classification and identity, report
bytes, exit codes, repeated projections, partial output residue, and the
strictly non-admitting argument boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Callable
from typing import Any

from evoom_guard import cli, release_source_producer_receipt

BASELINE_COMMIT = "08c721a5b7d6b4be675144fe0d1c065d27c5bf71"
SCHEMA_VERSION = "cli-release-source-producer-receipt-characterization-v1"
CASE_NAMES = (
    "create_argument_failure_identity",
    "create_context_property_rebinds_reader",
    "create_context_unicodeerror",
    "create_domain_error_class_and_provider_snapshot",
    "create_eager_stdin_first_reads_handoff",
    "create_handoff_stdin",
    "create_out_property_rebinds_abspath",
    "create_output_failure_identity",
    "create_producer_property_rebinds_reader",
    "create_producer_valueerror",
    "create_projection_failure_identity",
    "create_provider_baseexception_identity",
    "create_provider_frozen_before_arguments",
    "create_provider_oserror_preserves_receipt",
    "create_provider_valueerror",
    "create_reporter_frozen_before_projection",
    "create_source_oserror",
    "create_source_property_rebinds_reader",
    "create_stdin_reporter_rebind",
    "create_success_boundary",
    "reverify_allow_flag_failure_after_report",
    "reverify_argument_failure_identity",
    "reverify_context_property_rebinds_reader",
    "reverify_context_unicodeerror",
    "reverify_domain_error_class_and_provider_snapshot",
    "reverify_eager_stdin_first_reads_all",
    "reverify_external_helper_is_live_after_stdin",
    "reverify_github_policy_property_rebinds_reader",
    "reverify_github_policy_valueerror",
    "reverify_handoff_stdin",
    "reverify_output_failure_identity",
    "reverify_producer_property_rebinds_reader",
    "reverify_projection_failure_identity",
    "reverify_provider_baseexception_identity",
    "reverify_provider_frozen_before_arguments",
    "reverify_provider_oserror_preserves_provider_outputs",
    "reverify_provider_valueerror",
    "reverify_reporter_frozen_before_projection",
    "reverify_source_oserror",
    "reverify_source_property_rebinds_reader",
    "reverify_stdin_reporter_rebind",
    "reverify_success_default_nonadmitting",
    "reverify_success_opt_in_nonadmitting",
    "reverify_verdict_stdin",
    "verify_allow_flag_failure_after_report",
    "verify_argument_failure_identity",
    "verify_context_property_rebinds_reader",
    "verify_context_unicodeerror",
    "verify_domain_error_class_and_provider_snapshot",
    "verify_eager_stdin_first_reads_all",
    "verify_external_helper_is_live_after_stdin",
    "verify_handoff_stdin",
    "verify_output_failure_identity",
    "verify_producer_property_rebinds_reader",
    "verify_projection_failure_identity",
    "verify_provider_baseexception_identity",
    "verify_provider_frozen_before_arguments",
    "verify_provider_oserror",
    "verify_provider_valueerror",
    "verify_reporter_frozen_before_projection",
    "verify_source_oserror",
    "verify_source_property_rebinds_reader",
    "verify_stdin_reporter_rebind",
    "verify_success_default_nonadmitting",
    "verify_success_opt_in_nonadmitting",
    "verify_verdict_stdin",
)

_SOURCE = {
    "format": "EVOGUARD_RELEASE_SOURCE_V1",
    "repository": "owner/project",
    "target_commit_sha": "1" * 40,
}
_CONTEXT = {
    "format": "EVOGUARD_RELEASE_SOURCE_CONTEXT_V1",
    "policy_digest": "sha256:" + "2" * 64,
}
_PRODUCER = {
    "workflow_repository": "owner/project",
    "workflow_run_id": "123456",
    "runner_class": "github-hosted",
}
_RECORD = {"sha256": "3" * 64}

_CREATE_ALLOWED = frozenset(
    {
        "verdict",
        "handoff",
        "source",
        "context",
        "producer",
        "out",
        "bootstrap_guard_sha",
        "git_repository",
        "git_repository_bare",
        "force",
    }
)
_VERIFY_ALLOWED = frozenset(
    {
        "receipt",
        "handoff",
        "verdict",
        "source",
        "context",
        "producer",
        "bootstrap_guard_sha",
        "git_repository",
        "git_repository_bare",
        "allow_nonadmitting_evidence",
    }
)
_REVERIFY_ALLOWED = frozenset(
    {
        *_VERIFY_ALLOWED,
        "github_policy",
        "github_receipt_out",
        "github_raw_output_out",
        "gh_executable",
        "timeout_seconds",
    }
)
_FORBIDDEN_CAPABILITY_ARGS = frozenset(
    {
        "admission",
        "admit",
        "sign_key",
        "sign_pub",
        "provider_isolation",
        "provider_isolation_uid",
        "provider_isolation_gid",
        "gh_executable_sha256",
        "git_executable_sha256",
        "git_executable_pin",
    }
)


def canonical_json(value: Any) -> str:
    """Return the stable human-readable vector encoding."""

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


class _ExpectedFatal(BaseException):
    """Marker used to prove that uncaught failures preserve identity."""


class _ProbeDomainError(ValueError):
    """Stable domain exception imported by the command at function entry."""


class _LateDomainError(ValueError):
    """Replacement used to prove the entry snapshot does not drift."""


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
    """Mapping that records projection order and can fail or rebind once."""

    def __init__(
        self,
        events: list[str],
        name: str,
        value: dict[str, object],
        *,
        fail_key: str | None = None,
        failure: BaseException | None = None,
        rebind_reporter_key: str | None = None,
        late_reporter: Callable[..., None] | None = None,
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


class _CreatedReceipt(_ObservedMapping):
    def __init__(
        self,
        events: list[str],
        *,
        projection_failure: BaseException | None = None,
        late_reporter: Callable[..., None] | None = None,
    ) -> None:
        record = _ObservedMapping(
            events,
            "created.record",
            dict(_RECORD),
            fail_key="sha256" if projection_failure is not None else None,
            failure=projection_failure,
        )
        super().__init__(
            events,
            "created",
            {"record": record},
            rebind_reporter_key="record" if late_reporter is not None else None,
            late_reporter=late_reporter,
        )


class _InspectedReceipt:
    def __init__(self, events: list[str]) -> None:
        self._events = events
        self._payload = _ObservedMapping(
            events,
            "verified.payload",
            {
                "record": _ObservedMapping(
                    events,
                    "verified.record",
                    dict(_RECORD),
                )
            },
        )

    @property
    def payload(self) -> _ObservedMapping:
        self._events.append("projection:verified.receipt.payload")
        return self._payload


class _VerifiedReceipt:
    def __init__(
        self,
        events: list[str],
        *,
        projection_failure: BaseException | None = None,
        late_reporter: Callable[..., None] | None = None,
    ) -> None:
        self._events = events
        self._projection_failure = projection_failure
        self._late_reporter = late_reporter
        self._receipt = _InspectedReceipt(events)

    @property
    def receipt(self) -> _InspectedReceipt:
        self._events.append("projection:verified.receipt")
        if self._late_reporter is not None:
            self._events.append("rebind:reporter-from-verified.receipt")
            cli._machine_report = self._late_reporter
        if self._projection_failure is not None:
            raise self._projection_failure
        return self._receipt


class _GitHubReceipt:
    def __init__(
        self,
        events: list[str],
        *,
        projection_failure: BaseException | None = None,
    ) -> None:
        self._events = events
        self._projection_failure = projection_failure

    @property
    def receipt_path(self) -> str:
        self._events.append("projection:github_receipt.receipt_path")
        return "/outputs/github-receipt.json"

    @property
    def raw_output_path(self) -> str:
        self._events.append("projection:github_receipt.raw_output_path")
        if self._projection_failure is not None:
            raise self._projection_failure
        return "/outputs/github-raw.txt"


class _AttestedReceipt:
    def __init__(
        self,
        events: list[str],
        *,
        projection_failure: BaseException | None = None,
        late_reporter: Callable[..., None] | None = None,
    ) -> None:
        self._events = events
        self._late_reporter = late_reporter
        self._verified = _VerifiedReceipt(events)
        self._github_receipt = _GitHubReceipt(
            events,
            projection_failure=projection_failure,
        )

    @property
    def verified(self) -> _VerifiedReceipt:
        self._events.append("projection:attested.verified")
        if self._late_reporter is not None:
            self._events.append("rebind:reporter-from-attested.verified")
            cli._machine_report = self._late_reporter
        return self._verified

    @property
    def github_receipt(self) -> _GitHubReceipt:
        self._events.append("projection:attested.github_receipt")
        return self._github_receipt


def _args(kind: str, events: list[str]) -> _SideEffectNamespace:
    values: dict[str, object] = {
        "source": "/inputs/source.json",
        "context": "/inputs/context.json",
        "producer": "/inputs/producer.json",
        "bootstrap_guard_sha": "4" * 64,
        "git_repository": "/trusted/repository.git",
        "git_repository_bare": True,
    }
    if kind == "create":
        values.update(
            verdict="/inputs/verdict.json",
            handoff="/inputs/handoff.json",
            out="/outputs/producer-receipt.json",
            force=False,
        )
    else:
        values.update(
            receipt="/inputs/producer-receipt.json",
            handoff="/inputs/handoff.json",
            verdict="/inputs/verdict.json",
            allow_nonadmitting_evidence=False,
        )
    if kind == "reverify":
        values.update(
            github_policy="/inputs/github-policy.json",
            github_receipt_out="/outputs/github-receipt.json",
            github_raw_output_out="/outputs/github-raw.txt",
            gh_executable="/trusted/bin/gh",
            timeout_seconds=47.5,
        )
    args = _SideEffectNamespace(**values)
    args.__dict__.update(
        _events=events,
        _tracked_names=frozenset(values),
        _property_effects={},
        _strict_allowed=None,
    )
    return args


def _jsonable(value: object) -> object:
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def capture_trace(case_name: str) -> dict[str, object]:
    """Capture one complete, reviewable command trace."""

    if case_name not in CASE_NAMES:
        raise KeyError(case_name)
    kind = case_name.split("_", 1)[0]
    events: list[str] = []
    calls: list[dict[str, object]] = []
    reports: list[dict[str, object]] = []
    output_sha256: list[str] = []
    files: dict[str, bytes] = {}
    expected_exception = _ExpectedFatal(f"expected:{case_name}")
    args = _args(kind, events)
    provider_failure: BaseException | None = None
    projection_failure: BaseException | None = None
    output_failure = False
    rebind_reporter_from_projection = False
    reader_failures: dict[str, BaseException] = {}

    original_reader = cli._read_external_finalizer_object
    original_external_inputs = cli._producer_receipt_external_inputs
    original_reporter = cli._machine_report
    original_abspath = cli.os.path.abspath
    original_format = (
        release_source_producer_receipt.RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT
    )
    original_error = release_source_producer_receipt.ReleaseSourceProducerReceiptError
    original_create = (
        release_source_producer_receipt.create_release_source_producer_receipt
    )
    original_verify = (
        release_source_producer_receipt.verify_release_source_producer_receipt
    )
    original_reverify = (
        release_source_producer_receipt.reverify_attested_release_source_producer_receipt
    )

    def emit(line: str) -> None:
        events.append("call:out")
        output_sha256.append(hashlib.sha256(line.encode("utf-8")).hexdigest())
        if output_failure:
            raise expected_exception

    def _report(
        label: str,
        output: Callable[[str], None],
        payload: dict[str, object],
    ) -> None:
        events.append(f"call:reporter:{label}")
        copied = json.loads(
            json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        )
        reports.append({"reporter": label, "payload": copied})
        output(
            json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        )

    def reporter(
        output: Callable[[str], None],
        payload: dict[str, object],
    ) -> None:
        _report("initial", output, payload)

    def late_reporter(
        output: Callable[[str], None],
        payload: dict[str, object],
    ) -> None:
        _report("late", output, payload)

    def reader(path: str, *, label: str) -> dict[str, object]:
        events.append(f"call:reader:{label}:{path}")
        calls.append({"name": "reader", "path": path, "label": label})
        failure = reader_failures.get(label)
        if failure is not None:
            raise failure
        return {
            "release source": dict(_SOURCE),
            "expected release source": dict(_SOURCE),
            "release-source context": dict(_CONTEXT),
            "expected release-source context": dict(_CONTEXT),
            "producer identity": dict(_PRODUCER),
            "expected producer identity": dict(_PRODUCER),
            "GitHub producer-attestation policy": {
                "repository": "owner/project",
                "workflow": "owner/project/.github/workflows/producer.yml",
            },
        }[label]

    def late_reader(path: str, *, label: str) -> dict[str, object]:
        events.append(f"call:late-reader:{label}:{path}")
        calls.append({"name": "late-reader", "path": path, "label": label})
        return {"late": label}

    def external_inputs(
        namespace: argparse.Namespace,
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        events.append("call:external-inputs:initial")
        return (
            cli._read_external_finalizer_object(
                namespace.source,
                label="expected release source",
            ),
            cli._read_external_finalizer_object(
                namespace.context,
                label="expected release-source context",
            ),
            cli._read_external_finalizer_object(
                namespace.producer,
                label="expected producer identity",
            ),
        )

    def late_external_inputs(
        _namespace: argparse.Namespace,
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        events.append("call:external-inputs:late")
        return (
            {"late": "source"},
            {"late": "context"},
            {"late": "producer"},
        )

    def fake_abspath(path: str) -> str:
        events.append(f"call:abspath:initial:{path}")
        return f"/absolute{path}"

    def late_abspath(path: str) -> str:
        events.append(f"call:abspath:late:{path}")
        return f"/late-absolute{path}"

    def log_provider(
        name: str,
        positional: tuple[object, ...],
        keyword: dict[str, object],
    ) -> None:
        events.append(f"call:provider:{name}")
        calls.append(
            {
                "name": name,
                "args": _jsonable(positional),
                "kwargs": _jsonable(keyword),
            }
        )

    def create_provider(
        *positional: object,
        **keyword: object,
    ) -> _CreatedReceipt:
        log_provider("create", positional, keyword)
        output_path = str(positional[2])
        files[output_path] = b'{"canonical":"producer-receipt"}\n'
        if provider_failure is not None:
            raise provider_failure
        return _CreatedReceipt(
            events,
            projection_failure=projection_failure,
            late_reporter=(
                late_reporter if rebind_reporter_from_projection else None
            ),
        )

    def verify_provider(
        *positional: object,
        **keyword: object,
    ) -> _VerifiedReceipt:
        log_provider("verify", positional, keyword)
        if provider_failure is not None:
            raise provider_failure
        return _VerifiedReceipt(
            events,
            projection_failure=projection_failure,
            late_reporter=(
                late_reporter if rebind_reporter_from_projection else None
            ),
        )

    def reverify_provider(
        *positional: object,
        **keyword: object,
    ) -> _AttestedReceipt:
        log_provider("reverify", positional, keyword)
        receipt_path = str(keyword["github_receipt_path"])
        raw_path = str(keyword["github_raw_output_path"])
        files[receipt_path] = b'{"fresh_provider_receipt":true}\n'
        files[raw_path] = b"fresh provider output\n"
        if provider_failure is not None:
            raise provider_failure
        return _AttestedReceipt(
            events,
            projection_failure=projection_failure,
            late_reporter=(
                late_reporter if rebind_reporter_from_projection else None
            ),
        )

    def late_create(*_args: object, **_kwargs: object) -> _CreatedReceipt:
        events.append("call:provider:late-create")
        raise AssertionError("late create provider was used")

    def late_verify(*_args: object, **_kwargs: object) -> _VerifiedReceipt:
        events.append("call:provider:late-verify")
        raise AssertionError("late verify provider was used")

    def late_reverify(*_args: object, **_kwargs: object) -> _AttestedReceipt:
        events.append("call:provider:late-reverify")
        raise AssertionError("late reverify provider was used")

    def rebind_reader() -> None:
        events.append("rebind:reader")
        cli._read_external_finalizer_object = late_reader

    def rebind_reporter() -> None:
        events.append("rebind:reporter")
        cli._machine_report = late_reporter

    def rebind_abspath() -> None:
        events.append("rebind:abspath")
        cli.os.path.abspath = late_abspath

    def rebind_external_inputs() -> None:
        events.append("rebind:external-inputs")
        cli._producer_receipt_external_inputs = late_external_inputs

    def fail_argument() -> None:
        events.append("raise:argument")
        raise expected_exception

    def rebind_create_imports() -> None:
        events.append("rebind:create-provider-format-error")
        release_source_producer_receipt.RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT = (
            "LATE_PRODUCER_RECEIPT_FORMAT"
        )
        release_source_producer_receipt.ReleaseSourceProducerReceiptError = (
            _LateDomainError
        )
        release_source_producer_receipt.create_release_source_producer_receipt = (
            late_create
        )

    def rebind_verify_imports() -> None:
        events.append("rebind:verify-provider-format-error")
        release_source_producer_receipt.RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT = (
            "LATE_PRODUCER_RECEIPT_FORMAT"
        )
        release_source_producer_receipt.ReleaseSourceProducerReceiptError = (
            _LateDomainError
        )
        release_source_producer_receipt.verify_release_source_producer_receipt = (
            late_verify
        )

    def rebind_reverify_imports() -> None:
        events.append("rebind:reverify-provider-format-error")
        release_source_producer_receipt.RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT = (
            "LATE_PRODUCER_RECEIPT_FORMAT"
        )
        release_source_producer_receipt.ReleaseSourceProducerReceiptError = (
            _LateDomainError
        )
        (
            release_source_producer_receipt.reverify_attested_release_source_producer_receipt
        ) = late_reverify

    if case_name == "create_argument_failure_identity":
        args._property_effects["verdict"] = fail_argument
    elif case_name == "create_eager_stdin_first_reads_handoff":
        args.verdict = "-"
        args._property_effects["handoff"] = fail_argument
    elif case_name == "create_handoff_stdin":
        args.handoff = "-"
    elif case_name == "create_stdin_reporter_rebind":
        args.verdict = "-"
        args._property_effects["verdict"] = rebind_reporter
    elif case_name == "create_source_property_rebinds_reader":
        args._property_effects["source"] = rebind_reader
    elif case_name == "create_context_property_rebinds_reader":
        args._property_effects["context"] = rebind_reader
    elif case_name == "create_producer_property_rebinds_reader":
        args._property_effects["producer"] = rebind_reader
    elif case_name == "create_source_oserror":
        reader_failures["release source"] = OSError("source unavailable")
    elif case_name == "create_context_unicodeerror":
        reader_failures["release-source context"] = UnicodeError("bad context text")
    elif case_name == "create_producer_valueerror":
        reader_failures["producer identity"] = ValueError("bad producer")
    elif case_name == "create_provider_frozen_before_arguments":
        args._property_effects["verdict"] = rebind_create_imports
    elif case_name == "create_domain_error_class_and_provider_snapshot":
        provider_failure = _ProbeDomainError("domain rejected")
        args._property_effects["verdict"] = rebind_create_imports
    elif case_name == "create_provider_oserror_preserves_receipt":
        provider_failure = OSError("create output failed late")
    elif case_name == "create_provider_valueerror":
        provider_failure = ValueError("create invalid")
    elif case_name == "create_provider_baseexception_identity":
        provider_failure = expected_exception
    elif case_name == "create_out_property_rebinds_abspath":
        args._property_effects["out"] = rebind_abspath
    elif case_name == "create_projection_failure_identity":
        projection_failure = expected_exception
    elif case_name == "create_reporter_frozen_before_projection":
        rebind_reporter_from_projection = True
    elif case_name == "create_output_failure_identity":
        output_failure = True
    elif case_name == "create_success_boundary":
        args._strict_allowed = _CREATE_ALLOWED
    elif case_name.startswith("verify_"):
        if case_name == "verify_argument_failure_identity":
            args._property_effects["receipt"] = fail_argument
        elif case_name == "verify_eager_stdin_first_reads_all":
            args.receipt = "-"
            args._property_effects["verdict"] = fail_argument
        elif case_name == "verify_handoff_stdin":
            args.handoff = "-"
        elif case_name == "verify_verdict_stdin":
            args.verdict = "-"
        elif case_name == "verify_stdin_reporter_rebind":
            args.receipt = "-"
            args._property_effects["receipt"] = rebind_reporter
        elif case_name == "verify_external_helper_is_live_after_stdin":
            args._property_effects["receipt"] = rebind_external_inputs
        elif case_name == "verify_source_property_rebinds_reader":
            args._property_effects["source"] = rebind_reader
        elif case_name == "verify_context_property_rebinds_reader":
            args._property_effects["context"] = rebind_reader
        elif case_name == "verify_producer_property_rebinds_reader":
            args._property_effects["producer"] = rebind_reader
        elif case_name == "verify_source_oserror":
            reader_failures["expected release source"] = OSError("source unavailable")
        elif case_name == "verify_context_unicodeerror":
            reader_failures["expected release-source context"] = UnicodeError(
                "bad context text"
            )
        elif case_name == "verify_provider_frozen_before_arguments":
            args._property_effects["receipt"] = rebind_verify_imports
        elif case_name == "verify_domain_error_class_and_provider_snapshot":
            provider_failure = _ProbeDomainError("domain rejected")
            args._property_effects["receipt"] = rebind_verify_imports
        elif case_name == "verify_provider_oserror":
            provider_failure = OSError("verify unavailable")
        elif case_name == "verify_provider_valueerror":
            provider_failure = ValueError("verify invalid")
        elif case_name == "verify_provider_baseexception_identity":
            provider_failure = expected_exception
        elif case_name == "verify_projection_failure_identity":
            projection_failure = expected_exception
        elif case_name == "verify_reporter_frozen_before_projection":
            rebind_reporter_from_projection = True
        elif case_name == "verify_output_failure_identity":
            output_failure = True
        elif case_name == "verify_success_opt_in_nonadmitting":
            args.allow_nonadmitting_evidence = True
            args._strict_allowed = _VERIFY_ALLOWED
        elif case_name == "verify_allow_flag_failure_after_report":
            args._property_effects["allow_nonadmitting_evidence"] = fail_argument
        elif case_name == "verify_success_default_nonadmitting":
            args._strict_allowed = _VERIFY_ALLOWED
    else:
        if case_name == "reverify_argument_failure_identity":
            args._property_effects["receipt"] = fail_argument
        elif case_name == "reverify_eager_stdin_first_reads_all":
            args.receipt = "-"
            args._property_effects["verdict"] = fail_argument
        elif case_name == "reverify_handoff_stdin":
            args.handoff = "-"
        elif case_name == "reverify_verdict_stdin":
            args.verdict = "-"
        elif case_name == "reverify_stdin_reporter_rebind":
            args.receipt = "-"
            args._property_effects["receipt"] = rebind_reporter
        elif case_name == "reverify_external_helper_is_live_after_stdin":
            args._property_effects["receipt"] = rebind_external_inputs
        elif case_name == "reverify_source_property_rebinds_reader":
            args._property_effects["source"] = rebind_reader
        elif case_name == "reverify_context_property_rebinds_reader":
            args._property_effects["context"] = rebind_reader
        elif case_name == "reverify_producer_property_rebinds_reader":
            args._property_effects["producer"] = rebind_reader
        elif case_name == "reverify_github_policy_property_rebinds_reader":
            args._property_effects["github_policy"] = rebind_reader
        elif case_name == "reverify_source_oserror":
            reader_failures["expected release source"] = OSError("source unavailable")
        elif case_name == "reverify_context_unicodeerror":
            reader_failures["expected release-source context"] = UnicodeError(
                "bad context text"
            )
        elif case_name == "reverify_github_policy_valueerror":
            reader_failures["GitHub producer-attestation policy"] = ValueError(
                "bad GitHub policy"
            )
        elif case_name == "reverify_provider_frozen_before_arguments":
            args._property_effects["receipt"] = rebind_reverify_imports
        elif case_name == "reverify_domain_error_class_and_provider_snapshot":
            provider_failure = _ProbeDomainError("domain rejected")
            args._property_effects["receipt"] = rebind_reverify_imports
        elif case_name == "reverify_provider_oserror_preserves_provider_outputs":
            provider_failure = OSError("fresh provider failed late")
        elif case_name == "reverify_provider_valueerror":
            provider_failure = ValueError("fresh provider invalid")
        elif case_name == "reverify_provider_baseexception_identity":
            provider_failure = expected_exception
        elif case_name == "reverify_projection_failure_identity":
            projection_failure = expected_exception
        elif case_name == "reverify_reporter_frozen_before_projection":
            rebind_reporter_from_projection = True
        elif case_name == "reverify_output_failure_identity":
            output_failure = True
        elif case_name == "reverify_success_opt_in_nonadmitting":
            args.allow_nonadmitting_evidence = True
            args._strict_allowed = _REVERIFY_ALLOWED
        elif case_name == "reverify_allow_flag_failure_after_report":
            args._property_effects["allow_nonadmitting_evidence"] = fail_argument
        elif case_name == "reverify_success_default_nonadmitting":
            args._strict_allowed = _REVERIFY_ALLOWED

    cli._read_external_finalizer_object = reader
    cli._producer_receipt_external_inputs = external_inputs
    cli._machine_report = reporter
    cli.os.path.abspath = fake_abspath
    release_source_producer_receipt.RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT = (
        "EVOGUARD_RELEASE_SOURCE_PRODUCER_RECEIPT_V1"
    )
    release_source_producer_receipt.ReleaseSourceProducerReceiptError = (
        _ProbeDomainError
    )
    release_source_producer_receipt.create_release_source_producer_receipt = (
        create_provider
    )
    release_source_producer_receipt.verify_release_source_producer_receipt = (
        verify_provider
    )
    (
        release_source_producer_receipt.reverify_attested_release_source_producer_receipt
    ) = reverify_provider

    command = {
        "create": cli.cmd_create_release_source_producer_receipt,
        "verify": cli.cmd_verify_release_source_producer_receipt,
        "reverify": cli.cmd_reverify_attested_release_source_producer_receipt,
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
        cli._producer_receipt_external_inputs = original_external_inputs
        cli._machine_report = original_reporter
        cli.os.path.abspath = original_abspath
        release_source_producer_receipt.RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT = (
            original_format
        )
        release_source_producer_receipt.ReleaseSourceProducerReceiptError = (
            original_error
        )
        release_source_producer_receipt.create_release_source_producer_receipt = (
            original_create
        )
        release_source_producer_receipt.verify_release_source_producer_receipt = (
            original_verify
        )
        (
            release_source_producer_receipt.reverify_attested_release_source_producer_receipt
        ) = original_reverify

    return {
        "calls": calls,
        "events": events,
        "files": {
            path: hashlib.sha256(content).hexdigest()
            for path, content in sorted(files.items())
        },
        "output_sha256": output_sha256,
        "reports": reports,
        "exception": exception,
        "exit_code": exit_code,
    }


def capture_case(case_name: str) -> dict[str, object]:
    """Return one compact but byte- and order-sensitive vector case."""

    trace = capture_trace(case_name)
    behavior = {
        key: trace[key]
        for key in ("calls", "events", "files", "output_sha256", "reports")
    }
    behavior_bytes = json.dumps(
        behavior,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return {
        "activity_counts": [
            len(trace["calls"]),
            len(trace["events"]),
            len(trace["files"]),
            len(trace["output_sha256"]),
            len(trace["reports"]),
        ],
        "behavior_sha256": hashlib.sha256(behavior_bytes).hexdigest(),
        "exception": trace["exception"],
        "exit_code": trace["exit_code"],
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
