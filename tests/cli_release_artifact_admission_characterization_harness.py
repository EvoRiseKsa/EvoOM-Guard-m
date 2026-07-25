"""Deterministic characterization of Release Artifact Admission CLI adapters.

The vector freezes the two remaining public release-artifact commands before
their facade extraction.  It records entry snapshots versus live facade
helpers, eager path preflight and metadata reads, exception precedence and
identity, exact reports and exits, repeated result projections, partial output
residue, and the online-seal/offline-verify authority boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Callable
from typing import Any

from evoom_guard import cli, finalizer_derivation, github_attestation, signing
from evoom_guard.admission import release_artifact

BASELINE_COMMIT = "b87ae48926a1233e656e38c2ec989a165426c050"
SCHEMA_VERSION = "cli-release-artifact-admission-characterization-v1"

CASE_NAMES = (
    "seal_alias_rejected_before_metadata",
    "seal_bind_error_is_rejected",
    "seal_builder_property_rebinds_reader",
    "seal_domain_error_class_frozen_at_entry",
    "seal_entry_provider_is_frozen_before_arguments",
    "seal_existing_output_rejected_before_metadata",
    "seal_finalizer_error_is_rejected",
    "seal_format_is_frozen_at_entry",
    "seal_github_error_is_rejected",
    "seal_key_helper_is_live_after_metadata_reads",
    "seal_key_registry_is_live_but_signer_key_reader_is_frozen",
    "seal_missing_event_path",
    "seal_nested_helper_is_live_after_event_read",
    "seal_output_failure_identity",
    "seal_preflight_baseexception_identity",
    "seal_preflight_helper_is_live_after_environment_read",
    "seal_preflight_reads_complete_path_set_before_rejecting_stdin",
    "seal_projection_failure_identity",
    "seal_provider_baseexception_identity",
    "seal_provider_oserror_preserves_partial_bundle",
    "seal_reader_oserror_is_rejected",
    "seal_reporter_is_live_after_projection",
    "seal_signer_domain_collision_precedes_execution_pins",
    "seal_signing_error_is_rejected",
    "seal_success_online_boundary",
    "seal_unicode_error_is_rejected",
    "seal_value_error_is_rejected",
    "verify_artifact_stdin_after_bundle_read",
    "verify_bundle_property_baseexception_identity",
    "verify_bundle_stdin_short_circuits_artifact",
    "verify_domain_error_class_frozen_at_entry",
    "verify_entry_provider_is_frozen_before_arguments",
    "verify_format_is_frozen_at_entry",
    "verify_key_helper_is_live_after_metadata_reads",
    "verify_nested_helper_is_live_after_stdin_guard",
    "verify_output_failure_identity",
    "verify_projection_failure_identity",
    "verify_provider_baseexception_identity",
    "verify_provider_oserror_is_rejected",
    "verify_reader_is_live_during_nested_reads",
    "verify_reader_unicode_error_is_rejected",
    "verify_reporter_is_live_after_projection",
    "verify_signing_error_is_rejected",
    "verify_success_offline_closed_world",
    "verify_value_error_is_rejected",
)

_NESTED_VALUES: dict[str, dict[str, object]] = {
    "expected protected-main release source": {
        "format": "EVOGUARD_RELEASE_SOURCE_V1",
        "repository": "EvoRiseKsa/EvoOM-Guard-m",
        "target_commit_sha": "1" * 40,
    },
    "expected release-source context": {
        "format": "EVOGUARD_RELEASE_SOURCE_CONTEXT_V1",
        "policy_digest": "sha256:" + "2" * 64,
    },
    "expected release-source producer": {
        "workflow": ".github/workflows/release-source-producer.yml",
        "workflow_sha256": "3" * 64,
    },
    "expected release-source admitter": {
        "workflow": ".github/workflows/release-source-admitter.yml",
        "workflow_sha256": "4" * 64,
    },
    "expected release-source GitHub policy": {
        "repository": "EvoRiseKsa/EvoOM-Guard-m",
        "source_ref": "refs/heads/main",
    },
    "protected release-artifact builder identity": {
        "workflow": ".github/workflows/release-artifact-builder.yml",
        "workflow_sha256": "5" * 64,
    },
    "protected release-artifact admitter identity": {
        "workflow": ".github/workflows/release-artifact-admitter.yml",
        "workflow_sha256": "6" * 64,
    },
    "GitHub Actions release-artifact workflow_run event payload": {
        "action": "completed",
        "workflow_run": {"id": 73, "conclusion": "success"},
    },
    "expected protected release-artifact builder identity": {
        "workflow": ".github/workflows/release-artifact-builder.yml",
        "workflow_sha256": "5" * 64,
    },
    "expected protected release-artifact admitter identity": {
        "workflow": ".github/workflows/release-artifact-admitter.yml",
        "workflow_sha256": "6" * 64,
    },
}

_KEY_IDS = {
    "/keys/trusted-finalizer.pub": "key-trusted-finalizer",
    "/keys/artifact-admission-v1.pub": "key-artifact-v1",
    "/keys/artifact-digest-admission-v2.pub": "key-artifact-v2",
    "/keys/release-source-finalizer-v1.pub": "key-source-finalizer",
    "/keys/release-source-admission-v2.pub": "key-source-admission",
    "/keys/release-artifact-admission-v1.pub": "key-release-artifact",
}

_SEAL_ARGS = frozenset(
    {
        "release_source_admission",
        "artifact",
        "out",
        "builder",
        "admitter",
        "expected_release_source",
        "expected_release_source_context",
        "expected_release_source_producer",
        "expected_release_source_admitter",
        "expected_release_source_bootstrap_guard_sha",
        "expected_release_source_github_policy",
        "expected_release_source_git_executable_sha256",
        "expected_release_source_gh_executable_sha256",
        "expected_release_source_provider_isolation_uid",
        "expected_release_source_provider_isolation_gid",
        "git_repository",
        "git_repository_bare",
        "git_executable",
        "git_executable_sha256",
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
        "release_source_admission_v2_pub",
    }
)

_VERIFY_ARGS = frozenset(
    {
        "bundle",
        "artifact",
        "trusted_pub",
        "expected_builder",
        "expected_admitter",
        "expected_release_source",
        "expected_release_source_context",
        "expected_release_source_producer",
        "expected_release_source_admitter",
        "expected_release_source_bootstrap_guard_sha",
        "expected_release_source_github_policy",
        "expected_release_source_git_executable_sha256",
        "expected_release_source_gh_executable_sha256",
        "expected_release_source_provider_isolation_uid",
        "expected_release_source_provider_isolation_gid",
        "expected_git_executable_sha256",
        "expected_gh_executable_sha256",
        "expected_provider_isolation_uid",
        "expected_provider_isolation_gid",
        "trusted_finalizer_pub",
        "artifact_admission_v1_pub",
        "artifact_digest_admission_v2_pub",
        "release_source_finalizer_v1_pub",
        "release_source_admission_v2_pub",
    }
)

FORBIDDEN_VERIFY_CAPABILITIES = frozenset(
    {
        "env",
        "environment",
        "gh_executable",
        "git_executable",
        "git_repository",
        "provider_isolation_uid",
        "provider_isolation_gid",
        "sign_key",
        "sign_pub",
        "timeout_seconds",
    }
)


def canonical_json(value: Any) -> str:
    """Return stable human-readable JSON for assertion diffs."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def compact_vector_json(value: dict[str, object]) -> str:
    """Encode one complete case per line while keeping metadata readable."""

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
    """Log reads, permit selected rebinding, and reject undeclared authority."""

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
    """Expose only the one environment read owned by the online seal adapter."""

    def __init__(
        self,
        events: list[str],
        *,
        event_path: str | None,
        on_get: Callable[[], None] | None = None,
    ) -> None:
        self.events = events
        self.event_path = event_path
        self.on_get = on_get

    def get(self, key: str, default: object = None) -> object:
        self.events.append(f"environment:get:{key}")
        if self.on_get is not None:
            callback, self.on_get = self.on_get, None
            callback()
        if key == "GITHUB_EVENT_PATH":
            return self.event_path
        raise AssertionError(f"unexpected environment lookup {key!r}")

    def __getitem__(self, key: str) -> object:
        raise AssertionError(f"unexpected environment item lookup {key!r}")

    def __iter__(self) -> Any:
        raise AssertionError("unexpected environment iteration")


class _ObservedMapping(dict[str, object]):
    def __init__(
        self,
        events: list[str],
        name: str,
        value: dict[str, object],
        *,
        fail_key: str | None = None,
        failure: BaseException | None = None,
        rebind_key: str | None = None,
        rebind: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(value)
        self._events = events
        self._name = name
        self._fail_key = fail_key
        self._failure = failure
        self._rebind_key = rebind_key
        self._rebind = rebind

    def __getitem__(self, key: str) -> object:
        self._events.append(f"projection:{self._name}[{key}]")
        if key == self._rebind_key and self._rebind is not None:
            self._rebind()
        if key == self._fail_key and self._failure is not None:
            raise self._failure
        return super().__getitem__(key)


class _ObservedArtifact:
    def __init__(
        self,
        events: list[str],
        *,
        name: str,
        failure: BaseException | None = None,
    ) -> None:
        self.events = events
        self.name = name
        self.failure = failure

    def as_dict(self) -> dict[str, object]:
        self.events.append(f"projection:{self.name}.as_dict")
        if self.failure is not None:
            raise self.failure
        return {"kind": "file", "sha256": "7" * 64, "size": 730}


class _SealedResult:
    def __init__(
        self,
        events: list[str],
        *,
        projection_failure: BaseException | None = None,
        rebind_reporter: Callable[[], None] | None = None,
    ) -> None:
        self.events = events
        self.projection_failure = projection_failure
        self.rebind_reporter = rebind_reporter
        self._artifact = _ObservedArtifact(events, name="sealed.artifact")
        self._manifest = _ObservedMapping(
            events,
            "sealed.manifest",
            {
                "release_source": {"target_commit_sha": "1" * 40},
                "builder": dict(_NESTED_VALUES["protected release-artifact builder identity"]),
                "admitter": dict(_NESTED_VALUES["protected release-artifact admitter identity"]),
                "authentication": _ObservedMapping(
                    events,
                    "sealed.manifest.authentication",
                    {"key_id": "key-release-artifact"},
                ),
            },
        )

    @property
    def bundle_path(self) -> str:
        self.events.append("projection:sealed.bundle_path")
        return "/outputs/release-artifact.raae"

    @property
    def artifact(self) -> _ObservedArtifact:
        self.events.append("projection:sealed.artifact")
        if self.projection_failure is not None:
            raise self.projection_failure
        return self._artifact

    @property
    def manifest(self) -> _ObservedMapping:
        self.events.append("projection:sealed.manifest")
        return self._manifest

    @property
    def decision(self) -> str:
        self.events.append("projection:sealed.decision")
        if self.rebind_reporter is not None:
            self.rebind_reporter()
        return "ALLOW"


class _Bundle:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self._manifest = _ObservedMapping(
            events,
            "verified.bundle.manifest",
            {
                "release_source": {"target_commit_sha": "1" * 40},
                "builder": dict(
                    _NESTED_VALUES["expected protected release-artifact builder identity"]
                ),
                "admitter": dict(
                    _NESTED_VALUES["expected protected release-artifact admitter identity"]
                ),
                "authentication": _ObservedMapping(
                    events,
                    "verified.bundle.manifest.authentication",
                    {"key_id": "key-release-artifact"},
                ),
            },
        )

    @property
    def manifest(self) -> _ObservedMapping:
        self.events.append("projection:verified.bundle.manifest")
        return self._manifest


class _VerifiedResult:
    def __init__(
        self,
        events: list[str],
        *,
        projection_failure: BaseException | None = None,
        rebind_reporter: Callable[[], None] | None = None,
    ) -> None:
        self.events = events
        self.projection_failure = projection_failure
        self.rebind_reporter = rebind_reporter
        self._bundle = _Bundle(events)
        self._artifact = _ObservedArtifact(events, name="verified.artifact")

    @property
    def bundle(self) -> _Bundle:
        self.events.append("projection:verified.bundle")
        if self.projection_failure is not None:
            raise self.projection_failure
        return self._bundle

    @property
    def decision(self) -> str:
        self.events.append("projection:verified.decision")
        return "ALLOW"

    @property
    def artifact(self) -> _ObservedArtifact:
        self.events.append("projection:verified.artifact")
        if self.rebind_reporter is not None:
            self.rebind_reporter()
        return self._artifact


def _args(events: list[str]) -> _SideEffectNamespace:
    values: dict[str, object] = {
        "release_source_admission": "/inputs/release-source.rsae",
        "artifact": "/inputs/release-artifact.pyz",
        "out": "/outputs/release-artifact.raae",
        "builder": "/inputs/release-artifact-builder.json",
        "admitter": "/inputs/release-artifact-admitter.json",
        "expected_release_source": "/inputs/release-source.json",
        "expected_release_source_context": "/inputs/release-source-context.json",
        "expected_release_source_producer": "/inputs/release-source-producer.json",
        "expected_release_source_admitter": "/inputs/release-source-admitter.json",
        "expected_release_source_bootstrap_guard_sha": "8" * 64,
        "expected_release_source_github_policy": "/inputs/release-source-policy.json",
        "expected_release_source_git_executable_sha256": "9" * 64,
        "expected_release_source_gh_executable_sha256": "a" * 64,
        "expected_release_source_provider_isolation_uid": 2001,
        "expected_release_source_provider_isolation_gid": 2002,
        "git_repository": "/git/repository",
        "git_repository_bare": False,
        "git_executable": "/usr/bin/git",
        "git_executable_sha256": "b" * 64,
        "gh_executable": "/usr/bin/gh",
        "gh_executable_sha256": "c" * 64,
        "provider_isolation_uid": 3001,
        "provider_isolation_gid": 3002,
        "timeout_seconds": 73,
        "sign_key": "/keys/release-artifact-admission-v1.key",
        "sign_pub": "/keys/release-artifact-admission-v1.pub",
        "trusted_finalizer_pub": "/keys/trusted-finalizer.pub",
        "artifact_admission_v1_pub": "/keys/artifact-admission-v1.pub",
        "artifact_digest_admission_v2_pub": ("/keys/artifact-digest-admission-v2.pub"),
        "release_source_finalizer_v1_pub": ("/keys/release-source-finalizer-v1.pub"),
        "release_source_admission_v2_pub": ("/keys/release-source-admission-v2.pub"),
        "bundle": "/inputs/release-artifact.raae",
        "trusted_pub": "/keys/release-artifact-admission-v1.pub",
        "expected_builder": "/inputs/release-artifact-builder.json",
        "expected_admitter": "/inputs/release-artifact-admitter.json",
        "expected_git_executable_sha256": "b" * 64,
        "expected_gh_executable_sha256": "c" * 64,
        "expected_provider_isolation_uid": 3001,
        "expected_provider_isolation_gid": 3002,
        # Negative controls: no command may silently acquire these capabilities.
        "force": True,
        "allow_overwrite": True,
        "network": "/forbidden/network",
        "github_token": "/forbidden/token",
        "home": "/forbidden/home",
    }
    args = _SideEffectNamespace(**values)
    args._events = events
    args._property_effects = {}
    args._read_counts = {}
    args._strict_allowed = None
    args._tracked_names = frozenset(values)
    return args


def _call_record(
    name: str,
    positional: tuple[object, ...],
    keyword: dict[str, object],
) -> dict[str, object]:
    def normalized(value: object) -> object:
        if isinstance(value, _Environment):
            return "<same-controlled-environment>"
        if isinstance(value, dict):
            return {str(key): normalized(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [normalized(item) for item in value]
        return value

    return {
        "name": name,
        "args": normalized(positional),
        "kwargs": normalized(keyword),
    }


def capture_case(case_name: str) -> dict[str, object]:
    """Capture one case through the historical public facade."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown Release Artifact Admission case: {case_name}")

    kind = case_name.split("_", 1)[0]
    events: list[str] = []
    calls: list[dict[str, object]] = []
    files: dict[str, str] = {}
    reports: list[dict[str, object]] = []
    report_sha256: list[str] = []
    args = _args(events)

    original_reporter = cli._machine_report
    original_reader = cli._read_external_finalizer_object
    original_nested = cli._release_artifact_nested_expectations
    original_preflight = cli._preflight_release_artifact_admission_paths
    original_key_helper = cli._release_artifact_key_separation
    original_bind = release_artifact.bind_release_artifact_admitter_runtime
    original_seal = release_artifact.seal_release_artifact_admission
    original_verify = release_artifact.verify_release_artifact_admission
    original_release_error = release_artifact.ReleaseArtifactAdmissionError
    original_format = release_artifact.RELEASE_ARTIFACT_ADMISSION_FORMAT
    original_git_pin = finalizer_derivation.git_executable_pin
    original_finalizer_error = finalizer_derivation.FinalizerDerivationError
    original_isolation = github_attestation.github_attestation_provider_isolation
    original_github_error = github_attestation.GitHubAttestationError
    original_public_key_id = signing.public_key_id
    original_signing_error = signing.SigningUnavailableError
    original_environment = os.environ

    expected_exception: BaseException | None = None
    provider_exception: BaseException | None = None
    projection_exception: BaseException | None = None
    output_exception: BaseException | None = None

    if case_name.endswith("provider_baseexception_identity"):
        provider_exception = SystemExit(f"{case_name}: provider stopped")
        expected_exception = provider_exception
    elif case_name.endswith("baseexception_identity"):
        expected_exception = KeyboardInterrupt(f"{case_name}: interrupted")
    elif case_name.endswith("projection_failure_identity"):
        projection_exception = RuntimeError(f"{case_name}: projection failed")
        expected_exception = projection_exception
    elif case_name.endswith("output_failure_identity"):
        output_exception = RuntimeError(f"{case_name}: output failed")
        expected_exception = output_exception

    def emit(message: str) -> None:
        parsed = json.loads(message)
        assert isinstance(parsed, dict)
        events.append(f"output:{parsed['status']}")
        reports.append(parsed)
        report_sha256.append(hashlib.sha256(message.encode("utf-8")).hexdigest())
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
        if case_name == "seal_reader_oserror_is_rejected" and label == (
            "expected release-source producer"
        ):
            raise OSError("producer metadata unavailable")
        if case_name == "seal_unicode_error_is_rejected" and label == (
            "protected release-artifact builder identity"
        ):
            raise UnicodeError("builder metadata is not UTF-8")
        if case_name == "verify_reader_unicode_error_is_rejected" and label == (
            "expected release-source GitHub policy"
        ):
            raise UnicodeError("source policy is not UTF-8")
        return dict(_NESTED_VALUES[label])

    def late_reader(path: str, *, label: str) -> dict[str, object]:
        events.append(f"reader:late:{label}:{path}")
        value = dict(_NESTED_VALUES[label])
        value["reader"] = "late"
        return value

    def rebind_reader() -> None:
        events.append("rebind:reader")
        cli._read_external_finalizer_object = late_reader

    def late_nested(namespace: argparse.Namespace) -> tuple[dict[str, object], ...]:
        assert namespace is args
        events.append("nested-helper:late")
        return (
            {"source": "late"},
            {"context": "late"},
            {"producer": "late"},
            {"admitter": "late"},
            {"policy": "late"},
        )

    def rebind_nested() -> None:
        events.append("rebind:nested-helper")
        cli._release_artifact_nested_expectations = late_nested  # type: ignore[assignment]

    def preflight(
        namespace: argparse.Namespace,
        *,
        event_path: str,
    ) -> None:
        events.append(f"preflight:original:{event_path}")
        if case_name == "seal_preflight_baseexception_identity":
            assert expected_exception is not None
            raise expected_exception
        original_preflight(namespace, event_path=event_path)

    def late_preflight(
        namespace: argparse.Namespace,
        *,
        event_path: str,
    ) -> None:
        events.append(f"preflight:late:{event_path}")
        original_preflight(namespace, event_path=event_path)

    def rebind_preflight() -> None:
        events.append("rebind:preflight")
        cli._preflight_release_artifact_admission_paths = late_preflight

    def public_key_id(path: str) -> str:
        events.append(f"public-key-id:entry:{path}")
        return _KEY_IDS[path]

    def late_public_key_id(path: str) -> str:
        events.append(f"public-key-id:late:{path}")
        return "late-" + _KEY_IDS[path]

    def rebind_public_key_id() -> None:
        events.append("rebind:public-key-id")
        signing.public_key_id = late_public_key_id

    def late_key_helper(namespace: argparse.Namespace) -> dict[str, str]:
        assert namespace is args
        events.append("key-helper:late")
        return {
            "trusted_finalizer": "late-trusted",
            "artifact_admission_v1": "late-artifact-v1",
            "artifact_digest_admission_v2": "late-artifact-v2",
            "release_source_finalizer_v1": "late-source-finalizer",
            "release_source_admission_v2": "late-source-admission",
        }

    def rebind_key_helper() -> None:
        events.append("rebind:key-helper")
        cli._release_artifact_key_separation = late_key_helper

    def git_pin(path: str, digest: str) -> dict[str, object]:
        events.append("git-pin:entry")
        calls.append(_call_record("git-pin", (path, digest), {}))
        return {"executable_path": path, "executable_sha256": digest}

    def isolation(
        path: str,
        digest: str,
        *,
        uid: int,
        gid: int,
    ) -> dict[str, object]:
        events.append("provider-isolation:entry")
        calls.append(
            _call_record(
                "provider-isolation",
                (path, digest),
                {"uid": uid, "gid": gid},
            )
        )
        return {
            "executable_path": path,
            "executable_sha256": digest,
            "uid": uid,
            "gid": gid,
        }

    def bind(
        builder: dict[str, object],
        admitter: dict[str, object],
        *,
        source: dict[str, object],
        environment: object,
        event_payload: dict[str, object],
    ) -> dict[str, object]:
        events.append("provider:bind")
        calls.append(
            _call_record(
                "bind-runtime",
                (builder, admitter),
                {
                    "source": source,
                    "environment": environment,
                    "event_payload": event_payload,
                },
            )
        )
        if case_name == "seal_bind_error_is_rejected":
            raise original_release_error("runtime binding rejected")
        return {
            "builder": builder,
            "admitter": admitter,
            "workflow_run_id": 73,
        }

    def late_bind(*_args: Any, **_kwargs: Any) -> dict[str, object]:
        events.append("provider:bind-late")
        return {"late": True}

    def seal_provider(
        *provider_args: object,
        **provider_kwargs: object,
    ) -> _SealedResult:
        events.append("provider:seal-entry")
        calls.append(_call_record("seal", provider_args, provider_kwargs))
        if case_name == "seal_value_error_is_rejected":
            raise ValueError("seal value rejected")
        if case_name == "seal_provider_oserror_preserves_partial_bundle":
            path = str(provider_args[2])
            files[path] = "partial-release-artifact-admission"
            events.append(f"io:partial-output:{path}")
            raise OSError("seal failed after partial output")
        if case_name == "seal_github_error_is_rejected":
            raise original_github_error("GitHub provider rejected")
        if case_name == "seal_finalizer_error_is_rejected":
            raise original_finalizer_error("Git executable rejected")
        if case_name == "seal_signing_error_is_rejected":
            raise original_signing_error("signing unavailable")
        if case_name == "seal_domain_error_class_frozen_at_entry":
            release_artifact.ReleaseArtifactAdmissionError = type(  # type: ignore[misc]
                "_LateReleaseArtifactError",
                (RuntimeError,),
                {},
            )
            raise original_release_error("entry domain error")
        if provider_exception is not None:
            raise provider_exception
        files[str(provider_args[2])] = "sealed-release-artifact-admission"
        return _SealedResult(
            events,
            projection_failure=projection_exception,
            rebind_reporter=(
                rebind_reporter if case_name == "seal_reporter_is_live_after_projection" else None
            ),
        )

    def late_seal(*_args: Any, **_kwargs: Any) -> _SealedResult:
        events.append("provider:seal-late")
        return _SealedResult(events)

    def verify_provider(
        *provider_args: object,
        **provider_kwargs: object,
    ) -> _VerifiedResult:
        events.append("provider:verify-entry")
        calls.append(_call_record("verify", provider_args, provider_kwargs))
        if case_name == "verify_value_error_is_rejected":
            raise ValueError("verify value rejected")
        if case_name == "verify_provider_oserror_is_rejected":
            raise OSError("bundle read failed")
        if case_name == "verify_signing_error_is_rejected":
            raise original_signing_error("verification key unavailable")
        if case_name == "verify_domain_error_class_frozen_at_entry":
            release_artifact.ReleaseArtifactAdmissionError = type(  # type: ignore[misc]
                "_LateReleaseArtifactError",
                (RuntimeError,),
                {},
            )
            raise original_release_error("entry domain error")
        if provider_exception is not None:
            raise provider_exception
        return _VerifiedResult(
            events,
            projection_failure=projection_exception,
            rebind_reporter=(
                rebind_reporter if case_name == "verify_reporter_is_live_after_projection" else None
            ),
        )

    def late_verify(*_args: Any, **_kwargs: Any) -> _VerifiedResult:
        events.append("provider:verify-late")
        return _VerifiedResult(events)

    environment = _Environment(
        events,
        event_path=(
            None if case_name == "seal_missing_event_path" else "/inputs/github-event.json"
        ),
        on_get=(
            rebind_nested
            if case_name == "seal_nested_helper_is_live_after_event_read"
            else (
                rebind_preflight
                if case_name == "seal_preflight_helper_is_live_after_environment_read"
                else None
            )
        ),
    )

    if case_name == "seal_preflight_reads_complete_path_set_before_rejecting_stdin":
        args.out = "-"
    elif case_name == "seal_alias_rejected_before_metadata":
        args.artifact = args.release_source_admission
    elif case_name == "seal_existing_output_rejected_before_metadata":
        args.out = __file__
    elif case_name == "seal_builder_property_rebinds_reader":
        # Read one happens in the complete preflight path set; read two precedes
        # the outer builder object read.
        args._property_effects[("builder", 2)] = rebind_reader
    elif case_name == "seal_entry_provider_is_frozen_before_arguments":
        args._property_effects[("release_source_admission", 1)] = lambda: (
            events.append("rebind:seal-provider"),
            setattr(release_artifact, "seal_release_artifact_admission", late_seal),
        )
    elif case_name == "seal_key_registry_is_live_but_signer_key_reader_is_frozen":
        # The helper imports the current module function at use time while the
        # outer signing-key lookup was imported at command entry.
        args._property_effects[("admitter", 2)] = rebind_public_key_id
    elif case_name == "seal_key_helper_is_live_after_metadata_reads":
        args._property_effects[("admitter", 2)] = rebind_key_helper
    elif case_name == "seal_signer_domain_collision_precedes_execution_pins":
        _KEY_IDS_OVERRIDE = dict(_KEY_IDS)
        _KEY_IDS_OVERRIDE["/keys/release-artifact-admission-v1.pub"] = "key-trusted-finalizer"

        def collision_public_key_id(path: str) -> str:
            events.append(f"public-key-id:entry:{path}")
            return _KEY_IDS_OVERRIDE[path]

        signing.public_key_id = collision_public_key_id
    elif case_name == "verify_bundle_stdin_short_circuits_artifact":
        args.bundle = "-"
    elif case_name == "verify_artifact_stdin_after_bundle_read":
        args.artifact = "-"
    elif case_name == "verify_bundle_property_baseexception_identity":
        assert expected_exception is not None

        def fail_bundle_read() -> None:
            events.append("argument-property-baseexception")
            raise expected_exception  # type: ignore[misc]

        args._property_effects["bundle"] = fail_bundle_read
    elif case_name == "verify_entry_provider_is_frozen_before_arguments":
        args._property_effects["bundle"] = lambda: (
            events.append("rebind:verify-provider"),
            setattr(
                release_artifact,
                "verify_release_artifact_admission",
                late_verify,
            ),
        )
    elif case_name == "verify_key_helper_is_live_after_metadata_reads":
        args._property_effects[("expected_admitter", 1)] = rebind_key_helper
    elif case_name == "verify_nested_helper_is_live_after_stdin_guard":
        args._property_effects["artifact"] = rebind_nested
    elif case_name == "verify_reader_is_live_during_nested_reads":
        args._property_effects["expected_release_source_context"] = rebind_reader

    if case_name == "seal_format_is_frozen_at_entry":
        args._property_effects[("release_source_admission", 1)] = lambda: (
            events.append("rebind:format"),
            setattr(
                release_artifact,
                "RELEASE_ARTIFACT_ADMISSION_FORMAT",
                "LATE_FORMAT",
            ),
        )
    elif case_name == "verify_format_is_frozen_at_entry":
        args._property_effects["bundle"] = lambda: (
            events.append("rebind:format"),
            setattr(
                release_artifact,
                "RELEASE_ARTIFACT_ADMISSION_FORMAT",
                "LATE_FORMAT",
            ),
        )

    args._strict_allowed = _SEAL_ARGS if kind == "seal" else _VERIFY_ARGS

    cli._machine_report = reporter
    cli._read_external_finalizer_object = reader
    cli._preflight_release_artifact_admission_paths = preflight
    release_artifact.bind_release_artifact_admitter_runtime = bind
    release_artifact.seal_release_artifact_admission = seal_provider
    release_artifact.verify_release_artifact_admission = verify_provider
    finalizer_derivation.git_executable_pin = git_pin
    github_attestation.github_attestation_provider_isolation = isolation
    signing.public_key_id = (
        signing.public_key_id
        if case_name == "seal_signer_domain_collision_precedes_execution_pins"
        else public_key_id
    )
    os.environ = environment  # type: ignore[assignment]  # noqa: B003

    exit_code: int | None = None
    exception: dict[str, object] | None = None
    try:
        command = (
            cli.cmd_seal_github_release_artifact_admission
            if kind == "seal"
            else cli.cmd_verify_github_release_artifact_admission
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
        cli._release_artifact_nested_expectations = original_nested
        cli._preflight_release_artifact_admission_paths = original_preflight
        cli._release_artifact_key_separation = original_key_helper
        release_artifact.bind_release_artifact_admitter_runtime = original_bind
        release_artifact.seal_release_artifact_admission = original_seal
        release_artifact.verify_release_artifact_admission = original_verify
        release_artifact.ReleaseArtifactAdmissionError = original_release_error
        release_artifact.RELEASE_ARTIFACT_ADMISSION_FORMAT = original_format
        finalizer_derivation.git_executable_pin = original_git_pin
        finalizer_derivation.FinalizerDerivationError = original_finalizer_error
        github_attestation.github_attestation_provider_isolation = original_isolation
        github_attestation.GitHubAttestationError = original_github_error
        signing.public_key_id = original_public_key_id
        signing.SigningUnavailableError = original_signing_error  # type: ignore[misc]
        os.environ = original_environment  # noqa: B003

    return {
        "calls": calls,
        "events": events,
        "exception": exception,
        "exit_code": exit_code,
        "files": files,
        "reports": reports,
        "report_sha256": report_sha256,
    }


def capture_vector() -> dict[str, object]:
    """Capture every frozen case in deterministic lexical order."""

    return {
        "baseline_commit": BASELINE_COMMIT,
        "cases": {name: capture_case(name) for name in sorted(CASE_NAMES)},
        "schema_version": SCHEMA_VERSION,
    }
