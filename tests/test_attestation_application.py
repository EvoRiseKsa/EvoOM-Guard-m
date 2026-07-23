"""Contracts for pure, wire-compatible attestation assembly."""

from __future__ import annotations

import ast
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import evoom_guard.application as application
import evoom_guard.guard as guard_module
from evoom_guard.application.attestation import build_attestation


class _TrackingArtifacts(dict[str, Any]):
    def __init__(self, events: list[str], *args: Any, **kwargs: Any) -> None:
        self._events = events
        super().__init__(*args, **kwargs)

    def get(self, key: str, default: Any = None) -> Any:
        self._events.append(f"artifact:{key}")
        return super().get(key, default)


def _policy_digest(policy: Mapping[str, Any]) -> str:
    assert policy == {"policy": "value"}
    return "policy-digest"


def test_application_exports_attestation_builder() -> None:
    assert application.build_attestation is build_attestation


def test_builder_matches_historical_guard_seam(monkeypatch: Any) -> None:
    policy = {"policy": "value"}
    manifest = {"tests": ["pack/test_contract.py"]}
    isolation = {"delivered": "docker"}
    artifacts = {
        "junit_sha256": "junit",
        "verifier_pack_sha256": "pack",
        "verifier_pack_manifest": manifest,
        "isolation_evidence": isolation,
        "deleted_paths_applied": ["obsolete.py"],
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "execution_state": "completed",
        "runtime_continuity": "snapshot_boundary_checked",
    }
    monkeypatch.setattr(guard_module, "_utc_now", lambda: "2026-07-23T00:00:00Z")
    monkeypatch.setattr(guard_module, "__version__", "test-version")
    monkeypatch.setattr(guard_module, "PACK_DIGEST_FORMAT", "PACK-FORMAT")
    monkeypatch.setattr(
        guard_module,
        "effective_policy_sha256",
        _policy_digest,
    )

    old = guard_module._build_attestation(
        "مرشح",
        safe_deleted=["obsolete.py"],
        test_command=["python", "-m", "pytest"],
        effective_policy=policy,
        art=artifacts,
        mode="blackbox",
    )
    new = build_attestation(
        "مرشح",
        safe_deleted=["obsolete.py"],
        test_command=["python", "-m", "pytest"],
        effective_policy=policy,
        artifacts=artifacts,
        mode="blackbox",
        now=lambda: "2026-07-23T00:00:00Z",
        guard_version=lambda: "test-version",
        candidate_digest=lambda value: guard_module.hashlib.sha256(
            value.encode("utf-8")
        ).hexdigest(),
        policy_digest=_policy_digest,
        pack_digest_format=lambda: "PACK-FORMAT",
    )

    assert new == old
    assert tuple(new) == tuple(old)


def test_guard_facade_retains_candidate_hashing_monkeypatch_seam(monkeypatch: Any) -> None:
    class _Digest:
        def hexdigest(self) -> str:
            return "patched-candidate-digest"

    observed: list[bytes] = []

    def patched_sha256(value: bytes) -> _Digest:
        observed.append(value)
        return _Digest()

    monkeypatch.setattr(guard_module.hashlib, "sha256", patched_sha256)
    payload = guard_module._build_attestation(
        "مرشح",
        safe_deleted=[],
        test_command=None,
        effective_policy={},
        art={},
        mode="repo",
    )

    assert observed == ["مرشح".encode(), b"{}"]
    assert payload["candidate_sha256"] == "patched-candidate-digest"


def test_provider_and_artifact_lookup_order_is_exact() -> None:
    events: list[str] = []
    artifacts = _TrackingArtifacts(events, verifier_pack_sha256="pack")

    def now() -> str:
        events.append("provider:now")
        return "2026-07-23T00:00:00Z"

    def version() -> str:
        events.append("provider:version")
        return "version"

    def candidate_digest(value: str) -> str:
        events.append("provider:candidate_digest")
        assert value == "candidate"
        return "candidate-digest"

    def digest(policy: Mapping[str, Any]) -> str:
        events.append("provider:policy_digest")
        return "digest"

    def pack_format() -> str:
        events.append("provider:pack_digest_format")
        return "PACK"

    payload = build_attestation(
        "candidate",
        safe_deleted=(),
        test_command=None,
        effective_policy={},
        artifacts=artifacts,
        mode="repo",
        now=now,
        guard_version=version,
        candidate_digest=candidate_digest,
        policy_digest=digest,
        pack_digest_format=pack_format,
    )

    assert len(payload) == 57
    assert events == [
        "provider:now",
        "provider:version",
        "provider:candidate_digest",
        "provider:policy_digest",
        "artifact:junit_sha256",
        "artifact:junit_digest_format",
        "artifact:verifier_pack_sha256",
        "artifact:verifier_pack_manifest",
        "artifact:verifier_pack_tests_passed",
        "artifact:verifier_pack_tests_total",
        "artifact:verifier_pack_junit_sha256",
        "artifact:verifier_pack_junit_digest_format",
        "artifact:verifier_pack_sha256",
        "provider:pack_digest_format",
        "artifact:isolation_evidence",
        "artifact:setup_isolation_evidence",
        "artifact:repo_suite_isolation_evidence",
        "artifact:verifier_pack_isolation_evidence",
        "artifact:blackbox_pack_isolation_evidence",
        "artifact:deleted_paths_applied",
        "artifact:repo_suite_junit_sha256",
        "artifact:repo_suite_junit_digest_format",
        "artifact:repo_suite_tests_passed",
        "artifact:repo_suite_tests_total",
        "artifact:repo_suite_verdict_source",
        "artifact:repo_suite_returncode",
        "artifact:repo_suite_passed",
        "artifact:repo_suite_started",
        "artifact:repo_suite_completed",
        "artifact:repo_suite_state",
        "artifact:repo_suite_image_digest",
        "artifact:base_sha",
        "artifact:head_sha",
        "artifact:base_tree_sha",
        "artifact:head_tree_sha",
        "artifact:policy_id",
        "artifact:policy_version",
        "artifact:execution_state",
        "artifact:execution_phase",
        "artifact:test_command_started",
        "artifact:delivered_isolation",
        "artifact:effective_candidate_isolation",
        "artifact:candidate_invocations",
        "artifact:candidate_launcher_invocation_observed",
        "artifact:verifier_pack_present",
        "artifact:verifier_pack_started",
        "artifact:verifier_pack_completed",
        "artifact:setup_isolation",
        "artifact:runtime_tree_sha256",
        "artifact:runtime_tree_digest_format",
        "artifact:runtime_tree_entries",
        "artifact:runtime_tree_bytes",
        "artifact:runtime_identity_elapsed_ms",
        "artifact:runtime_continuity",
    ]
    assert events.count("provider:now") == 1
    assert events.count("provider:version") == 1
    assert events.count("provider:candidate_digest") == 1
    assert events.count("provider:policy_digest") == 1
    assert events.count("provider:pack_digest_format") == 1


def test_copy_reference_and_falsey_compatibility() -> None:
    deleted = ["old.py"]
    command = ["python", "-m", "pytest"]
    policy: dict[str, Any] = {"nested": {"value": 1}}
    manifest: dict[str, Any] = {"tests": ["pack/test_contract.py"]}
    isolation: dict[str, Any] = {"delivered": "subprocess"}
    artifacts = {
        "verifier_pack_sha256": "",
        "verifier_pack_manifest": manifest,
        "isolation_evidence": isolation,
    }
    format_calls = 0

    def pack_format() -> str:
        nonlocal format_calls
        format_calls += 1
        return "PACK"

    payload = build_attestation(
        "candidate",
        safe_deleted=deleted,
        test_command=command,
        effective_policy=policy,
        artifacts=artifacts,
        mode="repo",
        now=lambda: "2026-07-23T00:00:00Z",
        guard_version=lambda: "version",
        candidate_digest=lambda value: guard_module.hashlib.sha256(
            value.encode("utf-8")
        ).hexdigest(),
        policy_digest=lambda _: "digest",
        pack_digest_format=pack_format,
    )

    assert payload["deleted_paths"] == deleted
    assert payload["deleted_paths"] is not deleted
    assert payload["test_command"] == command
    assert payload["test_command"] is not command
    assert payload["effective_policy"] is policy
    assert payload["verifier_pack_manifest"] is manifest
    assert payload["isolation_evidence"] is isolation
    assert payload["verifier_pack_digest_format"] is None
    assert format_calls == 0

    empty_command = build_attestation(
        "candidate",
        safe_deleted=(),
        test_command=[],
        effective_policy=policy,
        artifacts={},
        mode="repo",
        now=lambda: "2026-07-23T00:00:00Z",
        guard_version=lambda: "version",
        candidate_digest=lambda value: guard_module.hashlib.sha256(
            value.encode("utf-8")
        ).hexdigest(),
        policy_digest=lambda _: "digest",
        pack_digest_format=pack_format,
    )
    assert empty_command["test_command"] == "default:python -m pytest"


def test_attestation_application_has_no_effectful_or_upstream_imports() -> None:
    module_path = (
        Path(__file__).resolve().parents[1] / "evoom_guard" / "application" / "attestation.py"
    )
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    forbidden_prefixes = (
        "evoom_guard.guard",
        "evoom_guard.execution",
        "evoom_guard.verifiers",
        "evoom_guard.isolation",
        "evoom_guard.pack_manifest",
        "subprocess",
        "pathlib",
        "os",
    )
    assert not {module for module in imported_modules if module.startswith(forbidden_prefixes)}
