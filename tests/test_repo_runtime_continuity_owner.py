"""Direct contracts for the repository runtime-continuity owner."""

from __future__ import annotations

import sys
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from typing import Any

import pytest

from evoom_guard.domain.evidence import RuntimeIdentityEvidence
from evoom_guard.runtime_identity import RuntimeIdentity, RuntimeIdentityError
from evoom_guard.verifiers import repo_verifier
from evoom_guard.verifiers.repo_runtime_continuity import (
    RepoRuntimeContinuity,
    RepoRuntimeContinuityRequest,
    RepoRuntimeContinuityServices,
    runtime_identity_evidence_payload,
)


def _identity(
    label: str,
    elapsed_ms: float,
    *,
    entries: int = 3,
    regular_bytes: int = 17,
) -> RuntimeIdentity:
    return RuntimeIdentity(
        sha256=label * 64,
        entries=entries,
        regular_bytes=regular_bytes,
        elapsed_ms=elapsed_ms,
        records=(),
    )


def _owner(
    *,
    pack_configured: bool = True,
    container_mode: bool = False,
    setup_configured: bool = False,
    trust_setup_on_host: bool = False,
    capture: Any,
    verify: Any,
) -> tuple[RepoRuntimeContinuity, SimpleNamespace]:
    trace = SimpleNamespace(execution_phase="preflight")
    owner = RepoRuntimeContinuity(
        RepoRuntimeContinuityRequest(
            candidate_copy="candidate",
            pack_configured=pack_configured,
            container_mode=container_mode,
            setup_configured=setup_configured,
            trust_setup_on_host=trust_setup_on_host,
        ),
        RepoRuntimeContinuityServices(
            trace=trace,
            capture_identity=lambda: capture,
            verify_identity=lambda: verify,
        ),
    )
    return owner, trace


def test_no_pack_never_resolves_an_identity_provider() -> None:
    def unexpected() -> Any:
        raise AssertionError("no-pack path resolved an identity provider")

    trace = SimpleNamespace(execution_phase="repo_suite")
    owner = RepoRuntimeContinuity(
        RepoRuntimeContinuityRequest(
            candidate_copy="candidate",
            pack_configured=False,
            container_mode=True,
            setup_configured=True,
            trust_setup_on_host=False,
        ),
        RepoRuntimeContinuityServices(
            trace=trace,
            capture_identity=unexpected,
            verify_identity=unexpected,
        ),
    )

    assert owner.required is False
    assert owner.capture_baseline() is None
    assert trace.execution_phase == "repo_suite"
    assert runtime_identity_evidence_payload(owner.evidence()) == {
        "runtime_tree_sha256": None,
        "runtime_tree_digest_format": None,
        "runtime_tree_entries": None,
        "runtime_tree_bytes": None,
        "runtime_identity_elapsed_ms": 0.0,
        "runtime_continuity": "not_applicable",
    }


@pytest.mark.parametrize(
    (
        "container_mode",
        "setup_configured",
        "trust_setup_on_host",
        "expected",
    ),
    (
        (False, False, False, "snapshot_boundary_checked"),
        (True, False, False, "read_only_enforced"),
        (True, True, False, "read_only_enforced"),
        (True, True, True, "snapshot_boundary_checked"),
        (True, False, True, "read_only_enforced"),
    ),
)
def test_delivery_never_overclaims_host_setup(
    container_mode: bool,
    setup_configured: bool,
    trust_setup_on_host: bool,
    expected: str,
) -> None:
    owner, _trace = _owner(
        container_mode=container_mode,
        setup_configured=setup_configured,
        trust_setup_on_host=trust_setup_on_host,
        capture=lambda _root: _identity("a", 0.25),
        verify=lambda _root, _baseline: (_identity("a", 0.5), []),
    )

    assert owner.delivery == expected


def test_capture_suite_and_pack_accumulate_elapsed_and_finalize_continuity() -> None:
    baseline = _identity("a", 0.25)
    observations = iter(
        (
            _identity("a", 0.5),
            _identity("a", 0.75),
        )
    )
    events: list[str] = []

    def capture(root: str) -> RuntimeIdentity:
        events.append(f"capture:{root}")
        return baseline

    def verify(
        root: str,
        expected: RuntimeIdentity,
    ) -> tuple[RuntimeIdentity, list[str]]:
        assert expected is baseline
        events.append(f"verify:{root}")
        return next(observations), []

    owner, trace = _owner(
        container_mode=True,
        capture=capture,
        verify=verify,
    )

    assert owner.capture_baseline() is None
    assert owner.continuity == "incomplete"
    assert owner.verify_after_suite() is None
    assert owner.continuity == "incomplete"
    assert owner.verify_after_pack() is None
    assert owner.continuity == "read_only_enforced"
    assert owner.elapsed_ms == 1.5
    assert trace.execution_phase == "runtime_verification"
    assert events == [
        "capture:candidate",
        "verify:candidate",
        "verify:candidate",
    ]
    assert runtime_identity_evidence_payload(owner.evidence()) == {
        "runtime_tree_sha256": "a" * 64,
        "runtime_tree_digest_format": baseline.digest_format,
        "runtime_tree_entries": 3,
        "runtime_tree_bytes": 17,
        "runtime_identity_elapsed_ms": 1.5,
        "runtime_continuity": "read_only_enforced",
    }


def test_identity_providers_are_resolved_live_at_every_operation() -> None:
    baseline = _identity("a", 0.25)
    state: dict[str, Any] = {}
    events: list[str] = []
    trace = SimpleNamespace(execution_phase="preflight")

    def capture_late(_root: str) -> RuntimeIdentity:
        events.append("capture:late")
        return baseline

    def verify_suite(_root: str, _baseline: RuntimeIdentity):
        events.append("verify:suite")
        state["verify"] = verify_pack
        return _identity("a", 0.5), []

    def verify_pack(_root: str, _baseline: RuntimeIdentity):
        events.append("verify:pack")
        return _identity("a", 0.75), []

    state["capture"] = lambda _root: (_ for _ in ()).throw(
        AssertionError("captured provider used")
    )
    state["verify"] = verify_suite
    owner = RepoRuntimeContinuity(
        RepoRuntimeContinuityRequest(
            candidate_copy="candidate",
            pack_configured=True,
            container_mode=False,
            setup_configured=False,
            trust_setup_on_host=False,
        ),
        RepoRuntimeContinuityServices(
            trace=trace,
            capture_identity=lambda: state["capture"],
            verify_identity=lambda: state["verify"],
        ),
    )
    state["capture"] = capture_late

    assert owner.capture_baseline() is None
    assert owner.verify_after_suite() is None
    assert owner.verify_after_pack() is None
    assert events == ["capture:late", "verify:suite", "verify:pack"]


def test_facade_injects_live_capture_and_verify_providers(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "test_contract.py").write_text(
        "def test_contract():\n    assert True\n",
        encoding="utf-8",
    )
    baseline = _identity("a", 0.25)
    events: list[str] = []
    original_owner = repo_verifier.RepoRuntimeContinuity

    def unexpected(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("facade snapshotted an identity provider early")

    def verify_pack(
        _root: str,
        expected: RuntimeIdentity,
    ) -> tuple[RuntimeIdentity, list[str]]:
        assert expected is baseline
        events.append("verify:pack")
        return _identity("a", 0.75), []

    def verify_suite(
        _root: str,
        expected: RuntimeIdentity,
    ) -> tuple[RuntimeIdentity, list[str]]:
        assert expected is baseline
        events.append("verify:suite")
        monkeypatch.setattr(
            repo_verifier,
            "verify_runtime_identity",
            verify_pack,
        )
        return _identity("a", 0.5), []

    def capture(_root: str) -> RuntimeIdentity:
        events.append("capture")
        monkeypatch.setattr(
            repo_verifier,
            "verify_runtime_identity",
            verify_suite,
        )
        return baseline

    def construct_owner(*args: Any, **kwargs: Any) -> RepoRuntimeContinuity:
        owner = original_owner(*args, **kwargs)
        monkeypatch.setattr(
            repo_verifier,
            "capture_runtime_identity",
            capture,
        )
        return owner

    monkeypatch.setattr(repo_verifier, "capture_runtime_identity", unexpected)
    monkeypatch.setattr(repo_verifier, "verify_runtime_identity", unexpected)
    monkeypatch.setattr(repo_verifier, "RepoRuntimeContinuity", construct_owner)

    result = repo_verifier.RepoVerifier(
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        mem_limit_mb=0,
    ).verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {
            "repo_path": str(source),
            "verifier_pack": str(pack),
        },
    )

    assert result.passed, result.diagnostics
    assert events == ["capture", "verify:suite", "verify:pack"]


def test_capture_error_is_fail_closed_without_identity_claim() -> None:
    def capture(_root: str) -> RuntimeIdentity:
        raise RuntimeIdentityError("controlled capture failure")

    owner, _trace = _owner(
        capture=capture,
        verify=lambda *_args: pytest.fail("verify must not run"),
    )

    failure = owner.capture_baseline()

    assert failure is not None
    assert failure.kind == "capture_error"
    assert failure.diagnostics == (
        "candidate runtime identity failed: controlled capture failure"
    )
    assert owner.evidence().continuity == "unavailable"
    assert owner.phase == "failed"
    assert owner.baseline is None


def test_suite_verification_error_preserves_the_baseline_and_elapsed() -> None:
    baseline = _identity("a", 0.25)

    def verify(_root: str, _baseline: RuntimeIdentity):
        raise RuntimeIdentityError("controlled verification failure")

    owner, _trace = _owner(
        capture=lambda _root: baseline,
        verify=verify,
    )
    assert owner.capture_baseline() is None

    failure = owner.verify_after_suite()

    assert failure is not None
    assert failure.kind == "verification_error"
    assert failure.diagnostics == (
        "candidate runtime identity verification failed: "
        "controlled verification failure"
    )
    assert owner.elapsed_ms == 0.25
    assert owner.evidence().continuity == "verification_failed"
    assert owner.phase == "failed"


def test_suite_drift_is_phase_specific_and_keeps_all_changes() -> None:
    baseline = _identity("a", 0.25)
    changes = [f"path-{index}" for index in range(25)]
    owner, _trace = _owner(
        capture=lambda _root: baseline,
        verify=lambda _root, _baseline: (_identity("b", 0.5), changes),
    )
    assert owner.capture_baseline() is None

    failure = owner.verify_after_suite()

    assert failure is not None
    assert failure.kind == "suite_drift"
    assert failure.changes == tuple(changes)
    assert failure.diagnostics == (
        "repo suite modified the candidate tree before verifier-pack "
        "execution: " + ", ".join(changes[:20])
    )
    assert owner.continuity == "verification_failed"
    assert owner.phase == "failed"


def test_pack_drift_never_finalizes_continuity() -> None:
    baseline = _identity("a", 0.25)
    results = iter(
        (
            (_identity("a", 0.5), []),
            (_identity("b", 0.75), ["app.py"]),
        )
    )
    owner, _trace = _owner(
        container_mode=True,
        capture=lambda _root: baseline,
        verify=lambda _root, _baseline: next(results),
    )
    assert owner.capture_baseline() is None
    assert owner.verify_after_suite() is None

    failure = owner.verify_after_pack()

    assert failure is not None
    assert failure.kind == "pack_drift"
    assert failure.changes == ("app.py",)
    assert failure.diagnostics == (
        "verifier-pack execution modified the candidate tree: app.py"
    )
    assert owner.continuity == "verification_failed"
    assert owner.evidence().continuity == "verification_failed"
    assert owner.phase == "failed"


def test_pack_verification_cannot_skip_the_suite_checkpoint() -> None:
    owner, _trace = _owner(
        container_mode=True,
        capture=lambda _root: _identity("a", 0.25),
        verify=lambda _root, _baseline: (_identity("a", 0.5), []),
    )
    assert owner.capture_baseline() is None

    with pytest.raises(
        RuntimeError,
        match="expected 'suite_verified'",
    ):
        owner.verify_after_pack()

    assert owner.phase == "captured"
    assert owner.continuity == "incomplete"


def test_suite_failure_is_sticky_and_cannot_be_recovered_by_pack_check() -> None:
    observations = iter(
        (
            (_identity("b", 0.5), ["app.py"]),
            (_identity("a", 0.75), []),
        )
    )
    owner, _trace = _owner(
        container_mode=True,
        capture=lambda _root: _identity("a", 0.25),
        verify=lambda _root, _baseline: next(observations),
    )
    assert owner.capture_baseline() is None
    suite_failure = owner.verify_after_suite()
    assert suite_failure is not None

    pack_failure = owner.verify_after_pack()

    assert pack_failure is suite_failure
    assert owner.phase == "failed"
    assert owner.continuity == "verification_failed"
    assert owner.elapsed_ms == 0.75


def test_projected_domain_evidence_is_immutable() -> None:
    owner, _trace = _owner(
        pack_configured=False,
        capture=lambda *_args: pytest.fail("capture must not run"),
        verify=lambda *_args: pytest.fail("verify must not run"),
    )
    evidence = owner.evidence()

    assert isinstance(evidence, RuntimeIdentityEvidence)
    with pytest.raises(FrozenInstanceError):
        evidence.continuity = "changed"  # type: ignore[misc]
