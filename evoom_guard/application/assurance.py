# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Pure construction and evaluation of delivered assurance profiles."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, cast

from evoom_guard.domain.assurance import AssuranceProfile, VerifierPackAssurance
from evoom_guard.domain.verdict import (
    EXECUTION_COMPLETED,
    EXECUTION_NOT_STARTED,
    EXECUTION_STARTED_INCOMPLETE,
    EXECUTION_STATIC_GATE,
)

REPORT_INTEGRITY_RANK_POLICY: Mapping[str, int] = MappingProxyType(
    {
        "same_process_candidate_writable": 0,
        "external_process_isolated": 1,
    }
)
ISOLATION_RANK_POLICY: Mapping[str, int] = MappingProxyType(
    {"subprocess": 0, "docker": 1, "gvisor": 2}
)


def _profile_payload(
    profile: AssuranceProfile,
    *,
    legacy_pack_payload: dict[str, Any] | None = None,
    use_legacy_pack_payload: bool = False,
) -> dict[str, Any]:
    payload = cast(dict[str, Any], profile.to_payload())
    if use_legacy_pack_payload:
        # The historical private helper accepted arbitrary mapping values.
        # Preserve that private compatibility behavior at the wire facade
        # without admitting mutable/untyped values into the domain object.
        payload["verifier_pack"] = legacy_pack_payload
    return payload


def assurance_shortfall(
    assurance: dict[str, Any],
    *,
    require_report_integrity: str | None,
    require_candidate_isolation: str | None,
) -> str | None:
    """Return a human reason if the ACTUAL assurance is below what was required.

    Fail-closed: the check is against what the run really delivered
    (`assurance`), never against the requested CLI value — so Guard can never
    claim an assurance level it did not enforce.
    """
    if require_report_integrity:
        want = REPORT_INTEGRITY_RANK_POLICY.get(require_report_integrity)
        got = REPORT_INTEGRITY_RANK_POLICY.get(assurance.get("report_integrity", ""), -1)
        if want is None:
            return f"unknown --require-report-integrity value: {require_report_integrity!r}"
        if got < want:
            return (
                f"required report_integrity ≥ '{require_report_integrity}' but the run "
                f"delivered '{assurance.get('report_integrity')}' "
                "(use --blackbox for external_process_isolated)"
            )
    if require_candidate_isolation:
        want_i = ISOLATION_RANK_POLICY.get(require_candidate_isolation)
        got_i = ISOLATION_RANK_POLICY.get(assurance.get("candidate_isolation", ""), -1)
        if want_i is None:
            return f"unknown --require-candidate-isolation value: {require_candidate_isolation!r}"
        if got_i < want_i:
            return (
                f"required candidate_isolation ≥ '{require_candidate_isolation}' but the "
                f"run used '{assurance.get('candidate_isolation')}'"
            )
    return None


def static_assurance_profile(verifier_pack: str | None) -> dict[str, Any]:
    """Assurance delivered by a decision made before candidate execution.

    Requested runtime policy remains visible in ``attestation.effective_policy``.
    This object records only what actually happened: the diff pre-gate ran, while
    no candidate, suite, report channel, setup, or verifier pack was exercised.
    Runtime assurance floors therefore have nothing to rank on this path and must
    not replace an already-final static rejection with a synthetic runtime error.
    """
    pack: VerifierPackAssurance | None = None
    if verifier_pack:
        pack = VerifierPackAssurance(
            configured=True,
            present=None,
            integrity="not_evaluated_static_gate",
            identity_verified=None,
            execution_state=EXECUTION_STATIC_GATE,
            secrecy="not_evaluated_static_gate",
            snapshot_sha256=None,
        )
    return _profile_payload(
        AssuranceProfile(
            execution_state=EXECUTION_STATIC_GATE,
            execution_phase="pre_gate",
            harness_integrity="pre_gate_enforced",
            report_integrity="not_applicable_static_gate",
            candidate_isolation="not_run",
            suite_isolation="not_run",
            setup_isolation=None,
            runtime_continuity="not_applicable",
            verifier_pack=pack,
            overall_profile="static_gate",
            note=(
                "the diff pre-gate decided this result before candidate execution; "
                "no test command, runtime boundary, report channel, setup, or verifier "
                "pack was exercised. Requested runtime policy is recorded only in "
                "attestation.effective_policy."
            ),
        )
    )


def _pack_assurance_parts(
    verifier_pack: str | None,
    *,
    isolation: str = "not_run",
    blackbox: bool = False,
    evidence: dict[str, Any] | None = None,
) -> tuple[VerifierPackAssurance | None, dict[str, Any] | None, bool]:
    """Describe verifier-pack facts without turning configuration into evidence.

    A path in policy proves only that a pack was configured.  Presence, snapshot
    acceptance, execution, and the post-execution integrity check are separate
    facts supplied by the runner in ``evidence``.
    """
    if not verifier_pack:
        return None, None, False
    ev = evidence or {}
    present = ev.get("present")
    snapshot_sha256 = ev.get("snapshot_sha256")
    snapshot_accepted = bool(ev.get("snapshot_accepted") or snapshot_sha256)
    started = bool(ev.get("started"))
    completed = bool(ev.get("completed"))
    outcome = ev.get("outcome")

    if present is False:
        integrity = "not_evaluated_missing"
        identity_verified: bool | None = None
    elif outcome == "pack_invalid":
        integrity = "invalid"
        identity_verified = None
    elif outcome == "pack_identity_mismatch":
        integrity = "snapshot_identity_mismatch"
        identity_verified = False
    elif outcome == "pack_snapshot_changed":
        integrity = "snapshot_changed"
        identity_verified = False
    elif snapshot_accepted and completed:
        # Repo-native container packs are mounted read-only.  The black-box
        # judge executes its private snapshot on the host, so its integrity
        # mechanism is the completed pre/post snapshot check.  Being unmounted
        # from a candidate container is a secrecy property, not a read-only
        # mount property.
        integrity = (
            "verified_snapshot_read_only"
            if not blackbox and isolation in ("docker", "gvisor")
            else "verified_snapshot_pre_post"
        )
        identity_verified = True
    elif snapshot_accepted:
        integrity = "verified_snapshot_pre_execution"
        identity_verified = True
    else:
        integrity = "not_evaluated"
        identity_verified = None

    if completed:
        pack_execution = EXECUTION_COMPLETED
    elif started:
        pack_execution = EXECUTION_STARTED_INCOMPLETE
    else:
        pack_execution = EXECUTION_NOT_STARTED

    if not started:
        secrecy = "not_evaluated_no_execution"
    elif blackbox and ev.get("candidate_launcher_invocation_observed") is False:
        secrecy = "not_evaluated_no_candidate_execution"
    elif blackbox and isolation in ("docker", "gvisor"):
        secrecy = "unmounted_from_candidate"
    elif blackbox:
        secrecy = "reachable_same_host"
    else:
        secrecy = "readable_in_judge_process"

    legacy_payload = {
        "configured": True,
        "present": present,
        "integrity": integrity,
        "identity_verified": identity_verified,
        "execution_state": pack_execution,
        "secrecy": secrecy,
        "snapshot_sha256": snapshot_sha256,
    }
    present_is_typed = present is None or type(present) is bool
    snapshot_is_typed = snapshot_sha256 is None or isinstance(snapshot_sha256, str)
    if not (present_is_typed and snapshot_is_typed):
        return None, legacy_payload, True
    return (
        VerifierPackAssurance(
            configured=True,
            present=present,
            integrity=integrity,
            identity_verified=identity_verified,
            execution_state=pack_execution,
            secrecy=secrecy,
            snapshot_sha256=snapshot_sha256,
        ),
        None,
        False,
    )


def pack_assurance(
    verifier_pack: str | None,
    *,
    isolation: str = "not_run",
    blackbox: bool = False,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return the established verifier-pack payload from an immutable value."""

    value, legacy_payload, use_legacy_payload = _pack_assurance_parts(
        verifier_pack,
        isolation=isolation,
        blackbox=blackbox,
        evidence=evidence,
    )
    if use_legacy_payload:
        return legacy_payload
    return cast(dict[str, Any], value.to_payload()) if value is not None else None


def preflight_assurance_profile(
    verifier_pack: str | None,
    *,
    execution_state: str = EXECUTION_NOT_STARTED,
    execution_phase: str = "preflight",
    setup_isolation: str | None = None,
    runtime_continuity: str | None = None,
    pack_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assurance for a requested runtime evaluation that never started tests."""
    pack, legacy_pack, use_legacy_pack = _pack_assurance_parts(
        verifier_pack,
        evidence=pack_evidence,
        isolation="not_run",
    )
    return _profile_payload(
        AssuranceProfile(
            execution_state=execution_state,
            execution_phase=execution_phase,
            harness_integrity="pre_gate_enforced",
            report_integrity="not_applicable_not_run",
            candidate_isolation="not_run",
            suite_isolation="not_run",
            setup_isolation=setup_isolation,
            runtime_continuity=runtime_continuity or "not_applicable",
            verifier_pack=pack,
            overall_profile=(
                "execution_incomplete_before_tests"
                if execution_state == EXECUTION_STARTED_INCOMPLETE
                else "preflight"
            ),
            note=(
                "runtime verification did not start a test command (furthest phase: "
                f"{execution_phase}); no candidate isolation or report-integrity "
                "boundary is claimed. Requested policy remains in "
                "attestation.effective_policy."
            ),
        ),
        legacy_pack_payload=legacy_pack,
        use_legacy_pack_payload=use_legacy_pack,
    )


def assurance_profile(
    isolation: str,
    verifier_pack: str | None,
    *,
    blackbox: bool = False,
    composed_repo_suite: bool = False,
    repo_suite_required: bool = False,
    repo_suite_state: str | None = None,
    candidate_isolation: str | None = None,
    setup_isolation: str | None = None,
    runtime_continuity: str | None = None,
    execution_state: str = EXECUTION_COMPLETED,
    execution_phase: str = "complete",
    test_command_started: bool = True,
    pack_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if execution_state == EXECUTION_NOT_STARTED or not test_command_started:
        return preflight_assurance_profile(
            verifier_pack,
            execution_state=execution_state,
            execution_phase=execution_phase,
            setup_isolation=setup_isolation,
            runtime_continuity=runtime_continuity,
            pack_evidence=pack_evidence,
        )

    if pack_evidence is None and verifier_pack:
        # Backward-compatible helper calls model a completed execution. Guard
        # itself always passes explicit runner evidence.
        pack_evidence = {
            "present": True,
            "snapshot_accepted": True,
            "started": True,
            "completed": execution_state == EXECUTION_COMPLETED,
        }
    effective_isolation = "subprocess" if setup_isolation == "subprocess_host_opt_in" else isolation
    effective_candidate_isolation = (
        candidate_isolation if candidate_isolation is not None else effective_isolation
    )
    pack, legacy_pack, use_legacy_pack = _pack_assurance_parts(
        verifier_pack,
        isolation=(effective_candidate_isolation if blackbox else isolation),
        blackbox=blackbox,
        evidence=pack_evidence,
    )
    if blackbox:
        # ``isolation`` here is the DELIVERED boundary (from the runner), not the
        # requested flag — so candidate_isolation can never claim more than ran.
        report_integrity = (
            "same_process_candidate_writable"
            if composed_repo_suite
            else "external_process_isolated"
        )
        # A composite verdict is only as strong as its weakest required report
        # channel. The external pack cannot strengthen the repo-native suite's
        # candidate-writable JUnit+exit channel.
        return _profile_payload(
            AssuranceProfile(
                execution_state=execution_state,
                execution_phase=execution_phase,
                harness_integrity="pre_gate_enforced",
                report_integrity=report_integrity,
                candidate_isolation=effective_candidate_isolation,
                suite_isolation=isolation,
                setup_isolation=setup_isolation,
                runtime_continuity=runtime_continuity or "not_applicable",
                verifier_pack=pack,
                repo_native_suite=repo_suite_state
                or (
                    "composed_completed"
                    if composed_repo_suite
                    else "required_not_run_short_circuit"
                    if repo_suite_required
                    else "not_required_blackbox_only"
                ),
                repo_native_suite_present=True,
                overall_profile=(
                    (
                        "composite_blackbox_repo_native"
                        if composed_repo_suite
                        else "blackbox_composite_short_circuit"
                        if repo_suite_required
                        else "black_box_external_judge"
                    )
                    if execution_state == EXECUTION_COMPLETED
                    else "execution_incomplete"
                ),
                note=(
                    "The black-box phase has external_process_isolated report integrity: "
                    "its judge-owned pytest does not import the candidate, so candidate "
                    "report/exit forgery cannot reach that phase. "
                    + (
                        "The required repo-native phase has "
                        "same_process_candidate_writable report integrity, so the "
                        "composite reports that weaker level; use --blackbox-only when "
                        "an external_process_isolated floor is required. "
                        if composed_repo_suite
                        else "The repo-native phase remained required by policy but "
                        "did not become an executed report channel; the required "
                        f"pipeline stopped in state '{repo_suite_state}'. "
                        if repo_suite_required
                        else "The black-box phase is the only required report channel. "
                    )
                    + "candidate_isolation is what was OBSERVED during a launcher "
                    f"invocation ('{effective_candidate_isolation}'); preparing "
                    f"'{isolation}' alone is not evidence. A container boundary also "
                    "removes the pack from "
                    "the candidate's reach. "
                    + (
                        "Execution did not complete, so no clean verdict source is claimed. "
                        if execution_state != EXECUTION_COMPLETED
                        else ""
                    )
                    + "See docs/BLACKBOX.md."
                ),
            ),
            legacy_pack_payload=legacy_pack,
            use_legacy_pack_payload=use_legacy_pack,
        )
    overall = (
        "mixed_host_setup_repo_native"
        if setup_isolation == "subprocess_host_opt_in"
        else "isolated_repo_native"
        if isolation in ("docker", "gvisor")
        else "repo_native_same_process"
    )
    return _profile_payload(
        AssuranceProfile(
            execution_state=execution_state,
            execution_phase=execution_phase,
            harness_integrity="pre_gate_enforced",
            report_integrity="same_process_candidate_writable",
            candidate_isolation=effective_isolation,
            suite_isolation=isolation,
            setup_isolation=setup_isolation,
            runtime_continuity=runtime_continuity or "not_applicable",
            verifier_pack=pack,
            overall_profile=(
                overall if execution_state == EXECUTION_COMPLETED else "execution_incomplete"
            ),
            note=(
                "report_integrity is same_process_candidate_writable: a determined "
                "in-process patch can forge the JUnit report and exit code together. "
                "Guard blocks the harness edits/deletions and stdout forgery agents do "
                "in practice; it does not stop deliberate process-level forgery in "
                "source. The container modes isolate the host, not the report. Use "
                "--blackbox for external_process_isolated. "
                + (
                    "Execution did not complete, so no clean verdict source is claimed. "
                    if execution_state != EXECUTION_COMPLETED
                    else ""
                )
                + "See docs/ASSURANCE.md."
            ),
        ),
        legacy_pack_payload=legacy_pack,
        use_legacy_pack_payload=use_legacy_pack,
    )


__all__ = [
    "ISOLATION_RANK_POLICY",
    "REPORT_INTEGRITY_RANK_POLICY",
    "assurance_profile",
    "assurance_shortfall",
    "pack_assurance",
    "preflight_assurance_profile",
    "static_assurance_profile",
]
