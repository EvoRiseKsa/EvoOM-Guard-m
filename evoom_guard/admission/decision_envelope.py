# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Canonical, proof-bound admission-decision projections.

An admission-decision envelope is not a new authority and is not self-authenticating.
It is a small, interoperable projection of one exact proof whose original verifier
must succeed against external trust roots before the projection is trusted.  Keeping
that distinction explicit avoids turning copied JSON claims into an admission oracle.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from evoom_guard.evidence_bundle import (
    EvidenceBundleError,
    canonical_json_bytes,
    load_json_object_bytes,
)

IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
ADMISSION_DECISION_PREDICATE_TYPE = "https://schemas.evorise.tech/evoom-guard/admission-decision/v1"
ADMISSION_DECISION_FORMAT = "EVOGUARD_ADMISSION_DECISION_ENVELOPE_V1"
ADMISSION_DECISION_PROFILE_AGENT_CHANGE = "agent-change"
ADMISSION_DECISION_PROOF_FORMAT = "EVOGUARD_EVIDENCE_BUNDLE_V1"
ADMISSION_DECISION_PROOF_MODE = "PROOF_BOUND_PROJECTION"
ADMISSION_DECISION_SCOPE = "repository-change"

MAX_ADMISSION_DECISION_BYTES = 1 * 1024 * 1024
MAX_PROOF_BYTES = 66 * 1024 * 1024
MAX_CANDIDATE_BYTES = 64 * 1024 * 1024
MAX_RUN_ATTEMPT = 2_147_483_647

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_KEY_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}\Z")
_NUMERIC_ID = re.compile(r"[1-9][0-9]{0,255}\Z")

_ENVELOPE_KEYS = {"_type", "subject", "predicateType", "predicate"}
_STATEMENT_SUBJECT_KEYS = {"name", "digest"}
_DIGEST_KEYS = {"gitCommit"}
_PREDICATE_KEYS = {
    "format",
    "profile",
    "decision",
    "subject",
    "controls",
    "proof",
    "authority",
}
_CHANGE_SUBJECT_KEYS = {
    "kind",
    "repository",
    "repository_id",
    "pull_request_number",
    "base_sha",
    "base_tree_sha",
    "head_sha",
    "head_tree_sha",
    "candidate_sha256",
    "candidate_size",
}
_CONTROL_KEYS = {"policy_sha256", "verifier_pack_sha256"}
_PROOF_KEYS = {"format", "sha256", "size", "authentication"}
_PROOF_AUTHENTICATION_KEYS = {"finalizer", "change_authorization"}
_AUTHENTICATOR_KEYS = {"algorithm", "key_id", "purpose"}
_AUTHORITY_KEYS = {
    "mode",
    "admission_scope",
    "merge",
    "publication",
    "deployment",
    "external_action",
}


class AdmissionDecisionEnvelopeError(ValueError):
    """An envelope is malformed, non-canonical, or overclaims authority."""


@dataclass(frozen=True)
class InspectedAdmissionDecisionEnvelope:
    """Canonical bytes after structural validation only.

    This value is intentionally named ``Inspected`` rather than ``Verified``.
    A proof-family adapter must reverify the retained proof before the envelope
    may be used as a decision.
    """

    envelope_bytes: bytes

    def __post_init__(self) -> None:
        """Reject direct construction with bytes that were not inspected."""

        if (
            type(self.envelope_bytes) is not bytes
            or not 1 <= len(self.envelope_bytes) <= MAX_ADMISSION_DECISION_BYTES
        ):
            raise AdmissionDecisionEnvelopeError(
                "admission decision envelope bytes are outside the supported range"
            )
        try:
            parsed = load_json_object_bytes(self.envelope_bytes, "admission decision envelope")
            checked = validate_admission_decision_envelope(parsed)
            if canonical_json_bytes(checked) != self.envelope_bytes:
                raise AdmissionDecisionEnvelopeError(
                    "admission decision envelope is not canonical JSON"
                )
        except EvidenceBundleError as exc:
            raise AdmissionDecisionEnvelopeError(str(exc)) from exc

    @property
    def payload(self) -> dict[str, Any]:
        """Return a fresh validated view so callers cannot mutate retained truth."""

        try:
            parsed = load_json_object_bytes(self.envelope_bytes, "admission decision envelope")
        except EvidenceBundleError as exc:  # pragma: no cover - construction proved this
            raise AdmissionDecisionEnvelopeError(str(exc)) from exc
        return validate_admission_decision_envelope(parsed)


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdmissionDecisionEnvelopeError(f"{label} must be an object")
    return dict(value)


def _exact(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise AdmissionDecisionEnvelopeError(
            f"{label} keys are not exact "
            f"(missing={sorted(expected - actual)}, unknown={sorted(actual - expected)})"
        )


def _matched(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise AdmissionDecisionEnvelopeError(f"{label} is not canonical")
    return value


def _integer(value: object, *, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise AdmissionDecisionEnvelopeError(f"{label} is outside the supported range")
    return value


def _authenticator(value: object, *, label: str, purpose: str) -> dict[str, str]:
    authenticator = _object(value, label)
    _exact(authenticator, _AUTHENTICATOR_KEYS, label)
    if authenticator["algorithm"] != "Ed25519":
        raise AdmissionDecisionEnvelopeError(f"{label}.algorithm must be Ed25519")
    if authenticator["purpose"] != purpose:
        raise AdmissionDecisionEnvelopeError(f"{label}.purpose must be literal {purpose!r}")
    return {
        "algorithm": "Ed25519",
        "key_id": _matched(authenticator["key_id"], _KEY_ID, f"{label}.key_id"),
        "purpose": purpose,
    }


def _change_subject(value: object) -> dict[str, Any]:
    subject = _object(value, "admission predicate subject")
    _exact(subject, _CHANGE_SUBJECT_KEYS, "admission predicate subject")
    if subject["kind"] != "git-change":
        raise AdmissionDecisionEnvelopeError("predicate subject.kind must be git-change")
    base_sha = _matched(subject["base_sha"], _GIT_SHA, "subject.base_sha")
    head_sha = _matched(subject["head_sha"], _GIT_SHA, "subject.head_sha")
    if base_sha == head_sha:
        raise AdmissionDecisionEnvelopeError("subject base and head revisions must differ")
    return {
        "kind": "git-change",
        "repository": _matched(subject["repository"], _REPOSITORY, "subject.repository"),
        "repository_id": _matched(subject["repository_id"], _NUMERIC_ID, "subject.repository_id"),
        "pull_request_number": _integer(
            subject["pull_request_number"],
            label="subject.pull_request_number",
            minimum=1,
            maximum=MAX_RUN_ATTEMPT,
        ),
        "base_sha": base_sha,
        "base_tree_sha": _matched(subject["base_tree_sha"], _GIT_SHA, "subject.base_tree_sha"),
        "head_sha": head_sha,
        "head_tree_sha": _matched(subject["head_tree_sha"], _GIT_SHA, "subject.head_tree_sha"),
        "candidate_sha256": _matched(
            subject["candidate_sha256"], _SHA256, "subject.candidate_sha256"
        ),
        "candidate_size": _integer(
            subject["candidate_size"],
            label="subject.candidate_size",
            minimum=1,
            maximum=MAX_CANDIDATE_BYTES,
        ),
    }


def _controls(value: object) -> dict[str, Any]:
    controls = _object(value, "admission predicate controls")
    _exact(controls, _CONTROL_KEYS, "admission predicate controls")
    verifier_pack = controls["verifier_pack_sha256"]
    if verifier_pack is not None:
        verifier_pack = _matched(verifier_pack, _SHA256, "controls.verifier_pack_sha256")
    return {
        "policy_sha256": _matched(controls["policy_sha256"], _SHA256, "controls.policy_sha256"),
        "verifier_pack_sha256": verifier_pack,
    }


def _proof(value: object) -> dict[str, Any]:
    proof = _object(value, "admission predicate proof")
    _exact(proof, _PROOF_KEYS, "admission predicate proof")
    if proof["format"] != ADMISSION_DECISION_PROOF_FORMAT:
        raise AdmissionDecisionEnvelopeError("unsupported admission proof format")
    authentication = _object(proof["authentication"], "proof.authentication")
    _exact(
        authentication,
        _PROOF_AUTHENTICATION_KEYS,
        "proof.authentication",
    )
    finalizer = _authenticator(
        authentication["finalizer"],
        label="proof.authentication.finalizer",
        purpose="evoguard-evidence-envelope",
    )
    change_authorization = _authenticator(
        authentication["change_authorization"],
        label="proof.authentication.change_authorization",
        purpose="evoguard-agent-change-authorization-v1",
    )
    if finalizer["key_id"] == change_authorization["key_id"]:
        raise AdmissionDecisionEnvelopeError(
            "proof finalizer and change-authorization key roles must be separate"
        )
    return {
        "format": ADMISSION_DECISION_PROOF_FORMAT,
        "sha256": _matched(proof["sha256"], _SHA256, "proof.sha256"),
        "size": _integer(
            proof["size"],
            label="proof.size",
            minimum=1,
            maximum=MAX_PROOF_BYTES,
        ),
        "authentication": {
            "finalizer": finalizer,
            "change_authorization": change_authorization,
        },
    }


def _authority(value: object) -> dict[str, Any]:
    authority = _object(value, "admission predicate authority")
    _exact(authority, _AUTHORITY_KEYS, "admission predicate authority")
    if authority["mode"] != ADMISSION_DECISION_PROOF_MODE:
        raise AdmissionDecisionEnvelopeError("authority.mode is not proof-bound")
    if authority["admission_scope"] != ADMISSION_DECISION_SCOPE:
        raise AdmissionDecisionEnvelopeError("authority.admission_scope is unsupported")
    for field in ("merge", "publication", "deployment", "external_action"):
        if authority[field] is not False:
            raise AdmissionDecisionEnvelopeError(f"authority.{field} must be literal false")
    return {
        "mode": ADMISSION_DECISION_PROOF_MODE,
        "admission_scope": ADMISSION_DECISION_SCOPE,
        "merge": False,
        "publication": False,
        "deployment": False,
        "external_action": False,
    }


def validate_admission_decision_envelope(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and detach one closed-world Agent Change decision envelope."""

    envelope = _object(value, "admission decision envelope")
    _exact(envelope, _ENVELOPE_KEYS, "admission decision envelope")
    if envelope["_type"] != IN_TOTO_STATEMENT_TYPE:
        raise AdmissionDecisionEnvelopeError("unsupported in-toto statement type")
    if envelope["predicateType"] != ADMISSION_DECISION_PREDICATE_TYPE:
        raise AdmissionDecisionEnvelopeError("unsupported admission predicate type")

    predicate = _object(envelope["predicate"], "admission predicate")
    _exact(predicate, _PREDICATE_KEYS, "admission predicate")
    if predicate["format"] != ADMISSION_DECISION_FORMAT:
        raise AdmissionDecisionEnvelopeError("unsupported admission decision format")
    if predicate["profile"] != ADMISSION_DECISION_PROFILE_AGENT_CHANGE:
        raise AdmissionDecisionEnvelopeError("unsupported admission decision profile")
    if predicate["decision"] != "ALLOW":
        raise AdmissionDecisionEnvelopeError("Agent Change admission decision must be ALLOW")

    change_subject = _change_subject(predicate["subject"])
    statement_subjects = envelope["subject"]
    if not isinstance(statement_subjects, list) or len(statement_subjects) != 1:
        raise AdmissionDecisionEnvelopeError("in-toto statement must contain exactly one subject")
    statement_subject = _object(statement_subjects[0], "in-toto statement subject")
    _exact(statement_subject, _STATEMENT_SUBJECT_KEYS, "in-toto statement subject")
    digest = _object(statement_subject["digest"], "in-toto statement subject digest")
    _exact(digest, _DIGEST_KEYS, "in-toto statement subject digest")
    expected_name = (
        f"git+https://github.com/{change_subject['repository']}@{change_subject['head_sha']}"
    )
    if statement_subject["name"] != expected_name:
        raise AdmissionDecisionEnvelopeError(
            "in-toto subject name does not match the admitted repository/head"
        )
    if digest["gitCommit"] != change_subject["head_sha"]:
        raise AdmissionDecisionEnvelopeError(
            "in-toto subject digest does not match the admitted Git commit"
        )

    return {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [
            {
                "name": expected_name,
                "digest": {"gitCommit": change_subject["head_sha"]},
            }
        ],
        "predicateType": ADMISSION_DECISION_PREDICATE_TYPE,
        "predicate": {
            "format": ADMISSION_DECISION_FORMAT,
            "profile": ADMISSION_DECISION_PROFILE_AGENT_CHANGE,
            "decision": "ALLOW",
            "subject": change_subject,
            "controls": _controls(predicate["controls"]),
            "proof": _proof(predicate["proof"]),
            "authority": _authority(predicate["authority"]),
        },
    }


def canonical_admission_decision_envelope_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the unique canonical bytes for a valid envelope."""

    try:
        data = canonical_json_bytes(validate_admission_decision_envelope(value))
    except EvidenceBundleError as exc:
        raise AdmissionDecisionEnvelopeError(str(exc)) from exc
    if len(data) > MAX_ADMISSION_DECISION_BYTES:
        raise AdmissionDecisionEnvelopeError("admission decision envelope exceeds its size limit")
    return data


def inspect_admission_decision_envelope_bytes(
    data: bytes,
) -> InspectedAdmissionDecisionEnvelope:
    """Strictly parse canonical bytes without treating them as authoritative."""

    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_ADMISSION_DECISION_BYTES:
        raise AdmissionDecisionEnvelopeError(
            "admission decision envelope bytes are outside the supported range"
        )
    try:
        payload = load_json_object_bytes(data, "admission decision envelope")
        checked = validate_admission_decision_envelope(payload)
        if canonical_json_bytes(checked) != data:
            raise AdmissionDecisionEnvelopeError(
                "admission decision envelope is not canonical JSON"
            )
    except EvidenceBundleError as exc:
        raise AdmissionDecisionEnvelopeError(str(exc)) from exc
    return InspectedAdmissionDecisionEnvelope(envelope_bytes=data)


def build_agent_change_admission_decision_envelope(
    *,
    subject: Mapping[str, Any],
    controls: Mapping[str, Any],
    proof: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the only V1 profile without accepting caller-selected authority flags."""

    change_subject = _change_subject(subject)
    value = {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [
            {
                "name": (
                    f"git+https://github.com/{change_subject['repository']}"
                    f"@{change_subject['head_sha']}"
                ),
                "digest": {"gitCommit": change_subject["head_sha"]},
            }
        ],
        "predicateType": ADMISSION_DECISION_PREDICATE_TYPE,
        "predicate": {
            "format": ADMISSION_DECISION_FORMAT,
            "profile": ADMISSION_DECISION_PROFILE_AGENT_CHANGE,
            "decision": "ALLOW",
            "subject": change_subject,
            "controls": dict(controls),
            "proof": dict(proof),
            "authority": {
                "mode": ADMISSION_DECISION_PROOF_MODE,
                "admission_scope": ADMISSION_DECISION_SCOPE,
                "merge": False,
                "publication": False,
                "deployment": False,
                "external_action": False,
            },
        },
    }
    return validate_admission_decision_envelope(value)
