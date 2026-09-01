#!/usr/bin/env python3
"""Strict, canonical agent-origin metadata for agent-behaviour studies.

The record binds declared run provenance to exact prompt and candidate digests.
It is evaluation metadata, not an admission decision.  ``declared_unverified``
records are intentionally unauthenticated.  ``attested`` records are accepted
only when a caller supplies a trusted Ed25519 public key and a valid detached
signature over the domain-separated canonical claims bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

from evoom_guard.signing import verify_bytes_with_key_id
from evoom_guard.strict_json import strict_json_loads

AGENT_ORIGIN_SCHEMA = "evoguard-agent-origin-v1"
AGENT_ORIGIN_ATTESTATION_FORMAT = "EVOGUARD_AGENT_ORIGIN_ATTESTATION_V1"
AGENT_ORIGIN_ATTESTATION_DOMAIN = b"EVOGUARD_AGENT_ORIGIN_ATTESTATION_V1"
MAX_AGENT_ORIGIN_BYTES = 256 * 1024

_HEX_SHA256 = frozenset("0123456789abcdef")
_UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_ASSURANCE_STATUSES = frozenset({"declared_unverified", "attested"})
_RANDOMIZATION_MODES = frozenset(
    {"deterministic", "stochastic", "provider_unspecified"}
)
_PERMISSION_ACCESS = frozenset({"none", "read", "write", "execute", "invoke"})

_ROOT_KEYS = frozenset({"schema_version", "claims", "assurance"})
_CLAIMS_KEYS = frozenset({"agent", "task", "run", "prompt", "execution", "change"})
_AGENT_KEYS = frozenset(
    {"provider", "model", "model_version", "agent", "agent_version"}
)
_TASK_KEYS = frozenset({"repository_sha256", "task_sha256"})
_RUN_KEYS = frozenset(
    {
        "run_id",
        "started_utc",
        "completed_utc",
        "attempt",
        "max_attempts",
        "retry_of_run_id",
    }
)
_PROMPT_KEYS = frozenset({"sha256", "size_bytes", "content_disclosure"})
_EXECUTION_KEYS = frozenset({"tools", "permissions", "randomization"})
_TOOL_KEYS = frozenset({"name", "version", "descriptor_sha256"})
_PERMISSION_KEYS = frozenset({"capability", "access", "scope_sha256"})
_RANDOMIZATION_KEYS = frozenset({"mode", "seed", "settings_sha256"})
_CHANGE_KEYS = frozenset({"candidate_format", "candidate_sha256"})
_ASSURANCE_KEYS = frozenset({"status", "attestation"})
_ATTESTATION_KEYS = frozenset(
    {"format", "statement_sha256", "signature_algorithm", "key_id", "attester"}
)


class AgentOriginError(ValueError):
    """The agent-origin record is malformed, unbound, or unauthenticated."""


_VERIFIED_ORIGIN_TOKEN = object()


@dataclass(frozen=True, init=False)
class VerifiedAgentOrigin:
    """A canonical record that passed all requested external bindings."""

    payload: Mapping[str, Any]
    canonical_bytes: bytes
    status: str
    candidate_sha256: str
    candidate_format: str
    prompt_sha256: str
    prompt_size_bytes: int
    repository_sha256: str
    task_sha256: str
    attestation_key_id: str | None
    _validation_token: object = field(repr=False, compare=False)

    def __init__(self) -> None:
        raise TypeError(
            "VerifiedAgentOrigin instances must come from "
            "validate_agent_origin_bytes"
        )


@dataclass(frozen=True)
class AgentOriginRetryInput:
    """Exact bytes plus external bindings needed to revalidate one attempt."""

    record_bytes: bytes
    expected_candidate_sha256: str
    expected_candidate_format: str
    expected_prompt_sha256: str
    expected_prompt_size_bytes: int
    trusted_attestation_public_key_path: str | None = None
    attestation_signature: bytes | None = None


def _verified_origin(**values: Any) -> VerifiedAgentOrigin:
    """Construct the result type only after the byte validator succeeds."""

    instance = object.__new__(VerifiedAgentOrigin)
    fields = {
        **values,
        "_validation_token": _VERIFIED_ORIGIN_TOKEN,
    }
    for name in VerifiedAgentOrigin.__dataclass_fields__:
        object.__setattr__(instance, name, fields[name])
    return instance


def _deep_freeze(value: Any) -> Any:
    """Return an immutable copy so verified claims cannot drift after validation."""

    if isinstance(value, dict):
        return MappingProxyType({key: _deep_freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_deep_freeze(item) for item in value)
    return value


def canonical_json_bytes(value: object) -> bytes:
    """Encode one JSON value using the contract's canonical representation."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise AgentOriginError(f"agent-origin value is not canonical JSON: {exc}") from exc


def agent_origin_attestation_bytes(claims: dict[str, Any], *, attester: str) -> bytes:
    """Return exact domain-separated bytes authenticating claims and attester."""

    statement_bytes = canonical_json_bytes(
        {
            "attester": _bounded_text(attester, label="assurance.attestation.attester", limit=512),
            "claims": claims,
            "format": AGENT_ORIGIN_ATTESTATION_FORMAT,
        }
    )
    return (
        len(AGENT_ORIGIN_ATTESTATION_DOMAIN).to_bytes(8, "big")
        + AGENT_ORIGIN_ATTESTATION_DOMAIN
        + len(statement_bytes).to_bytes(8, "big")
        + statement_bytes
    )


def _expect_exact_keys(
    value: object, expected: frozenset[str], *, label: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgentOriginError(f"{label} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise AgentOriginError(f"{label} keys must be strings")
    observed = set(value)
    if observed != expected:
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        raise AgentOriginError(f"{label} keys differ (missing={missing}, extra={extra})")
    return value


def _bounded_text(value: object, *, label: str, limit: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise AgentOriginError(f"{label} must be a non-empty string of at most {limit} characters")
    if value != value.strip():
        raise AgentOriginError(f"{label} must not contain leading or trailing whitespace")
    if unicodedata.normalize("NFC", value) != value:
        raise AgentOriginError(f"{label} must use NFC-normalized Unicode")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise AgentOriginError(f"{label} contains a control character or invalid Unicode")
    return value


def _enum_text(
    value: object, *, label: str, allowed: frozenset[str]
) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise AgentOriginError(f"{label} is unsupported")
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or not set(value) <= _HEX_SHA256:
        raise AgentOriginError(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _positive_int(value: object, *, label: str, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise AgentOriginError(f"{label} must be an integer in [1, {maximum}]")
    return value


def _nonnegative_int(value: object, *, label: str, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise AgentOriginError(f"{label} must be an integer in [0, {maximum}]")
    return value


def _timestamp(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        raise AgentOriginError(f"{label} must use second-precision UTC form YYYY-MM-DDTHH:MM:SSZ")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise AgentOriginError(f"{label} is not a valid UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise AgentOriginError(f"{label} is not a canonical UTC timestamp")
    return parsed


def _validate_agent(value: object) -> None:
    agent = _expect_exact_keys(value, _AGENT_KEYS, label="claims.agent")
    for key in sorted(_AGENT_KEYS):
        _bounded_text(agent[key], label=f"claims.agent.{key}")


def _validate_task(value: object) -> None:
    task = _expect_exact_keys(value, _TASK_KEYS, label="claims.task")
    _sha256(task["repository_sha256"], label="claims.task.repository_sha256")
    _sha256(task["task_sha256"], label="claims.task.task_sha256")


def _validate_run(value: object) -> None:
    run = _expect_exact_keys(value, _RUN_KEYS, label="claims.run")
    run_id = _bounded_text(run["run_id"], label="claims.run.run_id")
    started = _timestamp(run["started_utc"], label="claims.run.started_utc")
    completed = _timestamp(run["completed_utc"], label="claims.run.completed_utc")
    if completed < started:
        raise AgentOriginError("claims.run.completed_utc precedes started_utc")
    attempt = _positive_int(run["attempt"], label="claims.run.attempt", maximum=1000)
    maximum = _positive_int(
        run["max_attempts"], label="claims.run.max_attempts", maximum=1000
    )
    if attempt > maximum:
        raise AgentOriginError("claims.run.attempt exceeds max_attempts")
    retry_of = run["retry_of_run_id"]
    if attempt == 1:
        if retry_of is not None:
            raise AgentOriginError("first attempt must set retry_of_run_id to null")
    else:
        retry_id = _bounded_text(retry_of, label="claims.run.retry_of_run_id")
        if retry_id == run_id:
            raise AgentOriginError("retry_of_run_id must differ from run_id")


def _validate_prompt(value: object) -> None:
    prompt = _expect_exact_keys(value, _PROMPT_KEYS, label="claims.prompt")
    _sha256(prompt["sha256"], label="claims.prompt.sha256")
    _nonnegative_int(
        prompt["size_bytes"], label="claims.prompt.size_bytes", maximum=64 * 1024 * 1024
    )
    _enum_text(
        prompt["content_disclosure"],
        label="claims.prompt.content_disclosure",
        allowed=frozenset({"public", "retained_external", "not_retained"}),
    )


def _validate_tools(value: object) -> None:
    if not isinstance(value, list) or len(value) > 256:
        raise AgentOriginError("claims.execution.tools must be an array of at most 256 entries")
    ordering: list[tuple[str, str, str]] = []
    for index, item in enumerate(value):
        tool = _expect_exact_keys(item, _TOOL_KEYS, label=f"claims.execution.tools[{index}]")
        name = _bounded_text(tool["name"], label=f"claims.execution.tools[{index}].name")
        version = _bounded_text(
            tool["version"], label=f"claims.execution.tools[{index}].version"
        )
        digest = _sha256(
            tool["descriptor_sha256"],
            label=f"claims.execution.tools[{index}].descriptor_sha256",
        )
        ordering.append((name, version, digest))
    if ordering != sorted(ordering) or len(set(ordering)) != len(ordering):
        raise AgentOriginError("claims.execution.tools must be unique and canonically sorted")


def _validate_permissions(value: object) -> None:
    if not isinstance(value, list) or len(value) > 256:
        raise AgentOriginError(
            "claims.execution.permissions must be an array of at most 256 entries"
        )
    ordering: list[tuple[str, str, str]] = []
    for index, item in enumerate(value):
        permission = _expect_exact_keys(
            item,
            _PERMISSION_KEYS,
            label=f"claims.execution.permissions[{index}]",
        )
        capability = _bounded_text(
            permission["capability"],
            label=f"claims.execution.permissions[{index}].capability",
        )
        access = permission["access"]
        access = _enum_text(
            access,
            label=f"claims.execution.permissions[{index}].access",
            allowed=_PERMISSION_ACCESS,
        )
        scope = _sha256(
            permission["scope_sha256"],
            label=f"claims.execution.permissions[{index}].scope_sha256",
        )
        ordering.append((capability, access, scope))
    if ordering != sorted(ordering) or len(set(ordering)) != len(ordering):
        raise AgentOriginError(
            "claims.execution.permissions must be unique and canonically sorted"
        )


def _validate_randomization(value: object) -> None:
    randomization = _expect_exact_keys(
        value, _RANDOMIZATION_KEYS, label="claims.execution.randomization"
    )
    mode = _enum_text(
        randomization["mode"],
        label="claims.execution.randomization.mode",
        allowed=_RANDOMIZATION_MODES,
    )
    seed = randomization["seed"]
    if seed is not None:
        _nonnegative_int(seed, label="claims.execution.randomization.seed", maximum=2**63 - 1)
    if mode == "deterministic" and seed is None:
        raise AgentOriginError("deterministic randomization requires an explicit seed")
    if mode == "provider_unspecified" and seed is not None:
        raise AgentOriginError("provider_unspecified randomization must set seed to null")
    _sha256(
        randomization["settings_sha256"],
        label="claims.execution.randomization.settings_sha256",
    )


def _validate_execution(value: object) -> None:
    execution = _expect_exact_keys(value, _EXECUTION_KEYS, label="claims.execution")
    _validate_tools(execution["tools"])
    _validate_permissions(execution["permissions"])
    _validate_randomization(execution["randomization"])


def _validate_change(value: object) -> None:
    change = _expect_exact_keys(value, _CHANGE_KEYS, label="claims.change")
    _enum_text(
        change["candidate_format"],
        label="claims.change.candidate_format",
        allowed=frozenset(
            {"EVOGUARD_CANDIDATE_TEXT_MAP_V2", "sha256_opaque_candidate_bytes"}
        ),
    )
    _sha256(change["candidate_sha256"], label="claims.change.candidate_sha256")


def _validate_claims(value: object) -> dict[str, Any]:
    claims = _expect_exact_keys(value, _CLAIMS_KEYS, label="claims")
    _validate_agent(claims["agent"])
    _validate_task(claims["task"])
    _validate_run(claims["run"])
    _validate_prompt(claims["prompt"])
    _validate_execution(claims["execution"])
    _validate_change(claims["change"])
    return claims


def _validate_attestation_shape(value: object) -> dict[str, Any]:
    attestation = _expect_exact_keys(value, _ATTESTATION_KEYS, label="assurance.attestation")
    if attestation["format"] != AGENT_ORIGIN_ATTESTATION_FORMAT:
        raise AgentOriginError("assurance.attestation.format is unsupported")
    _sha256(attestation["statement_sha256"], label="assurance.attestation.statement_sha256")
    if attestation["signature_algorithm"] != "Ed25519":
        raise AgentOriginError("assurance.attestation.signature_algorithm must be Ed25519")
    key_id = attestation["key_id"]
    if (
        not isinstance(key_id, str)
        or len(key_id) != 71
        or not key_id.startswith("sha256:")
        or not set(key_id[7:]) <= _HEX_SHA256
    ):
        raise AgentOriginError("assurance.attestation.key_id is invalid")
    _bounded_text(attestation["attester"], label="assurance.attestation.attester", limit=512)
    return attestation


def validate_agent_origin_bytes(
    data: bytes,
    *,
    expected_candidate_sha256: str,
    expected_candidate_format: str,
    expected_prompt_sha256: str,
    expected_prompt_size_bytes: int,
    expected_repository_sha256: str,
    expected_task_sha256: str,
    trusted_attestation_public_key_path: str | None = None,
    attestation_signature: bytes | None = None,
) -> VerifiedAgentOrigin:
    """Validate exact canonical bytes and required external bindings.

    The expected candidate descriptor, prompt descriptor, repository and task
    digests are mandatory so a syntactically valid record can never float free
    of the frozen inputs under study.
    ``attested`` records additionally require both external trust inputs; the
    status string alone is never accepted as evidence.
    """

    if not isinstance(data, bytes):
        raise TypeError(f"agent-origin data must be bytes, got {type(data).__name__}")
    if not data or len(data) > MAX_AGENT_ORIGIN_BYTES:
        raise AgentOriginError(
            f"agent-origin data is empty or exceeds the {MAX_AGENT_ORIGIN_BYTES}-byte limit"
        )
    expected_candidate = _sha256(
        expected_candidate_sha256, label="expected_candidate_sha256"
    )
    expected_format = _enum_text(
        expected_candidate_format,
        label="expected_candidate_format",
        allowed=frozenset(
            {"EVOGUARD_CANDIDATE_TEXT_MAP_V2", "sha256_opaque_candidate_bytes"}
        ),
    )
    expected_prompt = _sha256(expected_prompt_sha256, label="expected_prompt_sha256")
    expected_prompt_size = _nonnegative_int(
        expected_prompt_size_bytes,
        label="expected_prompt_size_bytes",
        maximum=64 * 1024 * 1024,
    )
    expected_repository = _sha256(
        expected_repository_sha256, label="expected_repository_sha256"
    )
    expected_task = _sha256(expected_task_sha256, label="expected_task_sha256")
    try:
        payload = strict_json_loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise AgentOriginError(f"agent-origin data is not strict UTF-8 JSON: {exc}") from exc
    root = _expect_exact_keys(payload, _ROOT_KEYS, label="agent-origin record")
    if root["schema_version"] != AGENT_ORIGIN_SCHEMA:
        raise AgentOriginError("agent-origin schema_version is unsupported")
    if canonical_json_bytes(root) != data:
        raise AgentOriginError("agent-origin record is not canonical JSON")

    claims = _validate_claims(root["claims"])
    candidate = claims["change"]["candidate_sha256"]
    candidate_format = claims["change"]["candidate_format"]
    prompt = claims["prompt"]["sha256"]
    prompt_size = claims["prompt"]["size_bytes"]
    repository = claims["task"]["repository_sha256"]
    task = claims["task"]["task_sha256"]
    if candidate != expected_candidate:
        raise AgentOriginError("agent-origin candidate digest differs from external expectation")
    if prompt != expected_prompt:
        raise AgentOriginError("agent-origin prompt digest differs from external expectation")
    if candidate_format != expected_format:
        raise AgentOriginError("agent-origin candidate format differs from external expectation")
    if prompt_size != expected_prompt_size:
        raise AgentOriginError("agent-origin prompt size differs from external expectation")
    if repository != expected_repository:
        raise AgentOriginError("agent-origin repository digest differs from external expectation")
    if task != expected_task:
        raise AgentOriginError("agent-origin task digest differs from external expectation")

    assurance = _expect_exact_keys(root["assurance"], _ASSURANCE_KEYS, label="assurance")
    status = assurance["status"]
    status = _enum_text(
        status, label="assurance.status", allowed=_ASSURANCE_STATUSES
    )
    attestation_key_id: str | None = None
    if status == "declared_unverified":
        if assurance["attestation"] is not None:
            raise AgentOriginError("declared_unverified assurance must not contain attestation")
        if trusted_attestation_public_key_path is not None or attestation_signature is not None:
            raise AgentOriginError(
                "declared_unverified record must not be upgraded by unrelated trust inputs"
            )
    else:
        attestation = _validate_attestation_shape(assurance["attestation"])
        if trusted_attestation_public_key_path is None or attestation_signature is None:
            raise AgentOriginError(
                "attested assurance requires a trusted public key and detached signature"
            )
        if not isinstance(attestation_signature, bytes):
            raise TypeError(
                "attestation_signature must be bytes, got "
                f"{type(attestation_signature).__name__}"
            )
        statement = agent_origin_attestation_bytes(
            claims,
            attester=attestation["attester"],
        )
        if hashlib.sha256(statement).hexdigest() != attestation["statement_sha256"]:
            raise AgentOriginError("attestation statement digest does not bind the claims")
        valid, observed_key_id = verify_bytes_with_key_id(
            statement,
            attestation_signature,
            trusted_attestation_public_key_path,
        )
        if observed_key_id != attestation["key_id"]:
            raise AgentOriginError("attestation key ID differs from the external trust root")
        if not valid:
            raise AgentOriginError("agent-origin attestation signature is invalid")
        attestation_key_id = observed_key_id

    return _verified_origin(
        payload=_deep_freeze(root),
        canonical_bytes=data,
        status=status,
        candidate_sha256=candidate,
        candidate_format=candidate_format,
        prompt_sha256=prompt,
        prompt_size_bytes=prompt_size,
        repository_sha256=repository,
        task_sha256=task,
        attestation_key_id=attestation_key_id,
    )


def validate_agent_origin_retry_chain(
    records: Sequence[AgentOriginRetryInput],
    *,
    expected_repository_sha256: str,
    expected_task_sha256: str,
    expected_attempt_count: int,
    expected_run_ids: Sequence[str],
) -> tuple[VerifiedAgentOrigin, ...]:
    """Validate one complete, non-branching retry chain.

    Each raw record is revalidated here with its external candidate/prompt
    descriptor and, for ``attested`` records, its external trust root and
    detached signature.  The externally committed exact attempt count and
    ordered run-ID roster prevent a truncated prefix or alternate branch from
    being presented as the complete chain.  This
    second boundary prevents retries from being counted as unrelated runs: it
    requires one root, consecutive attempts, an exact parent link, monotonic
    time, and stable task/model/prompt/tool/policy settings.  Candidate digests
    may differ because each attempt can produce a different change.  A
    stochastic seed may differ; deterministic seeds must remain identical.
    """

    if isinstance(records, (str, bytes, bytearray)) or not isinstance(
        records, Sequence
    ):
        raise AgentOriginError("retry chain must be a sequence of verified records")
    if not records or len(records) > 1000:
        raise AgentOriginError("retry chain must contain between 1 and 1000 records")

    expected_repository = _sha256(
        expected_repository_sha256, label="expected_repository_sha256"
    )
    expected_task = _sha256(expected_task_sha256, label="expected_task_sha256")
    attempt_count = _positive_int(
        expected_attempt_count,
        label="expected_attempt_count",
        maximum=1000,
    )
    if len(records) != attempt_count:
        raise AgentOriginError(
            "retry chain length differs from the external expected attempt count"
        )
    if isinstance(expected_run_ids, (str, bytes, bytearray)) or not isinstance(
        expected_run_ids, Sequence
    ):
        raise AgentOriginError("expected_run_ids must be an ordered sequence")
    expected_runs = tuple(
        _bounded_text(value, label=f"expected_run_ids[{index}]")
        for index, value in enumerate(expected_run_ids)
    )
    if len(expected_runs) != attempt_count or len(set(expected_runs)) != len(
        expected_runs
    ):
        raise AgentOriginError(
            "expected_run_ids must be an exact unique roster matching attempt count"
        )
    parsed: list[
        tuple[VerifiedAgentOrigin, dict[str, Any], tuple[str, str | None, str | None]]
    ] = []
    for index, retry_input in enumerate(records):
        if not isinstance(retry_input, AgentOriginRetryInput):
            raise AgentOriginError(
                f"retry chain item {index} is not an AgentOriginRetryInput"
            )
        record = validate_agent_origin_bytes(
            retry_input.record_bytes,
            expected_candidate_sha256=retry_input.expected_candidate_sha256,
            expected_candidate_format=retry_input.expected_candidate_format,
            expected_prompt_sha256=retry_input.expected_prompt_sha256,
            expected_prompt_size_bytes=retry_input.expected_prompt_size_bytes,
            expected_repository_sha256=expected_repository,
            expected_task_sha256=expected_task,
            trusted_attestation_public_key_path=(
                retry_input.trusted_attestation_public_key_path
            ),
            attestation_signature=retry_input.attestation_signature,
        )
        try:
            payload = strict_json_loads(record.canonical_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise AgentOriginError(
                f"retry chain item {index} no longer contains strict canonical JSON"
            ) from exc
        root = _expect_exact_keys(
            payload, _ROOT_KEYS, label=f"retry chain item {index}"
        )
        if canonical_json_bytes(root) != record.canonical_bytes:
            raise AgentOriginError(f"retry chain item {index} is not canonical JSON")
        if root["schema_version"] != AGENT_ORIGIN_SCHEMA:
            raise AgentOriginError(
                f"retry chain item {index} uses an unsupported schema"
            )
        claims = _validate_claims(root["claims"])
        assurance = _expect_exact_keys(
            root["assurance"], _ASSURANCE_KEYS, label=f"retry chain item {index} assurance"
        )
        status = _enum_text(
            assurance["status"],
            label=f"retry chain item {index} assurance.status",
            allowed=_ASSURANCE_STATUSES,
        )
        if status != record.status:
            raise AgentOriginError(f"retry chain item {index} status projection differs")
        attestation = assurance["attestation"]
        assurance_identity: tuple[str, str | None, str | None]
        if status == "declared_unverified":
            if attestation is not None or record.attestation_key_id is not None:
                raise AgentOriginError(
                    f"retry chain item {index} has inconsistent unverified assurance"
                )
            assurance_identity = (status, None, None)
        else:
            checked_attestation = _validate_attestation_shape(attestation)
            statement = agent_origin_attestation_bytes(
                claims,
                attester=checked_attestation["attester"],
            )
            if (
                record.attestation_key_id != checked_attestation["key_id"]
                or hashlib.sha256(statement).hexdigest()
                != checked_attestation["statement_sha256"]
            ):
                raise AgentOriginError(
                    f"retry chain item {index} attestation projection differs"
                )
            assurance_identity = (
                status,
                checked_attestation["attester"],
                checked_attestation["key_id"],
            )
        if record.payload != _deep_freeze(root):
            raise AgentOriginError(
                f"retry chain item {index} immutable payload differs from its bytes"
            )
        if (
            claims["change"]["candidate_sha256"] != record.candidate_sha256
            or claims["change"]["candidate_format"] != record.candidate_format
            or claims["prompt"]["sha256"] != record.prompt_sha256
            or claims["prompt"]["size_bytes"] != record.prompt_size_bytes
            or claims["task"]["repository_sha256"] != record.repository_sha256
            or claims["task"]["task_sha256"] != record.task_sha256
        ):
            raise AgentOriginError(
                f"retry chain item {index} verified projections differ from its bytes"
            )
        if record.repository_sha256 != expected_repository:
            raise AgentOriginError(
                f"retry chain item {index} repository differs from external expectation"
            )
        if record.task_sha256 != expected_task:
            raise AgentOriginError(
                f"retry chain item {index} task differs from external expectation"
            )
        parsed.append((record, claims, assurance_identity))

    ordered = sorted(parsed, key=lambda item: item[1]["run"]["attempt"])
    attempts = [item[1]["run"]["attempt"] for item in ordered]
    if attempts != list(range(1, len(ordered) + 1)):
        raise AgentOriginError("retry chain attempts must be unique and consecutive from 1")

    run_ids = [item[1]["run"]["run_id"] for item in ordered]
    if len(set(run_ids)) != len(run_ids):
        raise AgentOriginError("retry chain run_id values must be unique")
    if tuple(run_ids) != expected_runs:
        raise AgentOriginError(
            "retry chain run IDs differ from the external frozen roster"
        )

    root_claims = ordered[0][1]
    root_run = root_claims["run"]
    max_attempts = root_run["max_attempts"]
    if len(ordered) > max_attempts:
        raise AgentOriginError("retry chain contains more records than max_attempts")

    def stable_projection(claims: dict[str, Any]) -> bytes:
        randomization = claims["execution"]["randomization"]
        projection = {
            "agent": claims["agent"],
            "task": claims["task"],
            "prompt": claims["prompt"],
            "tools": claims["execution"]["tools"],
            "permissions": claims["execution"]["permissions"],
            "randomization": {
                "mode": randomization["mode"],
                "settings_sha256": randomization["settings_sha256"],
                "seed": (
                    randomization["seed"]
                    if randomization["mode"] == "deterministic"
                    else None
                ),
            },
            "candidate_format": claims["change"]["candidate_format"],
        }
        return canonical_json_bytes(projection)

    expected_projection = stable_projection(root_claims)
    expected_assurance = ordered[0][2]
    previous_run = root_run
    for position, (_, claims, assurance_identity) in enumerate(ordered):
        run = claims["run"]
        if run["max_attempts"] != max_attempts:
            raise AgentOriginError("retry chain max_attempts must remain stable")
        if stable_projection(claims) != expected_projection:
            raise AgentOriginError(
                "retry chain task, model, prompt, tools, permissions, or settings drifted"
            )
        if assurance_identity != expected_assurance:
            raise AgentOriginError(
                "retry chain assurance status, attester, or key identity drifted"
            )
        if position == 0:
            if run["retry_of_run_id"] is not None:
                raise AgentOriginError("retry chain root must not reference a parent")
        else:
            if run["retry_of_run_id"] != previous_run["run_id"]:
                raise AgentOriginError(
                    "retry chain must reference the immediately preceding run"
                )
            if _timestamp(
                run["started_utc"], label="claims.run.started_utc"
            ) < _timestamp(
                previous_run["completed_utc"], label="claims.run.completed_utc"
            ):
                raise AgentOriginError("retry chain attempts overlap or move backward in time")
        previous_run = run

    return tuple(item[0] for item in ordered)
