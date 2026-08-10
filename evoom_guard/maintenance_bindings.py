# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Closed-world bindings for a maintenance release source.

These V2 values are deliberately side-by-side with the published release-source
V1 contracts.  They separate the trusted workflow object, the frozen
maintenance base, and the candidate source object.  No function in this module
selects a branch, opens Git, invokes a provider, or grants publication authority.
It only validates already-derived identities and produces canonical bytes.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

from evoom_guard.evidence_bundle import EvidenceBundleError, canonical_json_bytes

RELEASE_SOURCE_FORMAT_V2 = "EVOGUARD_RELEASE_SOURCE_V2"
RELEASE_SOURCE_CONTEXT_FORMAT_V2 = "EVOGUARD_RELEASE_SOURCE_CONTEXT_V2"
RELEASE_SOURCE_BINDINGS_FORMAT_V2 = "EVOGUARD_RELEASE_SOURCE_GIT_BINDINGS_V2"
RELEASE_SOURCE_HANDOFF_FORMAT_V2 = "EVOGUARD_RELEASE_SOURCE_FINALIZER_HANDOFF_V2"

MAX_RUN_ATTEMPT = 2_147_483_647
MAX_VERDICT_BYTES = 8 * 1024 * 1024
MAX_HANDOFF_BYTES = 512 * 1024
MAX_WORKFLOW_PATH_LENGTH = 256
MAX_MATERIAL_PATH_LENGTH = 512

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_NUMERIC_ID = re.compile(r"[1-9][0-9]{0,255}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}\Z")
_WORKFLOW_PATH = re.compile(r"\.github/workflows/[A-Za-z0-9][A-Za-z0-9_.-]*\.ya?ml\Z")
_BRANCH_REF = re.compile(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,254}\Z")

_SOURCE_KEYS = {
    "format",
    "repository",
    "repository_id",
    "default_branch",
    "trusted_workflow_ref",
    "trusted_workflow_sha",
    "trusted_workflow_tree",
    "trusted_workflow_path",
    "trusted_workflow_blob_sha",
    "maintenance_base_ref",
    "maintenance_base_sha",
    "maintenance_base_tree",
    "target_source_ref",
    "target_source_sha",
    "target_source_tree",
}
_RUN_KEYS = {"run_id", "run_attempt"}
_FILE_MATERIAL_KEYS = {"path", "blob_sha", "sha256"}
_PACK_MATERIAL_KEYS = {"root_path", "tree_sha", "sha256"}
_TRUSTED_INPUT_KEYS = {
    "source_sha",
    "source_tree",
    "policy",
    "verifier_pack",
    "control_tools",
}
_CONTEXT_KEYS = {
    "format",
    "source",
    "evaluation",
    "trusted_inputs",
    "candidate_sha256",
}
_BINDINGS_KEYS = {"format", "source", "trusted_inputs", "candidate_sha256"}
_DESCRIPTOR_KEYS = {"sha256", "size"}
_HANDOFF_KEYS = {"format", "source", "context", "upstream", "record"}


class MaintenanceBindingError(ValueError):
    """A maintenance-source identity is incomplete, ambiguous, or inconsistent."""


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise MaintenanceBindingError(
            f"{label} keys are not exact (missing={missing}, extra={extra})"
        )


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MaintenanceBindingError(f"{label} must be an object")
    return dict(value)


def _string(value: object, *, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise MaintenanceBindingError(f"{label} is not canonical")
    return value


def _git_sha(value: object, label: str) -> str:
    return _string(value, label=label, pattern=_GIT_SHA)


def _sha256(value: object, label: str) -> str:
    return _string(value, label=label, pattern=_SHA256)


def _numeric_id(value: object, label: str) -> str:
    return _string(value, label=label, pattern=_NUMERIC_ID)


def _run_attempt(value: object, label: str) -> int:
    if type(value) is not int:
        raise MaintenanceBindingError(f"{label} must be an integer")
    if value < 1 or value > MAX_RUN_ATTEMPT:
        raise MaintenanceBindingError(f"{label} is outside the supported range")
    return value


def _relative_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_MATERIAL_PATH_LENGTH:
        raise MaintenanceBindingError(f"{label} is not a bounded relative path")
    if value.startswith("/") or "\\" in value or "\x00" in value:
        raise MaintenanceBindingError(f"{label} is not a canonical POSIX path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise MaintenanceBindingError(f"{label} contains an unsafe path component")
    if any(part.casefold() == ".git" for part in parts):
        raise MaintenanceBindingError(f"{label} traverses reserved .git state")
    return value


def _branch_ref(value: object, label: str) -> str:
    ref = _string(value, label=label, pattern=_BRANCH_REF)
    suffix = ref.removeprefix("refs/heads/")
    if "//" in suffix or ".." in suffix or suffix.endswith((".", "/")) or "@{" in suffix:
        raise MaintenanceBindingError(f"{label} is not a canonical branch ref")
    components = suffix.split("/")
    if any(component.startswith(".") or component.endswith(".lock") for component in components):
        raise MaintenanceBindingError(f"{label} violates Git reference component rules")
    return ref


def _workflow_path(value: object, label: str) -> str:
    path = _string(value, label=label, pattern=_WORKFLOW_PATH)
    if len(path) > MAX_WORKFLOW_PATH_LENGTH:
        raise MaintenanceBindingError(f"{label} exceeds the supported path length")
    return path


def validate_run(value: Mapping[str, Any], *, label: str = "run") -> dict[str, Any]:
    run = _object(value, label)
    _exact_keys(run, _RUN_KEYS, label)
    return {
        "run_id": _numeric_id(run["run_id"], f"{label}.run_id"),
        "run_attempt": _run_attempt(run["run_attempt"], f"{label}.run_attempt"),
    }


def validate_release_source_v2(value: Mapping[str, Any]) -> dict[str, Any]:
    source = _object(value, "release source V2")
    _exact_keys(source, _SOURCE_KEYS, "release source V2")
    if source["format"] != RELEASE_SOURCE_FORMAT_V2:
        raise MaintenanceBindingError("unsupported release source V2 format")
    repository = _string(source["repository"], label="source.repository", pattern=_REPOSITORY)
    repository_id = _numeric_id(source["repository_id"], "source.repository_id")
    if source["default_branch"] != "main":
        raise MaintenanceBindingError("source.default_branch must be literal main")
    trusted_ref = _branch_ref(source["trusted_workflow_ref"], "source.trusted_workflow_ref")
    if trusted_ref != "refs/heads/main":
        raise MaintenanceBindingError("source.trusted_workflow_ref must be literal refs/heads/main")
    maintenance_ref = _branch_ref(source["maintenance_base_ref"], "source.maintenance_base_ref")
    target_ref = _branch_ref(source["target_source_ref"], "source.target_source_ref")
    if maintenance_ref == trusted_ref or target_ref in {trusted_ref, maintenance_ref}:
        raise MaintenanceBindingError(
            "trusted workflow, maintenance base, and target source refs must be distinct"
        )
    workflow_path = _workflow_path(
        source["trusted_workflow_path"], "source.trusted_workflow_path"
    )
    return {
        "format": RELEASE_SOURCE_FORMAT_V2,
        "repository": repository,
        "repository_id": repository_id,
        "default_branch": "main",
        "trusted_workflow_ref": trusted_ref,
        "trusted_workflow_sha": _git_sha(
            source["trusted_workflow_sha"], "source.trusted_workflow_sha"
        ),
        "trusted_workflow_tree": _git_sha(
            source["trusted_workflow_tree"], "source.trusted_workflow_tree"
        ),
        "trusted_workflow_path": workflow_path,
        "trusted_workflow_blob_sha": _git_sha(
            source["trusted_workflow_blob_sha"], "source.trusted_workflow_blob_sha"
        ),
        "maintenance_base_ref": maintenance_ref,
        "maintenance_base_sha": _git_sha(
            source["maintenance_base_sha"], "source.maintenance_base_sha"
        ),
        "maintenance_base_tree": _git_sha(
            source["maintenance_base_tree"], "source.maintenance_base_tree"
        ),
        "target_source_ref": target_ref,
        "target_source_sha": _git_sha(source["target_source_sha"], "source.target_source_sha"),
        "target_source_tree": _git_sha(source["target_source_tree"], "source.target_source_tree"),
    }


def _validate_file_material(value: object, *, label: str) -> dict[str, str]:
    material = _object(value, label)
    _exact_keys(material, _FILE_MATERIAL_KEYS, label)
    return {
        "path": _relative_path(material["path"], f"{label}.path"),
        "blob_sha": _git_sha(material["blob_sha"], f"{label}.blob_sha"),
        "sha256": _sha256(material["sha256"], f"{label}.sha256"),
    }


def _validate_pack_material(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    material = _object(value, "trusted_inputs.verifier_pack")
    _exact_keys(material, _PACK_MATERIAL_KEYS, "trusted_inputs.verifier_pack")
    return {
        "root_path": _relative_path(
            material["root_path"], "trusted_inputs.verifier_pack.root_path"
        ),
        "tree_sha": _git_sha(material["tree_sha"], "trusted_inputs.verifier_pack.tree_sha"),
        "sha256": _sha256(material["sha256"], "trusted_inputs.verifier_pack.sha256"),
    }


def validate_trusted_inputs_v2(
    value: Mapping[str, Any], *, source: Mapping[str, Any]
) -> dict[str, Any]:
    inputs = _object(value, "trusted inputs V2")
    _exact_keys(inputs, _TRUSTED_INPUT_KEYS, "trusted inputs V2")
    source_sha = _git_sha(inputs["source_sha"], "trusted_inputs.source_sha")
    source_tree = _git_sha(inputs["source_tree"], "trusted_inputs.source_tree")
    if (
        source_sha != source["trusted_workflow_sha"]
        or source_tree != source["trusted_workflow_tree"]
    ):
        raise MaintenanceBindingError(
            "policy, pack, and control tools must be sourced from the trusted workflow commit/tree"
        )
    policy = _validate_file_material(inputs["policy"], label="trusted_inputs.policy")
    pack = _validate_pack_material(inputs["verifier_pack"])
    controls_value = inputs["control_tools"]
    if not isinstance(controls_value, list) or not controls_value or len(controls_value) > 64:
        raise MaintenanceBindingError("trusted_inputs.control_tools must contain 1..64 entries")
    controls = [
        _validate_file_material(item, label=f"trusted_inputs.control_tools[{index}]")
        for index, item in enumerate(controls_value)
    ]
    paths = [item["path"] for item in controls]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise MaintenanceBindingError(
            "trusted_inputs.control_tools must be uniquely sorted by canonical path"
        )
    file_paths = [policy["path"], *paths]
    for index, left in enumerate(file_paths):
        for right in file_paths[index + 1 :]:
            if left == right or left.startswith(f"{right}/") or right.startswith(f"{left}/"):
                raise MaintenanceBindingError(
                    "trusted file materials collide or overlap by canonical path"
                )
    if pack is not None:
        root = pack["root_path"]
        if any(
            path == root or path.startswith(f"{root}/") or root.startswith(f"{path}/")
            for path in file_paths
        ):
            raise MaintenanceBindingError(
                "verifier-pack root collides or overlaps with a trusted file material"
            )
    trusted_inputs = {
        "source_sha": source_sha,
        "source_tree": source_tree,
        "policy": policy,
        "verifier_pack": pack,
        "control_tools": controls,
    }
    workflow_path = _workflow_path(
        source.get("trusted_workflow_path"), "source.trusted_workflow_path"
    )
    workflow_blob_sha = _git_sha(
        source.get("trusted_workflow_blob_sha"), "source.trusted_workflow_blob_sha"
    )
    require_trusted_workflow_material_v2(
        workflow_path=workflow_path,
        workflow_blob_sha=workflow_blob_sha,
        trusted_inputs=trusted_inputs,
        label="trusted finalizer",
    )
    return trusted_inputs


def require_trusted_workflow_material_v2(
    *,
    workflow_path: object,
    workflow_blob_sha: object,
    trusted_inputs: Mapping[str, Any],
    label: str,
) -> None:
    """Require one actor workflow path/blob in the trusted-main material set."""

    path = _relative_path(workflow_path, f"{label}.workflow_path")
    blob_sha = _git_sha(workflow_blob_sha, f"{label}.workflow_blob_sha")
    controls = trusted_inputs.get("control_tools")
    if not isinstance(controls, list):
        raise MaintenanceBindingError(f"{label} cannot be bound without trusted control tools")
    matches = [item for item in controls if isinstance(item, dict) and item.get("path") == path]
    if len(matches) != 1 or matches[0].get("blob_sha") != blob_sha:
        raise MaintenanceBindingError(
            f"{label} workflow path/blob is not an exact trusted-main material"
        )


def validate_release_source_context_v2(value: Mapping[str, Any]) -> dict[str, Any]:
    context = _object(value, "release source context V2")
    _exact_keys(context, _CONTEXT_KEYS, "release source context V2")
    if context["format"] != RELEASE_SOURCE_CONTEXT_FORMAT_V2:
        raise MaintenanceBindingError("unsupported release source context V2 format")
    source = validate_release_source_v2(_object(context["source"], "context.source"))
    evaluation = validate_run(
        _object(context["evaluation"], "context.evaluation"), label="context.evaluation"
    )
    inputs = validate_trusted_inputs_v2(
        _object(context["trusted_inputs"], "context.trusted_inputs"), source=source
    )
    return {
        "format": RELEASE_SOURCE_CONTEXT_FORMAT_V2,
        "source": source,
        "evaluation": evaluation,
        "trusted_inputs": inputs,
        "candidate_sha256": _sha256(context["candidate_sha256"], "context.candidate_sha256"),
    }


def validate_release_source_bindings_v2(value: Mapping[str, Any]) -> dict[str, Any]:
    bindings = _object(value, "release source Git bindings V2")
    _exact_keys(bindings, _BINDINGS_KEYS, "release source Git bindings V2")
    if bindings["format"] != RELEASE_SOURCE_BINDINGS_FORMAT_V2:
        raise MaintenanceBindingError("unsupported release source Git bindings V2 format")
    source = validate_release_source_v2(_object(bindings["source"], "bindings.source"))
    inputs = validate_trusted_inputs_v2(
        _object(bindings["trusted_inputs"], "bindings.trusted_inputs"), source=source
    )
    return {
        "format": RELEASE_SOURCE_BINDINGS_FORMAT_V2,
        "source": source,
        "trusted_inputs": inputs,
        "candidate_sha256": _sha256(bindings["candidate_sha256"], "bindings.candidate_sha256"),
    }


def context_from_release_source_bindings_v2(
    bindings: Mapping[str, Any], *, upstream: Mapping[str, Any]
) -> dict[str, Any]:
    checked = validate_release_source_bindings_v2(bindings)
    return validate_release_source_context_v2(
        {
            "format": RELEASE_SOURCE_CONTEXT_FORMAT_V2,
            "source": checked["source"],
            "evaluation": validate_run(upstream, label="upstream"),
            "trusted_inputs": checked["trusted_inputs"],
            "candidate_sha256": checked["candidate_sha256"],
        }
    )


def _descriptor(value: object, *, label: str, maximum_size: int) -> dict[str, Any]:
    descriptor = _object(value, label)
    _exact_keys(descriptor, _DESCRIPTOR_KEYS, label)
    size = descriptor["size"]
    if type(size) is not int or size < 1 or size > maximum_size:
        raise MaintenanceBindingError(f"{label}.size is outside the supported range")
    return {
        "sha256": _sha256(descriptor["sha256"], f"{label}.sha256"),
        "size": size,
    }


def validate_release_source_handoff_v2(value: Mapping[str, Any]) -> dict[str, Any]:
    handoff = _object(value, "release source handoff V2")
    _exact_keys(handoff, _HANDOFF_KEYS, "release source handoff V2")
    if handoff["format"] != RELEASE_SOURCE_HANDOFF_FORMAT_V2:
        raise MaintenanceBindingError("unsupported release source handoff V2 format")
    source = validate_release_source_v2(_object(handoff["source"], "handoff.source"))
    context = validate_release_source_context_v2(_object(handoff["context"], "handoff.context"))
    upstream = validate_run(
        _object(handoff["upstream"], "handoff.upstream"), label="handoff.upstream"
    )
    if context["source"] != source:
        raise MaintenanceBindingError("handoff source does not exactly match its context source")
    if context["evaluation"] != upstream:
        raise MaintenanceBindingError("handoff upstream run does not exactly match evaluation")
    return {
        "format": RELEASE_SOURCE_HANDOFF_FORMAT_V2,
        "source": source,
        "context": context,
        "upstream": upstream,
        "record": _descriptor(
            handoff["record"], label="handoff.record", maximum_size=MAX_VERDICT_BYTES
        ),
    }


def canonical_validated_bytes(
    value: Mapping[str, Any],
    *,
    validator: Callable[[Mapping[str, Any]], dict[str, Any]],
) -> bytes:
    """Validate one closed-world object, then encode its unique JSON bytes."""

    try:
        return canonical_json_bytes(validator(value))
    except EvidenceBundleError as exc:
        raise MaintenanceBindingError(str(exc)) from exc


def require_canonical_bytes(
    data: bytes,
    *,
    validator: Callable[[Mapping[str, Any]], dict[str, Any]],
    label: str,
) -> dict[str, Any]:
    """Parse one JSON object and reject alternate encodings of a valid value."""

    from evoom_guard.evidence_bundle import load_json_object_bytes

    try:
        parsed = load_json_object_bytes(data, label)
        checked = validator(parsed)
        if canonical_json_bytes(checked) != data:
            raise MaintenanceBindingError(f"{label} is not canonical JSON")
    except EvidenceBundleError as exc:
        raise MaintenanceBindingError(str(exc)) from exc
    return checked
