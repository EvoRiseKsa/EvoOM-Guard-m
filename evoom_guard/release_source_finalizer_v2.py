# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Maintenance-aware release-source finalizer V2 manifest contract.

V1 remains unchanged and DENY-only.  V2 is also DENY-only: it authenticates a
maintenance-source evidence snapshot, but intentionally does not authorize a
tag, release, package, deployment, or publication.  The distinct format,
purpose, key domain, and byte prefix prevent a V1 signature from being replayed
as V2 (or as either admitting contract).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from evoom_guard.maintenance_bindings import (
    MAX_HANDOFF_BYTES,
    MAX_VERDICT_BYTES,
    MaintenanceBindingError,
    canonical_validated_bytes,
    validate_release_source_context_v2,
    validate_release_source_v2,
    validate_run,
)

RELEASE_SOURCE_EVIDENCE_FORMAT_V2 = "EVOGUARD_RELEASE_SOURCE_EVIDENCE_V2"
RELEASE_SOURCE_FINALIZER_SIGNATURE_PURPOSE_V2 = "evoguard-release-source-finalizer-v2"
RELEASE_SOURCE_FINALIZER_KEY_DOMAIN_V2 = "release-source-finalizer-v2"
RELEASE_SOURCE_FINALIZER_SIGNATURE_DOMAIN_V2 = (
    RELEASE_SOURCE_EVIDENCE_FORMAT_V2.encode("ascii") + b"\0"
)

RELEASE_SOURCE_FINALIZER_MANIFEST_PATH_V2 = "bundle.json"
RELEASE_SOURCE_FINALIZER_SIGNATURE_PATH_V2 = "bundle.sig"
RELEASE_SOURCE_FINALIZER_RECORD_PATH_V2 = "record/verdict.json"
RELEASE_SOURCE_FINALIZER_HANDOFF_PATH_V2 = "materials/release-source-finalizer-handoff-v2.json"

_KEY_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MANIFEST_KEYS = {
    "format",
    "decision",
    "source",
    "context",
    "upstream",
    "record",
    "handoff",
    "authentication",
}
_DESCRIPTOR_KEYS = {"path", "sha256", "size"}
_AUTHENTICATION_KEYS = {
    "algorithm",
    "key_id",
    "purpose",
    "key_domain",
    "signature_path",
}


class ReleaseSourceFinalizerV2Error(MaintenanceBindingError):
    """A V2 finalizer manifest is incomplete, replayable, or inconsistent."""


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseSourceFinalizerV2Error(f"{label} must be an object")
    return dict(value)


def _exact(value: Mapping[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise ReleaseSourceFinalizerV2Error(f"{label} keys are not exact")


def _descriptor(value: object, *, label: str, path: str, maximum_size: int) -> dict[str, Any]:
    descriptor = _object(value, label)
    _exact(descriptor, _DESCRIPTOR_KEYS, label)
    if descriptor["path"] != path:
        raise ReleaseSourceFinalizerV2Error(f"{label}.path is not literal {path}")
    sha256 = descriptor["sha256"]
    if not isinstance(sha256, str) or _SHA256.fullmatch(sha256) is None:
        raise ReleaseSourceFinalizerV2Error(f"{label}.sha256 is not canonical")
    size = descriptor["size"]
    if type(size) is not int or not 1 <= size <= maximum_size:
        raise ReleaseSourceFinalizerV2Error(f"{label}.size is outside the supported range")
    return {"path": path, "sha256": sha256, "size": size}


def _authentication(value: object) -> dict[str, str]:
    authentication = _object(value, "finalizer V2 authentication")
    _exact(authentication, _AUTHENTICATION_KEYS, "finalizer V2 authentication")
    expected = {
        "algorithm": "Ed25519",
        "purpose": RELEASE_SOURCE_FINALIZER_SIGNATURE_PURPOSE_V2,
        "key_domain": RELEASE_SOURCE_FINALIZER_KEY_DOMAIN_V2,
        "signature_path": RELEASE_SOURCE_FINALIZER_SIGNATURE_PATH_V2,
    }
    for key, wanted in expected.items():
        if authentication[key] != wanted:
            raise ReleaseSourceFinalizerV2Error(
                f"finalizer V2 authentication.{key} is not {wanted!r}"
            )
    key_id = authentication["key_id"]
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        raise ReleaseSourceFinalizerV2Error("finalizer V2 authentication.key_id is not canonical")
    return {**expected, "key_id": key_id}


def validate_release_source_finalizer_v2(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    manifest = _object(value, "release-source finalizer V2 manifest")
    _exact(manifest, _MANIFEST_KEYS, "release-source finalizer V2 manifest")
    if manifest["format"] != RELEASE_SOURCE_EVIDENCE_FORMAT_V2:
        raise ReleaseSourceFinalizerV2Error("unsupported release-source finalizer V2 format")
    if manifest["decision"] != "DENY":
        raise ReleaseSourceFinalizerV2Error("release-source finalizer V2 remains deny-only")
    try:
        source = validate_release_source_v2(_object(manifest["source"], "finalizer.source"))
        context = validate_release_source_context_v2(
            _object(manifest["context"], "finalizer.context")
        )
        upstream = validate_run(
            _object(manifest["upstream"], "finalizer.upstream"),
            label="finalizer.upstream",
        )
    except MaintenanceBindingError as exc:
        raise ReleaseSourceFinalizerV2Error(str(exc)) from exc
    if context["source"] != source:
        raise ReleaseSourceFinalizerV2Error(
            "finalizer V2 source does not exactly match its context"
        )
    if context["evaluation"] != upstream:
        raise ReleaseSourceFinalizerV2Error(
            "finalizer V2 upstream run does not exactly match evaluation"
        )
    return {
        "format": RELEASE_SOURCE_EVIDENCE_FORMAT_V2,
        "decision": "DENY",
        "source": source,
        "context": context,
        "upstream": upstream,
        "record": _descriptor(
            manifest["record"],
            label="finalizer.record",
            path=RELEASE_SOURCE_FINALIZER_RECORD_PATH_V2,
            maximum_size=MAX_VERDICT_BYTES,
        ),
        "handoff": _descriptor(
            manifest["handoff"],
            label="finalizer.handoff",
            path=RELEASE_SOURCE_FINALIZER_HANDOFF_PATH_V2,
            maximum_size=MAX_HANDOFF_BYTES,
        ),
        "authentication": _authentication(manifest["authentication"]),
    }


def canonical_release_source_finalizer_v2_bytes(
    value: Mapping[str, Any],
) -> bytes:
    return canonical_validated_bytes(value, validator=validate_release_source_finalizer_v2)


def release_source_finalizer_v2_signature_message(
    value: Mapping[str, Any],
) -> bytes:
    """Return the exact bytes an Ed25519 V2 finalizer signature must cover."""

    return RELEASE_SOURCE_FINALIZER_SIGNATURE_DOMAIN_V2 + (
        canonical_release_source_finalizer_v2_bytes(value)
    )
