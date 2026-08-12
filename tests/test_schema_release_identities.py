# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Release-tag identity gates for packaged JSON Schema contracts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCHEMA_ROOT = ROOT / "evoom_guard" / "schemas"
RAW_V460_ROOT = (
    "https://raw.githubusercontent.com/EvoRiseKsa/EvoOM-Guard-m/"
    "v4.6.0/evoom_guard/schemas/"
)

V460_RAW_SCHEMAS = (
    "admission-decision-envelope-1.schema.json",
    "admission-decision-envelope-2.schema.json",
    "agent-change-git-bindings-2.schema.json",
    "agent-change-proposal-2.schema.json",
    "release-artifact-admission-2.schema.json",
    "release-source-2.schema.json",
    "release-source-admission-3.schema.json",
    "release-source-context-2.schema.json",
    "release-source-finalizer-2.schema.json",
    "release-source-git-bindings-2.schema.json",
    "release-source-handoff-2.schema.json",
    "release-source-producer-receipt-2.schema.json",
)
V460_BLOB_SCHEMAS = {
    "blast-radius-materialized-change-2.schema.json": (
        "https://github.com/EvoRiseKsa/EvoOM-Guard-m/blob/v4.6.0/"
        "evoom_guard/schemas/blast-radius-materialized-change-2.schema.json"
    )
}

LEGACY_CHANGE_ATTEMPT_ID = (
    "https://raw.githubusercontent.com/EvoRiseKsa/EvoOM-Guard-m/main/"
    "evoom_guard/schemas/change-attempt-observation-1.schema.json"
)
LEGACY_CHANGE_ATTEMPT_SHA256 = (
    "f0cedd1e960ef4d1fdb8fbdab089902af4388ed97faacd5ec30b93f51f7eafb5"
)


def _schema(name: str) -> dict[str, object]:
    return json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))


def test_all_thirteen_new_v460_schema_identities_are_release_pinned() -> None:
    expected = {name: RAW_V460_ROOT + name for name in V460_RAW_SCHEMAS}
    expected.update(V460_BLOB_SCHEMAS)

    assert len(expected) == 13
    assert {name: _schema(name)["$id"] for name in expected} == expected


def test_no_new_packaged_schema_identity_remains_branch_mutable() -> None:
    mutable = {
        path.name
        for path in SCHEMA_ROOT.glob("*.schema.json")
        if "/main/" in str(_schema(path.name).get("$id", ""))
        or "/blob/main/" in str(_schema(path.name).get("$id", ""))
    }

    assert mutable == {"change-attempt-observation-1.schema.json"}


def test_shipped_change_attempt_schema_bytes_and_identity_are_not_rewritten() -> None:
    path = SCHEMA_ROOT / "change-attempt-observation-1.schema.json"
    payload = path.read_bytes()

    assert json.loads(payload)["$id"] == LEGACY_CHANGE_ATTEMPT_ID
    assert hashlib.sha256(payload).hexdigest() == LEGACY_CHANGE_ATTEMPT_SHA256
