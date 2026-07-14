# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Stable report envelope for semantic verdict-record verification."""

from __future__ import annotations

from typing import Any

RECORD_VERIFIER_VERSION = "1.0"
# This is intentionally pinned independently of both the producer's current
# alias and the shared vocabulary. A future contract module must not silently
# make this verifier claim support before its semantics are implemented.
SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.11"})


class _Checks:
    """Collect ordered semantic checks and render the public report envelope."""

    def __init__(self) -> None:
        self.items: list[dict[str, str]] = []

    def pass_(self, check_id: str, message: str) -> None:
        self.items.append({"id": check_id, "status": "pass", "message": message})

    def fail(self, check_id: str, message: str) -> None:
        self.items.append({"id": check_id, "status": "fail", "message": message})

    def skip(self, check_id: str, message: str) -> None:
        self.items.append({"id": check_id, "status": "skip", "message": message})

    def expect(self, check_id: str, condition: bool, ok: str, failed: str) -> None:
        if condition:
            self.pass_(check_id, ok)
        else:
            self.fail(check_id, failed)

    def report(self, record_schema_version: object = None) -> dict[str, Any]:
        counts = {
            status: sum(item["status"] == status for item in self.items)
            for status in ("pass", "fail", "skip")
        }
        return {
            "record_verifier": "evoguard",
            "record_verifier_version": RECORD_VERIFIER_VERSION,
            "scope": "semantic_consistency_only",
            "signature_checked": False,
            "supported_schema_versions": sorted(SUPPORTED_SCHEMA_VERSIONS),
            "record_schema_version": (
                record_schema_version
                if isinstance(record_schema_version, str)
                else None
            ),
            "ok": counts["fail"] == 0,
            "summary": {
                "passed": counts["pass"],
                "failed": counts["fail"],
                "skipped": counts["skip"],
                "total": len(self.items),
            },
            "checks": self.items,
        }
