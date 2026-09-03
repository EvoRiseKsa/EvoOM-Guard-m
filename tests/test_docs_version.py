# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Documentation and runtime version-drift gate.

Every user-facing install/pin reference must use the latest protected-tree
recorded consumer release. A source tree may legitimately prepare a newer
runtime before its immutable GitHub Release exists, or observe a stable
publication before its release evidence is committed.
``docs/RELEASE_STATUS.md`` records those boundaries explicitly. ``evo-guard
init`` must never guess a release ref: every documented invocation supplies an
exact tag or full SHA. JSON-schema examples use explicit runtime placeholders
unless the example is intentionally bound to one immutable release. The
byte-pinned v3.7 Trusted Finalizer templates remain the sole historical pin
exception because changing those URLs without matching reviewed SHA-256 values
would be unsafe.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from evoom_guard import __version__

ROOT = Path(__file__).parents[1]
_FROZEN_RELEASE_PINS = {
    ("examples/trusted-finalizer/reverify.yml", "3.7.0"),
    ("examples/trusted-finalizer/seal.yml", "3.7.0"),
}

# Files a user copies install/pin instructions from. CHANGELOG.md is excluded
# because it legitimately names every past version; PROOFS/CATALOG records
# historical runs and use narrative text, not pin patterns.
_DOC_FILES = (
    [ROOT / "README.md"]
    + sorted((ROOT / "docs").rglob("*.md"))
    + sorted((ROOT / "examples").rglob("*.md"))
    + sorted((ROOT / "examples").rglob("*.yml"))
    + sorted((ROOT / "examples").rglob("*.yaml"))
    + [
        ROOT / ".github" / "workflows" / "evoguard-reverify.yml",
        ROOT / ".github" / "workflows" / "evoguard-seal.yml",
    ]
)

_PIN_PATTERNS = (
    re.compile(r"EvoOM-Guard-m(?:\.git)?@v(\d+\.\d+\.\d+)"),
    re.compile(r"releases/download/v(\d+\.\d+\.\d+)/"),
)
_TOOL_VERSION_RE = re.compile(r'"(?:tool_)?version":\s*"([^"]+)"')
_PREPUBLICATION_CONDITION_RE = re.compile(
    r"(?:only\s+after|after).{0,80}(?:release.{0,80}published|published.{0,80}release)",
    re.IGNORECASE,
)
_CANONICAL_IDENTITY = (
    "Copyright © 2026 EvoRise Tech. All rights reserved.",
    "Author / original creator: Mana Alharbi.",
    "Licensor: EvoRise Tech.",
)
_LIVE_LICENSE_DOCUMENTS = (
    ROOT / "LICENSE",
    ROOT / "NOTICE",
    ROOT / "COMMERCIAL-LICENSING.md",
    ROOT / "LICENSE_ARABIC_SUMMARY.md",
    ROOT / "README.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "GOVERNANCE.md",
    ROOT / "docs" / "GOVERNANCE.md",
    ROOT / "docs" / "PROJECT_STATUS.md",
)


def _release_status_from(
    status: dict[str, object],
    *,
    source_version: str,
) -> tuple[str, str, str]:
    if status["schema_version"] == "evoguard-project-status-v3":
        record_path = status["published_release"]["record"]
        release_authority = json.loads(
            (ROOT / record_path).read_text(encoding="utf-8")
        )
        consumer_version = release_authority["source"]["version"]
        lifecycle = status["source"]["lifecycle"]
        state = {
            "unreleased-development": "pre-release",
            "release-candidate": "pre-release",
            "release-line": "direct-recorded",
        }[lifecycle]
    else:
        ledger_path = status["published_release"]["ledger"]
        release_authority = json.loads(
            (ROOT / ledger_path).read_text(encoding="utf-8")
        )
        consumer_version = release_authority["project"]["version"]
        lifecycle = status["source"]["lifecycle"]
        state = {
            "unreleased-development": "pre-release",
            "release-candidate": "pre-release",
            "published-unledgered": "published-unledgered",
            "release-line": "ledger-recorded",
        }[lifecycle]
    return source_version, consumer_version, state


def _release_status() -> tuple[str, str, str]:
    status = json.loads((ROOT / "PROJECT_STATUS.json").read_text(encoding="utf-8"))
    return _release_status_from(status, source_version=__version__)


def _assurance_boundary_version() -> str:
    """Return the newest release with validated A-through-H feature evidence."""

    status = json.loads((ROOT / "PROJECT_STATUS.json").read_text(encoding="utf-8"))
    if status["schema_version"] != "evoguard-project-status-v3":
        return _release_status()[1]
    ledger_path = status["historical_evidence"]["latest_validated_a_h_ledger"]
    ledger = json.loads((ROOT / ledger_path).read_text(encoding="utf-8"))
    return ledger["project"]["version"]


class DocsVersionDriftTests(unittest.TestCase):
    def test_v3_source_lifecycle_preserves_the_direct_consumer_boundary(self) -> None:
        status = json.loads(
            (ROOT / "PROJECT_STATUS.json").read_text(encoding="utf-8")
        )
        for lifecycle, source_version, state in (
            ("unreleased-development", "4.9.0.dev0", "pre-release"),
            ("release-candidate", "4.9.0", "pre-release"),
            ("release-line", "4.8.1", "direct-recorded"),
        ):
            with self.subTest(lifecycle=lifecycle):
                candidate = json.loads(json.dumps(status))
                candidate["source"]["lifecycle"] = lifecycle
                self.assertEqual(
                    _release_status_from(candidate, source_version=source_version),
                    (source_version, "4.8.1", state),
                )

    def test_every_taught_pin_matches_the_latest_published_version(self) -> None:
        stale: list[str] = []
        prepublication_conditions: list[str] = []
        source_version, consumer_version, state = _release_status()
        self.assertEqual(source_version, __version__)
        allowed_pins = {consumer_version}
        if state in {"ledger-recorded", "direct-recorded"}:
            self.assertEqual(consumer_version, __version__)
            allowed_pins.add(__version__)

        for path in _DOC_FILES:
            text = path.read_text(encoding="utf-8")
            relative = path.relative_to(ROOT).as_posix()
            lines = text.splitlines()
            for lineno, line in enumerate(lines, 1):
                for pattern in _PIN_PATTERNS:
                    for match in pattern.finditer(line):
                        pinned = match.group(1)
                        if pinned not in allowed_pins and (relative, pinned) not in _FROZEN_RELEASE_PINS:
                            stale.append(
                                f"{relative}:{lineno}: pins v{pinned} but the latest "
                                "protected-tree recorded consumer version is "
                                f"v{consumer_version}"
                            )
                        if pinned == __version__ and state in {
                            "ledger-recorded",
                            "direct-recorded",
                        }:
                            context = " ".join(lines[max(0, lineno - 5) : lineno + 2])
                            if _PREPUBLICATION_CONDITION_RE.search(context) is not None:
                                prepublication_conditions.append(
                                    f"{relative}:{lineno}: v{pinned} pin retains a nearby "
                                    "pre-publication condition"
                                )

        self.assertEqual(
            stale,
            [],
            "docs teach an install/pin that is neither the latest published "
            "protected-tree recorded consumer release nor an explicit frozen byte-pinned "
            "reference:\n"
            + "\n".join(stale),
        )
        self.assertEqual(
            prepublication_conditions,
            [],
            "a published-release pin must not retain a stale pre-publication "
            "condition:\n" + "\n".join(prepublication_conditions),
        )

    def test_release_status_and_consumer_docs_are_consistent(self) -> None:
        source_version, consumer_version, state = _release_status()
        self.assertEqual(source_version, __version__)
        release_url = (
            "https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/"
            f"v{consumer_version}"
        )
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        status = (ROOT / "docs" / "PROJECT_STATUS.md").read_text(encoding="utf-8")
        for relative, text in (("README.md", readme), ("docs/PROJECT_STATUS.md", status)):
            self.assertIn(
                release_url,
                text,
                f"{relative} must link the latest published version explicitly",
            )
            self.assertRegex(
                text,
                re.compile(
                    rf"latest\s+immutable\s+consumer\s+release.*"
                    rf"\[`v{re.escape(consumer_version)}`\]",
                    re.IGNORECASE | re.DOTALL,
                ),
                f"{relative} must identify the protected-tree recorded release",
            )

        release_status = (ROOT / "docs" / "RELEASE_STATUS.md").read_text(encoding="utf-8")
        if state == "pre-release":
            self.assertIn(__version__, release_status)
            self.assertRegex(
                release_status,
                re.compile(r"unreleased|not (?:yet )?a\s+consumer release", re.I),
            )
        elif state == "published-unledgered":
            self.assertNotEqual(consumer_version, __version__)
            self.assertIn(__version__, release_status)
            self.assertRegex(
                release_status,
                re.compile(
                    r"published stable GitHub release.*"
                    r"has\s+no\s+valid\s+protected-tree\s+release\s+ledger",
                    re.I | re.S,
                ),
            )
            self.assertIn("not a signed ledger", release_status)
            self.assertIn(f"`v{consumer_version}`", release_status)
        elif state == "direct-recorded":
            self.assertEqual(consumer_version, __version__)
            self.assertIn("direct", release_status.lower())
            self.assertIn("same-owner", release_status)
            self.assertRegex(
                release_status,
                re.compile(
                    r"not\s+(?:an?\s+)?(?:A-through-H\s+)?release\s+ledger",
                    re.I,
                ),
            )
        else:
            self.assertEqual(state, "ledger-recorded")
            self.assertEqual(consumer_version, __version__)

    def test_documented_init_commands_supply_an_explicit_ref(self) -> None:
        paths = (ROOT / "README.md", ROOT / "docs" / "ADOPTION.md", ROOT / "docs" / "GUARD.md")
        commands: list[str] = []
        for path in paths:
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if line.strip().startswith("evo-guard init"):
                    commands.append(f"{path.relative_to(ROOT)}:{lineno}: {line.strip()}")
        self.assertTrue(commands, "consumer docs should include an init example")
        missing_ref = [command for command in commands if "--ref " not in command]
        self.assertEqual(
            missing_ref,
            [],
            "every executable init example must choose an explicit immutable ref:\n"
            + "\n".join(missing_ref),
        )

    def test_json_schema_example_uses_a_runtime_version_placeholder(self) -> None:
        text = (ROOT / "docs" / "JSON_SCHEMA.md").read_text(encoding="utf-8")
        versions = _TOOL_VERSION_RE.findall(text)
        self.assertTrue(versions, "JSON_SCHEMA.md should show a tool_version example")
        self.assertEqual(set(versions), {"<runtime-version>"})

    def test_action_example_in_readme_exists(self) -> None:
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("EvoRiseKsa/EvoOM-Guard-m@", text)

    def test_no_install_assets_use_the_complete_current_checksum_set(self) -> None:
        _source_version, consumer_version, _state = _release_status()
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        base = (
            "https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/download/"
            f"v{consumer_version}/"
        )
        for asset in ("evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS"):
            self.assertIn(base + asset, text)
        self.assertIn("sha256sum -c SHA256SUMS", text)

    def test_user_facing_github_actions_are_commit_pinned(self) -> None:
        paths = _DOC_FILES + [ROOT / "evoom_guard" / "cli" / "__init__.py"]
        unpinned: list[str] = []
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for lineno, line in enumerate(text.splitlines(), 1):
                for action, target in re.findall(
                    r"(actions/[A-Za-z0-9_.-]+)@([^\s#]+)", line
                ):
                    if re.fullmatch(r"[0-9a-f]{40}", target) is None:
                        unpinned.append(
                            f"{path.relative_to(ROOT)}:{lineno}: {action}@{target}"
                        )
        self.assertEqual(unpinned, [])

    def test_runtime_guidance_does_not_claim_unavailable_pypi_extras(self) -> None:
        paths = list((ROOT / "evoom_guard").rglob("*.py")) + [
            ROOT / "ops" / "build_pyz.py"
        ]
        broken = re.compile(r'pip install\s+["\']evoom-guard\[[^]]+\]["\']')
        hits: list[str] = []
        for path in paths:
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if broken.search(line):
                    hits.append(f"{path.relative_to(ROOT)}:{lineno}: {line.strip()}")
        self.assertEqual(hits, [])

    def test_source_line_guides_state_the_consumer_boundary(self) -> None:
        source_version, consumer_version, state = _release_status()
        assurance_version = _assurance_boundary_version()
        self.assertIn(
            state,
            {
                "pre-release",
                "published-unledgered",
                "ledger-recorded",
                "direct-recorded",
            },
        )
        source_line = source_version.removesuffix(".dev0")
        paths = (
            ROOT / "docs" / "BLACKBOX.md",
            ROOT / "docs" / "INDEPENDENT_EVALUATION.md",
            ROOT / "docs" / "OPERATING_PROFILES.md",
            ROOT / "docs" / "RECORD_VERIFICATION.md",
            ROOT / "docs" / "OPERATIONAL_TELEMETRY.md",
        )
        for path in paths:
            text = path.read_text(encoding="utf-8")
            relative = path.relative_to(ROOT)
            self.assertIn(
                f"v{assurance_version}",
                text,
                f"{relative} must identify the validated feature-evidence boundary",
            )
            if state == "ledger-recorded":
                self.assertIn(
                    source_line,
                    text,
                    f"{relative} must identify the release-line source",
                )
            else:
                self.assertRegex(
                    text,
                    re.compile(
                        r"release boundary|ledger-recorded|consumer release",
                        re.I,
                    ),
                    f"{relative} must identify its stable consumer boundary",
                )
        if state in {"ledger-recorded", "direct-recorded"}:
            self.assertEqual(source_version, consumer_version)

    def test_stable_getting_started_does_not_teach_unverified_profile_flags(self) -> None:
        text = (ROOT / "docs" / "START_HERE.md").read_text(encoding="utf-8")
        source_version, consumer_version, state = _release_status()
        assurance_version = _assurance_boundary_version()
        project_status = json.loads(
            (ROOT / "PROJECT_STATUS.json").read_text(encoding="utf-8")
        )
        self.assertIn(
            state,
            {
                "pre-release",
                "published-unledgered",
                "ledger-recorded",
                "direct-recorded",
            },
        )
        source_line = source_version.removesuffix(".dev0")
        executable_blocks = re.findall(r"```(?:bash|sh|shell)?\s*\n(.*?)```", text, re.S)
        self.assertFalse(
            any("--operating-profile" in block for block in executable_blocks),
            "stable getting-started commands must not teach an unverified profile flag",
        )
        lines = text.splitlines()
        for lineno, line in enumerate(lines):
            if "--operating-profile" not in line:
                continue
            context = " ".join(lines[max(0, lineno - 2) : lineno + 3])
            expected_boundary = (
                consumer_version
                if (
                    project_status["schema_version"]
                    == "evoguard-project-status-v3"
                )
                else assurance_version
            )
            self.assertIn(expected_boundary, context)
            if state not in {"ledger-recorded", "direct-recorded"}:
                self.assertRegex(
                    context,
                    re.compile(
                        r"source[- ]line|included|absent|verify|release boundary",
                        re.I,
                    ),
                )
        if state in {"ledger-recorded", "direct-recorded"}:
            self.assertEqual(source_line, consumer_version)
            self.assertRegex(
                text,
                re.compile(r"ledger-recorded|direct record|consumer release", re.I),
            )
            self.assertIn(source_line, text)
        else:
            self.assertIn(consumer_version, text)

    def test_current_product_name_does_not_drift_to_the_historical_brand(self) -> None:
        historical_files = {
            ROOT / "docs" / "PROOFS.md",
            ROOT / "docs" / "history" / "CHANGELOG-v1.md",
        }
        hits: list[str] = []
        paths = [ROOT / "README.md"] + sorted((ROOT / "docs").rglob("*.md"))
        for path in paths:
            if path in historical_files:
                continue
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if "EvoGuard" not in line:
                    continue
                if re.search(r"\bv[1-3]\.\d+\.\d+\b", line) is not None:
                    continue
                hits.append(f"{path.relative_to(ROOT)}:{lineno}: {line.strip()}")
        self.assertEqual(
            hits,
            [],
            "use 'EvoOM Guard' for the current product; reserve 'EvoGuard' "
            "for explicit historical records:\n" + "\n".join(hits),
        )

    def test_public_license_documents_use_the_canonical_v4_model(self) -> None:
        title = "EVORISE SOURCE-AVAILABLE LICENSE"
        obsolete = (
            "EvoRise Research and Evaluation License",
            "LicenseRef-EvoRise-Research-Evaluation-1.0",
            "COMMERCIAL-LICENSE.md",
            "LICENSE_TRANSITION_V4.md",
        )
        paths = (
            ROOT / "LICENSE",
            ROOT / "NOTICE",
            ROOT / "README.md",
            ROOT / "CHANGELOG.md",
            ROOT / "LICENSE_HISTORY.md",
            ROOT / "LICENSE_ARABIC_SUMMARY.md",
            ROOT / "THIRD_PARTY.md",
            ROOT / "docs" / "PROJECT_STATUS.md",
            ROOT / "docs" / "RELEASE_STATUS.md",
        )

        self.assertIn(title, (ROOT / "LICENSE").read_text(encoding="utf-8"))
        self.assertIn(
            "LicenseRef-EvoRise-Source-Available-1.0",
            (ROOT / "NOTICE").read_text(encoding="utf-8"),
        )
        self.assertTrue((ROOT / "COMMERCIAL-LICENSING.md").is_file())
        self.assertFalse((ROOT / "COMMERCIAL-LICENSE.md").exists())
        self.assertFalse((ROOT / "docs" / "LICENSE_TRANSITION_V4.md").exists())

        for path in paths:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(
                obsolete[0], text, f"{path.relative_to(ROOT)} has the retired license name"
            )
            self.assertNotIn(
                obsolete[1], text, f"{path.relative_to(ROOT)} has the retired SPDX id"
            )
            self.assertNotIn(
                obsolete[2], text, f"{path.relative_to(ROOT)} links the retired page"
            )
            self.assertNotIn(
                obsolete[3], text, f"{path.relative_to(ROOT)} links internal transition notes"
            )

    def test_live_license_identity_does_not_drift(self) -> None:
        license_lines = (ROOT / "LICENSE").read_text(encoding="utf-8").splitlines()
        notice_lines = (ROOT / "NOTICE").read_text(encoding="utf-8").splitlines()
        self.assertEqual(tuple(license_lines[5:8]), _CANONICAL_IDENTITY)
        self.assertEqual(tuple(notice_lines[:3]), _CANONICAL_IDENTITY)

        obsolete_identity = "EvoRise Company"
        for path in _LIVE_LICENSE_DOCUMENTS:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(
                obsolete_identity,
                text,
                f"{path.relative_to(ROOT)} uses the retired licensing identity",
            )


if __name__ == "__main__":
    unittest.main()
