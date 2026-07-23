# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
"""Documentation and runtime version-drift gate.

Every user-facing install/pin reference must use the latest published consumer
release. A source tree may legitimately prepare a newer runtime before its
immutable GitHub Release exists; ``docs/RELEASE_STATUS.md`` records the source
and latest-published versions explicitly. ``evo-guard init`` must never guess a
release ref: every documented invocation supplies an exact tag or full SHA.
JSON-schema examples always use the current source runtime. The byte-pinned
v3.7 Trusted Finalizer templates remain the sole historical pin exception
because changing those URLs without matching reviewed SHA-256 values would be
unsafe.
"""

from __future__ import annotations

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
_TOOL_VERSION_RE = re.compile(r'"(?:tool_)?version":\s*"(\d+\.\d+\.\d+)"')
_PREPUBLICATION_CONDITION_RE = re.compile(
    r"(?:only\s+after|after).{0,80}(?:release.{0,80}published|published.{0,80}release)",
    re.IGNORECASE,
)
_RELEASE_STATUS_RE = re.compile(
    r"^---\s*\n"
    r"source_version:\s*(?P<source>\d+\.\d+\.\d+)\s*\n"
    r"latest_published_version:\s*(?P<published>\d+\.\d+\.\d+)\s*\n"
    r"state:\s*(?P<state>pre-release|published)\s*\n"
    r"---\s*$",
    re.MULTILINE,
)


def _release_status() -> tuple[str, str, str]:
    text = (ROOT / "docs" / "RELEASE_STATUS.md").read_text(encoding="utf-8")
    match = _RELEASE_STATUS_RE.search(text)
    if match is None:
        raise AssertionError("docs/RELEASE_STATUS.md front matter is missing or invalid")
    return match.group("source"), match.group("published"), match.group("state")


class DocsVersionDriftTests(unittest.TestCase):
    def test_every_taught_pin_matches_the_latest_published_version(self) -> None:
        stale: list[str] = []
        prepublication_conditions: list[str] = []
        source_version, published_version, state = _release_status()
        self.assertEqual(source_version, __version__)
        allowed_pins = {published_version}
        if state == "published":
            self.assertEqual(published_version, __version__)
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
                                f"published consumer version is v{published_version}"
                            )
                        if pinned == __version__ and state == "published":
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
            "consumer release nor an explicit frozen byte-pinned reference:\n"
            + "\n".join(stale),
        )
        self.assertEqual(
            prepublication_conditions,
            [],
            "a published-release pin must not retain a stale pre-publication "
            "condition:\n" + "\n".join(prepublication_conditions),
        )

    def test_release_status_and_consumer_docs_are_consistent(self) -> None:
        source_version, published_version, state = _release_status()
        self.assertEqual(source_version, __version__)
        release_url = (
            "https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/"
            f"v{published_version}"
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
                    rf"v{re.escape(published_version)}.{{0,180}}"
                    r"(?:published|immutable GitHub Release)",
                    re.IGNORECASE | re.DOTALL,
                ),
                f"{relative} must describe the latest published version as a released version",
            )

        release_status = (ROOT / "docs" / "RELEASE_STATUS.md").read_text(encoding="utf-8")
        if state == "pre-release":
            self.assertIn(f"v{__version__}", release_status)
            self.assertRegex(release_status, re.compile(r"not yet a published", re.I))
        else:
            self.assertEqual(published_version, __version__)

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

    def test_json_schema_example_tool_version_is_current(self) -> None:
        text = (ROOT / "docs" / "JSON_SCHEMA.md").read_text(encoding="utf-8")
        versions = _TOOL_VERSION_RE.findall(text)
        self.assertTrue(versions, "JSON_SCHEMA.md should show a tool_version example")
        for version in versions:
            self.assertEqual(
                version,
                __version__,
                f"docs/JSON_SCHEMA.md example shows tool_version {version!r} but the "
                f"package is {__version__!r}",
            )

    def test_action_example_in_readme_exists(self) -> None:
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("EvoRiseKsa/EvoOM-Guard-m@", text)

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


if __name__ == "__main__":
    unittest.main()
