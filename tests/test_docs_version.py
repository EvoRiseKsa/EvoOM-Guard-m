# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Docs⟷code version-drift gate.

Every *install/pin* reference in the docs (``uses: …@vX.Y.Z``, ``pip install
git+…@vX.Y.Z``, ``releases/download/vX.Y.Z/``, the JSON-schema ``tool_version``
example) must point at the current ``evoom_guard.__version__``. The current
consumer version is documented through an exact published-release reference,
not a stale pre-publication condition. The only exceptions are the byte-pinned,
frozen v3.7 Trusted Finalizer reference templates: changing their URL without a
matching reviewed SHA-256 would be unsafe.

Historical *narrative* mentions ("v2.0.0 consolidated the engine…", the PROOFS
records, CHANGELOG entries) are deliberately NOT checked: only the patterns a
user would copy to install or pin the tool.
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
# (it legitimately names every past version); PROOFS/CATALOG record historical
# runs and use narrative text, not pin patterns.
_DOC_FILES = (
    [ROOT / "README.md"]
    + sorted((ROOT / "docs").rglob("*.md"))
    + sorted((ROOT / "examples").rglob("*.md"))
    + sorted((ROOT / "examples").rglob("*.yml"))
    + sorted((ROOT / "examples").rglob("*.yaml"))
)

# Install/pin shapes taught by the docs. Each captures the version they pin.
_PIN_PATTERNS = (
    # - uses: EvoRiseKsa/EvoOM-Guard-m@v3.2.2   /  pip install git+…EvoOM-Guard-m@v3.2.2
    # / git+…EvoOM-Guard-m.git@v3.2.2
    re.compile(r"EvoOM-Guard-m(?:\.git)?@v(\d+\.\d+\.\d+)"),
    # release-asset download URLs
    re.compile(r"releases/download/v(\d+\.\d+\.\d+)/"),
)

# The JSON-schema example payloads show the current tool version — both the
# guard verdict's "tool_version" and the doctor report's "version".
_TOOL_VERSION_RE = re.compile(r'"(?:tool_)?version":\s*"(\d+\.\d+\.\d+)"')
_PREPUBLICATION_CONDITION_RE = re.compile(
    r"(?:only\s+after|after).{0,80}(?:release.{0,80}published|published.{0,80}release)",
    re.IGNORECASE,
)


class DocsVersionDriftTests(unittest.TestCase):
    def test_every_taught_pin_matches_the_package_version(self) -> None:
        stale: list[str] = []
        prepublication_conditions: list[str] = []
        for path in _DOC_FILES:
            text = path.read_text(encoding="utf-8")
            relative = path.relative_to(ROOT).as_posix()
            lines = text.splitlines()
            for lineno, line in enumerate(lines, 1):
                for pat in _PIN_PATTERNS:
                    for m in pat.finditer(line):
                        pinned = m.group(1)
                        if pinned != __version__ and (relative, pinned) not in _FROZEN_RELEASE_PINS:
                            stale.append(
                                f"{relative}:{lineno}: pins v{pinned} but the "
                                f"package is v{__version__}"
                            )
                        if pinned == __version__:
                            context = " ".join(lines[max(0, lineno - 5) : lineno + 2])
                            if _PREPUBLICATION_CONDITION_RE.search(context) is not None:
                                prepublication_conditions.append(
                                    f"{relative}:{lineno}: v{pinned} pin retains a nearby "
                                    "pre-publication condition"
                                )
        self.assertEqual(
            stale, [],
            "docs teach an install/pin for a version that is neither the current "
            "source runtime nor an explicit frozen byte-pinned reference:\n"
            + "\n".join(stale),
        )
        self.assertEqual(
            prepublication_conditions,
            [],
            "a published-release pin must not retain a stale pre-publication "
            "condition:\n" + "\n".join(prepublication_conditions),
        )

    def test_current_release_is_documented_with_an_exact_published_reference(self) -> None:
        release_url = (
            "https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/"
            f"v{__version__}"
        )
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        status = (ROOT / "docs" / "PROJECT_STATUS.md").read_text(encoding="utf-8")
        for relative, text in (("README.md", readme), ("docs/PROJECT_STATUS.md", status)):
            self.assertIn(
                release_url,
                text,
                f"{relative} must link the current released version explicitly",
            )
            self.assertRegex(
                text,
                re.compile(
                    rf"v{re.escape(__version__)}.{{0,180}}"
                    r"(?:published|immutable GitHub Release)",
                    re.IGNORECASE | re.DOTALL,
                ),
                f"{relative} must describe the current version as a published release",
            )

    def test_json_schema_example_tool_version_is_current(self) -> None:
        text = (ROOT / "docs" / "JSON_SCHEMA.md").read_text(encoding="utf-8")
        versions = _TOOL_VERSION_RE.findall(text)
        self.assertTrue(versions, "JSON_SCHEMA.md should show a tool_version example")
        for v in versions:
            self.assertEqual(
                v, __version__,
                f"docs/JSON_SCHEMA.md example shows tool_version {v!r} but the "
                f"package is {__version__!r}",
            )

    def test_action_example_in_readme_exists(self) -> None:
        # The README quick-start must reference the action by its real repo path.
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("EvoRiseKsa/EvoOM-Guard-m@", text)

    def test_user_facing_github_actions_are_commit_pinned(self) -> None:
        paths = _DOC_FILES + [ROOT / "evoom_guard" / "cli.py"]
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
        paths = list((ROOT / "evoom_guard").glob("*.py")) + [ROOT / "ops" / "build_pyz.py"]
        broken = re.compile(r'pip install\s+["\']evoom-guard\[[^]]+\]["\']')
        hits: list[str] = []
        for path in paths:
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if broken.search(line):
                    hits.append(f"{path.relative_to(ROOT)}:{lineno}: {line.strip()}")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
