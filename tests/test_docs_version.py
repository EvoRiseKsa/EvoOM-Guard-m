# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Docs⟷code version-drift gate.

Every *install/pin* reference in the docs (``uses: …@vX.Y.Z``, ``pip install
git+…@vX.Y.Z``, ``releases/download/vX.Y.Z/``, the JSON-schema ``tool_version``
example) must point at the CURRENT ``evoom_guard.__version__``. A release that
bumps the code version without bumping every taught pin ships copy-paste
instructions for a different tool than the one being released — the exact
"README says v3.2.2 but GUARD.md says v3.2.1" drift an external review caught.

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

# Files a user copies install/pin instructions from. CHANGELOG.md is excluded
# (it legitimately names every past version); PROOFS/CATALOG record historical
# runs and use narrative text, not pin patterns.
_DOC_FILES = (
    [ROOT / "README.md"]
    + sorted((ROOT / "docs").glob("*.md"))
    + sorted((ROOT / "examples").glob("*.yml"))
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


class DocsVersionDriftTests(unittest.TestCase):
    def test_every_taught_pin_matches_the_package_version(self) -> None:
        stale: list[str] = []
        for path in _DOC_FILES:
            text = path.read_text(encoding="utf-8")
            for lineno, line in enumerate(text.splitlines(), 1):
                for pat in _PIN_PATTERNS:
                    for m in pat.finditer(line):
                        if m.group(1) != __version__:
                            stale.append(
                                f"{path.relative_to(ROOT)}:{lineno}: pins "
                                f"v{m.group(1)} but the package is v{__version__}"
                            )
        self.assertEqual(
            stale, [],
            "docs teach an install/pin for a version that is not the current "
            "release — update them in the same change as the version bump:\n"
            + "\n".join(stale),
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


if __name__ == "__main__":
    unittest.main()
