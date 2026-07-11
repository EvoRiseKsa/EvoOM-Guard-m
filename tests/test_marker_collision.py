# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Block-marker collision — found by running Guard on Guard's own repository.

Guard's dirs/diff path used to serialize every changed file into the
``<<<FILE: …>>> … <<<END FILE>>>`` text format and then RE-PARSE it. A target
file whose *content* legitimately contains a literal ``<<<END FILE>>>`` line
(Guard's own ``guard.py`` and test files do!) terminated its own block early —
the verified copy got a silently TRUNCATED file, so an honest change produced a
bogus FAIL (SyntaxError in the copy) instead of a PASS.

The fix threads the structured ``{path: content}`` mapping end-to-end
(``blocks_from_dirs`` → ``guard(file_blocks=…)`` → the verifier/black-box/
coverage appliers), so the dirs/diff path never round-trips content through the
marker syntax. These tests pin that contract on a repo that embeds the markers
in its source — the self-hosting shape.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from evoom_guard.guard import PASS, blocks_from_dirs, guard, guard_from_diff

HAS_GIT = shutil.which("git") is not None

# A source file whose CONTENT contains the block markers verbatim — the shape
# that used to truncate. The suite asserts on a value defined AFTER the marker
# lines, so a truncated copy cannot pass.
TRICKY_SRC = (
    "MARKER_OPEN = '<<<FILE: x>>>'\n"
    "MARKER_END = '<<<END FILE>>>'\n"
    "TEMPLATE = '''\n"
    "<<<FILE: {path}>>>\n"
    "{body}\n"
    "<<<END FILE>>>\n"
    "'''\n"
    "ANSWER = 42\n"
)
TRICKY_TEST = (
    "import sys, os\n"
    "sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))\n"
    "from pkg.tricky import ANSWER, MARKER_END\n\n"
    "def test_answer_defined_after_the_markers():\n"
    "    assert ANSWER == 42\n"
    "    assert MARKER_END == '<<<END FILE>>>'\n"
)
TEST_CMD = [sys.executable, "-m", "pytest", "-q", "--color=no", "-p", "no:cacheprovider"]


def _make_repo(root: str) -> None:
    os.makedirs(os.path.join(root, "pkg"))
    os.makedirs(os.path.join(root, "tests"))
    with open(os.path.join(root, "pkg", "__init__.py"), "w", encoding="utf-8") as f:
        f.write("")
    with open(os.path.join(root, "pkg", "tricky.py"), "w", encoding="utf-8") as f:
        f.write(TRICKY_SRC)
    with open(os.path.join(root, "tests", "test_tricky.py"), "w", encoding="utf-8") as f:
        f.write(TRICKY_TEST)


class MarkerCollisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = tempfile.mkdtemp(prefix="evo_marker_base_")
        self.head = tempfile.mkdtemp(prefix="evo_marker_head_")
        _make_repo(self.base)
        _make_repo(self.head)
        # head makes an HONEST edit to the marker-bearing file
        with open(os.path.join(self.head, "pkg", "tricky.py"), "a", encoding="utf-8") as f:
            f.write("EXTRA = 'honest edit'\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.base, ignore_errors=True)
        shutil.rmtree(self.head, ignore_errors=True)

    def test_blocks_from_dirs_returns_intact_content(self) -> None:
        blocks, deleted = blocks_from_dirs(self.base, self.head)
        self.assertEqual(deleted, [])
        self.assertEqual(list(blocks), ["pkg/tricky.py"])
        content = blocks["pkg/tricky.py"]
        # Everything after the embedded end-marker must survive.
        self.assertIn("ANSWER = 42", content)
        self.assertIn("EXTRA = 'honest edit'", content)

    def test_structured_dirs_path_passes_on_a_marker_bearing_repo(self) -> None:
        blocks, deleted = blocks_from_dirs(self.base, self.head)
        r = guard(
            self.base, "",  # candidate text unused when file_blocks is given
            deleted=tuple(deleted), file_blocks=blocks,
            test_command=TEST_CMD, timeout=120,
        )
        self.assertEqual(r.verdict, PASS, r.reason + " | " + r.diagnostics[:400])

    @unittest.skipUnless(HAS_GIT, "needs git for the diff path")
    def test_diff_path_passes_on_a_marker_bearing_repo(self) -> None:
        # The exact self-hosting shape: stand in the head checkout and pipe
        # `git diff` (committed base → edited working tree) into the guard —
        # on a repo whose source embeds the markers.
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        repo = tempfile.mkdtemp(prefix="evo_marker_git_")
        try:
            _make_repo(repo)  # base content
            subprocess.run(["git", "init", "-q", repo], check=True)
            subprocess.run(["git", "-C", repo, "add", "-A"], check=True)
            subprocess.run(["git", "-C", repo, "commit", "-qm", "base"],
                           check=True, env=env)
            # The honest working-tree edit to the marker-bearing file.
            with open(os.path.join(repo, "pkg", "tricky.py"), "a", encoding="utf-8") as f:
                f.write("EXTRA = 'honest edit'\n")
            diff = subprocess.run(
                ["git", "-C", repo, "diff", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout
            self.assertIn("<<<END FILE>>>", diff)  # the collision is really in play
            r, deleted = guard_from_diff(repo, diff, test_command=TEST_CMD, timeout=120)
            self.assertEqual(r.verdict, PASS, r.reason + " | " + r.diagnostics[:400])
            self.assertEqual(deleted, [])
        finally:
            shutil.rmtree(repo, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
