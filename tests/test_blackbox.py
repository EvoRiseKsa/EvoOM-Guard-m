# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""The external black-box judge — proving the same-process forgery is defeated.

`tests/test_report_integrity.py` pins that the DEFAULT (same-process) judge
returns a false PASS for an `atexit`+`os._exit`+JUnit forgery. This module runs
the identical forgery under `--blackbox` and shows it is **caught**, because the
verdict now comes from the judge's own process — which never imports the
candidate. That is the whole point of the black-box judge, so it gets a direct
before/after proof, not just a unit test of the plumbing.

The target is a tiny CLI (`python -m calc add A B`). The judge-owned pack invokes
it across a process boundary via `$EVOGUARD_TARGET` and asserts on its stdout.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

from evoom_guard.guard import FAIL, PASS, guard


def _write(root: str, rel: str, content: str) -> None:
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path) or root, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


# A CLI target: `python -m calc add 2 3` -> prints the sum.
CALC_MAIN = (
    "import sys\n"
    "def add(a, b):\n"
    "    return a + b\n"
    "if __name__ == '__main__':\n"
    "    _, op, a, b = sys.argv\n"
    "    print(add(int(a), int(b)))\n"
)

# The judge-owned pack: invokes the candidate CLI out-of-process and checks output.
PACK_TEST = (
    "import os, subprocess, sys\n"
    "TARGET = os.environ['EVOGUARD_TARGET']\n"
    "PY = os.environ.get('EVOGUARD_PYTHON', sys.executable)\n"
    "def _run(*args):\n"
    "    return subprocess.run([PY, '-m', 'calc', *args], cwd=TARGET,\n"
    "        capture_output=True, text=True).stdout.strip()\n"
    "def test_add():\n"
    "    assert _run('add', '2', '3') == '5'\n"
    "def test_add_more():\n"
    "    assert _run('add', '10', '20') == '30'\n"
)


def _repo(tmp: str) -> str:
    repo = os.path.join(tmp, "repo")
    _write(repo, "calc/__init__.py", "")
    _write(repo, "calc/__main__.py", CALC_MAIN)
    # A repo-native test exists too, but black-box mode judges via the pack only.
    _write(repo, "tests/test_calc.py", "from calc.__main__ import add\n\ndef test_add():\n    assert add(2, 3) == 5\n")
    return repo


def _pack(tmp: str) -> str:
    pack = os.path.join(tmp, "pack")
    _write(pack, "test_pack_protocol.py", PACK_TEST)
    return pack


def _block(path: str, content: str) -> str:
    return f"<<<FILE: {path}>>>\n{content}<<<END FILE>>>\n"


@unittest.skipIf(sys.platform == "win32", "black-box demo uses POSIX subprocess semantics")
class BlackboxJudgeTests(unittest.TestCase):
    def test_honest_fix_passes_black_box(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = _repo(tmp), _pack(tmp)
            # No-op source touch; the CLI already returns correct sums.
            r = guard(repo, _block("calc/note.py", "# ok\n"), verifier_pack=pack, blackbox=True)
            self.assertEqual(r.verdict, PASS)
            self.assertEqual((r.tests_passed, r.tests_total), (2, 2))
            self.assertEqual(r.verdict_source, "blackbox")
            assert r.assurance is not None
            self.assertEqual(r.assurance["report_integrity"], "external_process_isolated")
            self.assertEqual(r.assurance["overall_profile"], "black_box_external_judge")

    def test_wrong_answer_fails_black_box(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = _repo(tmp), _pack(tmp)
            broken = CALC_MAIN.replace("return a + b", "return a + b + 1")
            r = guard(repo, _block("calc/__main__.py", broken), verifier_pack=pack, blackbox=True)
            self.assertEqual(r.verdict, FAIL)

    def test_the_same_process_forgery_is_DEFEATED_under_blackbox(self) -> None:
        # THE PROOF. The identical atexit + os._exit + JUnit forgery that yields a
        # false PASS under the default judge (see test_report_integrity.py) cannot
        # move the black-box verdict: it runs only in the candidate's CLI
        # subprocess, never in the judge's process.
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = _repo(tmp), _pack(tmp)
            evil = (
                "import atexit, os, sys\n"
                "def add(a, b):\n"
                "    return a + b + 1\n"  # WRONG on purpose
                "def _forge():\n"
                "    for a in sys.argv:\n"
                "        if a.startswith('--junitxml='):\n"
                "            try:\n"
                "                open(a.split('=', 1)[1], 'w').write(\n"
                "                    '<testsuites><testsuite tests=\"2\" failures=\"0\" "
                "errors=\"0\" skipped=\"0\"/></testsuites>')\n"
                "            except OSError:\n"
                "                pass\n"
                "    os._exit(0)\n"
                "atexit.register(_forge)\n"
                "if __name__ == '__main__':\n"
                "    _, op, a, b = sys.argv\n"
                "    print(add(int(a), int(b)))\n"
            )
            r = guard(repo, _block("calc/__main__.py", evil), verifier_pack=pack, blackbox=True)
            # Wrong answer (add returns a+b+1) → the pack's assertion fails, and the
            # forgery in the CLI subprocess cannot reach the judge's report.
            self.assertEqual(r.verdict, FAIL)
            assert r.assurance is not None
            self.assertEqual(r.assurance["report_integrity"], "external_process_isolated")

    def test_blackbox_requires_a_pack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            r = guard(repo, _block("calc/note.py", "# ok\n"), blackbox=True)
            self.assertEqual(r.verdict, "ERROR")
            self.assertIn("verifier-pack", r.reason)

    def test_harness_edit_still_rejected_in_blackbox(self) -> None:
        # Black-box does not weaken mechanism 1: editing a repo test is still REJECTED
        # before anything runs.
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = _repo(tmp), _pack(tmp)
            r = guard(
                repo, _block("tests/test_calc.py", "def test_add():\n    assert True\n"),
                verifier_pack=pack, blackbox=True,
            )
            self.assertEqual(r.verdict, "REJECTED")


if __name__ == "__main__":
    unittest.main()
