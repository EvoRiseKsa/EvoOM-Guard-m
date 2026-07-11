# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Enforceable assurance policy + black-box attestation (v3.1).

`assurance` used to be descriptive only. These tests pin that it is now a
**fail-closed contract**: if a caller requires a report_integrity or isolation
level the run did not actually deliver, the verdict is refused with
`assurance_requirement_not_met` — Guard never claims an assurance it did not
enforce. They also pin that black-box verdicts now carry a full attestation
(the gap the review found), and that the judge's exit code — not a report a
candidate child could forge — decides the black-box verdict.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

from evoom_guard.guard import (
    ERROR,
    FAIL,
    PASS,
    REASON_ASSURANCE_REQUIREMENT_NOT_MET,
    guard,
)


def _write(root: str, rel: str, content: str) -> None:
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path) or root, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _block(path: str, content: str) -> str:
    return f"<<<FILE: {path}>>>\n{content}<<<END FILE>>>\n"


def _repo(tmp: str) -> str:
    repo = os.path.join(tmp, "repo")
    _write(repo, "pkg/__init__.py", "")
    _write(repo, "pkg/m.py", "def f():\n    return 1\n")
    _write(repo, "tests/test_m.py", "from pkg.m import f\n\ndef test_v():\n    assert f() == 1\n")
    return repo


class AssurancePolicyTests(unittest.TestCase):
    def test_default_judge_refuses_when_external_integrity_required(self) -> None:
        # The same-process judge cannot deliver external_process_isolated — the
        # policy must fail-closed, not silently ship a weaker guarantee.
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            r = guard(
                repo, _block("pkg/m.py", "def f():\n    return 1\n"),
                require_report_integrity="external_process_isolated",
            )
            self.assertEqual(r.verdict, ERROR)
            self.assertEqual(r.reason_code, REASON_ASSURANCE_REQUIREMENT_NOT_MET)
            self.assertIn("--blackbox", r.reason)

    def test_default_judge_passes_when_only_same_process_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            r = guard(
                repo, _block("pkg/m.py", "def f():\n    return 1\n"),
                require_report_integrity="same_process_candidate_writable",
            )
            self.assertEqual(r.verdict, PASS)

    def test_isolation_floor_refuses_subprocess(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            r = guard(
                repo, _block("pkg/m.py", "def f():\n    return 1\n"),
                require_candidate_isolation="docker",
            )
            self.assertEqual(r.verdict, ERROR)
            self.assertEqual(r.reason_code, REASON_ASSURANCE_REQUIREMENT_NOT_MET)

    def test_the_check_is_against_what_ran_not_the_request(self) -> None:
        # Even a genuinely passing change is refused if the delivered assurance is
        # below the requirement — the guarantee can never be over-claimed.
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            r = guard(
                repo, _block("pkg/m.py", "def f():\n    return 1\n"),
                require_report_integrity="external_process_isolated",
            )
            self.assertNotEqual(r.verdict, PASS)


@unittest.skipIf(sys.platform == "win32", "black-box demo uses POSIX subprocess semantics")
class BlackboxAttestationTests(unittest.TestCase):
    CALC = (
        "import sys\n"
        "def add(a, b):\n    return a + b\n"
        "if __name__ == '__main__':\n"
        "    _, op, a, b = sys.argv\n    print(add(int(a), int(b)))\n"
    )
    PACK = (
        "import os, subprocess, sys\n"
        "T = os.environ['EVOGUARD_TARGET']\n"
        "def test_add():\n"
        "    r = subprocess.run([sys.executable, '-m', 'calc', 'add', '2', '3'],\n"
        "        cwd=T, capture_output=True, text=True)\n"
        "    assert r.stdout.strip() == '5'\n"
    )

    def _repo_pack(self, tmp: str) -> tuple[str, str]:
        repo = os.path.join(tmp, "repo")
        _write(repo, "calc/__init__.py", "")
        _write(repo, "calc/__main__.py", self.CALC)
        pack = os.path.join(tmp, "pack")
        _write(pack, "test_pack.py", self.PACK)
        _write(pack, "pack.json", '{"id": "calc-proto", "version": "1.0.0", "target_type": "cli"}')
        return repo, pack

    def test_blackbox_verdict_carries_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = self._repo_pack(tmp)
            r = guard(repo, _block("calc/note.py", "# ok\n"), verifier_pack=pack, blackbox=True)
            self.assertEqual(r.verdict, PASS)
            att = r.attestation
            assert att is not None
            self.assertEqual(att["mode"], "blackbox")
            self.assertTrue(att["candidate_sha256"])
            self.assertTrue(att["verifier_pack_sha256"])  # pack digest bound to the verdict
            self.assertEqual(att["verifier_pack_manifest"]["id"], "calc-proto")

    def test_blackbox_meets_external_integrity_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = self._repo_pack(tmp)
            r = guard(
                repo, _block("calc/note.py", "# ok\n"), verifier_pack=pack, blackbox=True,
                require_report_integrity="external_process_isolated",
            )
            self.assertEqual(r.verdict, PASS)  # requirement satisfied → not refused

    def test_child_forging_junit_cannot_flip_the_blackbox_verdict(self) -> None:
        # A candidate CLI that returns a WRONG answer and also forges the JUnit
        # report from its own (child) process. The judge grades by its OWN exit
        # code, so the forged report only touches counts, never the verdict.
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = self._repo_pack(tmp)
            evil = (
                "import os, sys\n"
                "def add(a, b):\n    return a + b + 1\n"  # WRONG
                "if __name__ == '__main__':\n"
                "    for a in sys.argv:\n"
                "        if a.startswith('--junitxml='):\n"
                "            try: open(a.split('=',1)[1],'w').write("
                "'<testsuite tests=\"1\" failures=\"0\" errors=\"0\"/>')\n"
                "            except OSError: pass\n"
                "    _, op, x, y = sys.argv\n    print(add(int(x), int(y)))\n"
                "    os._exit(0)\n"
            )
            r = guard(repo, _block("calc/__main__.py", evil), verifier_pack=pack, blackbox=True)
            self.assertEqual(r.verdict, FAIL)  # wrong answer caught; forgery irrelevant


if __name__ == "__main__":
    unittest.main()
