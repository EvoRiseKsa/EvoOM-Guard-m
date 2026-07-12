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
    _assurance_profile,
    _assurance_shortfall,
    guard,
)


def test_host_setup_opt_in_degrades_overall_candidate_isolation() -> None:
    assurance = _assurance_profile(
        "docker", None, setup_isolation="subprocess_host_opt_in"
    )
    assert assurance["suite_isolation"] == "docker"
    assert assurance["setup_isolation"] == "subprocess_host_opt_in"
    assert assurance["candidate_isolation"] == "subprocess"
    assert _assurance_shortfall(
        assurance,
        require_report_integrity=None,
        require_candidate_isolation="docker",
    ) is not None


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
    # calc CLI: `add`/`mul` delegate to an internal ops module the repo suite can
    # test independently of the pack's external protocol.
    OPS = "def add(a, b):\n    return a + b\n\ndef mul(a, b):\n    return a * b\n"
    MAIN = (
        "import sys\nfrom calc.ops import add, mul\n"
        "if __name__ == '__main__':\n"
        "    _, op, a, b = sys.argv\n"
        "    fn = add if op == 'add' else mul\n"
        "    print(fn(int(a), int(b)))\n"
    )
    # Repo-native suite: exercises mul (a dimension the add-only pack never sees).
    REPO_TEST = "from calc.ops import mul\n\ndef test_mul():\n    assert mul(2, 3) == 6\n"
    # Pack: invokes the candidate via the delivered-isolation launcher, add only.
    PACK = (
        "import os, subprocess, sys\n"
        "def _run(*a):\n"
        "    py = os.environ.get('EVOGUARD_PYTHON') or sys.executable\n"
        "    ex = os.environ.get('EVOGUARD_EXEC')\n"
        "    cmd = [ex, py, '-m', 'calc', *a] if ex else [py, '-m', 'calc', *a]\n"
        "    cwd = None if ex else os.environ.get('EVOGUARD_TARGET')\n"
        "    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True).stdout.strip()\n"
        "def test_add():\n    assert _run('add', '2', '3') == '5'\n"
    )

    def _repo_pack(self, tmp: str, *, with_repo_suite: bool = False) -> tuple[str, str]:
        repo = os.path.join(tmp, "repo")
        _write(repo, "calc/__init__.py", "")
        _write(repo, "calc/ops.py", self.OPS)
        _write(repo, "calc/__main__.py", self.MAIN)
        if with_repo_suite:
            _write(repo, "tests/test_ops.py", self.REPO_TEST)
        pack = os.path.join(tmp, "pack")
        _write(pack, "test_pack.py", self.PACK)
        _write(pack, "pack.json", '{"id": "calc-proto", "version": "1.0.0", "target_type": "cli"}')
        return repo, pack

    # ---- attestation is now complete, and bound to what was judged ---------- #
    def test_blackbox_verdict_carries_full_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = self._repo_pack(tmp)
            r = guard(repo, _block("calc/note.py", "# ok\n"),
                      verifier_pack=pack, blackbox=True, blackbox_only=True)
            self.assertEqual(r.verdict, PASS)
            att = r.attestation
            assert att is not None
            self.assertEqual(att["mode"], "blackbox")
            self.assertTrue(att["candidate_sha256"])
            self.assertTrue(att["verifier_pack_sha256"])
            self.assertEqual(att["verifier_pack_manifest"]["id"], "calc-proto")
            # The gaps the review flagged are now filled:
            self.assertTrue(att["junit_sha256"])                       # report digest, not null
            self.assertIsNotNone(att["isolation_evidence"])            # delivered boundary bound
            self.assertEqual(att["isolation_evidence"]["delivered"], "subprocess")

    def test_blackbox_meets_external_integrity_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = self._repo_pack(tmp)
            r = guard(
                repo, _block("calc/note.py", "# ok\n"), verifier_pack=pack,
                blackbox=True, blackbox_only=True,
                require_report_integrity="external_process_isolated",
            )
            self.assertEqual(r.verdict, PASS)

    def test_child_forging_junit_cannot_flip_the_blackbox_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = self._repo_pack(tmp)
            evil = (
                "import os, sys\nfrom calc.ops import add\n"
                "if __name__ == '__main__':\n"
                "    for a in sys.argv:\n"
                "        if a.startswith('--junitxml='):\n"
                "            try: open(a.split('=',1)[1],'w').write("
                "'<testsuite tests=\"1\" failures=\"0\" errors=\"0\"/>')\n"
                "            except OSError: pass\n"
                "    _, op, x, y = sys.argv\n    print(add(int(x), int(y)) + 1)\n"  # WRONG
                "    os._exit(0)\n"
            )
            r = guard(repo, _block("calc/__main__.py", evil),
                      verifier_pack=pack, blackbox=True, blackbox_only=True)
            self.assertEqual(r.verdict, FAIL)


@unittest.skipIf(sys.platform == "win32", "black-box demo uses POSIX subprocess semantics")
class BlackboxIsolationHonestyTests(BlackboxAttestationTests):
    """The four false-PASS attacks the review proved — each must now fail-closed."""

    # ---- #1: isolation the run did not deliver must NEVER pass a docker floor -- #
    def test_fake_docker_is_refused_not_passed(self) -> None:
        # Request docker with an image that cannot exist; require docker. The old
        # build wrote candidate_isolation:docker and PASSED. It must now be ERROR,
        # and must never claim docker it did not run.
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = self._repo_pack(tmp)
            r = guard(
                repo, _block("calc/note.py", "# ok\n"), verifier_pack=pack,
                blackbox=True, blackbox_only=True,
                isolation="docker", docker_image="definitely-does-not-exist:never",
                require_candidate_isolation="docker",
            )
            self.assertEqual(r.verdict, ERROR)
            self.assertNotEqual(r.assurance["candidate_isolation"], "docker")

    def test_require_docker_on_subprocess_delivery_is_refused(self) -> None:
        # No container requested/delivered → the docker floor must fail-closed,
        # checked against DELIVERED isolation, not the flag.
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = self._repo_pack(tmp)
            r = guard(
                repo, _block("calc/note.py", "# ok\n"), verifier_pack=pack,
                blackbox=True, blackbox_only=True,
                require_candidate_isolation="docker",
            )
            self.assertEqual(r.verdict, ERROR)
            self.assertEqual(r.reason_code, REASON_ASSURANCE_REQUIREMENT_NOT_MET)
            self.assertEqual(r.assurance["candidate_isolation"], "subprocess")

    # ---- #3: a deletion in the change is APPLIED to the judged tree ---------- #
    def test_deletion_is_applied_in_blackbox(self) -> None:
        # The CLI depends on calc/dep.py; deleting it must break the candidate the
        # pack exercises → FAIL. If the deletion were ignored (the old bug) the
        # pack would pass. The attestation must also record the applied deletion.
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = self._repo_pack(tmp)
            _write(repo, "calc/dep.py", "TOKEN = 1\n")
            _write(repo, "calc/ops.py",
                   "from calc.dep import TOKEN\n"
                   "def add(a, b):\n    return a + b + (TOKEN - 1)\n"
                   "def mul(a, b):\n    return a * b\n")
            r = guard(
                repo, _block("calc/note.py", "# ok\n"),
                deleted=("calc/dep.py",),
                verifier_pack=pack, blackbox=True, blackbox_only=True,
            )
            self.assertEqual(r.verdict, FAIL)          # deletion really applied
            self.assertIn("calc/dep.py", r.attestation["deleted_paths_applied"])

    # ---- #4: the pack must not REPLACE the repo's own suite ------------------ #
    def test_repo_suite_failure_blocks_even_when_pack_passes(self) -> None:
        # Break mul (repo suite fails) but keep add correct (pack passes). The
        # composite verdict must FAIL — a green pack cannot mask the regression.
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = self._repo_pack(tmp, with_repo_suite=True)
            broken = "def add(a, b):\n    return a + b\n\ndef mul(a, b):\n    return a * b + 1\n"
            r = guard(repo, _block("calc/ops.py", broken), verifier_pack=pack, blackbox=True)
            self.assertEqual(r.verdict, FAIL)
            self.assertIn("repo's own test suite", r.reason)

    def test_composite_passes_when_both_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = self._repo_pack(tmp, with_repo_suite=True)
            r = guard(repo, _block("calc/note.py", "# ok\n"), verifier_pack=pack, blackbox=True)
            self.assertEqual(r.verdict, PASS)
            self.assertEqual(r.attestation["repo_suite_passed"], True)

    # ---- honesty: subprocess boundary does not claim to protect the pack ----- #
    def test_repo_native_pack_secrecy_is_reported_honestly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = self._repo_pack(tmp)
            r = guard(
                repo,
                _block("calc/note.py", "# ok\n"),
                verifier_pack=pack,
            )
            self.assertEqual(
                r.assurance["verifier_pack"]["secrecy"], "readable_in_judge_process"
            )

    def test_blackbox_subprocess_pack_secrecy_is_reported_honestly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = self._repo_pack(tmp)
            r = guard(
                repo,
                _block("calc/note.py", "# ok\n"),
                verifier_pack=pack,
                blackbox=True,
                blackbox_only=True,
            )
            self.assertEqual(
                r.assurance["verifier_pack"]["secrecy"], "reachable_same_host"
            )


if __name__ == "__main__":
    unittest.main()
