# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Docker E2E: prove the black-box candidate boundary ISOLATES, on a real daemon.

The unit tests prove the *fail-closed* half — a container that cannot be
delivered never yields a PASS. They cannot prove the other half: that when Docker
IS available, the candidate is really confined and cannot reach the host, the
judge-owned pack, or the judge's report. That is an operating-system property of
a live container, so it is proven here against a real daemon (skipped when none
is reachable — e.g. this repo's sandbox; run in CI, which has Docker).

The design makes the isolation proof self-certifying: a **malicious probe
candidate** actively tries every escape (write the read-only repo mount, write
the container root, open a network socket, locate the pack/report) and prints the
outcome; a judge-owned pack asserts every attempt was BLOCKED/ABSENT. So a
`PASS` verdict *is* the proof the boundary held — and any breach flips the pack to
a `FAIL`, failing this test loudly rather than silently shipping a hole.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest

from evoom_guard.guard import ERROR, FAIL, PASS, guard

E2E_IMAGE = os.environ.get("EVOGUARD_E2E_IMAGE", "python:3.12-slim")
# A runner-bearing image (has pytest) for the composite-under-docker case; when
# unset that one test skips, since python:slim has no test runner to run the
# repo's own suite inside the container.
E2E_PYTEST_IMAGE = os.environ.get("EVOGUARD_E2E_PYTEST_IMAGE")


def _docker_daemon_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True, timeout=30,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _ensure_image(image: str) -> bool:
    try:
        if subprocess.run(["docker", "image", "inspect", image],
                          capture_output=True, timeout=60).returncode == 0:
            return True
        return subprocess.run(["docker", "pull", image],
                              capture_output=True, timeout=600).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _w(root: str, rel: str, content: str) -> None:
    p = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(p) or root, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)


def _block(path: str, content: str) -> str:
    return f"<<<FILE: {path}>>>\n{content}<<<END FILE>>>\n"


# A candidate that, on `probe`, ACTIVELY attempts to escape the container and
# reports what it managed; on `add`/`mul` it behaves normally.
PROBE_MAIN = r'''
import json, os, socket, sys


def _probe():
    out = {}
    # (5) the repo copy must be mounted READ-ONLY
    try:
        open("/candidate/PWNED_repo", "w").write("x"); out["repo_write"] = "ALLOWED"
    except OSError:
        out["repo_write"] = "BLOCKED"
    # (2) no writable host outside the sanctioned tmpfs — the root fs is read-only
    try:
        open("/PWNED_root", "w").write("x"); out["root_write"] = "ALLOWED"
    except OSError:
        out["root_write"] = "BLOCKED"
    # (6) network must be 'none'
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=3); out["net"] = "ALLOWED"
    except OSError:
        out["net"] = "BLOCKED"
    # (3)(4) the judge-owned pack and report must not exist in the container
    markers = ("test_pack.py", "pack.json", "judge-blackbox.xml")
    found = False
    for base in ("/candidate", "/tmp", "/root", "/home", "/work"):
        for dp, _dn, fs in os.walk(base):
            if any(m in fs for m in markers):
                found = True
    out["pack_or_report"] = "FOUND" if found else "ABSENT"
    print(json.dumps(out))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "probe":
        _probe()
    else:
        from calc.ops import add, mul
        _, op, a, b = sys.argv
        print((add if op == "add" else mul)(int(a), int(b)))
'''

PROBE_PACK = r'''
import json, os, subprocess, sys


def _run(*a):
    py = os.environ.get("EVOGUARD_PYTHON") or sys.executable
    ex = os.environ.get("EVOGUARD_EXEC")
    cmd = [ex, py, "-m", "calc", *a] if ex else [py, "-m", "calc", *a]
    cwd = None if ex else os.environ.get("EVOGUARD_TARGET")
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True).stdout.strip()


def test_isolation_holds():
    data = json.loads(_run("probe"))
    # Every escape the candidate tried must have failed.
    assert data["repo_write"] == "BLOCKED", data
    assert data["root_write"] == "BLOCKED", data
    assert data["net"] == "BLOCKED", data
    assert data["pack_or_report"] == "ABSENT", data
'''

ADD_PACK = (
    "import os, subprocess, sys\n"
    "def _run(*a):\n"
    "    py = os.environ.get('EVOGUARD_PYTHON') or sys.executable\n"
    "    ex = os.environ.get('EVOGUARD_EXEC')\n"
    "    cmd = [ex, py, '-m', 'calc', *a] if ex else [py, '-m', 'calc', *a]\n"
    "    cwd = None if ex else os.environ.get('EVOGUARD_TARGET')\n"
    "    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True).stdout.strip()\n"
    "def test_add():\n    assert _run('add', '2', '3') == '5'\n"
)
OPS = "def add(a, b):\n    return a + b\n\ndef mul(a, b):\n    return a * b\n"


@unittest.skipUnless(_docker_daemon_ok(), "needs a reachable Docker daemon (run in CI)")
class BlackboxDockerE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not _ensure_image(E2E_IMAGE):
            raise unittest.SkipTest(f"could not obtain image {E2E_IMAGE!r}")

    def _probe_repo_pack(self, tmp: str) -> tuple[str, str]:
        repo = os.path.join(tmp, "repo")
        _w(repo, "calc/__init__.py", "")
        _w(repo, "calc/ops.py", OPS)
        _w(repo, "calc/__main__.py", PROBE_MAIN)
        pack = os.path.join(tmp, "pack")
        _w(pack, "test_pack.py", PROBE_PACK)
        return repo, pack

    # ---- the core proof: a malicious candidate cannot escape the container ---- #
    def test_candidate_is_actually_confined(self) -> None:
        # (2)(3)(4)(5)(6) all at once: the probe tries host writes, network, and
        # locating the pack/report; the pack asserts each failed. PASS == isolated.
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = self._probe_repo_pack(tmp)
            r = guard(
                repo, _block("calc/note.py", "# ok\n"), verifier_pack=pack,
                blackbox=True, blackbox_only=True,
                isolation="docker", docker_image=E2E_IMAGE,
                require_candidate_isolation="docker",
                require_report_integrity="external_process_isolated",
            )
            self.assertEqual(r.verdict, PASS, r.diagnostics)
            self.assertEqual(r.assurance["candidate_isolation"], "docker")

    # ---- (1) a nonexistent image fails closed, never a silent host fallback --- #
    def test_missing_image_errors_no_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = self._probe_repo_pack(tmp)
            r = guard(
                repo, _block("calc/note.py", "# ok\n"), verifier_pack=pack,
                blackbox=True, blackbox_only=True,
                isolation="docker", docker_image="evoguard-does-not-exist:never",
                require_candidate_isolation="docker",
            )
            self.assertEqual(r.verdict, ERROR)
            self.assertNotEqual(r.assurance["candidate_isolation"], "docker")

    # ---- (9) attestation binds the delivered boundary + image digest --------- #
    def test_attestation_records_delivered_docker_and_image_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            _w(repo, "calc/__init__.py", "")
            _w(repo, "calc/ops.py", OPS)
            _w(repo, "calc/__main__.py",
               "import sys\nfrom calc.ops import add, mul\n"
               "if __name__ == '__main__':\n"
               "    _, op, a, b = sys.argv\n"
               "    print((add if op == 'add' else mul)(int(a), int(b)))\n")
            pack = os.path.join(tmp, "pack")
            _w(pack, "test_pack.py", ADD_PACK)
            r = guard(
                repo, _block("calc/note.py", "# ok\n"), verifier_pack=pack,
                blackbox=True, blackbox_only=True,
                isolation="docker", docker_image=E2E_IMAGE,
            )
            self.assertEqual(r.verdict, PASS, r.diagnostics)
            iso = r.attestation["isolation_evidence"]
            self.assertEqual(iso["delivered"], "docker")
            self.assertEqual(iso["network"], "none")
            self.assertTrue(iso["image_digest"])  # bound to the exact runtime image

    # ---- (7) a deletion is applied INSIDE the judged container --------------- #
    def test_deletion_is_applied_in_container(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            _w(repo, "calc/__init__.py", "")
            _w(repo, "calc/dep.py", "TOKEN = 1\n")
            _w(repo, "calc/ops.py",
               "from calc.dep import TOKEN\n"
               "def add(a, b):\n    return a + b + (TOKEN - 1)\n"
               "def mul(a, b):\n    return a * b\n")
            _w(repo, "calc/__main__.py",
               "import sys\nfrom calc.ops import add, mul\n"
               "if __name__ == '__main__':\n"
               "    _, op, a, b = sys.argv\n"
               "    print((add if op == 'add' else mul)(int(a), int(b)))\n")
            pack = os.path.join(tmp, "pack")
            _w(pack, "test_pack.py", ADD_PACK)
            r = guard(
                repo, _block("calc/note.py", "# ok\n"), deleted=("calc/dep.py",),
                verifier_pack=pack, blackbox=True, blackbox_only=True,
                isolation="docker", docker_image=E2E_IMAGE,
            )
            # dep.py is gone in the container → import fails → pack fails → FAIL.
            self.assertEqual(r.verdict, FAIL)
            self.assertIn("calc/dep.py", r.attestation["deleted_paths_applied"])

    # ---- (10) no containers leak after the verdict (--rm reaps them) --------- #
    def test_no_container_leak(self) -> None:
        before = subprocess.run(["docker", "ps", "-aq"], capture_output=True, text=True).stdout
        with tempfile.TemporaryDirectory() as tmp:
            repo, pack = self._probe_repo_pack(tmp)
            guard(repo, _block("calc/note.py", "# ok\n"), verifier_pack=pack,
                  blackbox=True, blackbox_only=True,
                  isolation="docker", docker_image=E2E_IMAGE)
        after = subprocess.run(["docker", "ps", "-aq"], capture_output=True, text=True).stdout
        self.assertEqual(before.split(), after.split(), "a container was left behind")

    # ---- (8) composite: a failing repo suite blocks PASS, under docker ------- #
    @unittest.skipUnless(E2E_PYTEST_IMAGE, "set EVOGUARD_E2E_PYTEST_IMAGE (image with pytest)")
    def test_repo_suite_failure_blocks_pass_under_docker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            _w(repo, "calc/__init__.py", "")
            _w(repo, "calc/ops.py", OPS)
            _w(repo, "calc/__main__.py",
               "import sys\nfrom calc.ops import add, mul\n"
               "if __name__ == '__main__':\n"
               "    _, op, a, b = sys.argv\n"
               "    print((add if op == 'add' else mul)(int(a), int(b)))\n")
            _w(repo, "tests/test_ops.py", "from calc.ops import mul\ndef test_mul():\n    assert mul(2, 3) == 6\n")
            pack = os.path.join(tmp, "pack")
            _w(pack, "test_pack.py", ADD_PACK)
            broken = "def add(a, b):\n    return a + b\n\ndef mul(a, b):\n    return a * b + 1\n"
            r = guard(
                repo, _block("calc/ops.py", broken), verifier_pack=pack, blackbox=True,
                isolation="docker", docker_image=E2E_PYTEST_IMAGE,
            )
            self.assertEqual(r.verdict, FAIL)
            self.assertIn("repo's own test suite", r.reason)
            self.assertEqual(
                r.attestation["repo_suite_image_digest"],
                r.attestation["isolation_evidence"]["image_digest"],
            )


if __name__ == "__main__":
    unittest.main()
