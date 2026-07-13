# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""The candidate launcher must never invoke a shell.

`CandidateRunner` builds a launcher that runs the candidate under the delivered
isolation. Container options (`docker_network`, `docker_image`, runtime) come
from the workflow owner, not the candidate — but building a shell command by
string-joining them is still a command-injection surface a security reviewer
will (rightly) flag. These tests pin that the launcher execs an argv **list**
via ``os.execvp`` with no shell, so a value like ``none; touch PWNED`` is passed
literally and never interpreted.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

from evoom_guard.candidate_runner import CandidateRunner, IsolationUnavailable


class LauncherIsShellFreeTests(unittest.TestCase):
    def test_generated_launcher_uses_execvp_not_a_shell(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            launcher = CandidateRunner._write_launcher(
                tmp, {"mode": "docker", "prefix": ["docker", "run", "img"]}
            )
            body = open(launcher, encoding="utf-8").read()
            self.assertIn("os.execvp", body)
            self.assertNotIn("/bin/sh", body)
            self.assertNotIn("shell=True", body)

    @unittest.skipIf(os.name == "nt", "POSIX executable launcher contract")
    def test_launcher_does_not_interpret_shell_metacharacters(self) -> None:
        # The "prefix" stands in for the docker argv; here it just echoes the argv
        # it receives. We invoke the launcher with an injection-looking argument
        # and prove (a) no shell ran (no PWNED file) and (b) the argument arrived
        # as one literal string.
        with tempfile.TemporaryDirectory() as tmp:
            prefix = [
                sys.executable, "-c",
                "import sys, pathlib; pathlib.Path('ARGV').write_text(repr(sys.argv[1:]))",
            ]
            launcher = CandidateRunner._write_launcher(tmp, {"mode": "docker", "prefix": prefix})
            payload = "x; touch PWNED"
            subprocess.run([launcher, payload], cwd=tmp, capture_output=True, text=True, timeout=30)
            self.assertFalse(os.path.exists(os.path.join(tmp, "PWNED")),
                             "a shell ran — injection succeeded")
            argv = open(os.path.join(tmp, "ARGV"), encoding="utf-8").read()
            self.assertIn(payload, argv)  # arrived as a single literal element

    @unittest.skipIf(os.name == "nt", "POSIX executable launcher contract")
    def test_subprocess_launcher_runs_in_the_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "t")
            os.makedirs(target)
            launcher = CandidateRunner._write_launcher(tmp, {"mode": "subprocess", "target": target})
            r = subprocess.run(
                [launcher, sys.executable, "-c", "import os; print(os.getcwd())"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(os.path.realpath(r.stdout.strip()), os.path.realpath(target))

    def test_windows_blackbox_launcher_fails_closed_with_guidance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = CandidateRunner(isolation="subprocess")
            # Simulate the Windows branch on every CI host; the native Windows
            # job exercises the same path without relying on this patch.
            with mock.patch("evoom_guard.candidate_runner.os.name", "nt"):
                with self.assertRaisesRegex(
                    IsolationUnavailable, "POSIX host.*WSL on Windows"
                ):
                    runner.prepare(tmp, tmp)
            self.assertFalse(os.path.exists(os.path.join(tmp, "evoguard_exec.py")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "evoguard_exec.py.json")))

    def test_windows_container_launchers_fail_before_any_docker_call(self) -> None:
        for isolation in ("docker", "gvisor"):
            with self.subTest(isolation=isolation), tempfile.TemporaryDirectory() as tmp:
                runner = CandidateRunner(
                    isolation=isolation,
                    docker_image="python:3.12-slim",
                )
                with mock.patch("evoom_guard.candidate_runner.os.name", "nt"), \
                        mock.patch("evoom_guard.candidate_runner.shutil.which") as which, \
                        mock.patch("evoom_guard.candidate_runner.subprocess.run") as run:
                    with self.assertRaisesRegex(
                        IsolationUnavailable, "POSIX host.*WSL on Windows"
                    ):
                        runner.prepare(tmp, tmp)
                which.assert_not_called()
                run.assert_not_called()
                self.assertFalse(os.path.exists(os.path.join(tmp, "evoguard_exec.py")))
                self.assertFalse(
                    os.path.exists(os.path.join(tmp, "evoguard_exec.py.json"))
                )


class ContainerPrefixTests(unittest.TestCase):
    def test_malicious_docker_network_stays_one_literal_argv_element(self) -> None:
        # Even a hostile --network value is a single argv element in the prefix, so
        # execvp hands it to docker verbatim (docker rejects it as an invalid
        # network) — it is never a shell fragment.
        evil = "none; touch PWNED"
        runner = CandidateRunner(isolation="docker", docker_image="img", docker_network=evil)
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch("evoom_guard.candidate_runner.os.name", "posix"), \
                mock.patch("evoom_guard.candidate_runner.shutil.which", return_value="/usr/bin/docker"), \
                mock.patch("evoom_guard.candidate_runner.subprocess.run",
                           return_value=types.SimpleNamespace(returncode=0, stdout="28", stderr="")), \
                mock.patch.object(CandidateRunner, "_ensure_image", return_value="sha256:abc"), \
                mock.patch.object(CandidateRunner, "_delivery_probe", return_value=None):
            launcher, _env, evidence = runner.prepare(tmp, tmp)
            cfg = json.load(open(launcher + ".json", encoding="utf-8"))
        self.assertEqual(evidence.delivered, "docker")
        self.assertEqual(cfg["prefix"][-1], "sha256:abc")
        self.assertNotIn("img", cfg["prefix"])
        cap_index = cfg["prefix"].index("--cap-drop")
        self.assertEqual(cfg["prefix"][cap_index + 1], "ALL")
        self.assertIn(evil, cfg["prefix"])                 # preserved intact…
        self.assertEqual(cfg["prefix"].count(evil), 1)     # …as exactly one element


if __name__ == "__main__":
    unittest.main()
