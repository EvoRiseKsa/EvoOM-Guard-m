"""Execution-state evidence emitted directly by :class:`RepoVerifier`."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from evoom_guard.verifiers.repo_verifier import RepoVerifier


def _write(root: str, rel: str, content: str) -> None:
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path) or root, exist_ok=True)
    with open(path, "w", encoding="utf-8") as stream:
        stream.write(content)


def _candidate() -> str:
    return "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"


class RepoExecutionTraceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = os.path.join(self.tmp.name, "repo")
        _write(self.repo, "app.py", "VALUE = 1\n")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _verify(self, *, command: list[str], **problem):
        return RepoVerifier(test_command=command, mem_limit_mb=0).verify(
            _candidate(), {"repo_path": self.repo, **problem}
        )

    def test_missing_pack_is_preflight_and_not_present(self) -> None:
        missing = os.path.join(self.tmp.name, "missing-pack")
        result = self._verify(
            command=[sys.executable, "-c", "raise SystemExit(0)"],
            verifier_pack=missing,
        )

        self.assertEqual(result.artifact["outcome"], "pack_invalid")
        self.assertFalse(result.artifact["verifier_pack_present"])
        self.assertEqual(result.artifact["execution_state"], "not_started")
        self.assertEqual(result.artifact["execution_phase"], "preflight")
        self.assertFalse(result.artifact["test_command_started"])
        self.assertEqual(result.artifact["delivered_isolation"], "not_run")

    def test_suite_file_not_found_did_not_start_target(self) -> None:
        result = self._verify(command=["definitely-not-an-executable"])

        self.assertEqual(result.artifact["outcome"], "test_command_unavailable")
        self.assertEqual(result.artifact["execution_state"], "not_started")
        self.assertEqual(result.artifact["execution_phase"], "repo_suite")
        self.assertFalse(result.artifact["test_command_started"])
        self.assertFalse(result.artifact["test_command_completed"])
        self.assertEqual(result.artifact["delivered_isolation"], "not_run")

    def test_suite_timeout_records_started_but_incomplete(self) -> None:
        timeout = subprocess.TimeoutExpired(["judge"], 1)
        with mock.patch(
            "evoom_guard.verifiers.repo_verifier._run_bounded_subprocess",
            side_effect=timeout,
        ):
            result = self._verify(command=["judge"])

        self.assertEqual(result.artifact["execution_state"], "started_incomplete")
        self.assertEqual(result.artifact["execution_phase"], "repo_suite")
        self.assertTrue(result.artifact["test_command_started"])
        self.assertFalse(result.artifact["test_command_completed"])
        self.assertEqual(result.artifact["delivered_isolation"], "subprocess")

    def test_completed_suite_records_completed_even_without_junit(self) -> None:
        result = self._verify(
            command=[sys.executable, "-c", "raise SystemExit(0)"]
        )

        self.assertEqual(result.artifact["execution_state"], "completed")
        self.assertEqual(result.artifact["execution_phase"], "repo_suite")
        self.assertTrue(result.artifact["test_command_started"])
        self.assertTrue(result.artifact["test_command_completed"])
        self.assertFalse(result.artifact["verifier_pack_started"])

    def test_pack_timeout_preserves_completed_suite_evidence(self) -> None:
        pack = os.path.join(self.tmp.name, "pack")
        _write(pack, "test_contract.py", "def test_contract():\n    assert True\n")

        def run(command, **kwargs):
            if "pytest" in command and any("evo_pack_snapshot_" in p for p in command):
                raise subprocess.TimeoutExpired(command, 1)
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        with mock.patch(
            "evoom_guard.verifiers.repo_verifier._run_bounded_subprocess",
            side_effect=run,
        ):
            result = self._verify(
                command=[sys.executable, "-c", "raise SystemExit(0)"],
                verifier_pack=pack,
            )

        self.assertEqual(result.artifact["execution_state"], "started_incomplete")
        self.assertEqual(result.artifact["execution_phase"], "verifier_pack")
        self.assertTrue(result.artifact["test_command_started"])
        self.assertTrue(result.artifact["test_command_completed"])
        self.assertTrue(result.artifact["verifier_pack_started"])
        self.assertFalse(result.artifact["verifier_pack_completed"])
        self.assertTrue(result.artifact["verifier_pack_present"])

    def test_docker_exit_125_did_not_start_suite_target(self) -> None:
        verifier = RepoVerifier(
            test_command=["python", "-c", "pass"],
            isolation="docker",
            docker_image="judge:latest",
            mem_limit_mb=0,
        )
        process = subprocess.CompletedProcess(
            ["docker", "run"], 125, stdout="", stderr="daemon unavailable"
        )
        host_xml = os.path.join(self.tmp.name, "not-created.xml")
        with mock.patch.object(
            verifier, "_resolve_docker_image", return_value="sha256:judge"
        ), mock.patch.object(
            verifier, "_run_docker", return_value=(host_xml, process, False)
        ):
            result = verifier.verify(_candidate(), {"repo_path": self.repo})

        self.assertEqual(result.artifact["execution_state"], "not_started")
        self.assertFalse(result.artifact["test_command_started"])
        self.assertEqual(result.artifact["delivered_isolation"], "not_run")

    def test_docker_runner_cleans_up_on_base_exception_and_reraises(self) -> None:
        verifier = RepoVerifier(
            isolation="docker", docker_image="judge:latest", mem_limit_mb=0
        )
        with mock.patch.object(
            verifier, "_docker_command", return_value=["docker", "run"]
        ), mock.patch(
            "evoom_guard.verifiers.repo_verifier._run_bounded_subprocess",
            side_effect=KeyboardInterrupt(),
        ) as run, mock.patch(
            "evoom_guard.verifiers.repo_verifier._cleanup_docker_container",
            return_value=True,
        ) as cleanup:
            with self.assertRaises(KeyboardInterrupt):
                verifier._run_docker(["python"], self.repo, self.tmp.name)

        self.assertEqual(run.call_count, 1)
        cleanup_name = cleanup.call_args.args[0]
        self.assertTrue(cleanup_name.startswith("evoguard_"))

    def test_docker_setup_cleans_up_on_base_exception_and_reraises(self) -> None:
        verifier = RepoVerifier(
            setup_command=["prepare"],
            test_command=["python", "-c", "pass"],
            isolation="docker",
            docker_image="judge:latest",
            mem_limit_mb=0,
        )
        with mock.patch.object(
            verifier, "_resolve_docker_image", return_value="sha256:judge"
        ), mock.patch(
            "evoom_guard.verifiers.repo_verifier._run_bounded_subprocess",
            side_effect=KeyboardInterrupt(),
        ) as run, mock.patch(
            "evoom_guard.verifiers.repo_verifier._cleanup_docker_container",
            return_value=True,
        ) as cleanup:
            with self.assertRaises(KeyboardInterrupt):
                verifier.verify(_candidate(), {"repo_path": self.repo})

        self.assertEqual(run.call_count, 1)
        cleanup_name = cleanup.call_args.args[0]
        self.assertTrue(cleanup_name.startswith("evoguard_setup_"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
