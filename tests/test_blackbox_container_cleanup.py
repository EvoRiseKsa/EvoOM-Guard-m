# -----------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available - see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Candidate Docker containers are reaped when the black-box judge is aborted."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

import evoom_guard.blackbox as blackbox_module
from evoom_guard.blackbox import run_blackbox
from evoom_guard.candidate_runner import CANDIDATE_CID_DIRNAME, CandidateRunner
from evoom_guard.guard import ERROR, REASON_RUNTIME_CLEANUP_FAILED, guard

_CID_A = "a" * 64
_CID_B = "b" * 64


class _TimedOutJudgeProcess:
    pid = 4321
    returncode: int | None = None

    def __init__(self, primary: BaseException) -> None:
        self.primary = primary
        self.wait_calls = 0

    def communicate(self, *, timeout: int) -> tuple[str, str]:
        del timeout
        raise self.primary

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, *, timeout: float) -> int:
        del timeout
        self.wait_calls += 1
        if self.wait_calls == 1:
            raise subprocess.TimeoutExpired(["pytest"], 2)
        self.returncode = -9
        return self.returncode

    def terminate(self) -> None:
        raise AssertionError("POSIX judge cleanup must signal the process group")

    def kill(self) -> None:
        raise AssertionError("POSIX judge cleanup must signal the process group")


class _CompletedLeaderWithDescendant(_TimedOutJudgeProcess):
    def __init__(self) -> None:
        super().__init__(RuntimeError("unused"))
        self.returncode = 0

    def communicate(self, *, timeout: int) -> tuple[str, str]:
        del timeout
        return "judge output", ""


class _DockerEvidence:
    def as_dict(self) -> dict[str, object]:
        return {
            "requested": "docker",
            "delivered": "docker",
            "image_digest": "sha256:judge-pinned-image",
        }


class _ObservedInvocationRecorder:
    path = "/judge/invocation.sock"
    token = "observed-invocation"

    def drain(self) -> int:
        return 1

    def close(self) -> None:
        return None


def _repo_pack_candidate(tmp_path: Path) -> tuple[Path, Path, str]:
    repo = tmp_path / "repo"
    pack = tmp_path / "pack"
    repo.mkdir()
    pack.mkdir()
    (repo / "app.py").write_text("value = 1\n", encoding="utf-8")
    (pack / "test_protocol.py").write_text(
        "def test_protocol():\n    assert True\n", encoding="utf-8"
    )
    candidate = "<<<FILE: app.py>>>\nvalue = 2\n<<<END FILE>>>\n"
    return repo, pack, candidate


def _prepare_with_cid(
    _runner: CandidateRunner, workdir: str, _target: str
) -> tuple[str, dict[str, str], _DockerEvidence]:
    cidfile_dir = Path(workdir, CANDIDATE_CID_DIRNAME)
    cidfile_dir.mkdir()
    (cidfile_dir / "candidate.cid").write_text(_CID_A + "\n", encoding="ascii")
    return "launcher", {"EVOGUARD_TARGET": "candidate"}, _DockerEvidence()


def _completed_judge(
    command: list[str], **_kwargs: object
) -> subprocess.CompletedProcess[str]:
    xml_arg = next(part for part in command if part.startswith("--junitxml="))
    Path(xml_arg.split("=", 1)[1]).write_text(
        '<testsuites><testsuite tests="1" failures="0" errors="0">'
        '<testcase name="ok"/></testsuite></testsuites>',
        encoding="utf-8",
    )
    return subprocess.CompletedProcess(command, 0, "", "")


def test_judge_timeout_kills_the_isolated_process_group_and_preserves_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _TimedOutJudgeProcess(
        subprocess.TimeoutExpired(["pytest"], timeout=1)
    )
    popen_kwargs: dict[str, object] = {}
    group_signals: list[tuple[int, int]] = []
    group_alive = True

    def fake_popen(command: list[str], **kwargs: object) -> _TimedOutJudgeProcess:
        assert command == ["pytest"]
        popen_kwargs.update(kwargs)
        return process

    def fake_killpg(process_group: int, sig: int) -> None:
        nonlocal group_alive
        if sig == 0:
            if group_alive:
                return
            raise ProcessLookupError(process_group)
        group_signals.append((process_group, int(sig)))
        if int(sig) == int(getattr(signal, "SIGKILL", 9)):
            group_alive = False
            process.returncode = -9

    monkeypatch.setattr(blackbox_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(blackbox_module.os, "name", "posix")
    monkeypatch.setattr(blackbox_module.os, "killpg", fake_killpg, raising=False)
    monkeypatch.setattr(blackbox_module, "_JUDGE_TERMINATION_GRACE_SECONDS", 0.0)

    with pytest.raises(subprocess.TimeoutExpired):
        blackbox_module._run_judge_process(
            ["pytest"], cwd="/judge", env={}, timeout=1
        )

    assert popen_kwargs["start_new_session"] is True
    assert group_signals == [
        (process.pid, int(signal.SIGTERM)),
        (process.pid, int(getattr(signal, "SIGKILL", 9))),
    ]
    assert process.poll() == -9


def test_completed_leader_still_cleans_its_live_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _CompletedLeaderWithDescendant()
    group_alive = True
    group_signals: list[int] = []

    def fake_killpg(_process_group: int, sig: int) -> None:
        nonlocal group_alive
        if sig == 0:
            if group_alive:
                return
            raise ProcessLookupError
        group_signals.append(int(sig))
        if int(sig) == int(signal.SIGTERM):
            group_alive = False

    monkeypatch.setattr(
        blackbox_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(blackbox_module.os, "name", "posix")
    monkeypatch.setattr(blackbox_module.os, "killpg", fake_killpg, raising=False)

    completed = blackbox_module._run_judge_process(
        ["pytest"], cwd="/judge", env={}, timeout=1
    )

    assert completed.returncode == 0
    assert completed.stdout == "judge output"
    assert group_signals == [int(signal.SIGTERM)]


def test_surviving_group_after_sigkill_is_an_explicit_cleanup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _CompletedLeaderWithDescendant()

    def immortal_group(_process_group: int, _sig: int) -> None:
        return None

    monkeypatch.setattr(blackbox_module.os, "name", "posix")
    monkeypatch.setattr(blackbox_module.os, "killpg", immortal_group, raising=False)
    monkeypatch.setattr(blackbox_module, "_JUDGE_TERMINATION_GRACE_SECONDS", 0.0)

    with pytest.raises(
        blackbox_module.JudgeProcessCleanupError, match="survived SIGKILL"
    ):
        blackbox_module._terminate_judge_process_group(process)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group contract")
def test_normal_completion_reaps_term_ignoring_background_descendant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ready = tmp_path / "child-ready"
    survived = tmp_path / "child-survived"
    child_code = (
        "import signal, sys, time\n"
        "from pathlib import Path\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "Path(sys.argv[1]).write_text('ready')\n"
        "time.sleep(5)\n"
        "Path(sys.argv[2]).write_text('survived')\n"
    )
    parent_code = (
        "import subprocess, sys, time\n"
        "from pathlib import Path\n"
        "ready, survived = sys.argv[1], sys.argv[2]\n"
        "subprocess.Popen(\n"
        "    [sys.executable, '-c', sys.argv[3], ready, survived],\n"
        "    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,\n"
        "    stderr=subprocess.DEVNULL, close_fds=True,\n"
        ")\n"
        "deadline = time.monotonic() + 3\n"
        "while not Path(ready).exists() and time.monotonic() < deadline:\n"
        "    time.sleep(0.01)\n"
        "if not Path(ready).exists():\n"
        "    raise SystemExit('child did not become ready')\n"
    )
    monkeypatch.setattr(blackbox_module, "_JUDGE_TERMINATION_GRACE_SECONDS", 0.5)

    completed = blackbox_module._run_judge_process(
        [sys.executable, "-c", parent_code, str(ready), str(survived), child_code],
        cwd=str(tmp_path),
        env=dict(os.environ),
        timeout=5,
    )

    assert completed.returncode == 0
    assert ready.exists()
    # The child ignored TERM and closed the captured streams. A clean return
    # therefore proves the post-completion PGID check escalated to KILL.
    time.sleep(0.05)
    assert not survived.exists()


def test_judge_cleanup_baseexception_cannot_mask_original_interrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _TimedOutJudgeProcess(KeyboardInterrupt("stop judge"))

    monkeypatch.setattr(
        blackbox_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        blackbox_module,
        "_terminate_judge_process_group",
        lambda _process: (_ for _ in ()).throw(SystemExit("cleanup failed")),
    )

    with pytest.raises(KeyboardInterrupt, match="stop judge"):
        blackbox_module._run_judge_process(
            ["pytest"], cwd="/judge", env={}, timeout=1
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable launcher contract")
def test_launcher_allocates_parallel_unique_cidfiles_outside_target(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    cidfile_dir = tmp_path / CANDIDATE_CID_DIRNAME
    cidfile_dir.mkdir()
    echo_argv = "import json, sys; print(json.dumps(sys.argv), flush=True)"
    launcher = CandidateRunner._write_launcher(
        str(tmp_path),
        {
            "mode": "docker",
            "prefix": [
                sys.executable,
                "-c",
                echo_argv,
                "docker",
                "run",
                "--rm",
                "sha256:pinned",
            ],
            "cidfile_dir": str(cidfile_dir),
        },
    )

    processes = [
        subprocess.Popen(
            [launcher, f"payload-{index}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for index in range(2)
    ]
    argvs: list[list[str]] = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, stderr
        argvs.append(json.loads(stdout))

    cid_paths: list[Path] = []
    for index, argv in enumerate(argvs):
        cid_index = argv.index("--cidfile")
        cid_path = Path(argv[cid_index + 1])
        cid_paths.append(cid_path)
        assert cid_path.parent == cidfile_dir
        assert cid_path.suffix == ".cid"
        assert target not in cid_path.parents
        assert argv[cid_index + 2] == "sha256:pinned"
        assert argv[-1] == f"payload-{index}"
        assert "--rm" in argv
    assert cid_paths[0] != cid_paths[1]


def test_prepare_container_configures_judge_owned_cid_directory(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    runner = CandidateRunner(isolation="docker", docker_image="mutable:tag")
    with (
        mock.patch("evoom_guard.candidate_runner.os.name", "posix"),
        mock.patch(
            "evoom_guard.candidate_runner.shutil.which", return_value="/usr/bin/docker"
        ),
        mock.patch(
            "evoom_guard.candidate_runner.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout="28", stderr=""),
        ),
        mock.patch.object(CandidateRunner, "_ensure_image", return_value="sha256:pinned"),
    ):
        launcher, _env, _evidence = runner.prepare(str(tmp_path), str(target))

    cfg = json.loads(Path(launcher + ".json").read_text(encoding="utf-8"))
    launcher_body = Path(launcher).read_text(encoding="utf-8")
    cidfile_dir = Path(cfg["cidfile_dir"])
    assert cidfile_dir == tmp_path / CANDIDATE_CID_DIRNAME
    assert target not in cidfile_dir.parents
    assert cfg["prefix"][-1] == "sha256:pinned"
    assert cfg["prefix"][:3] == ["docker", "run", "--rm"]
    assert "secrets.token_hex(16)" in launcher_body
    assert "['--cidfile', cidfile, prefix[-1]]" in launcher_body
    assert "os.execvp(cmd[0], cmd)" in launcher_body


def test_cleanup_parses_only_valid_cids_and_continues_after_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cidfile_dir = tmp_path / CANDIDATE_CID_DIRNAME
    cidfile_dir.mkdir()
    (cidfile_dir / "01-valid.cid").write_text(_CID_A + "\n", encoding="ascii")
    (cidfile_dir / "02-duplicate.cid").write_text(_CID_A, encoding="ascii")
    (cidfile_dir / "03-valid.cid").write_text(_CID_B, encoding="ascii")
    (cidfile_dir / "04-option.cid").write_text("--force", encoding="ascii")
    (cidfile_dir / "05-short.cid").write_text("c" * 63, encoding="ascii")
    (cidfile_dir / "06-extra.cid").write_text(_CID_A + "\nattack", encoding="ascii")
    (cidfile_dir / "ignored.txt").write_text("d" * 64, encoding="ascii")
    (cidfile_dir / "directory.cid").mkdir()

    calls: list[tuple[list[str], dict[str, object]]] = []
    present = {_CID_A, _CID_B}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs))
        if command[1] == "ps":
            container_id = command[-1].removeprefix("id=")
            stdout = container_id + "\n" if container_id in present else ""
            return subprocess.CompletedProcess(command, 0, stdout, "")
        if command[-1] == _CID_A:
            raise OSError("transient Docker failure")
        present.discard(command[-1])
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(blackbox_module.subprocess, "run", fake_run)
    blackbox_module._cleanup_candidate_containers(str(cidfile_dir))

    assert [command for command, _kwargs in calls if command[1] == "rm"] == [
        ["docker", "rm", "-f", _CID_A],
        ["docker", "rm", "-f", _CID_B],
    ]
    for _command, kwargs in calls:
        assert kwargs == {
            "capture_output": True,
            "text": True,
            "timeout": 30,
            "check": False,
        }


def test_strict_cid_directory_scan_failure_is_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cidfile_dir = tmp_path / CANDIDATE_CID_DIRNAME
    cidfile_dir.mkdir()

    def unreadable(_path: str) -> object:
        raise PermissionError("cid directory unreadable")

    monkeypatch.setattr(blackbox_module.os, "scandir", unreadable)

    assert blackbox_module._candidate_container_ids(str(cidfile_dir)) == []
    with pytest.raises(
        blackbox_module.CandidateContainerCleanupError,
        match="could not scan candidate cidfile directory",
    ):
        blackbox_module._candidate_container_ids(str(cidfile_dir), strict=True)


def test_known_absent_container_is_a_success_even_when_rescan_is_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cidfile_dir = tmp_path / CANDIDATE_CID_DIRNAME
    cidfile_dir.mkdir()
    calls: list[list[str]] = []

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert command[1] == "ps"
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(blackbox_module.subprocess, "run", fake_run)
    blackbox_module._cleanup_candidate_containers(
        str(cidfile_dir),
        strict=True,
        known_container_ids={_CID_A},
    )

    assert len(calls) == 1
    assert calls[0][-1] == f"id={_CID_A}"


@pytest.mark.parametrize("rescan_failure", ["empty", "exception"])
def test_observed_cid_cannot_be_forgotten_before_public_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rescan_failure: str,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    scan_calls = 0

    def changing_scan(_cidfile_dir: str, *, strict: bool = False) -> list[str]:
        nonlocal scan_calls
        scan_calls += 1
        if scan_calls == 1:
            return [_CID_A]
        if scan_calls == 2 and rescan_failure == "exception":
            assert strict is True
            raise blackbox_module.CandidateContainerCleanupError(
                "transient cidfile rescan failure"
            )
        return []

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        if command[1] == "ps":
            # The empty-rescan case must still probe the CID saved during the
            # evidence pass. Keep it present so a failed removal is decisive.
            stdout = _CID_A + "\n" if rescan_failure == "empty" else ""
            return subprocess.CompletedProcess(command, 0, stdout, "")
        assert command[:3] == ["docker", "rm", "-f"]
        return subprocess.CompletedProcess(command, 1, "", "removal rejected")

    monkeypatch.setattr(
        blackbox_module._InvocationRecorder,
        "create",
        lambda _workdir: _ObservedInvocationRecorder(),
    )
    monkeypatch.setattr(CandidateRunner, "prepare", _prepare_with_cid)
    monkeypatch.setattr(blackbox_module, "_run_judge_process", _completed_judge)
    monkeypatch.setattr(blackbox_module, "_candidate_container_ids", changing_scan)
    monkeypatch.setattr(blackbox_module.subprocess, "run", fake_run)

    raw = run_blackbox(
        str(repo), candidate, str(pack), isolation="docker", docker_image="image"
    )

    assert raw.passed is False
    assert raw.ran is False
    assert raw.error == "candidate container cleanup failed"
    assert raw.execution_state == "started_incomplete"
    assert raw.candidate_launcher_invocation_observed is True

    monkeypatch.setattr(blackbox_module, "run_blackbox", lambda *_a, **_k: raw)
    public = guard(
        str(repo),
        candidate,
        verifier_pack=str(pack),
        blackbox=True,
        blackbox_only=True,
        isolation="docker",
        docker_image="image",
        require_candidate_isolation="docker",
    )
    assert public.verdict == ERROR
    assert public.passed is False
    assert public.reason_code == REASON_RUNTIME_CLEANUP_FAILED
    assert public.verdict_source is None
    assert public.execution_state == "started_incomplete"


def test_timeout_force_removes_candidate_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    cleanup_commands: list[list[str]] = []
    container_present = True

    def timed_out_judge(command: list[str], **_kwargs: object) -> None:
        raise subprocess.TimeoutExpired(command, 1)

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal container_present
        if command[1] == "ps":
            stdout = _CID_A + "\n" if container_present else ""
            return subprocess.CompletedProcess(command, 0, stdout, "")
        assert command[:3] == ["docker", "rm", "-f"]
        cleanup_commands.append(command)
        container_present = False
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(CandidateRunner, "prepare", _prepare_with_cid)
    monkeypatch.setattr(blackbox_module, "_run_judge_process", timed_out_judge)
    monkeypatch.setattr(blackbox_module.subprocess, "run", fake_run)
    monkeypatch.setattr(blackbox_module.time, "sleep", lambda _seconds: None)

    result = run_blackbox(
        str(repo), candidate, str(pack), timeout=1, isolation="docker"
    )

    assert result.error == "timeout"
    assert cleanup_commands == [["docker", "rm", "-f", _CID_A]]


@pytest.mark.parametrize("failure", ["nonzero", "timeout"])
def test_normal_judge_cleanup_failure_cannot_return_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[1] == "ps":
            return subprocess.CompletedProcess(command, 0, _CID_A + "\n", "")
        assert command[:3] == ["docker", "rm", "-f"]
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, timeout=30)
        return subprocess.CompletedProcess(command, 1, "", "daemon rejected removal")

    monkeypatch.setattr(CandidateRunner, "prepare", _prepare_with_cid)
    monkeypatch.setattr(blackbox_module, "_run_judge_process", _completed_judge)
    monkeypatch.setattr(blackbox_module.subprocess, "run", fake_run)

    result = run_blackbox(
        str(repo), candidate, str(pack), timeout=1, isolation="docker"
    )

    assert result.passed is False
    assert result.ran is False
    assert result.error == "candidate container cleanup failed"
    assert _CID_A in result.diagnostics
    assert result.started is True
    assert result.completed is False
    assert result.execution_state == "started_incomplete"


def test_normal_judge_cleanup_success_preserves_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    container_present = True
    cleanup_commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal container_present
        if command[1] == "ps":
            stdout = _CID_A + "\n" if container_present else ""
            return subprocess.CompletedProcess(command, 0, stdout, "")
        cleanup_commands.append(command)
        container_present = False
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(CandidateRunner, "prepare", _prepare_with_cid)
    monkeypatch.setattr(blackbox_module, "_run_judge_process", _completed_judge)
    monkeypatch.setattr(blackbox_module.subprocess, "run", fake_run)

    result = run_blackbox(
        str(repo), candidate, str(pack), timeout=1, isolation="docker"
    )

    assert result.passed is True
    assert result.ran is True
    assert result.error is None
    assert cleanup_commands == [["docker", "rm", "-f", _CID_A]]


def test_keyboard_interrupt_is_preserved_after_cleanup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    cleanup_commands: list[list[str]] = []

    def interrupted_judge(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt("stop the judge")

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[1] == "ps":
            return subprocess.CompletedProcess(command, 0, _CID_A + "\n", "")
        assert command[:3] == ["docker", "rm", "-f"]
        cleanup_commands.append(command)
        raise OSError("daemon disappeared during cleanup")

    monkeypatch.setattr(CandidateRunner, "prepare", _prepare_with_cid)
    monkeypatch.setattr(blackbox_module, "_run_judge_process", interrupted_judge)
    monkeypatch.setattr(blackbox_module.subprocess, "run", fake_run)
    monkeypatch.setattr(blackbox_module.time, "sleep", lambda _seconds: None)

    with pytest.raises(KeyboardInterrupt, match="stop the judge"):
        run_blackbox(str(repo), candidate, str(pack), isolation="docker")

    assert cleanup_commands == [["docker", "rm", "-f", _CID_A]]


def test_cleanup_keyboard_interrupt_is_not_hidden_after_normal_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)

    def completed(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        xml_arg = next(part for part in command if part.startswith("--junitxml="))
        Path(xml_arg.split("=", 1)[1]).write_text(
            '<testsuites><testsuite tests="1" failures="0" errors="0">'
            '<testcase name="ok"/></testsuite></testsuites>',
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    def interrupted_cleanup(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt("operator stopped cleanup")

    monkeypatch.setattr(CandidateRunner, "prepare", _prepare_with_cid)
    monkeypatch.setattr(blackbox_module, "_run_judge_process", completed)
    monkeypatch.setattr(
        blackbox_module, "_cleanup_candidate_containers", interrupted_cleanup
    )

    with pytest.raises(KeyboardInterrupt, match="operator stopped cleanup"):
        run_blackbox(str(repo), candidate, str(pack), isolation="docker")


def test_cleanup_baseexception_does_not_mask_original_keyboard_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)

    def interrupted_judge(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt("operator stopped judge")

    def exiting_cleanup(*_args: object, **_kwargs: object) -> None:
        raise SystemExit("cleanup exit")

    monkeypatch.setattr(CandidateRunner, "prepare", _prepare_with_cid)
    monkeypatch.setattr(blackbox_module, "_run_judge_process", interrupted_judge)
    monkeypatch.setattr(blackbox_module, "_cleanup_candidate_containers", exiting_cleanup)

    with pytest.raises(KeyboardInterrupt, match="operator stopped judge"):
        run_blackbox(str(repo), candidate, str(pack), isolation="docker")
