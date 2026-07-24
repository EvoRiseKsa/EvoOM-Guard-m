"""Deterministic pre-extraction oracle for black-box pack execution.

The harness exercises the production ``run_blackbox`` facade while replacing
only operating-system effects.  It freezes the ordering, live lookup, object
identity, lifecycle, report interpretation, and exception precedence that a
later owner extraction must preserve.
"""

from __future__ import annotations

import copy
import json
import subprocess
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from unittest.mock import patch

import evoom_guard.blackbox as blackbox_module
from evoom_guard.blackbox import BlackboxResult, run_blackbox

SCHEMA_VERSION = "blackbox-pack-phase-v1"
NORMALIZED_FIELDS = (
    "temporary_paths",
    "current_python_executable",
    "invocation_tokens",
)

CASE_NAMES = (
    "command_baseexception",
    "distiller_baseexception",
    "exit_0_mismatch",
    "exit_0_pass",
    "exit_1_fail",
    "exit_1_mismatch",
    "exit_2_error",
    "judge_cleanup_error",
    "malformed_xml",
    "missing_xml",
    "output_limit",
    "parser_baseexception",
    "post_snapshot_drift",
    "pre_snapshot_drift",
    "reader_baseexception",
    "run_baseexception",
    "timeout",
    "zero_tests",
)

_TOKEN = "blackbox-pack-characterization-token"
_CANDIDATE = "<<<FILE: app.py>>>\nvalue = 2\n<<<END FILE>>>\n"
_JUNIT_PASS = (
    '<testsuites><testsuite tests="2" failures="0" errors="0" skipped="0">'
    '<testcase name="one"/><testcase name="two"/></testsuite></testsuites>'
)
_JUNIT_FAIL = (
    '<testsuites><testsuite tests="2" failures="1" errors="0" skipped="0">'
    '<testcase name="one"><failure message="frozen"/></testcase>'
    '<testcase name="two"/></testsuite></testsuites>'
)
_JUNIT_ZERO = (
    '<testsuites><testsuite tests="0" failures="0" errors="0" skipped="0"></testsuite></testsuites>'
)
_MALFORMED_XML = "<testsuites><broken"


class _Evidence:
    def as_dict(self) -> dict[str, object]:
        return {
            "requested": "subprocess",
            "delivered": "subprocess",
            "note": "characterization boundary",
        }


class _Recorder:
    def __init__(self, workdir: str, events: list[str]) -> None:
        self.path = str(Path(workdir) / "invocation.sock")
        self.token = _TOKEN
        self._events = events

    def drain(self) -> int:
        self._events.append("evidence:drain")
        return 1

    def close(self) -> None:
        self._events.append("cleanup:recorder-close")


class _TempFactory:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.counter = 0

    def __call__(self, *, prefix: str = "tmp", **_kwargs: object) -> str:
        self.counter += 1
        path = self.root / f"{prefix}{self.counter}"
        path.mkdir(parents=True)
        return str(path)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _source_tree(workspace: Path) -> tuple[Path, Path]:
    repo = workspace / "source-repo"
    pack = workspace / "source-pack"
    repo.mkdir(parents=True)
    pack.mkdir(parents=True)
    _write(repo / "app.py", "value = 1\n")
    _write(pack / "test_protocol.py", "def test_protocol():\n    assert True\n")
    _write(
        pack / "pack.json",
        '{"id":"blackbox-pack-characterization","version":"1","target_type":"cli"}\n',
    )
    return repo, pack


def _serialize_result(result: BlackboxResult) -> dict[str, Any]:
    return {field: copy.deepcopy(getattr(result, field)) for field in result._fields}


def _normalize(
    value: Any,
    *,
    roots: tuple[str, ...],
    key: str = "",
) -> Any:
    if isinstance(value, dict):
        return {
            item_key: _normalize(item_value, roots=roots, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_normalize(item, roots=roots, key=key) for item in value]
    if not isinstance(value, str):
        return value
    normalized = value.replace(_TOKEN, "<TOKEN>")
    normalized = normalized.replace(
        str(Path(blackbox_module.sys.executable)),
        "<CURRENT_PYTHON>",
    )
    for root in sorted(set(roots), key=len, reverse=True):
        normalized = normalized.replace(root, "<TEMP>")
        normalized = normalized.replace(root.replace("\\", "/"), "<TEMP>")
        normalized = normalized.replace(root.replace("\\", "\\\\"), "<TEMP>")
    if "<TEMP>" in normalized:
        normalized = normalized.replace("\\", "/")
        while "<TEMP>//" in normalized:
            normalized = normalized.replace("<TEMP>//", "<TEMP>/")
    return normalized


def _report_for_case(case_name: str) -> str | None:
    if case_name == "missing_xml":
        return None
    if case_name == "malformed_xml":
        return _MALFORMED_XML
    if case_name == "zero_tests":
        return _JUNIT_ZERO
    if case_name in {"exit_0_mismatch", "exit_1_fail"}:
        return _JUNIT_FAIL
    return _JUNIT_PASS


def _returncode_for_case(case_name: str) -> int:
    if case_name in {"exit_1_fail", "exit_1_mismatch"}:
        return 1
    if case_name == "exit_2_error":
        return 2
    return 0


def capture_case(case_name: str, workspace: Path) -> dict[str, Any]:
    """Capture one pack-phase branch through the unchanged public facade."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown black-box pack case: {case_name}")
    workspace.mkdir(parents=True)
    repo, pack = _source_tree(workspace)
    events: list[str] = []
    state: dict[str, Any] = {
        "verify_identity_ids": [],
        "cleanup": None,
        "command_identity_preserved": None,
        "attach_manifest_identity_preserved": None,
        "attach_deleted_identity_preserved": None,
    }
    clock_values = iter((10.0, 10.5))

    real_verify = blackbox_module.verify_pack_snapshot
    real_command = blackbox_module._judge_command
    real_parse = blackbox_module.parse_junit_xml
    real_distill = blackbox_module.distill_diagnostics
    real_attach = blackbox_module._attach_candidate_execution_evidence

    def perf_counter() -> float:
        events.append("clock")
        return next(clock_values)

    verify_calls = 0

    def verify_snapshot(
        snapshot: str,
        identity: tuple[str, dict | None],
    ) -> None:
        nonlocal verify_calls
        verify_calls += 1
        events.append(f"verify:{verify_calls}")
        state["verify_identity_ids"].append(id(identity))
        state["verified_manifest"] = identity[1]
        if case_name == "pre_snapshot_drift" and verify_calls == 1:
            raise blackbox_module.PackManifestError("frozen pre-snapshot drift")
        if case_name == "post_snapshot_drift" and verify_calls == 2:
            raise blackbox_module.PackManifestError("frozen post-snapshot drift")
        real_verify(snapshot, identity)

    def judge_command(pack_snapshot: str, xml_path: str) -> list[str]:
        events.append("command")
        if case_name == "command_baseexception":
            raise KeyboardInterrupt("frozen command interrupt")
        command = real_command(pack_snapshot, xml_path)
        state["command_id"] = id(command)
        state["pack_snapshot"] = pack_snapshot
        state["xml_path"] = xml_path
        return command

    def run_judge(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        events.append("run")
        state["command_identity_preserved"] = id(command) == state.get("command_id")
        state["judge_cwd"] = kwargs.get("cwd")
        state["judge_timeout"] = kwargs.get("timeout")
        if case_name == "timeout":
            raise subprocess.TimeoutExpired(command, 7)
        if case_name == "output_limit":
            raise blackbox_module.JudgeOutputLimitError(4096)
        if case_name == "judge_cleanup_error":
            raise blackbox_module.JudgeProcessCleanupError("frozen judge cleanup failure")
        if case_name == "run_baseexception":
            raise KeyboardInterrupt("frozen run interrupt")
        return subprocess.CompletedProcess(
            command,
            _returncode_for_case(case_name),
            stdout="frozen stdout",
            stderr="frozen stderr",
        )

    report = _report_for_case(case_name)

    def read_report(path: str) -> str | None:
        events.append("read")
        state["read_path"] = path
        if case_name == "reader_baseexception":
            raise KeyboardInterrupt("frozen reader interrupt")
        return report

    def parse_report(text: str) -> object:
        events.append("parse")
        state["parsed_exact_report_object"] = text is report
        if case_name == "parser_baseexception":
            raise KeyboardInterrupt("frozen parser interrupt")
        return real_parse(text)

    def distill(output: str) -> str:
        events.append("distill")
        state["diagnostic_input"] = output
        if case_name == "distiller_baseexception":
            raise KeyboardInterrupt("frozen distiller interrupt")
        return real_distill(output)

    def create_recorder(workdir: str) -> _Recorder:
        return _Recorder(workdir, events)

    def prepare(
        _runner: object,
        workdir: str,
        target_dir: str,
    ) -> tuple[str, dict[str, str], _Evidence]:
        events.append("prepare")
        state["target_dir"] = target_dir
        return (
            "launcher",
            {
                "EVOGUARD_EXEC": "frozen-launcher",
                "EVOGUARD_TARGET": target_dir,
            },
            _Evidence(),
        )

    def attach_evidence(
        result: BlackboxResult,
        **kwargs: object,
    ) -> BlackboxResult:
        events.append("attach")
        attached = real_attach(result, **kwargs)
        state["attach_manifest_identity_preserved"] = attached.pack_manifest is result.pack_manifest
        state["attach_deleted_identity_preserved"] = (
            attached.deleted_applied is result.deleted_applied
        )
        state["attach_wait_for_late"] = kwargs.get("wait_for_late_container_evidence")
        return attached

    def cleanup(_cidfile_dir: str, **kwargs: object) -> None:
        events.append("cleanup:containers")
        state["cleanup"] = {
            "wait_for_late_cidfiles": kwargs.get("wait_for_late_cidfiles"),
            "strict": kwargs.get("strict"),
        }

    def remove_tree(path: str, **kwargs: object) -> None:
        label = "pack-workdir" if "evo_blackbox_pack_" in path else "workdir"
        events.append(f"cleanup:rmtree:{label}")
        state.setdefault("rmtree_ignore_errors", []).append(kwargs.get("ignore_errors"))

    with ExitStack() as stack:
        stack.enter_context(
            patch.object(
                blackbox_module.tempfile,
                "mkdtemp",
                side_effect=_TempFactory(workspace / "runtime-temp"),
            )
        )
        stack.enter_context(
            patch.object(blackbox_module.time, "perf_counter", side_effect=perf_counter)
        )
        stack.enter_context(
            patch.object(
                blackbox_module._InvocationRecorder,
                "create",
                side_effect=create_recorder,
            )
        )
        stack.enter_context(patch.object(blackbox_module.CandidateRunner, "prepare", prepare))
        stack.enter_context(
            patch.object(
                blackbox_module,
                "verify_pack_snapshot",
                side_effect=verify_snapshot,
            )
        )
        stack.enter_context(
            patch.object(blackbox_module, "_judge_command", side_effect=judge_command)
        )
        stack.enter_context(
            patch.object(
                blackbox_module,
                "_run_judge_process",
                side_effect=run_judge,
            )
        )
        stack.enter_context(
            patch.object(blackbox_module, "read_junit_xml", side_effect=read_report)
        )
        stack.enter_context(
            patch.object(blackbox_module, "parse_junit_xml", side_effect=parse_report)
        )
        stack.enter_context(
            patch.object(
                blackbox_module,
                "distill_diagnostics",
                side_effect=distill,
            )
        )
        stack.enter_context(
            patch.object(
                blackbox_module,
                "_attach_candidate_execution_evidence",
                side_effect=attach_evidence,
            )
        )
        stack.enter_context(
            patch.object(
                blackbox_module,
                "_cleanup_candidate_containers",
                side_effect=cleanup,
            )
        )
        stack.enter_context(patch.object(blackbox_module.shutil, "rmtree", side_effect=remove_tree))
        try:
            result = run_blackbox(
                str(repo),
                _CANDIDATE,
                str(pack),
                timeout=7,
            )
        except BaseException as exc:
            observed: dict[str, Any] = {
                "exception": {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
            }
        else:
            observed = {
                "result": _serialize_result(result),
                "result_type_exact": type(result) is BlackboxResult,
            }
            verified_manifest = state.get("verified_manifest")
            if verified_manifest is not None:
                observed["result_manifest_identity_preserved"] = (
                    result.pack_manifest is verified_manifest
                )

    state.pop("verified_manifest", None)
    identity_ids = state.pop("verify_identity_ids")
    state["same_pack_identity_for_every_verification"] = (
        len(identity_ids) <= 1 or len(set(identity_ids)) == 1
    )
    state.pop("command_id", None)
    roots = (str(workspace), str(workspace.resolve()))
    return _normalize(
        {
            **observed,
            "events": events,
            "state": state,
        },
        roots=roots,
    )


def capture_live_lookup(workspace: Path) -> dict[str, Any]:
    """Prove every facade provider is resolved at its historical call site."""

    workspace.mkdir(parents=True)
    repo, pack = _source_tree(workspace)
    events: list[str] = []

    real_verify = blackbox_module.verify_pack_snapshot
    real_command = blackbox_module._judge_command
    real_parse = blackbox_module.parse_junit_xml
    real_distill = blackbox_module.distill_diagnostics
    real_attach = blackbox_module._attach_candidate_execution_evidence

    def late_attach(
        result: BlackboxResult,
        **kwargs: object,
    ) -> BlackboxResult:
        events.append("late:attach")
        return real_attach(result, **kwargs)

    def late_distill(output: str) -> str:
        events.append("late:distill")
        blackbox_module._attach_candidate_execution_evidence = late_attach
        return real_distill(output)

    def late_parse(text: str) -> object:
        events.append("late:parse")
        blackbox_module.distill_diagnostics = late_distill
        return real_parse(text)

    def late_read(_path: str) -> str:
        events.append("late:read")
        blackbox_module.parse_junit_xml = late_parse
        return _JUNIT_PASS

    def late_verify(
        snapshot: str,
        identity: tuple[str, dict | None],
    ) -> None:
        events.append("late:verify-after")
        blackbox_module.read_junit_xml = late_read
        real_verify(snapshot, identity)

    def late_run(
        command: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        events.append("late:run")
        blackbox_module.verify_pack_snapshot = late_verify
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="live stdout",
            stderr="live stderr",
        )

    def late_command(pack_snapshot: str, xml_path: str) -> list[str]:
        events.append("late:command")
        blackbox_module._run_judge_process = late_run
        return real_command(pack_snapshot, xml_path)

    def first_verify(
        snapshot: str,
        identity: tuple[str, dict | None],
    ) -> None:
        events.append("initial:verify-before")
        blackbox_module._judge_command = late_command
        real_verify(snapshot, identity)

    def late_clock() -> float:
        events.append("late:clock-end")
        return 20.5

    def first_clock() -> float:
        events.append("initial:clock-start")
        blackbox_module.time.perf_counter = late_clock
        return 20.0

    def prepare(
        _runner: object,
        workdir: str,
        target_dir: str,
    ) -> tuple[str, dict[str, str], _Evidence]:
        return (
            "launcher",
            {
                "EVOGUARD_EXEC": "live-launcher",
                "EVOGUARD_TARGET": target_dir,
            },
            _Evidence(),
        )

    with ExitStack() as stack:
        stack.enter_context(
            patch.object(
                blackbox_module.tempfile,
                "mkdtemp",
                side_effect=_TempFactory(workspace / "runtime-temp"),
            )
        )
        stack.enter_context(patch.object(blackbox_module.time, "perf_counter", new=first_clock))
        stack.enter_context(
            patch.object(
                blackbox_module._InvocationRecorder,
                "create",
                side_effect=lambda workdir: _Recorder(workdir, events),
            )
        )
        stack.enter_context(patch.object(blackbox_module.CandidateRunner, "prepare", prepare))
        stack.enter_context(patch.object(blackbox_module, "verify_pack_snapshot", new=first_verify))
        # These guards intentionally install the current objects unchanged.
        # Later providers rebind them during the call; ExitStack then restores
        # the module so the live-lookup proof cannot leak into another case.
        stack.enter_context(
            patch.object(
                blackbox_module,
                "_judge_command",
                new=blackbox_module._judge_command,
            )
        )
        stack.enter_context(
            patch.object(
                blackbox_module,
                "_run_judge_process",
                new=blackbox_module._run_judge_process,
            )
        )
        stack.enter_context(
            patch.object(
                blackbox_module,
                "read_junit_xml",
                new=blackbox_module.read_junit_xml,
            )
        )
        stack.enter_context(
            patch.object(
                blackbox_module,
                "parse_junit_xml",
                new=blackbox_module.parse_junit_xml,
            )
        )
        stack.enter_context(
            patch.object(
                blackbox_module,
                "distill_diagnostics",
                new=blackbox_module.distill_diagnostics,
            )
        )
        stack.enter_context(
            patch.object(
                blackbox_module,
                "_attach_candidate_execution_evidence",
                new=blackbox_module._attach_candidate_execution_evidence,
            )
        )
        stack.enter_context(
            patch.object(
                blackbox_module,
                "_cleanup_candidate_containers",
                side_effect=lambda *_args, **_kwargs: events.append("cleanup:containers"),
            )
        )
        stack.enter_context(
            patch.object(
                blackbox_module.shutil,
                "rmtree",
                side_effect=lambda *_args, **_kwargs: None,
            )
        )
        result = run_blackbox(str(repo), _CANDIDATE, str(pack), timeout=7)

    return {
        "events": events,
        "passed": result.passed,
        "ran": result.ran,
        "candidate_invocations": result.candidate_invocations,
    }


def capture_all(workspace: Path) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "normalization": list(NORMALIZED_FIELDS),
        "cases": {name: capture_case(name, workspace / name) for name in CASE_NAMES},
        "live_lookup": capture_live_lookup(workspace / "live-lookup"),
    }


def canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
