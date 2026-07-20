"""Deterministic observable seam for the external black-box judge.

The harness patches operating-system execution, never verdict composition.  It
keeps pack snapshotting, candidate patch/deletion application, JUnit parsing,
receipt/CID evidence composition, and public cleanup precedence in the real
implementation.  Only temporary paths, recorder tokens, container IDs, and
elapsed fields are normalized.
"""

from __future__ import annotations

import copy
import inspect
import json
import subprocess
import sys
from collections.abc import Callable
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from unittest.mock import patch

import evoom_guard.blackbox as blackbox_module
from evoom_guard.blackbox import BlackboxResult, run_blackbox
from evoom_guard.candidate_runner import CANDIDATE_CID_DIRNAME, IsolationUnavailable
from evoom_guard.pack_manifest import PackManifestError

SCHEMA_VERSION = "blackbox-characterization-v1"
NORMALIZED_FIELDS = (
    "temporary_paths",
    "invocation_tokens",
    "container_ids",
    "elapsed",
    "current_python_executable",
)

GROUP_CASES = {
    "preflight": (
        "missing_pack",
        "invalid_pack",
        "pack_identity_mismatch",
        "patch_apply_failure",
        "patch_and_deletion",
        "isolation_unavailable",
    ),
    "judge": (
        "judge_timeout",
        "judge_output_limit",
        "judge_cleanup_failure",
        "no_junit",
        "junit_mismatch_exit_0",
        "junit_mismatch_exit_1",
        "exit_0_pass",
        "exit_1_fail",
        "exit_2_error",
        "pack_snapshot_before",
        "pack_snapshot_after",
    ),
    "evidence_cleanup": (
        "receipt_absent",
        "receipt_present",
        "docker_receipt_valid_cid",
        "docker_receipt_without_cid",
        "docker_cid_without_receipt",
        "monotonic_observed_cid",
        "normal_cleanup_contract",
        "timeout_cleanup_contract",
        "cleanup_failure_overrides_result",
        "cleanup_keyboard_interrupt",
        "cleanup_system_exit",
        "primary_exception_precedes_cleanup",
        "primary_keyboard_interrupt_cleanup_system_exit",
        "primary_system_exit_cleanup_keyboard_interrupt",
        "recorder_close_keyboard_interrupt",
        "primary_keyboard_interrupt_recorder_close_system_exit",
    ),
}

VECTOR_FILES = {
    "contract": "blackbox-contract-v1.json",
    "preflight": "blackbox-preflight-v1.json",
    "judge": "blackbox-judge-v1.json",
    "evidence_cleanup": "blackbox-evidence-cleanup-v1.json",
}

_CID = "c" * 64
_TOKEN = "characterization-secret-token"
_CANDIDATE = "<<<FILE: app.py>>>\nvalue = 2\n<<<END FILE>>>\n"
_PATCH = (
    "<<<PATCH: app.py>>>\n"
    "<<<SEARCH>>>\nvalue = 1\n"
    "<<<REPLACE>>>\nvalue = 2\n"
    "<<<END PATCH>>>\n"
)
_MISSING_PATCH = (
    "<<<PATCH: missing.py>>>\n"
    "<<<SEARCH>>>\nold\n"
    "<<<REPLACE>>>\nnew\n"
    "<<<END PATCH>>>\n"
)
_JUNIT_PASS = (
    '<testsuites><testsuite tests="2" failures="0" errors="0" skipped="0">'
    '<testcase name="one"/><testcase name="two"/></testsuite></testsuites>'
)
_JUNIT_FAIL = (
    '<testsuites><testsuite tests="2" failures="1" errors="0" skipped="0">'
    '<testcase name="one"><failure message="deterministic"/></testcase>'
    '<testcase name="two"/></testsuite></testsuites>'
)


class _Evidence:
    def __init__(self, requested: str, delivered: str) -> None:
        self.requested = requested
        self.delivered = delivered

    def as_dict(self) -> dict[str, object]:
        return {
            "requested": self.requested,
            "delivered": self.delivered,
            "note": "characterization boundary",
        }


class _Recorder:
    def __init__(
        self,
        workdir: str,
        count: int,
        trace: dict[str, Any],
        close_error: BaseException | None = None,
    ) -> None:
        self.path = str(Path(workdir) / "invocation.sock")
        self.token = _TOKEN
        self._count = count
        self._trace = trace
        self._close_error = close_error
        trace["recorder"] = {
            "path": self.path,
            "token": self.token,
            "drain_calls": 0,
            "close_calls": 0,
            "closed": False,
        }

    def drain(self) -> int:
        self._trace["recorder"]["drain_calls"] += 1
        return self._count

    def close(self) -> None:
        self._trace["recorder"]["close_calls"] += 1
        self._trace["recorder"]["closed"] = True
        if self._close_error is not None:
            raise self._close_error


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
    pack_dir = workspace / "source-pack"
    repo.mkdir(parents=True)
    pack_dir.mkdir(parents=True)
    _write(repo / "app.py", "value = 1\n")
    _write(repo / "obsolete.txt", "remove me\n")
    _write(pack_dir / "test_protocol.py", "def test_protocol():\n    assert True\n")
    _write(
        pack_dir / "pack.json",
        '{"id":"characterization","version":"1","target_type":"cli"}\n',
    )
    return repo, pack_dir


def _normalize(
    value: Any,
    *,
    temporary_roots: tuple[str, ...],
    token: str,
    cids: tuple[str, ...],
    key: str = "",
) -> Any:
    if key == "elapsed" or key.endswith("_elapsed") or key.endswith("_elapsed_ms"):
        return "<ELAPSED>"
    if key in {"token", "invocation_token"} and isinstance(value, str):
        return "<TOKEN>"
    if isinstance(value, dict):
        return {
            item_key: _normalize(
                item_value,
                temporary_roots=temporary_roots,
                token=token,
                cids=cids,
                key=str(item_key),
            )
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [
            _normalize(
                item,
                temporary_roots=temporary_roots,
                token=token,
                cids=cids,
                key=key,
            )
            for item in value
        ]
    if not isinstance(value, str):
        return value
    normalized = value
    for root in sorted(set(temporary_roots), key=len, reverse=True):
        normalized = normalized.replace(root, "<TEMP>")
        normalized = normalized.replace(root.replace("\\", "\\\\"), "<TEMP>")
        normalized = normalized.replace(root.replace("\\", "/"), "<TEMP>")
    normalized = normalized.replace(token, "<TOKEN>")
    for index, cid in enumerate(cids, start=1):
        normalized = normalized.replace(cid, f"<CID-{index}>")
    if "<TEMP>" in normalized:
        normalized = normalized.replace("\\", "/")
        while "<TEMP>//" in normalized:
            normalized = normalized.replace("<TEMP>//", "<TEMP>/")
    return normalized


def _serialize_result(result: BlackboxResult) -> dict[str, Any]:
    return {field: copy.deepcopy(getattr(result, field)) for field in result._fields}


def _parameter_contract(function: Callable[..., object]) -> list[dict[str, str]]:
    return [
        {
            "name": parameter.name,
            "kind": parameter.kind.name,
            "default": (
                "<REQUIRED>"
                if parameter.default is inspect.Parameter.empty
                else repr(parameter.default)
            ),
        }
        for parameter in inspect.signature(function).parameters.values()
    ]


def capture_contract() -> dict[str, Any]:
    """Freeze the public callable and append-only NamedTuple compatibility seam."""

    return {
        "schema_version": SCHEMA_VERSION,
        "normalization": list(NORMALIZED_FIELDS),
        "blackbox_result": {
            "kind": "NamedTuple",
            "field_order": list(BlackboxResult._fields),
            "field_defaults": copy.deepcopy(BlackboxResult._field_defaults),
            "legacy_minimum_arity": 6,
        },
        "run_blackbox_parameters": _parameter_contract(run_blackbox),
    }


def _receipt_count(case_name: str) -> int:
    if case_name in {
        "receipt_absent",
        "isolation_unavailable",
        "pack_snapshot_before",
        "docker_cid_without_receipt",
    }:
        return 0
    return 1


def _judge_configuration(case_name: str) -> tuple[int, str | None]:
    if case_name in {"junit_mismatch_exit_0"}:
        return 0, _JUNIT_FAIL
    if case_name in {"junit_mismatch_exit_1"}:
        return 1, _JUNIT_PASS
    if case_name in {"exit_1_fail"}:
        return 1, _JUNIT_FAIL
    if case_name in {"exit_2_error"}:
        return 2, _JUNIT_PASS
    if case_name == "no_junit":
        return 0, None
    return 0, _JUNIT_PASS


def capture_case(case_name: str, workspace: Path) -> dict[str, Any]:
    all_cases = {case for cases in GROUP_CASES.values() for case in cases}
    if case_name not in all_cases:
        raise ValueError(f"unknown blackbox characterization case: {case_name}")
    workspace.mkdir(parents=True)
    repo, pack_dir = _source_tree(workspace)
    trace: dict[str, Any] = {
        "judge_calls": 0,
        "judge_invocations": [],
        "snapshot_checks": 0,
        "snapshot_verifications": [],
        "cleanup_calls": 0,
    }
    if case_name == "invalid_pack":
        _write(pack_dir / "pack.json", "{broken\n")

    docker_cases = {
        "docker_receipt_valid_cid",
        "docker_receipt_without_cid",
        "docker_cid_without_receipt",
        "monotonic_observed_cid",
    }
    delivered = "docker" if case_name in docker_cases else "subprocess"
    recorder_count = _receipt_count(case_name)
    original_verify = blackbox_module.verify_pack_snapshot

    def create_recorder(workdir: str) -> _Recorder:
        close_error: BaseException | None = None
        if case_name == "recorder_close_keyboard_interrupt":
            close_error = KeyboardInterrupt("characterization recorder close interrupt")
        elif case_name == "primary_keyboard_interrupt_recorder_close_system_exit":
            close_error = SystemExit("characterization recorder close exit")
        return _Recorder(workdir, recorder_count, trace, close_error)

    def prepare(
        _runner: object, workdir: str, target_dir: str
    ) -> tuple[str, dict[str, str], _Evidence]:
        if case_name == "isolation_unavailable":
            raise IsolationUnavailable("characterization isolation unavailable")
        Path(workdir, CANDIDATE_CID_DIRNAME).mkdir(exist_ok=True)
        trace["prepared_target"] = {
            "app": Path(target_dir, "app.py").read_text(encoding="utf-8"),
            "obsolete_exists": Path(target_dir, "obsolete.txt").exists(),
        }
        return (
            "launcher",
            {
                "EVOGUARD_EXEC": "characterization-launcher",
                "EVOGUARD_TARGET": target_dir,
            },
            _Evidence(delivered, delivered),
        )

    def verify_snapshot(snapshot: str, identity: tuple[str, dict | None]) -> None:
        trace["snapshot_checks"] += 1
        trace["snapshot_verifications"].append(
            {
                "path": snapshot,
                "sha256": identity[0],
                "manifest": copy.deepcopy(identity[1]),
            }
        )
        if case_name == "pack_snapshot_before" and trace["snapshot_checks"] == 1:
            raise PackManifestError("snapshot changed before judge start")
        if case_name == "pack_snapshot_after" and trace["snapshot_checks"] == 2:
            raise PackManifestError("snapshot changed after judge completion")
        original_verify(snapshot, identity)

    def judge(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        trace["judge_calls"] += 1
        recorded_command = list(command)
        if recorded_command and recorded_command[0] == sys.executable:
            recorded_command[0] = "<CURRENT_PYTHON>"
        raw_env = _kwargs.get("env")
        env = raw_env if isinstance(raw_env, dict) else {}
        trace["judge_invocations"].append(
            {
                "argv": recorded_command,
                "cwd": _kwargs.get("cwd"),
                "timeout": _kwargs.get("timeout"),
                "env": {
                    key: env.get(key)
                    for key in (
                        "HOME",
                        "LANG",
                        "PYTHONDONTWRITEBYTECODE",
                        "PYTHONNOUSERSITE",
                        "EVOGUARD_EXEC",
                        "EVOGUARD_TARGET",
                    )
                },
            }
        )
        if case_name in {"judge_timeout", "timeout_cleanup_contract"}:
            raise subprocess.TimeoutExpired(command, 7)
        if case_name == "judge_output_limit":
            raise blackbox_module.JudgeOutputLimitError(4096)
        if case_name == "judge_cleanup_failure":
            raise blackbox_module.JudgeProcessCleanupError(
                "characterization judge cleanup unproved"
            )
        if case_name in {
            "primary_exception_precedes_cleanup",
            "primary_keyboard_interrupt_cleanup_system_exit",
            "primary_keyboard_interrupt_recorder_close_system_exit",
        }:
            raise KeyboardInterrupt("characterization primary interrupt")
        if case_name == "primary_system_exit_cleanup_keyboard_interrupt":
            raise SystemExit("characterization primary exit")
        returncode, xml = _judge_configuration(case_name)
        if xml is not None:
            xml_arg = next(part for part in command if part.startswith("--junitxml="))
            Path(xml_arg.split("=", 1)[1]).write_text(
                xml, encoding="utf-8", newline="\n"
            )
        return subprocess.CompletedProcess(
            command,
            returncode,
            stdout="judge stdout",
            stderr="judge stderr",
        )

    def cleanup(*_args: object, **kwargs: object) -> None:
        trace["cleanup_calls"] += 1
        raw_known_cids = kwargs.get("known_container_ids")
        known_cids = (
            raw_known_cids
            if isinstance(raw_known_cids, (set, frozenset, list, tuple))
            else ()
        )
        trace["cleanup_known_cids"] = sorted(str(cid) for cid in known_cids)
        trace["cleanup_wait_for_late_cidfiles"] = kwargs.get(
            "wait_for_late_cidfiles"
        )
        trace["cleanup_strict"] = kwargs.get("strict")
        if case_name == "monotonic_observed_cid":
            trace["cleanup_rescan_cids"] = blackbox_module._candidate_container_ids(
                str(_args[0])
            )
        if case_name in {
            "cleanup_failure_overrides_result",
            "primary_exception_precedes_cleanup",
        }:
            raise blackbox_module.CandidateContainerCleanupError(
                "characterization candidate cleanup unproved"
            )
        if case_name in {
            "cleanup_keyboard_interrupt",
            "primary_system_exit_cleanup_keyboard_interrupt",
        }:
            raise KeyboardInterrupt("characterization cleanup interrupt")
        if case_name in {
            "cleanup_system_exit",
            "primary_keyboard_interrupt_cleanup_system_exit",
        }:
            raise SystemExit("characterization cleanup exit")

    candidate = _CANDIDATE
    deleted_paths: tuple[str, ...] = ()
    pack_argument = pack_dir
    expected_pack: str | None = None
    if case_name == "missing_pack":
        pack_argument = workspace / "missing-pack"
    elif case_name == "pack_identity_mismatch":
        expected_pack = "0" * 64
    elif case_name == "patch_apply_failure":
        candidate = _MISSING_PATCH
    elif case_name == "patch_and_deletion":
        candidate = _PATCH
        deleted_paths = ("obsolete.txt", "../ignored")

    with ExitStack() as stack:
        stack.enter_context(
            patch.object(
                blackbox_module.tempfile,
                "mkdtemp",
                side_effect=_TempFactory(workspace / "runtime-temp"),
            )
        )
        stack.enter_context(
            patch.object(
                blackbox_module._InvocationRecorder,
                "create",
                side_effect=create_recorder,
            )
        )
        stack.enter_context(
            patch.object(blackbox_module.CandidateRunner, "prepare", prepare)
        )
        stack.enter_context(
            patch.object(blackbox_module, "_run_judge_process", side_effect=judge)
        )
        stack.enter_context(
            patch.object(
                blackbox_module,
                "verify_pack_snapshot",
                side_effect=verify_snapshot,
            )
        )
        if case_name in docker_cases:
            cid_scans = 0

            def scan_cids(_cidfile_dir: str) -> list[str]:
                nonlocal cid_scans
                cid_scans += 1
                trace["cid_scan_calls"] = cid_scans
                if case_name == "docker_receipt_without_cid":
                    return []
                if case_name == "monotonic_observed_cid" and cid_scans > 1:
                    return []
                return [_CID]

            stack.enter_context(
                patch.object(
                    blackbox_module,
                    "_candidate_container_ids",
                    side_effect=scan_cids,
                )
            )
        cleanup_stub_cases = docker_cases | {
            "normal_cleanup_contract",
            "timeout_cleanup_contract",
            "docker_receipt_valid_cid",
            "monotonic_observed_cid",
            "cleanup_failure_overrides_result",
            "cleanup_keyboard_interrupt",
            "cleanup_system_exit",
            "primary_exception_precedes_cleanup",
            "primary_keyboard_interrupt_cleanup_system_exit",
            "primary_system_exit_cleanup_keyboard_interrupt",
            "recorder_close_keyboard_interrupt",
            "primary_keyboard_interrupt_recorder_close_system_exit",
        }
        if case_name in cleanup_stub_cases:
            stack.enter_context(
                patch.object(
                    blackbox_module,
                    "_cleanup_candidate_containers",
                    side_effect=cleanup,
                )
            )

        try:
            result = run_blackbox(
                str(repo),
                candidate,
                str(pack_argument),
                timeout=7,
                isolation=delivered,
                docker_image="sha256:characterization" if delivered == "docker" else None,
                deleted_paths=deleted_paths,
                expect_verifier_pack_sha256=expected_pack,
            )
        except BaseException as exc:
            observed: dict[str, Any] = {
                "exception": {
                    "type": type(exc).__name__,
                    "message": str(exc),
                },
                "trace": trace,
            }
        else:
            observed = {"result": _serialize_result(result), "trace": trace}

    roots = (
        str(workspace),
        str(workspace.resolve()),
    )
    return _normalize(
        observed,
        temporary_roots=roots,
        token=_TOKEN,
        cids=(_CID,),
    )


def capture_group(group_name: str, workspace: Path) -> dict[str, Any]:
    if group_name not in GROUP_CASES:
        raise ValueError(f"unknown blackbox characterization group: {group_name}")
    return {
        "schema_version": SCHEMA_VERSION,
        "normalization": list(NORMALIZED_FIELDS),
        "group": group_name,
        "cases": {
            case_name: capture_case(case_name, workspace / case_name)
            for case_name in GROUP_CASES[group_name]
        },
    }


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
