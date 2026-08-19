"""Deterministic characterization of Guard's unified-diff coordinator.

The harness drives the public ``guard_from_diff()`` facade while replacing only
its effect seams.  It freezes preflight order, workspace lifetime, exception
cut-offs, candidate serialization, option forwarding, SHA short-circuiting,
and late provider lookup before orchestration moves out of ``guard.py``.
"""

from __future__ import annotations

import importlib
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import patch

from evoom_guard.guard import guard_from_diff

guard_module = importlib.import_module("evoom_guard.guard")

TEXT_DIFF = """\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-VALUE = 1
+VALUE = 2
"""
UNSAFE_DIFF = """\
diff --git a/../outside.py b/../outside.py
--- a/../outside.py
+++ b/../outside.py
@@ -1 +1 @@
-OLD = 1
+NEW = 2
"""
BINARY_DIFF = """\
diff --git a/blob.bin b/blob.bin
GIT binary patch
literal 1
A
"""

CASE_NAMES = (
    "binary_preflight",
    "cleanup_exception_masks_success",
    "copy_exception_cleans_up",
    "empty_preflight",
    "explicit_sha_short_circuit",
    "guard_and_cleanup_exception",
    "guard_exception_cleans_up",
    "live_binary_reason_rebinding",
    "live_provider_rebinding",
    "live_reverse_reason_rebinding",
    "no_verifiable_changes",
    "pack_trust_preflight",
    "reverse_apply_failure",
    "success_forwards_every_option",
    "unsafe_path_preflight",
    "unverifiable_paths",
    "workspace_join_exception_cleans_up",
    "write_exception_cleans_up",
)


class ProbeError(RuntimeError):
    """Deterministic failure used to freeze exception boundaries."""


@dataclass
class ProbeResult:
    """The only mutable result attributes owned by ``guard_from_diff``."""

    marker: str
    source: str | None = "before"
    base_reconstruction: str | None = "before"


class MemoryWriter:
    """Record the historical ``open`` context-manager protocol exactly."""

    def __init__(self, timeline: list[str], *, fail: bool) -> None:
        self.timeline = timeline
        self.fail = fail

    def __enter__(self) -> MemoryWriter:
        self.timeline.append("write:enter")
        return self

    def write(self, value: str) -> int:
        self.timeline.append(f"write:data:{value!r}")
        if self.fail:
            raise ProbeError("synthetic write failure")
        return len(value)

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: object,
    ) -> bool:
        del exception_type, exception, traceback
        self.timeline.append("write:exit")
        return False


def _spec(case_name: str) -> dict[str, Any]:
    common: dict[str, Any] = {
        "diff_text": TEXT_DIFF,
        "pack_problem": None,
        "reverse_ok": True,
        "blocks": ({"app.py": "VALUE = 2\n"}, ["old.py"]),
        "raise_at": None,
        "cleanup_raises": False,
        "explicit_sha": False,
        "live": False,
        "late_reason": None,
    }
    cases: dict[str, dict[str, Any]] = {
        "empty_preflight": {"diff_text": " \n\t"},
        "binary_preflight": {"diff_text": BINARY_DIFF},
        "unsafe_path_preflight": {"diff_text": UNSAFE_DIFF},
        "pack_trust_preflight": {
            "pack_problem": "synthetic untrusted verifier pack",
        },
        "reverse_apply_failure": {"reverse_ok": False},
        "unverifiable_paths": {"raise_at": "blocks"},
        "no_verifiable_changes": {"blocks": ({}, [])},
        "success_forwards_every_option": {},
        "explicit_sha_short_circuit": {"explicit_sha": True},
        "live_binary_reason_rebinding": {
            "diff_text": BINARY_DIFF,
            "late_reason": "binary",
        },
        "live_provider_rebinding": {"live": True},
        "live_reverse_reason_rebinding": {
            "reverse_ok": False,
            "late_reason": "reverse",
        },
        "copy_exception_cleans_up": {"raise_at": "copy"},
        "write_exception_cleans_up": {"raise_at": "write"},
        "guard_exception_cleans_up": {"raise_at": "guard"},
        "cleanup_exception_masks_success": {"cleanup_raises": True},
        "guard_and_cleanup_exception": {
            "raise_at": "guard",
            "cleanup_raises": True,
        },
        "workspace_join_exception_cleans_up": {"raise_at": "join"},
    }
    if case_name not in cases:
        raise ValueError(f"unknown diff-verification case: {case_name}")
    return {**common, **cases[case_name]}


def capture_case(case_name: str, workspace: Path) -> dict[str, Any]:
    """Capture one public ``guard_from_diff`` path with deterministic effects."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown diff-verification case: {case_name}")
    spec = _spec(case_name)
    timeline: list[str] = []
    guard_call: dict[str, Any] | None = None
    result: Any = None
    deleted: list[str] | None = None
    exception: dict[str, str] | None = None
    exception_notes: list[str] = []
    workspace_path = str(workspace / "diff-workspace")
    original_join = guard_module.os.path.join
    original_binary_check = guard_module._is_binary_diff
    original_cleanup = guard_module.shutil.rmtree

    def fake_binary_check(value: str) -> bool:
        if spec["late_reason"] == "binary":
            timeline.append("reason:rebind:binary")
            guard_module.REASON_BINARY_PATCH = "late-binary-patch"
        return bool(original_binary_check(value))

    def fake_pack_check(
        head_dir: str,
        verifier_pack: str | None,
        pin: str | None,
    ) -> str | None:
        timeline.append(f"pack-check:{head_dir}:{verifier_pack}:{pin}")
        return spec["pack_problem"]

    def fake_mkdtemp(*, prefix: str) -> str:
        timeline.append(f"workspace:create:{prefix}")
        Path(workspace_path).mkdir(parents=True)
        return workspace_path

    def fake_join(parent: str, child: str) -> str:
        timeline.append(f"path:join:{child}")
        if spec["raise_at"] == "join" and child == "base":
            raise ProbeError("synthetic base-path failure")
        return original_join(parent, child)

    def fake_copy(head_dir: str, base_dir: str) -> None:
        timeline.append(f"copy:{head_dir}:{base_dir.endswith('base')}")
        if spec["live"]:
            guard_module._reverse_apply = late_reverse
        if spec["raise_at"] == "copy":
            raise ProbeError("synthetic copy failure")

    def fake_open(
        path: str,
        mode: str,
        *,
        encoding: str,
        newline: str | None = None,
    ) -> MemoryWriter:
        timeline.append(
            f"write:open:{path.endswith('patch.diff')}:{mode}:{encoding}:"
            f"{newline!r}"
        )
        return MemoryWriter(timeline, fail=spec["raise_at"] == "write")

    def early_reverse(_base_dir: str, _diff_file: str) -> bool:
        timeline.append("reverse:early")
        if spec["late_reason"] == "reverse":
            timeline.append("reason:rebind:reverse")
            guard_module.REASON_REVERSE_APPLY_FAILED = (
                "late-reverse-apply-failed"
            )
        return bool(spec["reverse_ok"])

    def late_reverse(_base_dir: str, _diff_file: str) -> bool:
        timeline.append("reverse:late")
        guard_module.blocks_from_dirs = late_blocks
        return True

    def early_blocks(_base_dir: str, _head_dir: str) -> tuple[dict[str, str], list[str]]:
        timeline.append("blocks:early")
        if spec["raise_at"] == "blocks":
            raise guard_module._UnverifiableChangedPathsError(
                [("blob.bin", "binary file")]
            )
        blocks, removed = spec["blocks"]
        return dict(blocks), list(removed)

    def late_blocks(_base_dir: str, _head_dir: str) -> tuple[dict[str, str], list[str]]:
        timeline.append("blocks:late")
        guard_module.guard = late_guard
        guard_module._diff_base_sha = late_base_sha
        guard_module._diff_head_sha = late_head_sha
        blocks, removed = spec["blocks"]
        return dict(blocks), list(removed)

    def early_base_sha(_text: str) -> str | None:
        timeline.append("sha:base:early")
        if spec["explicit_sha"]:
            raise ProbeError("base SHA parser must be short-circuited")
        return "inferred-base"

    def early_head_sha(_text: str) -> str | None:
        timeline.append("sha:head:early")
        if spec["explicit_sha"]:
            raise ProbeError("head SHA parser must be short-circuited")
        return "inferred-head"

    def late_base_sha(_text: str) -> str | None:
        timeline.append("sha:base:late")
        return "late-base"

    def late_head_sha(_text: str) -> str | None:
        timeline.append("sha:head:late")
        return "late-head"

    def _record_guard(
        label: str,
        base_dir: str,
        candidate: str,
        kwargs: dict[str, Any],
    ) -> ProbeResult:
        nonlocal guard_call
        timeline.append(f"guard:{label}")
        guard_call = {
            "label": label,
            "base_is_reconstructed": base_dir.endswith("base"),
            "candidate": candidate,
            "keyword_order": list(kwargs),
            "kwargs": kwargs,
        }
        if spec["raise_at"] == "guard":
            raise ProbeError("synthetic guard failure")
        return ProbeResult(label)

    def early_guard(
        base_dir: str,
        candidate: str,
        **kwargs: Any,
    ) -> ProbeResult:
        return _record_guard("early", base_dir, candidate, kwargs)

    def late_guard(
        base_dir: str,
        candidate: str,
        **kwargs: Any,
    ) -> ProbeResult:
        return _record_guard("late", base_dir, candidate, kwargs)

    def fake_cleanup(path: str) -> None:
        timeline.append(
            "workspace:cleanup:"
            f"{path == workspace_path}:{type(path) is not str}"
        )
        if spec["cleanup_raises"]:
            raise ProbeError("synthetic cleanup failure")
        original_cleanup(path)

    call_kwargs: dict[str, Any] = {
        "test_command": ["python", "-m", "pytest"],
        "setup_command": ["python", "-m", "pip", "install", "-e", "."],
        "trust_setup_on_host": True,
        "setup_output_globs": ("generated/**",),
        "protected": ("policy/**",),
        "allow": ("policy/approved.py",),
        "allow_new_tests": True,
        "timeout": 37,
        "mem_limit_mb": 731,
        "isolation": "docker",
        "docker_image": "python@sha256:" + ("a" * 64),
        "docker_network": "none",
        "verifier_pack": "trusted-pack",
        "expect_verifier_pack_sha256": "b" * 64,
        "diff_coverage": True,
        "min_diff_coverage": 87.5,
        "blackbox": True,
        "blackbox_only": True,
        "require_report_integrity": "external_process",
        "require_candidate_isolation": "container",
        "base_sha": "explicit-base" if spec["explicit_sha"] else None,
        "head_sha": "explicit-head" if spec["explicit_sha"] else None,
        "base_tree_sha": "base-tree",
        "head_tree_sha": "head-tree",
        "policy_id": "policy-id",
        "policy_version": "2026.07",
        "baseline_evidence": True,
        "require_demonstrated_fix": True,
        "strict_harness": True,
        "require_suite_continuity": True,
    }

    with ExitStack() as stack:
        stack.enter_context(
            patch.object(
                guard_module,
                "verifier_pack_trust_error",
                fake_pack_check,
            )
        )
        stack.enter_context(patch.object(guard_module.tempfile, "mkdtemp", fake_mkdtemp))
        stack.enter_context(patch.object(guard_module.os.path, "join", fake_join))
        stack.enter_context(patch.object(guard_module, "copy_repo_tree", fake_copy))
        stack.enter_context(patch.object(guard_module, "open", fake_open, create=True))
        stack.enter_context(
            patch.object(
                guard_module,
                "REASON_BINARY_PATCH",
                guard_module.REASON_BINARY_PATCH,
            )
        )
        stack.enter_context(
            patch.object(
                guard_module,
                "REASON_REVERSE_APPLY_FAILED",
                guard_module.REASON_REVERSE_APPLY_FAILED,
            )
        )
        stack.enter_context(
            patch.object(guard_module, "_is_binary_diff", fake_binary_check)
        )
        stack.enter_context(patch.object(guard_module, "_reverse_apply", early_reverse))
        stack.enter_context(patch.object(guard_module, "blocks_from_dirs", early_blocks))
        stack.enter_context(patch.object(guard_module, "_diff_base_sha", early_base_sha))
        stack.enter_context(patch.object(guard_module, "_diff_head_sha", early_head_sha))
        stack.enter_context(patch.object(guard_module, "guard", early_guard))
        stack.enter_context(patch.object(guard_module.shutil, "rmtree", fake_cleanup))
        try:
            result, deleted = guard_from_diff(
                "HEAD",
                spec["diff_text"],
                **call_kwargs,
            )
        except Exception as error:  # noqa: BLE001 - exception order is the contract
            exception = {
                "type": type(error).__name__,
                "message": str(error),
            }
            exception_notes = list(getattr(error, "__notes__", ()))

    normalized_guard: dict[str, Any] | None = None
    if guard_call is not None:
        forwarded = dict(guard_call["kwargs"])
        forwarded["test_command_identity"] = (
            forwarded.pop("test_command") is call_kwargs["test_command"]
        )
        forwarded["setup_command_identity"] = (
            forwarded.pop("setup_command") is call_kwargs["setup_command"]
        )
        forwarded["file_blocks"] = dict(forwarded["file_blocks"])
        normalized_guard = {
            **{key: value for key, value in guard_call.items() if key != "kwargs"},
            "kwargs": forwarded,
        }

    decision: dict[str, Any] | None = None
    if result is not None:
        decision = {
            "type": type(result).__name__,
            "verdict": getattr(result, "verdict", None),
            "reason_code": getattr(result, "reason_code", None),
            "reason": getattr(result, "reason", None),
            "source": getattr(result, "source", None),
            "base_reconstruction": getattr(result, "base_reconstruction", None),
            "marker": getattr(result, "marker", None),
        }

    return {
        "case": case_name,
        "timeline": timeline,
        "decision": decision,
        "deleted": deleted,
        "exception": exception,
        "exception_notes": exception_notes,
        "guard_call": normalized_guard,
    }
