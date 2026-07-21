# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Compatibility facade for candidate-boundary preparation.

The implementation lives in :mod:`evoom_guard.isolation.candidate`.  This
module preserves the historical imports and private monkeypatch seams used by
embedders and by the pre-refactor characterization suite.
"""

from __future__ import annotations

import os
import shutil
import subprocess

from evoom_guard.execution import (
    ProcessContainmentError as _SubprocessContainmentError,
)
from evoom_guard.execution import (
    ProcessOutputLimitExceeded as _SubprocessOutputLimitExceeded,
)
from evoom_guard.execution import (
    run_bounded_subprocess as _run_bounded_subprocess,
)
from evoom_guard.isolation.candidate import (
    CANDIDATE_CID_DIRNAME as _CANDIDATE_CID_DIRNAME,
)
from evoom_guard.isolation.candidate import (
    CandidateRunner as _CandidateRunner,
)
from evoom_guard.isolation.candidate import (
    IsolationEvidence as _IsolationEvidence,
)
from evoom_guard.isolation.candidate import (
    IsolationUnavailable,
)
from evoom_guard.isolation.docker import (
    DOCKER_CONTROL_TIMEOUT_SECONDS as _DOCKER_CONTROL_TIMEOUT_SECONDS,
)
from evoom_guard.isolation.docker import (
    DockerControlRequest,
    execute_docker_control,
    inspect_docker_image,
)

CANDIDATE_CID_DIRNAME = _CANDIDATE_CID_DIRNAME
IsolationEvidence = _IsolationEvidence
# Keep ``shutil`` reachable on this compatibility module: existing embedders
# patch ``candidate_runner.shutil.which`` to control Docker discovery.
_COMPATIBILITY_MODULES = (shutil,)


def _run_docker_control(
    command: list[str], *, timeout: float
) -> subprocess.CompletedProcess[str]:
    """Historical bounded Docker-control seam used by the facade class."""

    try:
        request = DockerControlRequest.from_command(
            command,
            timeout=timeout,
            environment=os.environ,
        )
        return execute_docker_control(
            request,
            process_runner=_run_bounded_subprocess,
            process_argv=command,
        ).as_completed_process(args=command)
    except (_SubprocessOutputLimitExceeded, _SubprocessContainmentError) as exc:
        raise IsolationUnavailable(
            f"Docker control command could not be safely captured: {exc}"
        ) from exc


class CandidateRunner(_CandidateRunner):
    """Backward-compatible class backed by the typed isolation implementation."""

    @staticmethod
    def _docker_control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        return _run_docker_control(command, timeout=timeout)

    @staticmethod
    def _image_digest(image: str) -> str | None:
        inspected = inspect_docker_image(
            image,
            control_runner=_run_docker_control,
            timeout=_DOCKER_CONTROL_TIMEOUT_SECONDS,
        )
        if inspected.returncode != 0:
            return None
        return inspected.stdout.strip() or None
