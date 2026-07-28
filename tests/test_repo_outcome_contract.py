"""Cross-layer invariants for repository execution outcomes and verdict states."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from repo_pack_characterization_harness import (
    CASE_NAMES as PACK_CASE_NAMES,
)
from repo_pack_characterization_harness import (
    capture_case as capture_pack_case,
)
from repo_setup_characterization_harness import (
    CASE_NAMES as SETUP_CASE_NAMES,
)
from repo_setup_characterization_harness import (
    capture_case as capture_setup_case,
)
from repo_suite_characterization_harness import (
    CASE_NAMES as SUITE_CASE_NAMES,
)
from repo_suite_characterization_harness import (
    capture_case as capture_suite_case,
)

from evoom_guard.application.repo_decision import OUTCOME_REASON_POLICY
from evoom_guard.domain.verdict import REASON_CONTRACT

CaptureCase = Callable[[str, Path], dict[str, Any]]

_CASES: tuple[tuple[str, CaptureCase, str], ...] = tuple(
    (owner, capture, case_name)
    for owner, capture, case_names in (
        ("suite", capture_suite_case, SUITE_CASE_NAMES),
        ("setup", capture_setup_case, SETUP_CASE_NAMES),
        ("pack", capture_pack_case, PACK_CASE_NAMES),
    )
    for case_name in case_names
)


@pytest.mark.parametrize(("owner", "capture", "case_name"), _CASES)
def test_repo_outcome_reason_allows_recorded_execution_state(
    owner: str,
    capture: CaptureCase,
    case_name: str,
    tmp_path: Path,
) -> None:
    artifact = capture(case_name, tmp_path)["result"]["artifact"]
    outcome = artifact.get("outcome")
    if outcome not in OUTCOME_REASON_POLICY:
        return

    verdict, reason_code = OUTCOME_REASON_POLICY[outcome]
    allowed_verdicts, allowed_states = REASON_CONTRACT[reason_code]
    execution_state = artifact["execution_state"]

    assert verdict in allowed_verdicts, (
        f"{owner}:{case_name} maps {outcome!r} to verdict {verdict!r}, "
        f"which reason {reason_code!r} does not allow"
    )
    assert execution_state in allowed_states, (
        f"{owner}:{case_name} maps {outcome!r} to reason {reason_code!r}, "
        f"which does not allow execution_state {execution_state!r}"
    )
