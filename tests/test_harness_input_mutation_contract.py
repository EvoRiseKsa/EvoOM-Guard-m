"""Focused contracts for reviewed ``harness_inputs`` security mutants."""

from __future__ import annotations

from pathlib import Path

import pytest

import evoom_guard.blackbox as blackbox_module
import evoom_guard.verifiers.harness_policy as harness_policy_module
from evoom_guard.blackbox import BlackboxResult, run_blackbox
from evoom_guard.guard import guard
from evoom_guard.policy.harness import (
    harness_input_path_conflicts,
    is_portable_repo_path,
    setup_output_harness_conflicts,
)
from evoom_guard.record_verifier import verify_record
from evoom_guard.verifiers.blackbox_pack import (
    BlackboxPackExecutionOutcome,
    BlackboxPackExecutionRequest,
    BlackboxPackVerdictFacts,
)
from evoom_guard.verifiers.candidate_preflight import (
    CandidatePreflightRequest,
    CandidatePreflightServices,
    evaluate_candidate_preflight,
)
from evoom_guard.verifiers.harness_policy import (
    HarnessInputIntegrityError,
    candidate_path_targets_harness_input,
)
from evoom_guard.verifiers.repo_candidate import (
    RepoCandidateAdmissionRequest,
    RepoCandidateAdmissionServices,
    admit_repo_candidate,
)

_HARNESS_INPUT = "judge/run-suite.py"


class _BlackboxEvidence:
    def as_dict(self) -> dict[str, object]:
        return {
            "requested": "subprocess",
            "delivered": "subprocess",
            "note": "mutation-contract boundary",
        }


class _BlackboxRecorder:
    def __init__(self, workdir: str) -> None:
        self.path = str(Path(workdir) / "invocation.sock")
        self.token = "mutation-contract-token"

    def drain(self) -> int:
        return 1

    def close(self) -> None:
        return None


def _make_blackbox_tree(root: Path) -> tuple[Path, Path]:
    repo = root / "repo"
    pack = root / "pack"
    harness = repo / Path(*_HARNESS_INPUT.split("/"))
    harness.parent.mkdir(parents=True)
    harness.write_text("# trusted wrapper\n", encoding="utf-8")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    pack.mkdir()
    (pack / "test_protocol.py").write_text(
        "def test_protocol():\n    assert True\n",
        encoding="utf-8",
    )
    return repo, pack


def _patch_blackbox_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        blackbox_module._InvocationRecorder,
        "create",
        lambda workdir: _BlackboxRecorder(workdir),
    )

    def prepare(
        _runner: object,
        _workdir: str,
        target_dir: str,
    ) -> tuple[str, dict[str, str], _BlackboxEvidence]:
        return (
            "mutation-contract-launcher",
            {
                "EVOGUARD_EXEC": "mutation-contract-launcher",
                "EVOGUARD_TARGET": target_dir,
            },
            _BlackboxEvidence(),
        )

    monkeypatch.setattr(blackbox_module.CandidateRunner, "prepare", prepare)
    monkeypatch.setattr(
        blackbox_module,
        "_cleanup_candidate_containers",
        lambda *_args, **_kwargs: None,
    )


def _passing_blackbox_result() -> BlackboxResult:
    return BlackboxResult(
        passed=True,
        tests_passed=1,
        tests_total=1,
        diagnostics="",
        ran=True,
        error=None,
        pack_sha256="0" * 64,
        junit_sha256="1" * 64,
        isolation={
            "requested": "subprocess",
            "delivered": "subprocess",
        },
        deleted_applied=[],
        started=True,
        completed=True,
        execution_state="completed",
        execution_phase="blackbox_pack",
        pack_present=True,
        candidate_invocations=1,
        candidate_launcher_invocation_observed=True,
    )


def test_candidate_preflight_makes_declared_harness_inputs_non_exemptible() -> None:
    """The declaration itself must reject a path when every other gate permits it."""

    result = evaluate_candidate_preflight(
        CandidatePreflightRequest(
            repo_path="trusted-repo",
            changed_paths=(_HARNESS_INPUT,),
            protected=("judge/**",),
            allow=("judge/**",),
            allow_new_tests=True,
            harness_inputs=(_HARNESS_INPUT,),
        ),
        services=CandidatePreflightServices(
            path_exists=lambda _path: True,
            discover_local_action_dirs=lambda _repo: (),
            is_safe_relpath=lambda _path: True,
            is_judge_autoexec=lambda _path: False,
            is_protected_config=lambda _path, *, strict_harness: False,
            is_protected_ci=lambda _path, *, local_action_dirs: False,
            is_protected=lambda _path, _protected: True,
            is_addable_new_test=lambda _path, _extra, **_kwargs: True,
            is_allowlist_exemptible=lambda _path, **_kwargs: True,
            matches_globs=lambda _path, _globs: True,
            verifier_pack_dir=lambda: "reserved-verifier-pack",
        ),
    )

    assert result.protected_violations == (_HARNESS_INPUT,)
    assert result.may_execute is False


def test_repo_candidate_forwards_harness_inputs_to_changed_path_policy() -> None:
    """Candidate admission must not silently drop the trusted declaration."""

    observed: list[tuple[str, ...]] = []

    def capture_policy(
        _paths,
        _extra,
        *,
        harness_inputs=(),
        **_kwargs,
    ):
        observed.append(tuple(harness_inputs))
        return None

    outcome = admit_repo_candidate(
        RepoCandidateAdmissionRequest(
            hypothesis="structured candidate",
            repo_path="trusted-repo",
        ),
        services=RepoCandidateAdmissionServices(
            is_directory=lambda: lambda _path: True,
            deleted_paths=lambda: (),
            file_blocks_override=lambda: {_HARNESS_INPUT: "# candidate\n"},
            target_files=lambda: (),
            extra_protected=lambda: (),
            allow=lambda: (),
            allow_new_tests=lambda: False,
            strict_harness=lambda: False,
            parse_file_blocks=lambda: lambda _text: {},
            parse_patch_blocks=lambda: lambda _text: [],
            parse_blocks_lenient=lambda: lambda _text, _default=None: ({}, []),
            discover_local_action_dirs=lambda: lambda _path: (),
            is_safe_relpath=lambda: lambda _path: True,
            join_path=lambda: lambda root, path: f"{root}/{path}",
            path_exists=lambda: lambda _path: True,
            reject_paths=lambda: capture_policy,
            harness_inputs=lambda: (_HARNESS_INPUT,),
        ),
    )

    assert outcome.candidate is not None
    assert observed == [(_HARNESS_INPUT,)]


def test_repo_candidate_forwards_harness_inputs_to_deletion_policy() -> None:
    """A deleted declared input must reach the same non-exemptible policy."""

    observed: list[tuple[tuple[str, ...], tuple[str, ...]]] = []

    def capture_policy(
        paths,
        _extra,
        *,
        harness_inputs=(),
        **_kwargs,
    ):
        observed.append((tuple(paths), tuple(harness_inputs)))
        return None

    outcome = admit_repo_candidate(
        RepoCandidateAdmissionRequest(
            hypothesis="structured candidate",
            repo_path="trusted-repo",
        ),
        services=RepoCandidateAdmissionServices(
            is_directory=lambda: lambda _path: True,
            deleted_paths=lambda: (_HARNESS_INPUT,),
            file_blocks_override=lambda: {"app.py": "# candidate\n"},
            target_files=lambda: (),
            extra_protected=lambda: (),
            allow=lambda: (),
            allow_new_tests=lambda: False,
            strict_harness=lambda: False,
            parse_file_blocks=lambda: lambda _text: {},
            parse_patch_blocks=lambda: lambda _text: [],
            parse_blocks_lenient=lambda: lambda _text, _default=None: ({}, []),
            discover_local_action_dirs=lambda: lambda _path: (),
            is_safe_relpath=lambda: lambda _path: True,
            join_path=lambda: lambda root, path: f"{root}/{path}",
            path_exists=lambda: lambda _path: True,
            reject_paths=lambda: capture_policy,
            harness_inputs=lambda: (_HARNESS_INPUT,),
        ),
    )

    assert outcome.candidate is not None
    assert observed == [
        (("app.py",), (_HARNESS_INPUT,)),
        ((_HARNESS_INPUT,), (_HARNESS_INPUT,)),
    ]


def test_setup_output_conflict_includes_declared_input_ancestors() -> None:
    """A setup exclusion matching an ancestor must not hide the helper below it."""

    assert setup_output_harness_conflicts(
        ("ci/scripts/run-suite.py",),
        ("**/scripts",),
    ) == ("ci/scripts/run-suite.py",)


def test_portable_path_rejects_windows_namespace_alias_spellings() -> None:
    """Candidate paths cannot use Win32 normalization or DOS aliases."""

    assert not is_portable_repo_path("judge/run-suite.py.")
    assert not is_portable_repo_path("judge/run-suite.py ")
    assert not is_portable_repo_path("judge/RUN-SU~1.PY")


def test_declared_harness_input_ancestor_is_a_path_conflict() -> None:
    """Deleting an ancestor must be equivalent to deleting the declared file."""

    assert harness_input_path_conflicts(
        "judge",
        (_HARNESS_INPUT,),
    )


def test_filesystem_alias_identity_is_a_path_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Existing symlink, junction, hardlink, and short-name aliases use samefile."""

    monkeypatch.setattr(
        harness_policy_module.os.path,
        "lexists",
        lambda _path: True,
    )
    monkeypatch.setattr(
        harness_policy_module.os.path,
        "samefile",
        lambda _candidate, trusted: trusted.endswith("run-suite.py"),
    )

    assert candidate_path_targets_harness_input(
        "trusted-repo",
        "judge-alias.py",
        (_HARNESS_INPUT,),
    )


def test_blackbox_compares_materialized_copy_with_trusted_source_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The black-box copy must not become its own trusted baseline."""

    repo, pack = _make_blackbox_tree(tmp_path)
    original_capture = blackbox_module.capture_harness_input_snapshot
    capture_roots: list[str] = []

    def divergent_second_capture(
        root: str,
        harness_inputs: tuple[str, ...],
    ) -> dict[str, tuple[str, int, str]]:
        capture_roots.append(root)
        snapshot = original_capture(root, harness_inputs)
        if len(capture_roots) == 2:
            kind, mode, _digest = snapshot[_HARNESS_INPUT]
            snapshot[_HARNESS_INPUT] = (kind, mode, "0" * 64)
        return snapshot

    monkeypatch.setattr(
        blackbox_module,
        "capture_harness_input_snapshot",
        divergent_second_capture,
    )
    monkeypatch.setattr(
        blackbox_module._InvocationRecorder,
        "create",
        lambda workdir: _BlackboxRecorder(workdir),
    )

    def must_not_prepare(*_args: object, **_kwargs: object) -> object:
        pytest.fail("candidate boundary prepared before materialization integrity")

    monkeypatch.setattr(
        blackbox_module.CandidateRunner,
        "prepare",
        must_not_prepare,
    )

    result = run_blackbox(
        str(repo),
        "structured candidate",
        str(pack),
        file_blocks={"app.py": "VALUE = 2\n"},
        harness_inputs=(_HARNESS_INPUT,),
    )

    assert len(capture_roots) == 2
    assert capture_roots[0] == str(repo)
    assert capture_roots[1] != str(repo)
    assert result.error == "candidate harness input changed"
    assert result.started is False
    assert result.execution_state == "not_started"


def test_blackbox_postcondition_invalidates_completed_pack_verdict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A green external pack cannot survive persistent helper drift."""

    repo, pack = _make_blackbox_tree(tmp_path)
    _patch_blackbox_boundary(monkeypatch)

    def execute_pack(
        request: BlackboxPackExecutionRequest,
        *,
        lifecycle: object,
        services: object,
    ) -> BlackboxPackExecutionOutcome:
        del lifecycle, services
        target = Path(request.environment["EVOGUARD_TARGET"])
        (target / Path(*_HARNESS_INPUT.split("/"))).write_text(
            "# runtime attacker\n",
            encoding="utf-8",
        )
        return BlackboxPackExecutionOutcome(
            terminal=BlackboxPackVerdictFacts(
                passed=True,
                tests_passed=1,
                tests_total=1,
                diagnostics="pack passed",
                ran=True,
                error=None,
                junit_sha256="1" * 64,
                started=True,
                completed=True,
                execution_state="completed",
                execution_phase="blackbox_pack",
                attach_candidate_evidence=True,
            )
        )

    monkeypatch.setattr(
        blackbox_module,
        "execute_blackbox_pack",
        execute_pack,
    )
    result = run_blackbox(
        str(repo),
        "structured candidate",
        str(pack),
        file_blocks={"app.py": "VALUE = 2\n"},
        harness_inputs=(_HARNESS_INPUT,),
    )

    assert result.passed is False
    assert result.ran is False
    assert result.error == "candidate harness input changed"
    assert result.started is True
    assert result.completed is True
    assert result.execution_state == "completed"
    assert result.candidate_launcher_invocation_observed is True
    assert _HARNESS_INPUT in result.diagnostics


def test_blackbox_postcondition_checks_terminal_without_candidate_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every terminal pack path is checked, including pre-invocation failure."""

    repo, pack = _make_blackbox_tree(tmp_path)
    _patch_blackbox_boundary(monkeypatch)

    def execute_pack(
        request: BlackboxPackExecutionRequest,
        *,
        lifecycle: object,
        services: object,
    ) -> BlackboxPackExecutionOutcome:
        del lifecycle, services
        target = Path(request.environment["EVOGUARD_TARGET"])
        (target / Path(*_HARNESS_INPUT.split("/"))).write_text(
            "# concurrent attacker\n",
            encoding="utf-8",
        )
        return BlackboxPackExecutionOutcome(
            terminal=BlackboxPackVerdictFacts(
                passed=False,
                tests_passed=0,
                tests_total=0,
                diagnostics="pack snapshot changed",
                ran=False,
                error="verifier pack snapshot changed",
            )
        )

    monkeypatch.setattr(
        blackbox_module,
        "execute_blackbox_pack",
        execute_pack,
    )
    result = run_blackbox(
        str(repo),
        "structured candidate",
        str(pack),
        file_blocks={"app.py": "VALUE = 2\n"},
        harness_inputs=(_HARNESS_INPUT,),
    )

    assert result.error == "candidate harness input changed"
    assert result.started is False
    assert result.execution_state == "not_started"
    assert result.candidate_launcher_invocation_observed is False
    assert _HARNESS_INPUT in result.diagnostics


def test_blackbox_trusted_binding_failure_is_an_assurance_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failure to bind the trusted source must not be blamed on the candidate."""

    repo, pack = _make_blackbox_tree(tmp_path)

    def fail_binding(
        _root: str,
        _harness_inputs: tuple[str, ...],
    ) -> dict[str, tuple[str, int, str]]:
        raise HarnessInputIntegrityError("source changed while hashing")

    monkeypatch.setattr(
        blackbox_module,
        "capture_harness_input_snapshot",
        fail_binding,
    )
    result = guard(
        str(repo),
        "structured candidate",
        file_blocks={"app.py": "VALUE = 2\n"},
        verifier_pack=str(pack),
        blackbox=True,
        blackbox_only=True,
        harness_inputs=(_HARNESS_INPUT,),
    )
    record = result.to_dict()

    assert result.verdict == "ERROR"
    assert result.reason_code == "assurance_requirement_not_met"
    assert record["test_command_ran"] is False
    assert record["execution_state"] == "not_started"
    assert verify_record(record)["ok"] is True


def test_guard_maps_blackbox_harness_drift_to_tampered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack = _make_blackbox_tree(tmp_path)

    def drifted_run(*_args: object, **_kwargs: object) -> BlackboxResult:
        return _passing_blackbox_result()._replace(
            passed=False,
            ran=False,
            error="candidate harness input changed",
            diagnostics=f"persistent drift: {_HARNESS_INPUT}",
        )

    monkeypatch.setattr(blackbox_module, "run_blackbox", drifted_run)
    result = guard(
        str(repo),
        "structured candidate",
        file_blocks={"app.py": "VALUE = 2\n"},
        verifier_pack=str(pack),
        blackbox=True,
        blackbox_only=True,
        harness_inputs=(_HARNESS_INPUT,),
    )

    assert result.verdict == "TAMPERED"
    assert result.reason_code == "candidate_tree_changed_during_run"
    assert result.to_dict()["verdict_source"] is None


def test_guard_forwards_nonempty_blackbox_harness_inputs_exactly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack = _make_blackbox_tree(tmp_path)
    observed: list[tuple[str, ...] | None] = []

    def capture_run(*_args: object, **kwargs: object) -> BlackboxResult:
        value = kwargs.get("harness_inputs")
        observed.append(value if isinstance(value, tuple) else None)
        return _passing_blackbox_result()

    monkeypatch.setattr(blackbox_module, "run_blackbox", capture_run)
    result = guard(
        str(repo),
        "structured candidate",
        file_blocks={"app.py": "VALUE = 2\n"},
        verifier_pack=str(pack),
        blackbox=True,
        blackbox_only=True,
        harness_inputs=(_HARNESS_INPUT,),
    )

    assert result.verdict == "PASS"
    assert observed == [(_HARNESS_INPUT,)]


def test_guard_omits_empty_blackbox_harness_keyword_for_compatibility(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack = _make_blackbox_tree(tmp_path)
    observed: list[bool] = []

    def legacy_run(*_args: object, **kwargs: object) -> BlackboxResult:
        observed.append("harness_inputs" in kwargs)
        return _passing_blackbox_result()

    monkeypatch.setattr(blackbox_module, "run_blackbox", legacy_run)
    result = guard(
        str(repo),
        "structured candidate",
        file_blocks={"app.py": "VALUE = 2\n"},
        verifier_pack=str(pack),
        blackbox=True,
        blackbox_only=True,
    )

    assert result.verdict == "PASS"
    assert observed == [False]
