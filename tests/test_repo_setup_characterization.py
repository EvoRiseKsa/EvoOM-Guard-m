"""Frozen equivalence gates for RepoVerifier's setup-command phase."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest
from repo_setup_characterization_harness import (
    CASE_NAMES,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
    capture_command,
    observe_live_operation_order,
)

from evoom_guard.verifiers import repo_setup, repo_verifier

VECTOR = Path(__file__).parent / "fixtures" / "refactor-safety" / "repo-setup-v1.json"


def _frozen() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_repo_setup_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_repo_setup_behavior(case_name: str, tmp_path: Path) -> None:
    expected = _frozen()["cases"][case_name]["sha256"]
    actual = capture_case(case_name, tmp_path)
    observed = hashlib.sha256(canonical_json(actual).encode("utf-8")).hexdigest()
    if observed != expected:
        pytest.fail(
            "repository setup behavior drifted:\n"
            f"expected sha256: {expected}\n"
            f"observed sha256: {observed}\n"
            "observed behavior:\n" + canonical_json(actual)
        )


@pytest.mark.parametrize(
    ("constructor", "problem", "expected"),
    (
        (["constructor", 1], ["problem"], ["constructor", "1"]),
        ([], ["problem", 2], ["problem", "2"]),
        (None, "tool  --flag value", ["tool", "--flag", "value"]),
    ),
)
def test_setup_command_precedence_and_token_normalization_are_frozen(
    constructor: object,
    problem: object,
    expected: list[str],
    tmp_path: Path,
) -> None:
    observed, events = capture_command(
        tmp_path,
        constructor_command=constructor,
        problem_command=problem,
    )
    assert observed == expected
    assert events == ["resolve", "pre-snapshot"]


def test_setup_operation_order_is_frozen(tmp_path: Path) -> None:
    assert observe_live_operation_order(tmp_path) == [
        "resolve-setup",
        "snapshot-pre",
        "run-setup",
        "snapshot-post",
        "changes",
        "resolve-suite",
        "run-suite",
    ]


def test_repo_setup_owner_exposes_immutable_typed_contracts() -> None:
    request = repo_setup.RepoSetupRequest(
        configured_command=None,
        candidate_copy="copy",
        files_changed=("app.py",),
        environment={},
        container_mode=False,
        resolved_image=None,
    )
    outcome = repo_setup.RepoSetupOutcome(requested=False)

    assert repo_setup.execute_repo_setup.__module__ == ("evoom_guard.verifiers.repo_setup")
    with pytest.raises(FrozenInstanceError):
        request.container_mode = True  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        outcome.requested = True  # type: ignore[misc]


def test_no_setup_command_reaches_the_suite_without_setup_effects(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source-no-setup"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.setattr(
        repo_verifier,
        "_run_bounded_subprocess",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(FileNotFoundError("controlled suite stop")),
    )

    result = repo_verifier.RepoVerifier(
        test_command=["suite"],
        mem_limit_mb=0,
    ).verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {"repo_path": str(source)},
    )

    assert result.artifact["outcome"] == "test_command_unavailable"
    assert result.artifact["execution_phase"] == "repo_suite"
    assert result.artifact["setup_isolation_evidence"] is None


def test_no_setup_command_performs_no_setup_specific_attribute_lookups(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A falsey command must not even construct setup's live-service request."""

    source = tmp_path / "source-no-setup-lookups"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    watched = {
        "trust_setup_on_host",
        "setup_output_globs",
        "timeout",
        "strict_harness",
        "docker_network",
        "docker_runtime",
    }

    class LookupProbe(repo_verifier.RepoVerifier):
        tracking = False
        lookups: dict[str, int]

        def __getattribute__(self, name: str):
            if name in watched and object.__getattribute__(self, "tracking"):
                lookups = object.__getattribute__(self, "lookups")
                lookups[name] = lookups.get(name, 0) + 1
            return super().__getattribute__(name)

    verifier = LookupProbe(test_command=["suite"], mem_limit_mb=0)
    verifier.lookups = {}
    verifier.tracking = True
    monkeypatch.setattr(
        repo_verifier,
        "execute_repo_setup",
        lambda *_args, **_kwargs: pytest.fail(
            "no-command path invoked repository setup"
        ),
    )
    monkeypatch.setattr(
        repo_verifier,
        "_resolve_host_command",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            FileNotFoundError("controlled suite stop")
        ),
    )

    result = verifier.verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {"repo_path": str(source)},
    )

    assert result.artifact["outcome"] == "test_command_unavailable"
    assert verifier.lookups == {"strict_harness": 1}


def test_host_resolver_can_change_setup_output_globs_before_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source-live-output-globs"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    verifier = repo_verifier.RepoVerifier(
        setup_command=["setup"],
        setup_output_globs=("early/**",),
        test_command=["suite"],
        mem_limit_mb=0,
    )
    observed: list[tuple[str, ...]] = []

    def resolver(command, *, cwd, env):
        verifier.setup_output_globs = ("late/**",)
        return command

    def snapshot(root, output_globs=(), *, baseline=None):
        observed.append(tuple(output_globs))
        raise repo_verifier.SetupFidelityError("controlled snapshot stop")

    monkeypatch.setattr(repo_verifier, "_resolve_host_command", resolver)
    monkeypatch.setattr(repo_verifier, "_setup_fidelity_snapshot", snapshot)

    result = verifier.verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {"repo_path": str(source)},
    )

    assert result.artifact["outcome"] == "setup_failed"
    assert observed == [("late/**",)]


def test_pre_snapshot_can_change_timeout_but_not_effective_strict_policy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source-live-host-policy"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    verifier = repo_verifier.RepoVerifier(
        timeout=7,
        strict_harness=False,
        setup_command=["setup"],
        test_command=["suite"],
        mem_limit_mb=0,
    )
    observed: dict[str, object] = {}

    def snapshot(root, output_globs=(), *, baseline=None):
        verifier.timeout = 13
        verifier.strict_harness = True
        return {"app.py": ("file", 0, "digest")}

    def runner(command, **kwargs):
        observed["timeout"] = kwargs["timeout"]
        observed["strict"] = kwargs[
            "require_process_group_cleanup_proof"
        ]
        raise FileNotFoundError("controlled setup stop")

    monkeypatch.setattr(repo_verifier, "_setup_fidelity_snapshot", snapshot)
    monkeypatch.setattr(repo_verifier, "_run_bounded_subprocess", runner)

    result = verifier.verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {"repo_path": str(source)},
    )

    assert result.artifact["outcome"] == "setup_failed"
    assert observed == {"timeout": 13, "strict": False}


def test_token_normalization_can_change_container_setup_trust(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source-live-trust"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    events: list[str] = []
    verifier = repo_verifier.RepoVerifier(
        isolation="docker",
        docker_image="judge:latest",
        test_command=["suite"],
        mem_limit_mb=0,
    )

    class TrustMutatingToken:
        def __str__(self) -> str:
            verifier.trust_setup_on_host = True
            events.append("token")
            return "setup"

    verifier.setup_command = [TrustMutatingToken()]  # type: ignore[list-item]
    monkeypatch.setattr(
        verifier,
        "_resolve_docker_image",
        lambda: "sha256:" + "a" * 64,
    )
    monkeypatch.setattr(
        verifier,
        "_docker_command",
        lambda *_args, **_kwargs: pytest.fail(
            "late trust opt-in still selected container setup"
        ),
    )

    def resolver(command, *, cwd, env):
        events.append("host-resolver")
        return command

    monkeypatch.setattr(repo_verifier, "_resolve_host_command", resolver)
    monkeypatch.setattr(
        repo_verifier,
        "_setup_fidelity_snapshot",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            repo_verifier.SetupFidelityError("controlled snapshot stop")
        ),
    )

    verifier.verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {"repo_path": str(source)},
    )

    assert events == ["token", "host-resolver"]


def test_docker_runner_can_change_isolation_before_timeout_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source-live-timeout-isolation"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    verifier = repo_verifier.RepoVerifier(
        isolation="docker",
        docker_image="judge:latest",
        setup_command=["setup"],
        test_command=["suite"],
        mem_limit_mb=0,
        timeout=7,
    )
    monkeypatch.setattr(
        verifier,
        "_resolve_docker_image",
        lambda: "sha256:" + "a" * 64,
    )
    monkeypatch.setattr(
        verifier,
        "_docker_command",
        lambda *_args, **_kwargs: ["docker", "setup"],
    )

    def runner(command, name):
        verifier.isolation = "gvisor"
        raise repo_verifier._DockerRunTimeout(
            subprocess.TimeoutExpired(command, 7),
            container_started=True,
        )

    monkeypatch.setattr(verifier, "_run_docker_client", runner)

    result = verifier.verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {"repo_path": str(source)},
    )

    assert result.artifact["setup_isolation"] == "gvisor"
    assert result.artifact["setup_isolation_evidence"]["requested"] == "gvisor"
    assert result.artifact["setup_isolation_evidence"]["delivered"] == "gvisor"


def test_docker_exit_125_uses_live_network_and_runtime_fields(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source-live-container-fields"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    verifier = repo_verifier.RepoVerifier(
        isolation="docker",
        docker_image="judge:latest",
        docker_network="none",
        setup_command=["setup"],
        test_command=["suite"],
        mem_limit_mb=0,
    )
    monkeypatch.setattr(
        verifier,
        "_resolve_docker_image",
        lambda: "sha256:" + "a" * 64,
    )
    monkeypatch.setattr(
        verifier,
        "_docker_command",
        lambda *_args, **_kwargs: ["docker", "setup"],
    )
    monkeypatch.setattr(
        verifier,
        "_run_docker_client",
        lambda command, name: subprocess.CompletedProcess(
            command, 125, "raw", "error"
        ),
    )

    def distill(text: str) -> str:
        verifier.docker_network = "late-network"
        verifier.docker_runtime = "late-runtime"
        return "DISTILLED"

    monkeypatch.setattr(repo_verifier, "distill_diagnostics", distill)

    result = verifier.verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {"repo_path": str(source)},
    )

    assert result.artifact["isolation_evidence"]["network"] == "late-network"
    assert result.artifact["isolation_evidence"]["runtime"] == "late-runtime"
    assert result.artifact["setup_isolation_evidence"]["network"] == (
        "late-network"
    )
    assert result.artifact["setup_isolation_evidence"]["runtime"] == (
        "late-runtime"
    )


def test_repo_verifier_resolves_host_setup_seams_at_each_operation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Each earlier operation may replace the next historical facade seam."""

    source = tmp_path / "source-live-host"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    events: list[str] = []
    run_count = 0

    def late_changes(before: Any, after: Any) -> list[str]:
        events.append("late-changes")
        return []

    def late_post(
        root: str,
        output_globs=(),
        *,
        baseline=None,
    ) -> dict[str, tuple[str, int, str]]:
        events.append("late-post")
        monkeypatch.setattr(
            repo_verifier,
            "_setup_fidelity_changes",
            late_changes,
        )
        return {"post": ("file", 0, "2")}

    def late_run(command: list[str], **kwargs: Any):
        nonlocal run_count
        run_count += 1
        if run_count == 1:
            events.append("late-run")
            monkeypatch.setattr(
                repo_verifier,
                "_setup_fidelity_snapshot",
                late_post,
            )
            return subprocess.CompletedProcess(command, 0, "", "")
        events.append("suite-stop")
        raise FileNotFoundError("controlled suite stop")

    def late_pre(
        root: str,
        output_globs=(),
        *,
        baseline=None,
    ) -> dict[str, tuple[str, int, str]]:
        events.append("late-pre")
        monkeypatch.setattr(
            repo_verifier,
            "_run_bounded_subprocess",
            late_run,
        )
        return {"pre": ("file", 0, "1")}

    def live_resolve(command: list[str], *, cwd: str, env: dict[str, str]):
        events.append("resolve")
        if len(events) == 1:
            monkeypatch.setattr(
                repo_verifier,
                "_setup_fidelity_snapshot",
                late_pre,
            )
        return command

    monkeypatch.setattr(
        repo_verifier,
        "_resolve_host_command",
        live_resolve,
    )
    monkeypatch.setattr(
        repo_verifier,
        "_setup_fidelity_snapshot",
        lambda *_args, **_kwargs: pytest.fail("snapshotted pre-setup fidelity seam was used"),
    )
    monkeypatch.setattr(
        repo_verifier,
        "_run_bounded_subprocess",
        lambda *_args, **_kwargs: pytest.fail("snapshotted setup runner seam was used"),
    )
    monkeypatch.setattr(
        repo_verifier,
        "_setup_fidelity_changes",
        lambda *_args, **_kwargs: pytest.fail("snapshotted setup changes seam was used"),
    )

    result = repo_verifier.RepoVerifier(
        setup_command=["setup"],
        test_command=["suite"],
        mem_limit_mb=0,
    ).verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {"repo_path": str(source)},
    )

    assert result.artifact["outcome"] == "test_command_unavailable"
    assert events == [
        "resolve",
        "late-pre",
        "late-run",
        "late-post",
        "late-changes",
        "resolve",
        "suite-stop",
    ]


def test_repo_verifier_resolves_docker_setup_methods_at_each_operation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Container-name/build/run/evidence/diagnostics lookups remain live."""

    source = tmp_path / "source-live-docker"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    events: list[str] = []
    verifier = repo_verifier.RepoVerifier(
        isolation="docker",
        docker_image="judge:latest",
        setup_command=["setup"],
        test_command=["suite"],
        mem_limit_mb=0,
    )
    monkeypatch.setattr(
        verifier,
        "_resolve_docker_image",
        lambda: "sha256:" + "a" * 64,
    )

    def late_evidence(delivered: str, image: str | None, *, note=None):
        events.append("late-evidence")
        return repo_verifier.IsolationObservation(
            requested="docker",
            delivered=delivered,
            image_digest=image,
            network="none",
            runtime=None,
            note=note,
        )

    def late_distill(text: str) -> str:
        events.append("late-distill")
        return "LATE"

    def late_run(command: list[str], name: str):
        events.append("late-run")
        monkeypatch.setattr(verifier, "_phase_isolation_evidence", late_evidence)
        monkeypatch.setattr(repo_verifier, "distill_diagnostics", late_distill)
        return subprocess.CompletedProcess(command, 3, "raw", "error")

    def late_build(
        command: list[str],
        copy: str,
        outdir: str | None,
        name: str,
        report_env=None,
        *,
        work_writable=False,
        pack_dir=None,
    ) -> list[str]:
        events.append("late-build")
        monkeypatch.setattr(verifier, "_run_docker_client", late_run)
        return ["docker", "setup"]

    def live_name(label: str) -> str:
        events.append("live-name")
        monkeypatch.setattr(verifier, "_docker_command", late_build)
        return "setup-name"

    monkeypatch.setattr(repo_verifier, "_docker_container_name", live_name)
    monkeypatch.setattr(
        verifier,
        "_docker_command",
        lambda *_args, **_kwargs: pytest.fail("snapshotted docker command builder was used"),
    )
    monkeypatch.setattr(
        verifier,
        "_run_docker_client",
        lambda *_args, **_kwargs: pytest.fail("snapshotted docker setup runner was used"),
    )
    monkeypatch.setattr(
        verifier,
        "_phase_isolation_evidence",
        lambda *_args, **_kwargs: pytest.fail("snapshotted phase-evidence builder was used"),
    )
    monkeypatch.setattr(
        repo_verifier,
        "distill_diagnostics",
        lambda *_args, **_kwargs: pytest.fail("snapshotted diagnostics seam was used"),
    )

    result = verifier.verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {"repo_path": str(source)},
    )

    assert result.diagnostics.endswith(": LATE")
    assert events == [
        "live-name",
        "late-build",
        "late-run",
        "late-evidence",
        "late-distill",
    ]


def test_setup_keyboard_interrupt_reaches_outer_workspace_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The extracted phase must not consume BaseException cleanup paths."""

    source = tmp_path / "source-interrupt"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    cleanups: list[tuple[tuple[tuple[str, str | None], ...], object]] = []
    original_cleanup = repo_verifier._cleanup_repo_workspaces

    def interrupt(*_args: Any, **_kwargs: Any):
        raise KeyboardInterrupt("controlled setup interruption")

    def record_cleanup(workspaces, *, primary):
        cleanups.append((tuple(workspaces), primary))
        return original_cleanup(workspaces, primary=primary)

    monkeypatch.setattr(repo_verifier, "_run_bounded_subprocess", interrupt)
    monkeypatch.setattr(
        repo_verifier,
        "_cleanup_repo_workspaces",
        record_cleanup,
    )

    with pytest.raises(KeyboardInterrupt, match="controlled setup interruption"):
        repo_verifier.RepoVerifier(
            setup_command=["setup"],
            test_command=["suite"],
            mem_limit_mb=0,
        ).verify(
            "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
            {"repo_path": str(source)},
        )

    assert len(cleanups) == 1
    workspaces, primary = cleanups[0]
    assert isinstance(primary, KeyboardInterrupt)
    assert workspaces[0][0] == "candidate workspace"
    assert workspaces[0][1]
    assert workspaces[1] == ("verifier-pack snapshot", None)


def test_setup_failure_keeps_accepted_pack_identity_sticky(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source-sticky"
    pack = tmp_path / "pack-sticky"
    source.mkdir()
    pack.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (pack / "test_contract.py").write_text(
        "def test_contract():\n    assert True\n",
        encoding="utf-8",
    )
    digest = "c" * 64
    manifest = {"id": "sticky", "version": "1"}

    monkeypatch.setattr(
        repo_verifier,
        "snapshot_pack",
        lambda _source, _destination: (digest, manifest),
    )
    monkeypatch.setattr(
        repo_verifier,
        "_run_bounded_subprocess",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 3, "", "failed"),
    )

    result = repo_verifier.RepoVerifier(
        setup_command=["setup"],
        test_command=["suite"],
        mem_limit_mb=0,
    ).verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {"repo_path": str(source), "verifier_pack": str(pack)},
    )

    assert result.artifact["outcome"] == "setup_failed"
    assert result.artifact["verifier_pack_sha256"] == digest
    assert result.artifact["verifier_pack_manifest"] == manifest
