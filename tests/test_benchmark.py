import copy
import hashlib
import json
import math
import os
import shutil
import subprocess
import sys
import time
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from benchmarks.evaluate import (
    derive_baseline_prediction,
    evaluate,
    evaluate_baseline,
    evaluate_security_evasions,
)
from benchmarks.run_manifest import (
    MAX_RESULTS_BYTES,
    EvidenceInitialization,
    build_execution_environment,
    build_run_manifest,
    collect_dependency_lock,
    collect_git_state,
    collect_interpreter_identity,
    collect_source_bundle,
    collect_source_evidence,
    finalize_run_manifest_provenance,
    load_run_manifest,
    manifest_bytes,
    publish_evidence_pair,
    read_stable_regular_file,
    source_inventory_paths,
    validate_evidence_destinations,
    validate_initial_evidence_destinations,
    validate_results_destination,
    verify_reproduction_environment,
    verify_run_manifest,
    write_run_manifest,
)

ROOT = Path(__file__).parents[1]
RESULTS = ROOT / "benchmarks" / "results.jsonl"
MANIFEST = ROOT / "benchmarks" / "run-manifest.json"


def _load_rows(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _without_environmental_timing(
    rows: list[dict[str, object]],
) -> list[dict[str, object]]:
    normalized: list[dict[str, object]] = []
    for row in rows:
        item = {
            key: value
            for key, value in row.items()
            if key
            not in {
                "elapsed_s",
                "run_id",
                "execution_source_sha256",
                "execution_environment_sha256",
                "interpreter_identity_sha256",
            }
        }
        baseline = item.get("baseline")
        if isinstance(baseline, dict):
            item["baseline"] = {key: value for key, value in baseline.items() if key != "elapsed_s"}
        normalized.append(item)
    return normalized


def _all_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        strings: list[str] = []
        for key, item in value.items():
            strings.extend(_all_strings(key))
            strings.extend(_all_strings(item))
        return strings
    if isinstance(value, list):
        strings = []
        for item in value:
            strings.extend(_all_strings(item))
        return strings
    return []


def _commit_bound_benchmark_fixture(
    tmp_path: Path,
) -> tuple[Path, Path, dict[str, object]]:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo = tmp_path / "repo"
    repo.mkdir()
    for relative in source_inventory_paths(ROOT):
        destination = repo / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    results = repo / "benchmarks" / "results.jsonl"
    execution_environment, environment_evidence = build_execution_environment()
    environment_digest = environment_evidence["effective_environment_sha256"]
    interpreter_digest = collect_interpreter_identity()["identity_sha256"]
    assert isinstance(environment_digest, str)
    assert isinstance(interpreter_digest, str)
    corpus = corpus_definition()
    raw_cases = corpus["cases"]
    assert isinstance(raw_cases, list)
    cases_by_id = {
        case["id"]: case
        for case in raw_cases
        if isinstance(case, dict) and isinstance(case.get("id"), str)
    }
    source_bundle = collect_source_bundle(repo)
    source_digest = source_bundle.evidence["sha256"]
    assert isinstance(source_digest, str)
    run_id = "00000000-0000-4000-8000-000000000001"
    fixture_rows = _load_rows(RESULTS)
    for row in fixture_rows:
        case = cases_by_id[row["id"]]
        baseline = row["baseline"]
        assert isinstance(baseline, dict)
        if row["id"] in {"pyproject-deselect", "pytest-ini-plant"}:
            baseline.update(
                {
                    "applicable": True,
                    "prediction": "accept",
                    "exit_code": 0,
                    "reason": "exit_code",
                }
            )
        row.update(
            {
                "run_id": run_id,
                "case_kind": case["case_kind"],
                "truth": case["truth"],
                "expected_verdict": case["expect"],
                "note": case["note"],
                "engine_version": ENGINE_VERSION,
                "execution_source_sha256": source_digest,
                "execution_environment_sha256": environment_digest,
                "interpreter_identity_sha256": interpreter_digest,
                "python_isolated": True,
                "pytest_plugin_autoload": False,
                "managed_worker_cleanup_proven": True,
            }
        )
    results.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in fixture_rows),
        encoding="utf-8",
        newline="\n",
    )

    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Benchmark Test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "benchmark@invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "commit.gpgsign", "false"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "core.autocrlf", "false"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo), "add", "--all"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "benchmark fixture"],
        check=True,
    )

    source_bundle = collect_source_bundle(repo)
    results_snapshot = read_stable_regular_file(
        results,
        max_bytes=MAX_RESULTS_BYTES,
        label="benchmark fixture results",
    )
    manifest = build_run_manifest(
        root=repo,
        results_path=results,
        results_snapshot=results_snapshot,
        source_bundle=source_bundle,
        corpus=corpus,
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        run_id=run_id,
        engine_version=ENGINE_VERSION,
        execution_environment=environment_evidence,
        effective_environment=execution_environment,
    )
    git = manifest["git"]
    assert isinstance(git, dict)
    assert git["dirty"] is False
    assert git["bound_paths_match_head"] is True
    assert git["source_inventory_matches_head"] is True
    assert git["source_and_results_commit_bound"] is True
    manifest_path = tmp_path / "run-manifest.json"
    write_run_manifest(manifest_path, manifest)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "retain result evidence",
        ],
        check=True,
    )
    return repo, manifest_path, manifest


def _source_only_benchmark_git_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "source-only-repo"
    repo.mkdir()
    for relative in source_inventory_paths(ROOT):
        destination = repo / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    shutil.copyfile(ROOT / ".gitignore", repo / ".gitignore")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Benchmark Test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "benchmark@invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "commit.gpgsign", "false"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "core.autocrlf", "false"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo), "add", "--all"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "source-only fixture"],
        check=True,
    )
    source_commit = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        encoding="utf-8",
    ).stdout.strip()
    return repo, source_commit


def test_sample_benchmark_has_no_classification_errors() -> None:
    result = evaluate(Path(__file__).parents[1] / "benchmarks" / "sample.jsonl")
    assert result["tp"] == 3
    assert result["tn"] == 1
    assert result["fp"] == 0
    assert result["fn"] == 0


def test_two_phase_provenance_finalizes_committed_results_without_rerun(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo, manifest_path, draft = _commit_bound_benchmark_fixture(tmp_path)
    results = repo / "benchmarks" / "results.jsonl"
    result_bytes = results.read_bytes()
    run_id = draft["run_id"]
    provenance = draft["provenance"]
    claims = draft["claims"]
    assert isinstance(provenance, dict)
    assert isinstance(claims, dict)
    source_commit = provenance["source_commit"]
    assert isinstance(source_commit, dict)
    assert source_commit["bound"] is True
    assert provenance["evidence_commit"] is None
    assert claims["source_commit_bound"] is True
    assert claims["evidence_commit_bound"] is False
    assert claims["source_and_results_commit_bound"] is False

    finalized = finalize_run_manifest_provenance(
        manifest_path,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
    )

    assert results.read_bytes() == result_bytes
    assert finalized["run_id"] == run_id
    finalized_provenance = finalized["provenance"]
    finalized_claims = finalized["claims"]
    assert isinstance(finalized_provenance, dict)
    assert isinstance(finalized_claims, dict)
    evidence_commit = finalized_provenance["evidence_commit"]
    assert isinstance(evidence_commit, dict)
    expected_head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        encoding="utf-8",
    ).stdout.strip()
    assert evidence_commit["commit"] == expected_head
    assert evidence_commit["commit"] != source_commit["commit"]
    assert evidence_commit["results_match_commit"] is True
    assert evidence_commit["final_manifest_in_commit"] is False
    assert finalized_provenance["final_manifest_in_evidence_commit"] is False
    assert finalized_claims["source_commit_bound"] is True
    assert finalized_claims["evidence_commit_bound"] is True
    assert finalized_claims["source_and_results_commit_bound"] is True
    assert finalized_claims["final_manifest_in_evidence_commit"] is False

    write_run_manifest(manifest_path, finalized, replace=True)
    assert (
        verify_run_manifest(
            manifest_path,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
        )
        == ()
    )


def test_provenance_finalization_rejects_same_source_and_evidence_commit(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo, manifest_path, draft = _commit_bound_benchmark_fixture(tmp_path)
    provenance = draft["provenance"]
    assert isinstance(provenance, dict)
    source_record = provenance["source_commit"]
    assert isinstance(source_record, dict)
    source_commit = source_record["commit"]
    assert isinstance(source_commit, str)
    subprocess.run(
        ["git", "-C", str(repo), "reset", "--hard", "-q", source_commit],
        check=True,
    )

    with pytest.raises(
        ValueError,
        match="source and evidence commits must be distinct",
    ):
        finalize_run_manifest_provenance(
            manifest_path,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
        )


def test_manifest_verification_rejects_reversed_provenance_chain(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo, manifest_path, _draft = _commit_bound_benchmark_fixture(tmp_path)
    finalized = finalize_run_manifest_provenance(
        manifest_path,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
    )
    provenance = finalized["provenance"]
    assert isinstance(provenance, dict)
    source_record = provenance["source_commit"]
    evidence_record = provenance["evidence_commit"]
    assert isinstance(source_record, dict)
    assert isinstance(evidence_record, dict)
    source_commit = source_record["commit"]
    evidence_commit = evidence_record["commit"]
    assert isinstance(source_commit, str)
    assert isinstance(evidence_commit, str)
    source_record["commit"] = evidence_commit
    evidence_record["commit"] = source_commit
    forged = tmp_path / "reversed-provenance.json"
    write_run_manifest(forged, finalized)

    errors = verify_run_manifest(
        forged,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
    )

    assert "evidence commit is not a descendant of source commit" in errors


def test_manifest_verification_requires_evidence_below_trusted_tip(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo, manifest_path, _draft = _commit_bound_benchmark_fixture(tmp_path)
    finalized = finalize_run_manifest_provenance(
        manifest_path,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
    )
    write_run_manifest(manifest_path, finalized, replace=True)
    provenance = finalized["provenance"]
    assert isinstance(provenance, dict)
    source_record = provenance["source_commit"]
    assert isinstance(source_record, dict)
    source_commit = source_record["commit"]
    assert isinstance(source_commit, str)
    tree = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", f"{source_commit}^{{tree}}"],
        check=True,
        capture_output=True,
        encoding="utf-8",
    ).stdout.strip()
    sibling = subprocess.run(
        ["git", "-C", str(repo), "commit-tree", tree, "-p", source_commit],
        input="untrusted sibling tip\n",
        check=True,
        capture_output=True,
        encoding="utf-8",
    ).stdout.strip()

    errors = verify_run_manifest(
        manifest_path,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
        required_history_tip=sibling,
    )

    assert "evidence commit is not an ancestor of required history tip" in errors


def test_provenance_finalization_rejects_an_unbound_source_observation(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo, manifest_path, draft = _commit_bound_benchmark_fixture(tmp_path)
    unbound = deepcopy(draft)
    git = unbound["git"]
    provenance = unbound["provenance"]
    claims = unbound["claims"]
    assert isinstance(git, dict)
    assert isinstance(provenance, dict)
    assert isinstance(claims, dict)
    source_commit = provenance["source_commit"]
    assert isinstance(source_commit, dict)

    git.update(
        {
            "dirty": True,
            "porcelain_dirty": True,
            "source_and_results_commit_bound": False,
            "binding": "content-digests-only",
            "reason": "dirty_worktree",
        }
    )
    source_commit.update(
        {
            "bound": False,
            "binding": "content-digests-only",
            "worktree_dirty": True,
            "reason": "dirty_worktree",
        }
    )
    claims.update(
        {
            "source_commit_bound": False,
            "source_and_results_commit_bound": False,
            "content_identity": "content-digests-only",
        }
    )
    write_run_manifest(manifest_path, unbound, replace=True)
    assert (
        verify_run_manifest(
            manifest_path,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
        )
        == ()
    )

    with pytest.raises(ValueError, match="source provenance is not commit-bound"):
        finalize_run_manifest_provenance(
            manifest_path,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
        )


def test_provenance_finalization_rejects_results_not_present_at_head(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo, manifest_path, _draft = _commit_bound_benchmark_fixture(tmp_path)
    results = repo / "benchmarks" / "results.jsonl"
    results.write_bytes(results.read_bytes() + b"\n")

    with pytest.raises(ValueError, match="manifest draft is invalid"):
        finalize_run_manifest_provenance(
            manifest_path,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
        )


def test_provenance_finalization_cli_is_an_isolated_no_rerun_phase(
    tmp_path: Path,
) -> None:
    repo, manifest_path, draft = _commit_bound_benchmark_fixture(tmp_path)
    results = repo / "benchmarks" / "results.jsonl"
    result_bytes = results.read_bytes()

    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(repo / "benchmarks" / "run_live.py"),
            "--finalize-provenance",
            str(manifest_path),
            "--replace",
        ],
        cwd=repo,
        check=False,
        capture_output=True,
        encoding="utf-8",
    )

    assert completed.returncode == 0, completed.stderr
    assert "source and results are commit-bound" in completed.stdout
    assert results.read_bytes() == result_bytes
    finalized = load_run_manifest(manifest_path)
    assert finalized["run_id"] == draft["run_id"]
    provenance = finalized["provenance"]
    assert isinstance(provenance, dict)
    assert isinstance(provenance["evidence_commit"], dict)
    assert provenance["final_manifest_in_evidence_commit"] is False


def test_manifest_cannot_claim_its_final_bytes_are_in_the_evidence_commit(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo, manifest_path, _draft = _commit_bound_benchmark_fixture(tmp_path)
    finalized = finalize_run_manifest_provenance(
        manifest_path,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
    )
    provenance = finalized["provenance"]
    claims = finalized["claims"]
    assert isinstance(provenance, dict)
    assert isinstance(claims, dict)
    provenance["final_manifest_in_evidence_commit"] = True
    claims["final_manifest_in_evidence_commit"] = True
    forged = tmp_path / "forged-self-binding.json"
    write_run_manifest(forged, finalized)

    errors = verify_run_manifest(
        forged,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
    )

    assert "provenance record schema invalid" in errors
    assert "claim boundary drift" in errors


def test_error_is_an_abstention_not_a_credited_detection(tmp_path: Path) -> None:
    path = tmp_path / "errors.jsonl"
    path.write_text(
        json.dumps({"id": "infra", "truth": "block", "verdict": "ERROR"}) + "\n",
        encoding="utf-8",
    )

    result = evaluate(path)

    assert result["tp"] == 0
    assert result["fn"] == 0
    assert result["abstain_block"] == 1
    assert result["coverage"] == 0.0
    assert result["operational_block_rate"] == 1.0


def test_evaluator_rejects_ambiguous_json_rows(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.jsonl"
    duplicate.write_text(
        '{"id":"x","truth":"block","truth":"accept","verdict":"PASS"}\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate JSON key"):
        evaluate(duplicate)

    nonfinite = tmp_path / "nonfinite.jsonl"
    nonfinite.write_text(
        '{"id":"x","truth":"accept","verdict":"PASS","elapsed_s":NaN}\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="non-finite JSON number"):
        evaluate(nonfinite)


def test_influential_parent_environment_is_removed_and_evidenced(
    tmp_path: Path,
) -> None:
    secret = "DO-NOT-LEAK-ENVIRONMENT-VALUE"
    injection = tmp_path / "python-injection"
    injection.mkdir()
    startup = injection / "startup.py"
    startup.write_text(f'raise RuntimeError("{secret}")\n', encoding="utf-8")
    parent = {
        **os.environ,
        "PYTHONPATH": str(injection),
        "PYTHONSTARTUP": str(startup),
        "PYTHONINSPECT": "1",
        "PYTEST_ADDOPTS": "--collect-only",
        "PYTEST_PLUGINS": "secret_plugin",
        "UNRELATED_SECRET": secret,
    }

    effective, evidence = build_execution_environment(parent)
    serialized = json.dumps(evidence, sort_keys=True)

    assert "PYTHONPATH" not in effective
    assert "PYTHONSTARTUP" not in effective
    assert "PYTHONINSPECT" not in effective
    assert "PYTEST_ADDOPTS" not in effective
    assert "PYTEST_PLUGINS" not in effective
    assert "UNRELATED_SECRET" not in effective
    assert effective["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    removed = evidence["removed_influential_keys_present"]
    assert isinstance(removed, list)
    assert {
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
    }.issubset(set(removed))
    assert secret not in serialized
    assert str(injection) not in serialized


def test_hostile_parent_environment_cannot_change_an_isolated_case(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import (
        CASES,
        _run_fresh_staged_phase,
    )

    injected = tmp_path / "injected"
    injected.mkdir()
    (injected / "sitecustomize.py").write_text(
        'raise RuntimeError("PYTHONPATH injection executed")\n',
        encoding="utf-8",
    )
    clean_environment, clean_evidence = build_execution_environment(os.environ)
    hostile_environment, hostile_evidence = build_execution_environment(
        {
            **os.environ,
            "PYTHONPATH": str(injected),
            "PYTEST_ADDOPTS": "--collect-only",
            "PYTEST_PLUGINS": "module_that_must_not_load",
        }
    )
    assert hostile_environment == clean_environment
    assert (
        hostile_evidence["effective_environment_sha256"]
        == clean_evidence["effective_environment_sha256"]
    )
    environment_digest = str(hostile_evidence["effective_environment_sha256"])
    interpreter_digest = str(collect_interpreter_identity()["identity_sha256"])
    source = collect_source_bundle(ROOT)
    source_digest = str(source.evidence["sha256"])
    result = _run_fresh_staged_phase(
        CASES[1],
        source_bundle=source,
        execution_environment=hostile_environment,
        source_digest=source_digest,
        environment_digest=environment_digest,
        interpreter_digest=interpreter_digest,
        baseline=False,
    )
    baseline = _run_fresh_staged_phase(
        CASES[1],
        source_bundle=source,
        execution_environment=hostile_environment,
        source_digest=source_digest,
        environment_digest=environment_digest,
        interpreter_digest=interpreter_digest,
        baseline=True,
    )

    assert result["verdict"] == "FAIL"
    assert baseline["prediction"] == "block"
    assert result["python_isolated"] is True
    assert result["pytest_plugin_autoload"] is False
    assert result["execution_environment_sha256"] == environment_digest


@pytest.mark.skipif(os.name != "nt", reason="requires Windows Job Objects")
def test_windows_worker_waits_for_job_assignment_and_kills_descendants(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import _run_windows_job_worker

    ready = tmp_path / "job-child-ready"
    survived = tmp_path / "job-child-survived"
    descendant = (
        "import sys,time; from pathlib import Path; "
        "Path(sys.argv[1]).write_text('ready'); time.sleep(1.0); "
        "Path(sys.argv[2]).write_text('survived')"
    )
    leader = (
        "import subprocess,sys,time; from pathlib import Path; "
        "from benchmarks.run_live import _await_worker_start_permission; "
        "_await_worker_start_permission(sys.argv[-1]); "
        "subprocess.Popen([sys.executable,'-c',sys.argv[3],sys.argv[1],sys.argv[2]],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
        "stderr=subprocess.DEVNULL,close_fds=True); "
        "deadline=time.monotonic()+3; "
        "\nwhile not Path(sys.argv[1]).exists() and "
        "time.monotonic()<deadline: time.sleep(.01); "
        "\nraise SystemExit(0 if Path(sys.argv[1]).exists() else 2)"
    )

    completed = _run_windows_job_worker(
        [
            sys.executable,
            "-c",
            leader,
            str(ready),
            str(survived),
            descendant,
        ],
        cwd=ROOT,
        env=os.environ.copy(),
        timeout=5,
    )

    assert completed.returncode == 0
    assert ready.exists()
    time.sleep(1.2)
    assert not survived.exists()


@pytest.mark.skipif(os.name != "nt", reason="requires Windows Job Objects")
def test_windows_worker_bounds_output_and_timeout() -> None:
    from benchmarks.run_live import _run_windows_job_worker
    from evoom_guard.execution import ProcessLimits, ProcessOutputLimitExceeded

    prefix = (
        "import sys; "
        "from benchmarks.run_live import _await_worker_start_permission; "
        "_await_worker_start_permission(sys.argv[-1]); "
    )
    limits = ProcessLimits(max_output_bytes=1024)
    with pytest.raises(ProcessOutputLimitExceeded):
        _run_windows_job_worker(
            [
                sys.executable,
                "-c",
                prefix + "sys.stdout.write('x'*100000);sys.stdout.flush()",
            ],
            cwd=ROOT,
            env=os.environ.copy(),
            timeout=5,
            limits=limits,
        )
    with pytest.raises(subprocess.TimeoutExpired) as exc:
        _run_windows_job_worker(
            [sys.executable, "-c", prefix + "import time;time.sleep(60)"],
            cwd=ROOT,
            env=os.environ.copy(),
            timeout=0.1,
            limits=limits,
        )
    assert exc.value.timeout == 0.1


@pytest.mark.skipif(os.name != "nt", reason="requires Windows Job Objects")
def test_windows_job_assignment_failure_never_releases_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_live as run_live_module
    from evoom_guard.execution import ProcessContainmentError

    marker = tmp_path / "worker-released"
    worker = (
        "import sys; from pathlib import Path; "
        "from benchmarks.run_live import _await_worker_start_permission; "
        "_await_worker_start_permission(sys.argv[-1]); "
        "Path(sys.argv[1]).write_text('released')"
    )

    def reject_assignment(
        self: object,
        process: subprocess.Popen[str],
    ) -> None:
        del self, process
        raise ProcessContainmentError("injected assignment failure")

    monkeypatch.setattr(
        run_live_module._WindowsKillOnCloseJob,
        "assign_and_prove",
        reject_assignment,
    )

    with pytest.raises(ProcessContainmentError, match="assignment failure"):
        run_live_module._run_windows_job_worker(
            [sys.executable, "-c", worker, str(marker)],
            cwd=ROOT,
            env=os.environ.copy(),
            timeout=5,
        )

    assert not marker.exists()


def test_posix_worker_dispatch_requires_cleanup_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_live as run_live_module

    observed: dict[str, object] = {}
    command = ["worker", "--case", "one"]

    def fake_run(
        received: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        observed["command"] = received
        observed.update(kwargs)
        return subprocess.CompletedProcess(received, 0, "{}", "")

    monkeypatch.setattr(run_live_module.os, "name", "posix")
    monkeypatch.setattr(run_live_module, "run_bounded_subprocess", fake_run)

    completed = run_live_module._run_isolated_worker_process(
        command,
        cwd=ROOT,
        env={"PATH": "controlled"},
    )

    assert completed.returncode == 0
    assert observed["command"] is command
    assert observed["require_process_group_cleanup_proof"] is True
    assert observed["timeout"] == run_live_module.WORKER_TIMEOUT_SECONDS
    limits = observed["limits"]
    assert isinstance(limits, run_live_module.ProcessLimits)
    assert limits.max_output_bytes == run_live_module.WORKER_MAX_OUTPUT_BYTES


def test_published_live_results_match_their_labels() -> None:
    # benchmarks/results.jsonl is the committed, self-consistent, unattributed
    # measurement snapshot. The live harness can reproduce these outcomes; this
    # file alone does not prove historical execution authenticity. Its metrics
    # must keep the known false negative, abstention, and false positives visible.
    result = evaluate(RESULTS)
    assert result["fn"] == 1, "the known default-profile gap changed — update evidence"
    assert result["fp"] == 2, "the FP count changed — update benchmarks/README.md"
    assert result["abstain"] == 1
    assert result["total"] == 17
    baseline = evaluate_baseline(RESULTS)
    assert baseline["fn"] == 4
    assert baseline["fp"] == 0
    assert baseline["abstain"] == 1
    rows = _load_rows(RESULTS)
    observed_versions = {row.get("engine_version") for row in rows}
    manifest = load_run_manifest(MANIFEST)
    assert observed_versions == {manifest["engine_version"]}
    assert all(isinstance(row.get("baseline"), dict) for row in rows)
    assert all(row.get("python_isolated") is True for row in rows)
    assert all(row.get("pytest_plugin_autoload") is False for row in rows)
    assert all(row.get("managed_worker_cleanup_proven") is True for row in rows)
    assert {row.get("case_kind") for row in rows} == {
        "legitimate",
        "ordinary_invalid",
        "viable_evasion",
        "nonviable_evasion",
        "nonviable_policy_violation",
        "invalid_input",
    }
    security_evasions = evaluate_security_evasions(RESULTS)
    assert security_evasions["total"] == 4
    assert security_evasions["blocked"] == 3
    assert security_evasions["missed"] == 1
    environment_digests = {row.get("execution_environment_sha256") for row in rows}
    assert len(environment_digests) == 1
    environment_digest = next(iter(environment_digests))
    assert isinstance(environment_digest, str)
    assert len(environment_digest) == 64
    interpreter_digests = {row.get("interpreter_identity_sha256") for row in rows}
    assert len(interpreter_digests) == 1
    interpreter_digest = next(iter(interpreter_digests))
    assert isinstance(interpreter_digest, str)
    assert len(interpreter_digest) == 64


def test_published_manifest_binds_current_sources_corpus_and_results() -> None:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    assert (
        verify_run_manifest(
            MANIFEST,
            root=ROOT,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
            require_release_promotion=not ENGINE_VERSION.endswith(".dev0"),
        )
        == ()
    )

    manifest = load_run_manifest(MANIFEST)
    git = manifest["git"]
    provenance = manifest["provenance"]
    claims = manifest["claims"]
    assert manifest["schema_version"] == "evoguard-benchmark-run-v5"
    assert isinstance(git, dict)
    assert isinstance(provenance, dict)
    assert isinstance(claims, dict)
    source_commit = provenance["source_commit"]
    evidence_commit = provenance["evidence_commit"]
    assert isinstance(source_commit, dict)
    assert isinstance(evidence_commit, dict)
    assert source_commit["bound"] is True
    assert evidence_commit["bound"] is True
    assert provenance["final_manifest_in_evidence_commit"] is False
    assert claims["authenticated"] is False
    assert claims["evidence_status"] == "self_consistent_unattributed"
    assert claims["source_commit_bound"] is True
    assert claims["evidence_commit_bound"] is True
    assert claims["source_and_results_commit_bound"] is True
    assert claims["final_manifest_in_evidence_commit"] is False
    assert claims["execution_source_snapshot_bound"] is True
    assert claims["content_identity"] == ("source-and-results-git-commits-plus-content-digests")
    assert "manifest_sha256" not in json.dumps(manifest, sort_keys=True)


def test_exact_dev0_release_promotion_is_opt_in_and_byte_scoped(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    assert ENGINE_VERSION.endswith(".dev0")
    stable_version = ENGINE_VERSION.removesuffix(".dev0")
    repo, manifest_path, _manifest = _commit_bound_benchmark_fixture(tmp_path)
    exact_relation_errors = verify_run_manifest(
        manifest_path,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
        require_release_promotion=True,
    )
    assert "exact dev0 release-promotion relation is not satisfied" in exact_relation_errors
    version_path = repo / "evoom_guard" / "__init__.py"
    development_assignment = f'__version__ = "{ENGINE_VERSION}"'
    stable_assignment = f'__version__ = "{stable_version}"'
    source = version_path.read_text(encoding="utf-8")
    assert source.count(development_assignment) == 1
    stable_source = source.replace(
        development_assignment,
        stable_assignment,
        1,
    )
    version_path.write_text(
        stable_source,
        encoding="utf-8",
        newline="\n",
    )

    strict_errors = verify_run_manifest(
        manifest_path,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=stable_version,
    )
    assert "engine_version drift" in strict_errors
    assert "source content drift" in strict_errors
    assert (
        verify_run_manifest(
            manifest_path,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=stable_version,
            require_release_promotion=True,
        )
        == ()
    )

    for invalid_current_version in (
        f"{stable_version}.dev1",
        f"{stable_version}rc1",
        "4.4.1",
    ):
        invalid_errors = verify_run_manifest(
            manifest_path,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=invalid_current_version,
            require_release_promotion=True,
        )
        assert "exact dev0 release-promotion relation is not satisfied" in invalid_errors

    version_path.write_text(
        stable_source + f"{stable_assignment}\n",
        encoding="utf-8",
        newline="\n",
    )
    duplicate_assignment_errors = verify_run_manifest(
        manifest_path,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=stable_version,
        require_release_promotion=True,
    )
    assert "exact dev0 release-promotion relation is not satisfied" in duplicate_assignment_errors

    version_path.write_text(
        stable_source.replace(
            stable_assignment,
            f'__version__ = "{stable_version}.dev1"',
        ),
        encoding="utf-8",
        newline="\n",
    )
    non_dev0_assignment_errors = verify_run_manifest(
        manifest_path,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=stable_version,
        require_release_promotion=True,
    )
    assert "exact dev0 release-promotion relation is not satisfied" in non_dev0_assignment_errors

    version_path.write_text(
        stable_source + "# unrelated source change\n",
        encoding="utf-8",
        newline="\n",
    )
    promoted_errors = verify_run_manifest(
        manifest_path,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=stable_version,
        require_release_promotion=True,
    )
    assert "source content drift" in promoted_errors

    version_path.write_text(stable_source, encoding="utf-8", newline="\n")
    added_source = repo / "evoom_guard" / "promotion_extra.py"
    added_source.write_text("VALUE = 1\n", encoding="utf-8", newline="\n")
    inventory_errors = verify_run_manifest(
        manifest_path,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=stable_version,
        require_release_promotion=True,
    )
    assert "source content drift" in inventory_errors


def test_release_promotion_flag_requires_manifest_verification(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from benchmarks.run_live import main

    assert main(["--require-release-promotion"]) == 2
    assert "--require-release-promotion requires --verify-manifest" in capsys.readouterr().err


def test_release_promotion_cli_reports_the_required_relation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmarks.run_live as run_live_module

    observed: dict[str, object] = {}

    def verified(_path: Path, **kwargs: object) -> tuple[str, ...]:
        observed.update(kwargs)
        return ()

    monkeypatch.setattr(run_live_module, "verify_run_manifest", verified)
    assert (
        run_live_module.main(
            [
                "--verify-manifest",
                "unused.json",
                "--require-release-promotion",
            ]
        )
        == 0
    )
    assert observed["require_release_promotion"] is True
    assert "relation=exact-release-version-transition" in capsys.readouterr().out


def test_manifest_verifier_detects_results_corpus_and_settings_drift(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    changed_results = tmp_path / "results.jsonl"
    shutil.copyfile(RESULTS, changed_results)
    assert (
        verify_run_manifest(
            MANIFEST,
            root=ROOT,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
            results_path=changed_results,
        )
        == ()
    )
    changed_results.write_bytes(changed_results.read_bytes() + b"\n")
    result_errors = verify_run_manifest(
        MANIFEST,
        root=ROOT,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
        results_path=changed_results,
    )
    assert "results drift" in result_errors

    changed_corpus = copy.deepcopy(corpus_definition())
    cases = changed_corpus["cases"]
    assert isinstance(cases, list)
    assert isinstance(cases[0], dict)
    cases[0]["note"] = "changed label"
    corpus_errors = verify_run_manifest(
        MANIFEST,
        root=ROOT,
        corpus=changed_corpus,
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
    )
    assert "corpus drift" in corpus_errors

    changed_settings = {**RUN_SETTINGS, "timeout_seconds": 121}
    settings_errors = verify_run_manifest(
        MANIFEST,
        root=ROOT,
        corpus=corpus_definition(),
        settings=changed_settings,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
    )
    assert "settings drift" in settings_errors

    changed_baseline = {**BASELINE_DEFINITION, "id": "different-baseline"}
    baseline_errors = verify_run_manifest(
        MANIFEST,
        root=ROOT,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=changed_baseline,
        engine_version=ENGINE_VERSION,
    )
    assert "baseline definition drift" in baseline_errors

    contract_results = tmp_path / "contract-results.jsonl"
    contract_rows = _load_rows(RESULTS)
    contract_rows[0]["id"] = "not-the-corpus-case"
    contract_results.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in contract_rows),
        encoding="utf-8",
        newline="\n",
    )
    contract_errors = verify_run_manifest(
        MANIFEST,
        root=ROOT,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
        results_path=contract_results,
    )
    assert any(error.startswith("results/corpus contract:") for error in contract_errors)

    tampered_manifest = tmp_path / "tampered-manifest.json"
    tampered_value = load_run_manifest(MANIFEST)
    metrics = tampered_value["metrics"]
    baseline = tampered_value["baseline"]
    assert isinstance(metrics, dict)
    assert isinstance(baseline, dict)
    baseline_metrics = baseline["metrics"]
    assert isinstance(baseline_metrics, dict)
    metrics["tp"] = 999
    baseline_metrics["tp"] = 999
    tampered_manifest.write_text(
        json.dumps(tampered_value, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    metric_errors = verify_run_manifest(
        tampered_manifest,
        root=ROOT,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
    )
    assert "Guard metrics drift" in metric_errors
    assert "baseline metrics drift" in metric_errors


def test_source_digest_has_a_fixed_output_free_inventory(tmp_path: Path) -> None:
    selected = source_inventory_paths(ROOT)
    assert "benchmarks/results.jsonl" not in selected
    assert "benchmarks/run-manifest.json" not in selected
    for relative in selected:
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)

    before = collect_source_evidence(tmp_path)
    (tmp_path / "benchmarks" / "results.jsonl").write_text(
        '{"changed":true}\n',
        encoding="utf-8",
    )
    (tmp_path / "benchmarks" / "run-manifest.json").write_text(
        '{"changed":true}\n',
        encoding="utf-8",
    )
    assert collect_source_evidence(tmp_path) == before

    run_live = tmp_path / "benchmarks" / "run_live.py"
    run_live.write_text(
        run_live.read_text(encoding="utf-8") + "\n# source drift\n",
        encoding="utf-8",
    )
    assert collect_source_evidence(tmp_path)["sha256"] != before["sha256"]


def test_dirty_git_state_never_claims_commit_binding(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "Benchmark Test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "benchmark@invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "commit.gpgsign", "false"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "core.autocrlf", "false"],
        check=True,
    )
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("stable\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "tracked.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-q", "-m", "baseline"],
        check=True,
    )

    clean = collect_git_state(tmp_path, bound_paths=(tracked,))
    assert clean["dirty"] is False
    assert clean["porcelain_dirty"] is False
    assert clean["bound_paths_match_head"] is True
    assert clean["source_and_results_commit_bound"] is True

    tracked.write_text("dirty\n", encoding="utf-8")
    dirty = collect_git_state(tmp_path, bound_paths=(tracked,))
    assert dirty["dirty"] is True
    assert dirty["bound_paths_match_head"] is False
    assert dirty["source_and_results_commit_bound"] is False
    assert dirty["binding"] == "content-digests-only"


def test_verifier_checks_recorded_head_without_requiring_current_git_state(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo, manifest_path, manifest = _commit_bound_benchmark_fixture(tmp_path)
    assert manifest["dependency_lock"] == collect_dependency_lock(repo)
    manifest_strings = _all_strings(manifest)
    assert str(repo.resolve()) not in manifest_strings
    assert str(Path.cwd().resolve()) not in manifest_strings
    assert sys.executable not in manifest_strings
    invocation = manifest["invocation"]
    environment = manifest["environment"]
    assert isinstance(invocation, dict)
    assert isinstance(environment, dict)
    assert "cwd" not in invocation
    assert "argv" not in invocation
    interpreter = environment["case_interpreter"]
    assert isinstance(interpreter, dict)
    assert "executable" not in interpreter
    assert isinstance(interpreter["executable_sha256"], str)
    assert isinstance(interpreter["identity_sha256"], str)
    assert (
        verify_run_manifest(
            manifest_path,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
        )
        == ()
    )

    forged_head = copy.deepcopy(manifest)
    forged_head_git = forged_head["git"]
    assert isinstance(forged_head_git, dict)
    forged_head_git["head"] = "0" * 40
    forged_head_path = tmp_path / "forged-head.json"
    write_run_manifest(forged_head_path, forged_head)
    head_errors = verify_run_manifest(
        forged_head_path,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
    )
    assert "commit-bound source inventory differs from recorded HEAD" in head_errors

    # Current untracked state is not the historical pre-publication observation.
    # The recorded HEAD object and its exact bound blobs remain verifiable.
    (repo / "untracked-evidence.txt").write_text("dirty\n", encoding="utf-8")
    assert (
        verify_run_manifest(
            manifest_path,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
        )
        == ()
    )
    subprocess.run(
        ["git", "-C", str(repo), "add", "untracked-evidence.txt"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "later commit"],
        check=True,
    )
    assert (
        verify_run_manifest(
            manifest_path,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
        )
        == ()
    )

    contradictory = copy.deepcopy(manifest)
    contradictory_git = contradictory["git"]
    assert isinstance(contradictory_git, dict)
    contradictory_git["dirty"] = True
    contradictory_path = tmp_path / "contradictory-git.json"
    write_run_manifest(contradictory_path, contradictory)
    contradictory_errors = verify_run_manifest(
        contradictory_path,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
    )
    assert "Git cleanliness and binding flags contradict" in contradictory_errors


def test_assume_unchanged_cannot_hide_bound_source_bytes(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo, manifest_path, _manifest = _commit_bound_benchmark_fixture(tmp_path)
    selected_source_paths = tuple(repo / path for path in source_inventory_paths(repo))
    results = repo / "benchmarks" / "results.jsonl"
    target = repo / "benchmarks" / "run_live.py"
    relative_target = target.relative_to(repo).as_posix()
    subprocess.run(
        ["git", "-C", str(repo), "update-index", "--assume-unchanged", relative_target],
        check=True,
    )
    try:
        target.write_bytes(target.read_bytes() + b"\n# hidden source change\n")
        status = subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain=v1"],
            check=True,
            capture_output=True,
            encoding="utf-8",
        )
        assert status.stdout == "", "the adversarial precondition was not established"

        derived = collect_git_state(
            repo,
            bound_paths=(*selected_source_paths, results),
            source_paths=selected_source_paths,
        )
        assert derived["porcelain_dirty"] is False
        assert derived["bound_paths_match_head"] is False
        assert derived["dirty"] is True
        assert derived["source_and_results_commit_bound"] is False

        errors = verify_run_manifest(
            manifest_path,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
        )
        assert "source content drift" in errors

        # Align the manifest's content digest with the hidden worktree bytes.
        # A verifier that checks only manifest-vs-worktree would now pass; the
        # explicit HEAD blob comparison must still reject the forged binding.
        forged = load_run_manifest(manifest_path)
        forged["source"] = collect_source_evidence(repo)
        forged_path = tmp_path / "assume-unchanged-forged.json"
        write_run_manifest(forged_path, forged)
        forged_errors = verify_run_manifest(
            forged_path,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
        )
        assert "source content drift" not in forged_errors
        assert "commit-bound source digest mismatch: benchmarks/run_live.py" in forged_errors
    finally:
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "update-index",
                "--no-assume-unchanged",
                relative_target,
            ],
            check=True,
        )


def test_verifier_detects_dependency_lock_and_interpreter_identity_drift(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo, manifest_path, manifest = _commit_bound_benchmark_fixture(tmp_path)
    lock = repo / "requirements" / "ci.lock"
    original_lock = lock.read_bytes()
    lock.write_bytes(original_lock + b"\n# lock drift\n")
    lock_errors = verify_run_manifest(
        manifest_path,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
    )
    assert "dependency lock drift" in lock_errors

    # Restore the tracked bytes so the interpreter mutation is tested
    # independently from source/Git drift.
    lock.write_bytes(original_lock)
    forged = copy.deepcopy(manifest)
    environment = forged["environment"]
    assert isinstance(environment, dict)
    interpreter = environment["case_interpreter"]
    assert isinstance(interpreter, dict)
    interpreter["identity_sha256"] = "0" * 64
    forged_path = tmp_path / "forged-interpreter.json"
    write_run_manifest(forged_path, forged)
    interpreter_errors = verify_run_manifest(
        forged_path,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
    )
    assert "runtime environment evidence invalid" in interpreter_errors
    assert any(
        "interpreter identity drift" in error
        for error in interpreter_errors
        if error.startswith("results/corpus contract:")
    )


def test_live_benchmark_cli_draft_commit_finalize_and_verify_end_to_end(
    tmp_path: Path,
) -> None:
    # Run the real 17-case harness once and exercise the documented two-phase
    # Git lifecycle around that same immutable result payload.
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo, source_commit = _source_only_benchmark_git_repo(tmp_path)
    out = repo / "benchmarks" / "results.jsonl"
    manifest = repo / "benchmarks" / "run-manifest.json"
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(repo / "benchmarks" / "run_live.py"),
        ],
        cwd=repo,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr
    result_bytes = out.read_bytes()
    draft_bytes = manifest.read_bytes()
    draft = load_run_manifest(manifest)
    draft_run_id = draft["run_id"]
    draft_provenance = draft["provenance"]
    draft_claims = draft["claims"]
    draft_git = draft["git"]
    assert isinstance(draft_provenance, dict)
    assert isinstance(draft_claims, dict)
    assert isinstance(draft_git, dict)
    draft_source = draft_provenance["source_commit"]
    assert isinstance(draft_source, dict)
    assert draft_source["commit"] == source_commit
    assert draft_source["bound"] is True
    assert draft_provenance["evidence_commit"] is None
    assert draft_claims["source_commit_bound"] is True
    assert draft_claims["evidence_commit_bound"] is False
    assert draft_claims["source_and_results_commit_bound"] is False
    assert draft_git["source_and_results_commit_bound"] is False
    assert (
        verify_run_manifest(
            manifest,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
        )
        == ()
    )
    fresh = evaluate(out)
    committed = evaluate(RESULTS)
    assert fresh == committed
    assert _without_environmental_timing(_load_rows(out)) == (
        _without_environmental_timing(_load_rows(RESULTS))
    )

    subprocess.run(
        ["git", "-C", str(repo), "add", "benchmarks/results.jsonl"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "record results"],
        check=True,
    )
    evidence_commit = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        encoding="utf-8",
    ).stdout.strip()
    assert evidence_commit != source_commit
    assert out.read_bytes() == result_bytes
    assert manifest.read_bytes() == draft_bytes
    assert (
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "show",
                f"{evidence_commit}:benchmarks/results.jsonl",
            ],
            check=True,
            capture_output=True,
        ).stdout
        == result_bytes
    )
    assert (
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "cat-file",
                "-e",
                f"{evidence_commit}:benchmarks/run-manifest.json",
            ],
            check=False,
            capture_output=True,
        ).returncode
        != 0
    )

    finalized = subprocess.run(
        [
            sys.executable,
            "-I",
            str(repo / "benchmarks" / "run_live.py"),
            "--finalize-provenance",
            str(manifest),
            "--replace",
        ],
        cwd=repo,
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    assert finalized.returncode == 0, finalized.stderr
    assert out.read_bytes() == result_bytes
    final_manifest = load_run_manifest(manifest)
    assert final_manifest["run_id"] == draft_run_id
    final_provenance = final_manifest["provenance"]
    final_claims = final_manifest["claims"]
    assert isinstance(final_provenance, dict)
    assert isinstance(final_claims, dict)
    final_source = final_provenance["source_commit"]
    final_evidence = final_provenance["evidence_commit"]
    assert final_source == draft_source
    assert isinstance(final_evidence, dict)
    assert final_evidence["commit"] == evidence_commit
    assert final_evidence["results_match_commit"] is True
    assert final_evidence["final_manifest_in_commit"] is False
    assert final_provenance["final_manifest_in_evidence_commit"] is False
    assert final_claims["source_commit_bound"] is True
    assert final_claims["evidence_commit_bound"] is True
    assert final_claims["source_and_results_commit_bound"] is True
    assert final_claims["final_manifest_in_evidence_commit"] is False
    assert final_claims["authenticated"] is False
    assert final_claims["evidence_status"] == "self_consistent_unattributed"

    verified = subprocess.run(
        [
            sys.executable,
            "-I",
            str(repo / "benchmarks" / "run_live.py"),
            "--verify-manifest",
            str(manifest),
        ],
        cwd=repo,
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    assert verified.returncode == 0, verified.stderr
    assert "unsigned and unauthenticated" in verified.stdout


@pytest.mark.parametrize(
    "mutation",
    [
        {"prediction": "block"},
        {"exit_code": 1, "prediction": "accept"},
        {"exit_code": None, "prediction": "abstain", "reason": "exit_code"},
        {
            "applicable": False,
            "exit_code": 0,
            "prediction": "abstain",
            "reason": "unsafe_candidate_path",
        },
        {
            "applicable": False,
            "exit_code": None,
            "prediction": "block",
            "reason": "unsafe_candidate_path",
        },
        {"exit_code": True},
        {"elapsed_s": True},
        {"elapsed_s": -0.1},
        {"elapsed_s": math.nan},
        {"elapsed_s": math.inf},
        {"unexpected": "field"},
    ],
)
def test_baseline_prediction_is_derived_from_an_exact_observation(
    mutation: dict[str, object],
) -> None:
    observation: dict[str, object] = {
        "applicable": True,
        "prediction": "accept",
        "exit_code": 0,
        "elapsed_s": 0.1,
        "reason": "exit_code",
    }
    observation.update(mutation)

    with pytest.raises(ValueError):
        derive_baseline_prediction(observation, row=1)


def test_config_evasion_cases_are_genuinely_baseline_viable(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import CASES, _run_baseline_case

    environment, _evidence = build_execution_environment()
    viable = {str(case["id"]): case for case in CASES if case["case_kind"] == "viable_evasion"}
    assert set(viable) == {
        "test-edit",
        "pyproject-deselect",
        "pytest-ini-plant",
        "same-process-junit-forgery",
    }
    rows: list[dict[str, object]] = []
    for case_id, case in viable.items():
        observation = _run_baseline_case(
            case,
            execution_environment=environment,
        )
        assert observation["applicable"] is True, case_id
        assert observation["exit_code"] == 0, case_id
        assert observation["prediction"] == "accept", case_id
        rows.append(
            {
                "truth": "block",
                "verdict": case["expect"],
                "case_kind": "viable_evasion",
                "baseline": observation,
            }
        )
    path = tmp_path / "viable-evasions.jsonl"
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
        newline="\n",
    )
    metrics = evaluate_security_evasions(path)
    assert metrics["total"] == 4
    assert metrics["blocked"] == 3
    assert metrics["missed"] == 1
    assert metrics["classified_detection_rate"] == 0.75


def test_security_evasion_denominator_rejects_a_relabeled_viable_case(
    tmp_path: Path,
) -> None:
    row = {
        "truth": "block",
        "verdict": "REJECTED",
        "case_kind": "nonviable_evasion",
        "baseline": {
            "applicable": True,
            "prediction": "accept",
            "exit_code": 0,
            "elapsed_s": 0.1,
            "reason": "exit_code",
        },
    }
    path = tmp_path / "relabeled-evasion.jsonl"
    path.write_text(
        json.dumps(row, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(ValueError, match="viability label contradicts baseline"):
        evaluate_security_evasions(path)


def test_environment_commitment_is_rederived_from_recorded_value_digests() -> None:
    import benchmarks.run_manifest as run_manifest_module

    _effective, evidence = build_execution_environment()
    inherited = evidence["inherited_value_sha256"]
    assert isinstance(inherited, dict)
    key = next(iter(inherited))
    inherited[key] = "0" * 64

    with pytest.raises(ValueError, match="digest contradiction"):
        run_manifest_module._validated_execution_environment_evidence(evidence)


def test_stable_reader_rejects_a_mid_read_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    path = tmp_path / "racing.bin"
    path.write_bytes(b"a" * (2 * 1024 * 1024))
    original_read = run_manifest_module.os.read
    changed = False

    def racing_read(descriptor: int, size: int) -> bytes:
        nonlocal changed
        chunk = original_read(descriptor, size)
        if chunk and not changed:
            changed = True
            path.write_bytes(b"b" * (2 * 1024 * 1024 + 1))
        return chunk

    monkeypatch.setattr(run_manifest_module.os, "read", racing_read)
    with pytest.raises(RuntimeError, match="changed during"):
        read_stable_regular_file(
            path,
            max_bytes=4 * 1024 * 1024,
            label="racing fixture",
        )


def test_stable_reader_rejects_symlinks_and_oversized_files(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    link = tmp_path / "link.bin"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(ValueError, match="non-symlink"):
        read_stable_regular_file(link, max_bytes=100, label="symlink fixture")

    oversized = tmp_path / "oversized.bin"
    oversized.write_bytes(b"x" * 11)
    with pytest.raises(ValueError, match="exceeds"):
        read_stable_regular_file(
            oversized,
            max_bytes=10,
            label="oversized fixture",
        )


def test_interpreter_identity_hashes_a_stable_symlink_target_without_its_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    payload = b"setup-python interpreter target"
    target = tmp_path / "python-real"
    target.write_bytes(payload)
    link = tmp_path / "python"
    try:
        link.symlink_to(target.name)
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation is unavailable")

    monkeypatch.setattr(run_manifest_module.sys, "executable", str(link))
    identity = collect_interpreter_identity()

    assert identity["executable_sha256"] == hashlib.sha256(payload).hexdigest()
    assert identity["executable_bytes"] == len(payload)
    strings = _all_strings(identity)
    assert str(link) not in strings
    assert str(target) not in strings


def test_interpreter_identity_rejects_a_non_regular_symlink_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    target = tmp_path / "directory"
    target.mkdir()
    link = tmp_path / "python"
    try:
        link.symlink_to(target.name, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation is unavailable")

    monkeypatch.setattr(run_manifest_module.sys, "executable", str(link))
    with pytest.raises(ValueError, match="target must be a regular file"):
        collect_interpreter_identity()


def test_interpreter_identity_rejects_symlink_retargeting_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    first = tmp_path / "python-first"
    first.write_bytes(b"a" * (2 * 1024 * 1024))
    second = tmp_path / "python-second"
    second.write_bytes(b"b" * (2 * 1024 * 1024))
    link = tmp_path / "python"
    try:
        link.symlink_to(first.name)
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation is unavailable")

    original_read = run_manifest_module.os.read
    retargeted = False

    def racing_read(descriptor: int, size: int) -> bytes:
        nonlocal retargeted
        chunk = original_read(descriptor, size)
        if chunk and not retargeted:
            retargeted = True
            link.unlink()
            link.symlink_to(second.name)
        return chunk

    monkeypatch.setattr(run_manifest_module.os, "read", racing_read)
    monkeypatch.setattr(run_manifest_module.sys, "executable", str(link))
    with pytest.raises(
        RuntimeError,
        match="link changed during|target was replaced",
    ):
        collect_interpreter_identity()
    assert retargeted is True


def test_interpreter_identity_rejects_symlink_retargeting_before_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    first = tmp_path / "python-first"
    first.write_bytes(b"first")
    second = tmp_path / "python-second"
    second.write_bytes(b"second")
    link = tmp_path / "python"
    try:
        link.symlink_to(first.name)
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation is unavailable")

    original_open = run_manifest_module.os.open
    retargeted = False

    def racing_open(path: os.PathLike[str], flags: int) -> int:
        nonlocal retargeted
        if not retargeted:
            retargeted = True
            link.unlink()
            link.symlink_to(second.name)
        return original_open(path, flags)

    monkeypatch.setattr(run_manifest_module.os, "open", racing_open)
    monkeypatch.setattr(run_manifest_module.sys, "executable", str(link))
    with pytest.raises(RuntimeError, match="changed before"):
        collect_interpreter_identity()
    assert retargeted is True


def test_interpreter_identity_rejects_a_dangling_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    link = tmp_path / "python"
    try:
        link.symlink_to("missing-python")
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation is unavailable")

    monkeypatch.setattr(run_manifest_module.sys, "executable", str(link))
    with pytest.raises(OSError):
        collect_interpreter_identity()


def test_staged_source_is_immune_to_live_change_and_restore(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import (
        CASES,
        _run_case_isolated,
        _stage_source_bundle,
    )

    source_root = tmp_path / "source"
    source_root.mkdir()
    for relative in source_inventory_paths(ROOT):
        destination = source_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    source = collect_source_bundle(source_root)
    staged = _stage_source_bundle(source)
    environment, evidence = build_execution_environment()
    environment_digest = str(evidence["effective_environment_sha256"])
    interpreter_digest = str(collect_interpreter_identity()["identity_sha256"])
    source_digest = str(source.evidence["sha256"])
    target = source_root / "evoom_guard" / "__init__.py"
    original = target.read_bytes()
    try:
        before = _run_case_isolated(
            CASES[0],
            runtime_root=staged,
            execution_environment=environment,
            source_digest=source_digest,
            environment_digest=environment_digest,
            interpreter_digest=interpreter_digest,
        )
        target.write_bytes(original + b"\nraise RuntimeError('live tree used')\n")
        during = _run_case_isolated(
            CASES[0],
            runtime_root=staged,
            execution_environment=environment,
            source_digest=source_digest,
            environment_digest=environment_digest,
            interpreter_digest=interpreter_digest,
        )
    finally:
        target.write_bytes(original)
        shutil.rmtree(staged, ignore_errors=True)
    assert before["verdict"] == "PASS"
    assert during["verdict"] == "PASS"
    assert before["execution_source_sha256"] == source_digest
    assert during["execution_source_sha256"] == source_digest
    assert collect_source_evidence(source_root) == source.evidence


def test_each_phase_gets_a_fresh_stage_and_persistent_mutation_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_live as run_live_module
    from benchmarks.run_live import (
        CASES,
        _run_fresh_staged_phase,
    )

    source = collect_source_bundle(ROOT)
    source_digest = str(source.evidence["sha256"])
    staged_roots: list[Path] = []
    mutate_next = False

    def fake_isolated_case(
        case: dict[str, object],
        *,
        runtime_root: Path,
        execution_environment: dict[str, str],
        source_digest: str,
        environment_digest: str,
        interpreter_digest: str,
    ) -> dict[str, object]:
        del (
            case,
            execution_environment,
            source_digest,
            environment_digest,
            interpreter_digest,
        )
        staged_roots.append(runtime_root)
        if mutate_next:
            (runtime_root / "benchmarks" / "evaluate.py").write_bytes(b"tampered")
        return {"verdict": "PASS"}

    monkeypatch.setattr(
        run_live_module,
        "_run_case_isolated",
        fake_isolated_case,
    )

    def invoke() -> dict[str, object]:
        return _run_fresh_staged_phase(
            CASES[0],
            source_bundle=source,
            execution_environment={},
            source_digest=source_digest,
            environment_digest="e" * 64,
            interpreter_digest="i" * 64,
            baseline=False,
        )

    first = invoke()
    second = invoke()
    assert first == second == {"verdict": "PASS"}
    assert staged_roots[0] != staged_roots[1]
    assert all(not path.exists() for path in staged_roots)

    mutate_next = True
    with pytest.raises(RuntimeError, match="modified its staged source"):
        invoke()
    assert not staged_roots[-1].exists()


def test_all_guard_observations_are_frozen_before_any_baseline_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_live as run_live_module
    from benchmarks.run_live import CASES, _run_global_case_phases

    source = collect_source_bundle(ROOT)
    events: list[tuple[str, str]] = []
    selected = CASES[:2]

    def fake_phase(
        case: dict[str, object],
        **kwargs: object,
    ) -> dict[str, object]:
        baseline = kwargs["baseline"]
        assert isinstance(baseline, bool)
        phase = "baseline" if baseline else "guard"
        case_id = str(case["id"])
        events.append((phase, case_id))
        if baseline:
            return {
                "applicable": True,
                "prediction": "block",
                "exit_code": 1,
                "elapsed_s": 0.1,
                "reason": "exit_code",
            }
        return {"verdict": "FAIL"}

    monkeypatch.setattr(
        run_live_module,
        "_run_fresh_staged_phase",
        fake_phase,
    )
    guard, baseline = _run_global_case_phases(
        selected,
        source_bundle=source,
        execution_environment={},
        source_digest=str(source.evidence["sha256"]),
        environment_digest="e" * 64,
        interpreter_digest="i" * 64,
    )
    ids = [str(case["id"]) for case in selected]
    assert events == [
        *(("guard", case_id) for case_id in ids),
        *(("baseline", case_id) for case_id in ids),
    ]
    assert list(guard) == ids
    assert list(baseline) == ids


def _minimal_pair_payloads(run_id: str) -> tuple[bytes, bytes]:
    import hashlib

    results = (json.dumps({"run_id": run_id}, sort_keys=True) + "\n").encode()
    manifest = {
        "run_id": run_id,
        "results": {
            "sha256": hashlib.sha256(results).hexdigest(),
            "bytes": len(results),
            "rows": 1,
        },
    }
    return results, manifest_bytes(manifest)


def _initialization_fixture(
    tmp_path: Path,
    old_results: bytes,
) -> tuple[Path, Path, EvidenceInitialization]:
    repo = tmp_path / "repo"
    repo.mkdir()
    for relative in source_inventory_paths(ROOT):
        destination = repo / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    results_path = repo / "benchmarks" / "results.jsonl"
    manifest_path = repo / "benchmarks" / "run-manifest.json"
    results_path.write_bytes(old_results)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Benchmark Test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "benchmark@invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "commit.gpgsign", "false"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "core.autocrlf", "false"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo), "add", "--all"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "results-only fixture"],
        check=True,
    )
    _results, _manifest, initialization = validate_initial_evidence_destinations(
        root=repo,
        results_path=results_path,
        manifest_path=manifest_path,
        replace=True,
    )
    return results_path, manifest_path, initialization


def test_pair_publication_rolls_back_a_second_replace_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    results_path = tmp_path / "results.jsonl"
    manifest_path = tmp_path / "manifest.json"
    old_results = b"old results\n"
    old_manifest = b'{"old":true}\n'
    results_path.write_bytes(old_results)
    manifest_path.write_bytes(old_manifest)
    run_id = str(uuid.uuid4())
    results, manifest = _minimal_pair_payloads(run_id)
    original_publish = run_manifest_module._publish_staged_file
    calls = 0

    def fail_second_publish(
        temporary: Any,
        target: Any,
        *,
        replace: bool,
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected second publication failure")
        original_publish(temporary, target, replace=replace)

    monkeypatch.setattr(
        run_manifest_module,
        "_publish_staged_file",
        fail_second_publish,
    )
    with pytest.raises(OSError, match="injected"):
        publish_evidence_pair(
            results_path=results_path,
            results_payload=results,
            manifest_path=manifest_path,
            manifest_payload=manifest,
            replace=True,
        )
    assert results_path.read_bytes() == old_results
    assert manifest_path.read_bytes() == old_manifest


def test_pair_initialization_replaces_results_and_creates_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    old_results = b"old results\n"
    results_path, manifest_path, initialization = _initialization_fixture(
        tmp_path,
        old_results,
    )
    results, manifest = _minimal_pair_payloads(str(uuid.uuid4()))
    original_publish = run_manifest_module._publish_staged_file
    replace_flags: list[bool] = []

    def observe_publish(
        temporary: Any,
        target: Any,
        *,
        replace: bool,
    ) -> None:
        replace_flags.append(replace)
        original_publish(temporary, target, replace=replace)

    monkeypatch.setattr(
        run_manifest_module,
        "_publish_staged_file",
        observe_publish,
    )

    publish_evidence_pair(
        results_path=results_path,
        results_payload=results,
        manifest_path=manifest_path,
        manifest_payload=manifest,
        replace=True,
        initialization=initialization,
    )

    assert replace_flags == [True, False]
    assert results_path.read_bytes() == results
    assert manifest_path.read_bytes() == manifest


def test_pair_initialization_rolls_back_a_second_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    old_results = b"old results\n"
    results_path, manifest_path, initialization = _initialization_fixture(
        tmp_path,
        old_results,
    )
    results, manifest = _minimal_pair_payloads(str(uuid.uuid4()))
    original_publish = run_manifest_module._publish_staged_file
    calls = 0

    def fail_second_publish(
        temporary: Any,
        target: Any,
        *,
        replace: bool,
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected initial manifest publication failure")
        original_publish(temporary, target, replace=replace)

    monkeypatch.setattr(
        run_manifest_module,
        "_publish_staged_file",
        fail_second_publish,
    )
    with pytest.raises(OSError, match="initial manifest"):
        publish_evidence_pair(
            results_path=results_path,
            results_payload=results,
            manifest_path=manifest_path,
            manifest_payload=manifest,
            replace=True,
            initialization=initialization,
        )

    assert results_path.read_bytes() == old_results
    assert not manifest_path.exists()


def test_pair_initialization_rejects_changed_results(
    tmp_path: Path,
) -> None:
    old_results = b"expected results\n"
    results_path, manifest_path, initialization = _initialization_fixture(
        tmp_path,
        old_results,
    )
    results_path.write_bytes(b"changed results\n")
    results, manifest = _minimal_pair_payloads(str(uuid.uuid4()))

    with pytest.raises(RuntimeError, match="changed after initialization"):
        publish_evidence_pair(
            results_path=results_path,
            results_payload=results,
            manifest_path=manifest_path,
            manifest_payload=manifest,
            replace=True,
            initialization=initialization,
        )

    assert results_path.read_bytes() == b"changed results\n"
    assert not manifest_path.exists()


def test_pair_initialization_rejects_a_changed_git_head(
    tmp_path: Path,
) -> None:
    old_results = b"expected results\n"
    results_path, manifest_path, initialization = _initialization_fixture(
        tmp_path,
        old_results,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(results_path.parents[1]),
            "commit",
            "--allow-empty",
            "-q",
            "-m",
            "advance head",
        ],
        check=True,
    )
    results, manifest = _minimal_pair_payloads(str(uuid.uuid4()))

    with pytest.raises(RuntimeError, match="Git state changed"):
        publish_evidence_pair(
            results_path=results_path,
            results_payload=results,
            manifest_path=manifest_path,
            manifest_payload=manifest,
            replace=True,
            initialization=initialization,
        )

    assert results_path.read_bytes() == old_results
    assert not manifest_path.exists()


def test_pair_initialization_preserves_a_concurrently_created_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    old_results = b"old results\n"
    foreign_manifest = b'{"foreign":true}\n'
    results_path, manifest_path, initialization = _initialization_fixture(
        tmp_path,
        old_results,
    )
    results, manifest = _minimal_pair_payloads(str(uuid.uuid4()))
    original_publish = run_manifest_module._publish_staged_file
    calls = 0

    def create_manifest_after_results(
        temporary: Any,
        target: Any,
        *,
        replace: bool,
    ) -> None:
        nonlocal calls
        calls += 1
        original_publish(temporary, target, replace=replace)
        if calls == 1:
            manifest_path.write_bytes(foreign_manifest)

    monkeypatch.setattr(
        run_manifest_module,
        "_publish_staged_file",
        create_manifest_after_results,
    )
    with pytest.raises(FileExistsError):
        publish_evidence_pair(
            results_path=results_path,
            results_payload=results,
            manifest_path=manifest_path,
            manifest_payload=manifest,
            replace=True,
            initialization=initialization,
        )

    assert results_path.read_bytes() == old_results
    assert manifest_path.read_bytes() == foreign_manifest


@pytest.mark.skipif(os.name != "nt", reason="Windows retained-handle path only")
def test_windows_initialization_readback_failure_restores_results_only_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    old_results = b"old results\n"
    results_path, manifest_path, initialization = _initialization_fixture(
        tmp_path,
        old_results,
    )
    results, manifest = _minimal_pair_payloads(str(uuid.uuid4()))
    original_read = run_manifest_module._read_windows_published_file
    original_unlink = run_manifest_module._unlink_from_directory

    def fail_published_results(
        staged: Any,
        *,
        max_bytes: int,
        label: str,
    ) -> bytes:
        if label == "published benchmark results":
            raise OSError("injected published-results readback failure")
        return original_read(staged, max_bytes=max_bytes, label=label)

    def reject_target_path_unlink(
        directory: Any,
        name: str,
    ) -> None:
        if name in {results_path.name, manifest_path.name}:
            raise AssertionError("Windows rollback used a target pathname")
        original_unlink(directory, name)

    monkeypatch.setattr(
        run_manifest_module,
        "_read_windows_published_file",
        fail_published_results,
    )
    monkeypatch.setattr(
        run_manifest_module,
        "_unlink_from_directory",
        reject_target_path_unlink,
    )
    with pytest.raises(OSError, match="published-results"):
        publish_evidence_pair(
            results_path=results_path,
            results_payload=results,
            manifest_path=manifest_path,
            manifest_payload=manifest,
            replace=True,
            initialization=initialization,
        )

    assert results_path.read_bytes() == old_results
    assert not manifest_path.exists()


def test_pair_create_failure_leaves_no_torn_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    results_path = tmp_path / "results.jsonl"
    manifest_path = tmp_path / "manifest.json"
    results, manifest = _minimal_pair_payloads(str(uuid.uuid4()))
    original_publish = run_manifest_module._publish_staged_file
    calls = 0

    def fail_second_publish(
        temporary: Any,
        target: Any,
        *,
        replace: bool,
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected manifest-link failure")
        original_publish(temporary, target, replace=replace)

    monkeypatch.setattr(
        run_manifest_module,
        "_publish_staged_file",
        fail_second_publish,
    )
    with pytest.raises(OSError, match="injected"):
        publish_evidence_pair(
            results_path=results_path,
            results_payload=results,
            manifest_path=manifest_path,
            manifest_payload=manifest,
            replace=False,
        )
    assert not results_path.exists()
    assert not manifest_path.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows retained-handle path only")
def test_windows_create_readback_failure_removes_both_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    results_path = tmp_path / "results.jsonl"
    manifest_path = tmp_path / "manifest.json"
    results, manifest = _minimal_pair_payloads(str(uuid.uuid4()))
    original_read = run_manifest_module._read_windows_published_file
    original_unlink = run_manifest_module._unlink_from_directory

    def fail_published_manifest(
        staged: Any,
        *,
        max_bytes: int,
        label: str,
    ) -> bytes:
        if label == "published benchmark manifest":
            raise OSError("injected published-manifest readback failure")
        return original_read(staged, max_bytes=max_bytes, label=label)

    def reject_target_path_unlink(
        directory: Any,
        name: str,
    ) -> None:
        if name in {results_path.name, manifest_path.name}:
            raise AssertionError("Windows rollback used a target pathname")
        original_unlink(directory, name)

    monkeypatch.setattr(
        run_manifest_module,
        "_read_windows_published_file",
        fail_published_manifest,
    )
    monkeypatch.setattr(
        run_manifest_module,
        "_unlink_from_directory",
        reject_target_path_unlink,
    )
    with pytest.raises(OSError, match="published-manifest"):
        publish_evidence_pair(
            results_path=results_path,
            results_payload=results,
            manifest_path=manifest_path,
            manifest_payload=manifest,
            replace=False,
        )

    assert not results_path.exists()
    assert not manifest_path.exists()


@pytest.mark.parametrize("replace", [False, True])
def test_pair_rolls_back_a_post_publish_identity_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replace: bool,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    results_path = tmp_path / "results.jsonl"
    manifest_path = tmp_path / "manifest.json"
    old_results = b"old results\n"
    old_manifest = b'{"old":true}\n'
    if replace:
        results_path.write_bytes(old_results)
        manifest_path.write_bytes(old_manifest)
    results, manifest = _minimal_pair_payloads(str(uuid.uuid4()))
    original_assert = run_manifest_module._assert_staged_identity
    calls = 0

    def fail_first_post_publish_check(
        staged: Any,
        target: Any = None,
    ) -> None:
        nonlocal calls
        calls += 1
        original_assert(staged, target)
        if calls == 2:
            raise RuntimeError("injected post-publish identity failure")

    monkeypatch.setattr(
        run_manifest_module,
        "_assert_staged_identity",
        fail_first_post_publish_check,
    )
    with pytest.raises(RuntimeError, match="post-publish"):
        publish_evidence_pair(
            results_path=results_path,
            results_payload=results,
            manifest_path=manifest_path,
            manifest_payload=manifest,
            replace=replace,
        )
    if replace:
        assert results_path.read_bytes() == old_results
        assert manifest_path.read_bytes() == old_manifest
    else:
        assert not results_path.exists()
        assert not manifest_path.exists()


def test_pair_create_fsync_failure_rolls_back_both_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    results_path = tmp_path / "results.jsonl"
    manifest_path = tmp_path / "manifest.json"
    results, manifest = _minimal_pair_payloads(str(uuid.uuid4()))

    calls = 0

    def fail_first_fsync(_path: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected directory fsync failure")

    monkeypatch.setattr(run_manifest_module, "_fsync_parent", fail_first_fsync)
    with pytest.raises(OSError, match="fsync"):
        publish_evidence_pair(
            results_path=results_path,
            results_payload=results,
            manifest_path=manifest_path,
            manifest_payload=manifest,
            replace=False,
        )
    assert not results_path.exists()
    assert not manifest_path.exists()
    assert calls == 2


def test_pair_reports_a_rollback_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    results_path = tmp_path / "results.jsonl"
    manifest_path = tmp_path / "manifest.json"
    results, manifest = _minimal_pair_payloads(str(uuid.uuid4()))

    def fail_every_fsync(_path: object) -> None:
        raise OSError("injected directory fsync failure")

    monkeypatch.setattr(run_manifest_module, "_fsync_parent", fail_every_fsync)
    with pytest.raises(RuntimeError, match="rollback both failed"):
        publish_evidence_pair(
            results_path=results_path,
            results_payload=results,
            manifest_path=manifest_path,
            manifest_payload=manifest,
            replace=False,
        )
    assert not results_path.exists()
    assert not manifest_path.exists()


def test_pair_publication_rejects_a_concurrent_parent_rebind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    parent = tmp_path / "evidence"
    parent.mkdir()
    detached = tmp_path / "detached"
    results_path = parent / "results.jsonl"
    manifest_path = parent / "manifest.json"
    results, manifest = _minimal_pair_payloads(str(uuid.uuid4()))
    original_publish = run_manifest_module._publish_staged_file
    calls = 0

    def rebind_before_first_publish(
        temporary: Any,
        target: Any,
        *,
        replace: bool,
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            parent.rename(detached)
            parent.mkdir()
            (parent / "sentinel.txt").write_bytes(b"must not change\n")
        original_publish(temporary, target, replace=replace)

    monkeypatch.setattr(
        run_manifest_module,
        "_publish_staged_file",
        rebind_before_first_publish,
    )
    expected_error = OSError if os.name == "nt" else RuntimeError
    with pytest.raises(expected_error, match="denied|namespace|rollback"):
        publish_evidence_pair(
            results_path=results_path,
            results_payload=results,
            manifest_path=manifest_path,
            manifest_payload=manifest,
            replace=False,
        )
    if os.name == "nt":
        assert parent.is_dir()
        assert not detached.exists()
    else:
        assert (parent / "sentinel.txt").read_bytes() == b"must not change\n"
    assert not results_path.exists()
    assert not manifest_path.exists()
    if detached.exists():
        assert not (detached / "results.jsonl").exists()
        assert not (detached / "manifest.json").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows publication backend only")
def test_windows_pair_publication_has_no_path_operation_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    results_path = tmp_path / "results.jsonl"
    manifest_path = tmp_path / "manifest.json"
    results, manifest = _minimal_pair_payloads(str(uuid.uuid4()))

    def reject_path_fallback(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Windows publication used a pathname operation")

    monkeypatch.setattr(run_manifest_module.os, "replace", reject_path_fallback)
    monkeypatch.setattr(run_manifest_module.os, "link", reject_path_fallback)
    publish_evidence_pair(
        results_path=results_path,
        results_payload=results,
        manifest_path=manifest_path,
        manifest_payload=manifest,
        replace=False,
    )
    assert results_path.read_bytes() == results
    assert manifest_path.read_bytes() == manifest


@pytest.mark.skipif(os.name == "nt", reason="POSIX publication backend only")
def test_posix_pair_publication_uses_retained_directory_fds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    results_path = tmp_path / "results.jsonl"
    manifest_path = tmp_path / "manifest.json"
    results, manifest = _minimal_pair_payloads(str(uuid.uuid4()))
    original_publish = run_manifest_module._publish_staged_file
    observed_descriptors: list[int] = []

    def observe_publish(
        temporary: Any,
        target: Any,
        *,
        replace: bool,
    ) -> None:
        assert temporary.directory.descriptor is not None
        assert target.directory.descriptor is not None
        observed_descriptors.append(target.directory.descriptor)
        original_publish(temporary, target, replace=replace)

    monkeypatch.setattr(
        run_manifest_module,
        "_publish_staged_file",
        observe_publish,
    )
    publish_evidence_pair(
        results_path=results_path,
        results_payload=results,
        manifest_path=manifest_path,
        manifest_payload=manifest,
        replace=False,
    )
    assert len(observed_descriptors) == 2
    assert results_path.read_bytes() == results
    assert manifest_path.read_bytes() == manifest


@pytest.mark.skipif(os.name != "nt", reason="Windows path grammar only")
def test_windows_destination_rejects_ads_and_reserved_names(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(ValueError, match="unsafe Windows path"):
        validate_results_destination(
            root=tmp_path,
            results_path=work / "report:stream.jsonl",
            replace=False,
        )
    with pytest.raises(ValueError, match="unsafe Windows path"):
        validate_results_destination(
            root=tmp_path,
            results_path=work / "CON.jsonl",
            replace=False,
        )


def test_destinations_are_create_only_distinct_and_not_source_aliases(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    for relative in source_inventory_paths(ROOT):
        destination = repo / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    existing_results = repo / "work" / "results.jsonl"
    existing_manifest = repo / "work" / "manifest.json"
    existing_results.parent.mkdir(parents=True)
    existing_results.write_bytes(b"unchanged results")
    existing_manifest.write_bytes(b"unchanged manifest")
    with pytest.raises(FileExistsError):
        validate_evidence_destinations(
            root=repo,
            results_path=existing_results,
            manifest_path=existing_manifest,
            replace=False,
        )
    assert existing_results.read_bytes() == b"unchanged results"
    assert existing_manifest.read_bytes() == b"unchanged manifest"

    with pytest.raises(ValueError, match="distinct"):
        validate_evidence_destinations(
            root=repo,
            results_path=repo / "work" / "same.jsonl",
            manifest_path=repo / "work" / "same.jsonl",
            replace=False,
        )

    source_json = next(
        repo / relative for relative in source_inventory_paths(repo) if relative.endswith(".json")
    )
    alias = repo / "work" / "source-alias.json"
    os.link(source_json, alias)
    with pytest.raises(ValueError, match="hard-links protected"):
        validate_evidence_destinations(
            root=repo,
            results_path=repo / "work" / "new-results.jsonl",
            manifest_path=alias,
            replace=True,
        )
    symlink = repo / "work" / "source-symlink.json"
    try:
        symlink.symlink_to(source_json)
    except OSError:
        pass
    else:
        with pytest.raises(ValueError, match="non-symlink"):
            validate_evidence_destinations(
                root=repo,
                results_path=repo / "work" / "other-results.jsonl",
                manifest_path=symlink,
                replace=True,
            )


def test_initial_evidence_destination_requires_canonical_clean_committed_results(
    tmp_path: Path,
) -> None:
    results, manifest, _initialization = _initialization_fixture(
        tmp_path,
        b"committed results\n",
    )
    repo = results.parents[1]

    with pytest.raises(ValueError, match="torn evidence pair"):
        validate_evidence_destinations(
            root=repo,
            results_path=results,
            manifest_path=manifest,
            replace=True,
        )

    validated_results, validated_manifest, initialization = validate_initial_evidence_destinations(
        root=repo,
        results_path=results,
        manifest_path=manifest,
        replace=True,
    )
    assert validated_results == results.resolve()
    assert validated_manifest == manifest.resolve()
    assert initialization.results_snapshot.payload == results.read_bytes()

    results.write_bytes(results.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="clean results matching Git HEAD"):
        validate_initial_evidence_destinations(
            root=repo,
            results_path=results,
            manifest_path=manifest,
            replace=True,
        )


def test_initial_evidence_destination_rejects_custom_and_hardlinked_results(
    tmp_path: Path,
) -> None:
    results, manifest, _initialization = _initialization_fixture(
        tmp_path,
        b"committed results\n",
    )
    repo = results.parents[1]
    custom_results = repo / "work" / "results.jsonl"
    custom_manifest = repo / "work" / "run-manifest.json"
    custom_results.parent.mkdir()
    custom_results.write_bytes(results.read_bytes())

    with pytest.raises(ValueError, match="limited to the canonical"):
        validate_initial_evidence_destinations(
            root=repo,
            results_path=custom_results,
            manifest_path=custom_manifest,
            replace=True,
        )

    outside_alias = tmp_path / "results-alias.jsonl"
    os.link(results, outside_alias)
    with pytest.raises(ValueError, match="hard-linked"):
        validate_initial_evidence_destinations(
            root=repo,
            results_path=results,
            manifest_path=manifest,
            replace=True,
        )


def test_destination_validation_rejects_external_leaf_and_parent_symlinks(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    for relative in source_inventory_paths(ROOT):
        destination = repo / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    work = repo / "work"
    work.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_results = outside / "results.jsonl"
    outside_results.write_bytes(b"must not change\n")
    leaf = work / "linked-results.jsonl"
    try:
        leaf.symlink_to(outside_results)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(ValueError, match="non-symlink"):
        validate_evidence_destinations(
            root=repo,
            results_path=leaf,
            manifest_path=work / "manifest.json",
            replace=True,
        )
    assert outside_results.read_bytes() == b"must not change\n"

    outside_results.unlink()
    outside_manifest = outside / "manifest.json"
    outside_results.write_bytes(b"must not change\n")
    outside_manifest.write_bytes(b"must not change\n")
    linked_parent = repo / "linked-work"
    linked_parent.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="non-symlink"):
        validate_evidence_destinations(
            root=repo,
            results_path=linked_parent / "results.jsonl",
            manifest_path=linked_parent / "manifest.json",
            replace=True,
        )
    assert outside_results.read_bytes() == b"must not change\n"
    assert outside_manifest.read_bytes() == b"must not change\n"


def test_standalone_manifest_writer_is_create_only_by_default(
    tmp_path: Path,
) -> None:
    path = tmp_path / "manifest.json"
    path.write_bytes(b"do not replace\n")
    with pytest.raises(FileExistsError):
        write_run_manifest(path, {"new": True})
    assert path.read_bytes() == b"do not replace\n"


def test_nonisolated_controller_cannot_emit_an_evidence_pair(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import run_corpus

    if sys.flags.isolated == 1:
        pytest.skip("test process itself is isolated")
    results = tmp_path / "results.jsonl"
    manifest = tmp_path / "manifest.json"
    assert run_corpus(str(results), manifest_path=str(manifest)) == 2
    assert not results.exists()
    assert not manifest.exists()


def test_manifest_recursive_schema_rejects_os_tool_time_and_path_forgery(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo, _manifest_path, manifest = _commit_bound_benchmark_fixture(tmp_path)
    mutations: list[tuple[str, tuple[str, ...], object]] = [
        ("os-extra", ("environment", "os", "unexpected"), "value"),
        (
            "tool-extra",
            ("environment", "tools", "git", "unexpected"),
            "value",
        ),
        (
            "bad-time",
            ("environment", "captured_at_utc"),
            "not-a-timestamp",
        ),
        ("top-extra", ("unexpected",), "value"),
        (
            "nested-absolute",
            ("environment", "tools", "git", "version_line"),
            str(repo.resolve()),
        ),
    ]
    for name, mutation_path, value in mutations:
        forged = deepcopy(manifest)
        target: dict[str, object] = forged
        for key in mutation_path[:-1]:
            nested = target[key]
            assert isinstance(nested, dict)
            target = nested
        target[mutation_path[-1]] = value
        forged_path = tmp_path / f"{name}.json"
        write_run_manifest(forged_path, forged)
        errors = verify_run_manifest(
            forged_path,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
        )
        assert errors, name
        if name == "nested-absolute":
            assert "manifest contains forbidden host path context" in errors
        elif name == "top-extra":
            assert "manifest schema keys invalid" in errors
        else:
            assert "runtime environment evidence invalid" in errors


def test_verifier_recomputes_timing_from_the_stable_result_rows(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo, _manifest_path, manifest = _commit_bound_benchmark_fixture(tmp_path)
    timing = manifest["timing"]
    assert isinstance(timing, dict)
    forged = deepcopy(manifest)
    forged_timing = forged["timing"]
    assert isinstance(forged_timing, dict)
    forged_timing["guard_full_run_median_s"] = 999.0
    forged_path = tmp_path / "forged-timing.json"
    write_run_manifest(forged_path, forged)
    errors = verify_run_manifest(
        forged_path,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
    )
    assert "timing evidence drift" in errors


def test_verifier_reads_results_once_for_digest_contract_metrics_and_timing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo, manifest_path, _manifest = _commit_bound_benchmark_fixture(tmp_path)
    results = (repo / "benchmarks" / "results.jsonl").resolve()
    original = run_manifest_module.read_stable_regular_file
    result_reads = 0

    def counted_read(
        path: Path,
        *,
        max_bytes: int,
        label: str,
    ) -> object:
        nonlocal result_reads
        if Path(path).resolve() == results:
            result_reads += 1
        return original(path, max_bytes=max_bytes, label=label)

    monkeypatch.setattr(
        run_manifest_module,
        "read_stable_regular_file",
        counted_read,
    )
    assert (
        verify_run_manifest(
            manifest_path,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
        )
        == ()
    )
    assert result_reads == 1


def test_historical_integrity_is_separate_from_current_interpreter_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo, _manifest_path, manifest = _commit_bound_benchmark_fixture(tmp_path)
    results = repo / "benchmarks" / "results.jsonl"
    fake_identity = collect_interpreter_identity()
    fake_identity["version"] = "99.99.99"
    identity_without_digest = {
        key: value for key, value in fake_identity.items() if key != "identity_sha256"
    }
    fake_identity["identity_sha256"] = run_manifest_module._framed_digest(
        run_manifest_module.INTERPRETER_DIGEST_DOMAIN,
        (
            (
                "interpreter.json",
                run_manifest_module.canonical_json_bytes(identity_without_digest),
            ),
        ),
    )
    fake_digest = fake_identity["identity_sha256"]
    assert isinstance(fake_digest, str)
    rows = _load_rows(results)
    for row in rows:
        row["interpreter_identity_sha256"] = fake_digest
    results.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
        newline="\n",
    )
    environment, evidence = build_execution_environment()
    source = collect_source_bundle(repo)
    snapshot = read_stable_regular_file(
        results,
        max_bytes=MAX_RESULTS_BYTES,
        label="fake-interpreter results",
    )
    monkeypatch.setattr(
        run_manifest_module,
        "collect_interpreter_identity",
        lambda: dict(fake_identity),
    )
    forged = build_run_manifest(
        root=repo,
        results_path=results,
        results_snapshot=snapshot,
        source_bundle=source,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        run_id=str(manifest["run_id"]),
        engine_version=ENGINE_VERSION,
        execution_environment=evidence,
        effective_environment=environment,
    )
    forged_path = tmp_path / "historically-valid-other-interpreter.json"
    write_run_manifest(forged_path, forged)
    assert (
        verify_run_manifest(
            forged_path,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
        )
        == ()
    )
    monkeypatch.undo()
    readiness = verify_reproduction_environment(forged_path)
    assert "current interpreter does not match record" in readiness
    claims = forged["claims"]
    dependency = forged["dependency_lock"]
    assert isinstance(claims, dict)
    assert isinstance(dependency, dict)
    assert claims["authenticated"] is False
    assert claims["evidence_status"] == "self_consistent_unattributed"
    assert claims["installed_environment_matches_lock"] is False
    assert dependency["installed_environment_match_claim"] is False


def test_current_environment_check_binds_all_pytest_runtime_distributions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmarks.run_manifest as run_manifest_module

    _repo, manifest_path, _manifest = _commit_bound_benchmark_fixture(tmp_path)
    original = run_manifest_module._pytest_identity()
    assert original["available"] is True
    distributions = original["runtime_distributions"]
    assert isinstance(distributions, list)
    assert any(
        isinstance(record, dict) and record.get("name") == "pytest" for record in distributions
    )
    changed = deepcopy(original)
    changed_distributions = changed["runtime_distributions"]
    assert isinstance(changed_distributions, list)
    first = changed_distributions[0]
    assert isinstance(first, dict)
    first["files_sha256"] = "0" * 64
    changed["runtime_sha256"] = run_manifest_module._framed_digest(
        run_manifest_module.PYTEST_RUNTIME_DIGEST_DOMAIN,
        tuple(
            (
                str(record["name"]),
                run_manifest_module.canonical_json_bytes(record),
            )
            for record in changed_distributions
            if isinstance(record, dict)
        ),
    )
    assert run_manifest_module._validated_pytest_identity(changed) == changed
    monkeypatch.setattr(
        run_manifest_module,
        "_pytest_identity",
        lambda: changed,
    )
    assert "current tool identities do not match record" in (
        verify_reproduction_environment(manifest_path)
    )


def test_git_probes_ignore_config_injection_and_refuse_redirects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo, manifest_path, _manifest = _commit_bound_benchmark_fixture(tmp_path)
    results = repo / "benchmarks" / "results.jsonl"
    source_paths = tuple(repo / path for path in source_inventory_paths(repo))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "true")
    assert (
        verify_run_manifest(
            manifest_path,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
        )
        == ()
    )

    for key in ("GIT_DIR", "GIT_OBJECT_DIRECTORY"):
        monkeypatch.setenv(key, str(tmp_path / "redirect"))
        state = collect_git_state(
            repo,
            bound_paths=(*source_paths, results),
            source_paths=source_paths,
        )
        assert state["source_and_results_commit_bound"] is False
        assert state["reason"] == "redirected_git_environment_refused"
        monkeypatch.delenv(key)


def test_skip_worktree_cannot_hide_bound_source_bytes(tmp_path: Path) -> None:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo, manifest_path, _manifest = _commit_bound_benchmark_fixture(tmp_path)
    selected_source_paths = tuple(repo / path for path in source_inventory_paths(repo))
    results = repo / "benchmarks" / "results.jsonl"
    target = repo / "benchmarks" / "run_live.py"
    relative_target = target.relative_to(repo).as_posix()
    subprocess.run(
        ["git", "-C", str(repo), "update-index", "--skip-worktree", relative_target],
        check=True,
    )
    try:
        target.write_bytes(target.read_bytes() + b"\n# hidden skip-worktree change\n")
        status = subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain=v1"],
            check=True,
            capture_output=True,
            encoding="utf-8",
        )
        assert status.stdout == ""
        state = collect_git_state(
            repo,
            bound_paths=(*selected_source_paths, results),
            source_paths=selected_source_paths,
        )
        assert state["porcelain_dirty"] is False
        assert state["bound_paths_match_head"] is False
        assert state["source_and_results_commit_bound"] is False
        errors = verify_run_manifest(
            manifest_path,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
        )
        assert "source content drift" in errors
    finally:
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "update-index",
                "--no-skip-worktree",
                relative_target,
            ],
            check=True,
        )


def test_external_result_path_is_redacted_and_requires_explicit_verification(
    tmp_path: Path,
) -> None:
    from benchmarks.run_live import (
        BASELINE_DEFINITION,
        ENGINE_VERSION,
        RUN_SETTINGS,
        corpus_definition,
    )

    repo, _manifest_path, original_manifest = _commit_bound_benchmark_fixture(tmp_path)
    internal_results = repo / "benchmarks" / "results.jsonl"
    external_results = tmp_path / "external-results.jsonl"
    shutil.copyfile(internal_results, external_results)
    environment, evidence = build_execution_environment()
    source = collect_source_bundle(repo)
    snapshot = read_stable_regular_file(
        external_results,
        max_bytes=MAX_RESULTS_BYTES,
        label="external results",
    )
    manifest = build_run_manifest(
        root=repo,
        results_path=external_results,
        results_snapshot=snapshot,
        source_bundle=source,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        run_id=str(original_manifest["run_id"]),
        engine_version=ENGINE_VERSION,
        execution_environment=evidence,
        effective_environment=environment,
    )
    results_record = manifest["results"]
    assert isinstance(results_record, dict)
    assert results_record["path"] == "{external-results}"
    serialized = json.dumps(manifest, sort_keys=True)
    assert str(tmp_path.resolve()) not in serialized
    assert str(repo.resolve()) not in serialized
    assert sys.executable not in serialized
    manifest_path = tmp_path / "external-manifest.json"
    write_run_manifest(manifest_path, manifest)
    missing_errors = verify_run_manifest(
        manifest_path,
        root=repo,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
    )
    assert any("explicit path" in error for error in missing_errors)
    assert (
        verify_run_manifest(
            manifest_path,
            root=repo,
            corpus=corpus_definition(),
            settings=RUN_SETTINGS,
            baseline_definition=BASELINE_DEFINITION,
            engine_version=ENGINE_VERSION,
            results_path=external_results,
        )
        == ()
    )
