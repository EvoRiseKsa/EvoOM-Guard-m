from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import evoom_guard.guard as guard_module
from evoom_guard.execution.judge_environment import create_judge_phase_environment
from evoom_guard.runtime_identity import capture_runtime_identity, verify_runtime_identity
from evoom_guard.verifiers.repo_verifier import RepoVerifier

_ENVIRONMENT_KEYS = (
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "XDG_CACHE_HOME",
    "GOCACHE",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONNOUSERSITE",
)


def test_phase_scratch_is_distinct_outside_candidate_and_not_in_runtime_identity(
    tmp_path: Path,
) -> None:
    judgment_root = tmp_path / "judgment"
    candidate = judgment_root / "repo"
    candidate.mkdir(parents=True)
    (candidate / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    baseline = capture_runtime_identity(str(candidate))

    environments = {
        phase: create_judge_phase_environment(str(judgment_root), phase)
        for phase in ("setup", "repo-suite", "verifier-pack")
    }

    phase_roots = {phase: Path(env["HOME"]).parent for phase, env in environments.items()}
    assert len(set(phase_roots.values())) == 3
    for phase, environment in environments.items():
        phase_root = phase_roots[phase]
        assert phase_root.parent == judgment_root
        assert phase_root.name.startswith(f".evoguard-{phase}-")
        assert candidate not in (phase_root, *phase_root.parents)
        assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
        assert environment["PYTHONNOUSERSITE"] == "1"
        for key in (
            "HOME",
            "TMPDIR",
            "TEMP",
            "TMP",
            "XDG_CACHE_HOME",
            "GOCACHE",
        ):
            path = Path(environment[key])
            assert path.is_dir()
            assert phase_root in (path, *path.parents)

    _observed, changes = verify_runtime_identity(str(candidate), baseline)
    assert changes == []


def test_phase_environment_keeps_only_required_windows_runtime_plumbing(tmp_path: Path) -> None:
    environment = create_judge_phase_environment(
        str(tmp_path),
        "repo-suite",
        ambient={
            "PATH": "tools",
            "SYSTEMROOT": r"C:\Windows",
            "WINDIR": r"C:\Windows",
            "COMSPEC": r"C:\Windows\System32\cmd.exe",
            "PATHEXT": ".EXE;.CMD",
            "USERPROFILE": r"C:\Users\candidate",
            "LOCALAPPDATA": r"C:\Users\candidate\AppData\Local",
            "GOCACHE": r"C:\attacker-go-cache",
            "TMP": r"C:\ambient-temp",
            "PYTHONPYCACHEPREFIX": r"C:\attacker-bytecode",
        },
        platform_name="nt",
    )

    assert environment["PATH"] == "tools"
    assert environment["SYSTEMROOT"] == r"C:\Windows"
    assert environment["WINDIR"] == r"C:\Windows"
    assert environment["COMSPEC"] == r"C:\Windows\System32\cmd.exe"
    assert environment["PATHEXT"] == ".EXE;.CMD"
    assert environment["TMP"] != r"C:\ambient-temp"
    assert environment["GOCACHE"] != r"C:\attacker-go-cache"
    assert Path(environment["GOCACHE"]).is_dir()
    assert "USERPROFILE" not in environment
    assert "LOCALAPPDATA" not in environment
    assert "PYTHONPYCACHEPREFIX" not in environment


def test_repeated_phase_allocations_are_unpredictable_and_unknown_phase_fails(
    tmp_path: Path,
) -> None:
    first = create_judge_phase_environment(str(tmp_path), "setup")
    second = create_judge_phase_environment(str(tmp_path), "setup")
    assert Path(first["HOME"]).parent != Path(second["HOME"]).parent
    with pytest.raises(ValueError, match="unsupported judge phase"):
        create_judge_phase_environment(str(tmp_path), "unknown")  # type: ignore[arg-type]


def test_phase_environment_cannot_read_an_ambient_external_bytecode_cache(
    tmp_path: Path,
) -> None:
    module = tmp_path / "target.py"
    prefix = tmp_path / "attacker-pycache"
    module.write_text("VALUE = 'poison'\n", encoding="utf-8")
    poisoned_environment = dict(os.environ)
    poisoned_environment["PYTHONPYCACHEPREFIX"] = str(prefix)
    poisoned_environment["PYTHONDONTWRITEBYTECODE"] = "1"
    subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import py_compile;"
                f"py_compile.compile({str(module)!r},doraise=True,"
                "invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)"
            ),
        ],
        check=True,
        env=poisoned_environment,
    )
    module.write_text("VALUE = 'source'\n", encoding="utf-8")
    command = [
        sys.executable,
        "-c",
        f"import sys;sys.path.insert(0,{str(tmp_path)!r});import target;print(target.VALUE)",
    ]

    poisoned = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        env=poisoned_environment,
    )
    judgment_root = tmp_path / "judgment"
    judgment_root.mkdir()
    phase_environment = create_judge_phase_environment(
        str(judgment_root),
        "repo-suite",
        ambient=poisoned_environment,
    )
    protected = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        env=phase_environment,
    )

    assert poisoned.stdout.strip() == "poison"
    assert "PYTHONPYCACHEPREFIX" not in phase_environment
    assert protected.stdout.strip() == "source"


def _capture_environment_command(destination: Path) -> list[str]:
    expression = (
        "import json,os,pathlib;"
        "root=pathlib.Path(os.environ['HOME']).parents[1];"
        "payload={'environment':{key:os.environ[key] for key in "
        f"{_ENVIRONMENT_KEYS!r}}},"
        "'visible_scratch':sorted(path.name for path in root.glob('.evoguard-*-*'))};"
        f"pathlib.Path({str(destination)!r}).write_text("
        "json.dumps(payload),"
        "encoding='utf-8')"
    )
    return [sys.executable, "-c", expression]


def _load_record(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_repo_baseline_delivers_distinct_setup_and_suite_go_caches_and_cleans_them(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup_record = tmp_path / "baseline-setup-environment.json"
    suite_record = tmp_path / "baseline-suite-environment.json"
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "app.py").write_text("VALUE = 1\n", encoding="utf-8")

    def record_environment(destination: Path) -> list[str]:
        expression = (
            "import json,os,pathlib;"
            f"pathlib.Path({str(destination)!r}).write_text("
            "json.dumps({key:os.environ[key] for key in "
            "('HOME','XDG_CACHE_HOME','GOCACHE')}),encoding='utf-8')"
        )
        return [sys.executable, "-c", expression]

    ambient_cache = tmp_path / "ambient-go-cache"
    ambient_cache.mkdir()
    monkeypatch.setenv("GOCACHE", str(ambient_cache))
    result = guard_module._run_baseline_suite(
        str(repository),
        test_command=record_environment(suite_record),
        setup_command=record_environment(setup_record),
        setup_output_globs=(),
        timeout=30,
        mem_limit_mb=0,
        strict_harness=False,
    )

    assert result["verdict"] == "PASS"
    environments = {
        "setup": _load_record(setup_record),
        "repo-suite": _load_record(suite_record),
    }
    roots = {
        phase: Path(environment["HOME"]).parent
        for phase, environment in environments.items()
    }
    assert len(set(roots.values())) == 2
    for phase, environment in environments.items():
        root = roots[phase]
        assert root.name.startswith(f".evoguard-{phase}-")
        assert Path(environment["GOCACHE"]).name == "go-build"
        assert root in Path(environment["GOCACHE"]).parents
        assert root in Path(environment["XDG_CACHE_HOME"]).parents
        assert environment["GOCACHE"] != str(ambient_cache)
        assert not root.exists()


def test_repo_verifier_delivers_separate_setup_suite_and_pack_environments(
    tmp_path: Path,
) -> None:
    setup_record = tmp_path / "setup-environment.json"
    suite_record = tmp_path / "suite-environment.json"
    pack_record = tmp_path / "pack-environment.json"

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / "test_app.py").write_text(
        "import json, os\n"
        "from pathlib import Path\n"
        "def test_app():\n"
        "    root = Path(os.environ['HOME']).parents[1]\n"
        f"    payload = {{'environment': {{key: os.environ[key] for key in {_ENVIRONMENT_KEYS!r}}}, "
        "'visible_scratch': sorted(path.name for path in root.glob('.evoguard-*-*'))}\n"
        f"    Path({str(suite_record)!r}).write_text("
        "json.dumps(payload), "
        "encoding='utf-8')\n"
        "    import app\n"
        "    assert app.VALUE == 2\n",
        encoding="utf-8",
    )
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "test_pack.py").write_text(
        "import json, os\n"
        "from pathlib import Path\n"
        "def test_pack_environment():\n"
        "    root = Path(os.environ['HOME']).parents[1]\n"
        f"    payload = {{'environment': {{key: os.environ[key] for key in {_ENVIRONMENT_KEYS!r}}}, "
        "'visible_scratch': sorted(path.name for path in root.glob('.evoguard-*-*'))}\n"
        f"    Path({str(pack_record)!r}).write_text("
        "json.dumps(payload), "
        "encoding='utf-8')\n"
        "    assert True\n",
        encoding="utf-8",
    )

    result = RepoVerifier(
        setup_command=_capture_environment_command(setup_record),
        mem_limit_mb=0,
    ).verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {"repo_path": str(repo), "verifier_pack": str(pack)},
    )

    assert result.passed, result.diagnostics
    records = {
        "setup": _load_record(setup_record),
        "repo-suite": _load_record(suite_record),
        "verifier-pack": _load_record(pack_record),
    }
    observed: dict[str, dict[str, str]] = {
        phase: record["environment"]  # type: ignore[assignment]
        for phase, record in records.items()
    }
    roots = {phase: Path(environment["HOME"]).parent for phase, environment in observed.items()}
    assert len(set(roots.values())) == 3
    for phase, root in roots.items():
        assert root.name.startswith(f".evoguard-{phase}-")
        assert not root.exists(), "phase scratch must leave with the judgment workspace"
    assert records["setup"]["visible_scratch"] == [roots["setup"].name]
    assert set(records["repo-suite"]["visible_scratch"]) == {
        roots["setup"].name,
        roots["repo-suite"].name,
    }
    assert set(records["verifier-pack"]["visible_scratch"]) == {
        root.name for root in roots.values()
    }
    for key in ("HOME", "TMPDIR", "TEMP", "TMP", "XDG_CACHE_HOME", "GOCACHE"):
        assert len({environment[key] for environment in observed.values()}) == 3
    for environment in observed.values():
        assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
        assert environment["PYTHONNOUSERSITE"] == "1"
        assert "PYTHONPYCACHEPREFIX" not in environment
