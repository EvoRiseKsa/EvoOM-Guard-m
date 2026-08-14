from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from tools.evaluation.failure_registry import (
    RegistryError,
    _disposition,
    build_registry,
    validate_registry,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "evidence" / "failure-registry" / "synthetic-observations-v1.json"
SCHEMA = (
    ROOT
    / "evidence"
    / "failure-registry"
    / "synthetic-failure-observation-registry-v1.schema.json"
)


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _write_registry(tmp_path: Path, value: dict[str, Any]) -> Path:
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def _git(repo: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    process = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        input=input_bytes,
        capture_output=True,
        check=False,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        timeout=30,
    )
    assert process.returncode == 0, process.stderr.decode("utf-8", errors="replace")
    return process.stdout


def _clone_current_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    # Reuse immutable existing objects without copying the full repository;
    # immediately internalize them so the validator sees no object alternate.
    _git(ROOT.parent, "clone", "--shared", str(ROOT), str(repo))
    _git(repo, "repack", "-a", "-d")
    alternates = repo / ".git" / "objects" / "info" / "alternates"
    alternates.unlink()
    return repo


def test_committed_registry_schema_is_closed_and_valid() -> None:
    schema = _load(SCHEMA)
    registry = _load(REGISTRY)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(registry)

    mutated = copy.deepcopy(registry)
    mutated["unreviewed_extension"] = True
    errors = list(Draft202012Validator(schema).iter_errors(mutated))
    assert any(error.validator == "additionalProperties" for error in errors)


def test_committed_registry_is_complete_and_history_bound() -> None:
    assert validate_registry(REGISTRY, root=ROOT) == 3


def test_parameterized_generator_reproduces_committed_registry() -> None:
    current = _load(REGISTRY)
    finalization_commit = current["benchmark_binding"]["finalization"]["commit"]
    assert build_registry(
        root=ROOT,
        finalization_commit=finalization_commit,
    ) == current


def test_registry_records_literal_admission_direction_failures() -> None:
    registry = _load(REGISTRY)
    observations = registry["observations"]
    assert [(item["case_id"], item["failure_class"]) for item in observations] == [
        ("same-process-junit-forgery", "false_accept"),
        ("legit-dependency-bump", "false_reject"),
        ("legit-dependency-bump-allowlist-refused", "false_reject"),
    ]
    assert [item["disposition"] for item in observations] == [
        "known_security_gap",
        "deliberate_policy_tradeoff",
        "deliberate_policy_tradeoff",
    ]


def test_reviewed_disposition_is_bound_to_exact_source_and_corpus() -> None:
    row = {"id": "legit-dependency-bump"}
    source_sha256 = "9cf960d38c43172a212b05bfa50c7a1ef80a2e34a753eb30243bb5b8ae6acad0"
    corpus_sha256 = "c473c62bf92c0faeb48bb56ec266d9b0d6adfe9f3ffb3ff45d91a813c3a1fd59"
    assert (
        _disposition(
            row,
            "false_reject",
            source_inventory_sha256=source_sha256,
            corpus_sha256=corpus_sha256,
        )
        == "deliberate_policy_tradeoff"
    )
    assert (
        _disposition(
            row,
            "false_reject",
            source_inventory_sha256=source_sha256,
            corpus_sha256="0" * 64,
        )
        == "unresolved"
    )
    assert (
        _disposition(
            row,
            "false_reject",
            source_inventory_sha256="0" * 64,
            corpus_sha256=corpus_sha256,
        )
        == "unresolved"
    )


@pytest.mark.parametrize(
    ("location", "field", "value"),
    [
        ("scope", "source_class", "field"),
        ("scope", "evidence_quality", "authenticated_field_observation"),
        ("scope", "authenticated", True),
        ("scope", "field_evidence", True),
        ("observation", "source_class", "field"),
        ("observation", "evidence_quality", "authenticated_field_observation"),
        ("observation", "authenticated", True),
        ("observation", "field_evidence", True),
    ],
)
def test_registry_rejects_synthetic_field_conflation(
    tmp_path: Path,
    location: str,
    field: str,
    value: object,
) -> None:
    registry = _load(REGISTRY)
    target = registry["scope"] if location == "scope" else registry["observations"][0]
    target[field] = value
    with pytest.raises(RegistryError, match="synthetic|field evidence|conflates"):
        validate_registry(_write_registry(tmp_path, registry), root=ROOT, verify_history=False)


def test_registry_rejects_omitted_failure_case_id(tmp_path: Path) -> None:
    registry = _load(REGISTRY)
    registry["observations"].pop(0)
    with pytest.raises(RegistryError, match="every literal observed-failure case id"):
        validate_registry(_write_registry(tmp_path, registry), root=ROOT, verify_history=False)


def test_registry_rejects_hidden_or_replaced_case_id(tmp_path: Path) -> None:
    registry = _load(REGISTRY)
    registry["observations"][0]["case_id"] = "redacted-case-0001"
    with pytest.raises(RegistryError, match="every literal observed-failure case id"):
        validate_registry(_write_registry(tmp_path, registry), root=ROOT, verify_history=False)


def test_registry_rejects_unbound_result_record(tmp_path: Path) -> None:
    registry = _load(REGISTRY)
    registry["observations"][0]["result_record_sha256"] = "0" * 64
    with pytest.raises(RegistryError, match="exactly match the bound failure rows"):
        validate_registry(_write_registry(tmp_path, registry), root=ROOT, verify_history=False)


def test_registry_rejects_manifest_binding_drift(tmp_path: Path) -> None:
    registry = _load(REGISTRY)
    registry["benchmark_binding"]["finalization"]["manifest_sha256"] = "0" * 64
    with pytest.raises(RegistryError, match="exact manifest/results pair"):
        validate_registry(_write_registry(tmp_path, registry), root=ROOT, verify_history=False)


def test_registry_rejects_unknown_observation_field(tmp_path: Path) -> None:
    registry = _load(REGISTRY)
    registry["observations"][0]["field_claim"] = True
    with pytest.raises(RegistryError, match="keys differ"):
        validate_registry(_write_registry(tmp_path, registry), root=ROOT, verify_history=False)


def test_registry_rejects_forged_finalization_hidden_by_git_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _clone_current_repo(tmp_path)
    registry_path = (
        repo / "evidence" / "failure-registry" / "synthetic-observations-v1.json"
    )
    registry = _load(registry_path)
    finalization_commit = registry["benchmark_binding"]["finalization"]["commit"]
    manifest_path = repo / "benchmarks" / "run-manifest.json"
    original_manifest = manifest_path.read_bytes()
    forged_manifest = original_manifest[:-1] + b" \n"
    assert forged_manifest != original_manifest
    manifest_path.write_bytes(forged_manifest)
    finalization = registry["benchmark_binding"]["finalization"]
    finalization["manifest_sha256"] = hashlib.sha256(forged_manifest).hexdigest()
    finalization["manifest_bytes"] = len(forged_manifest)
    registry_path.write_text(
        json.dumps(registry, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    forged_blob = _git(repo, "hash-object", "-w", "--stdin", input_bytes=forged_manifest)
    forged_blob_sha = forged_blob.decode("ascii").strip()
    index_path = tmp_path / "replacement.index"
    replacement_environment = {
        **os.environ,
        "GIT_INDEX_FILE": str(index_path),
        "GIT_TERMINAL_PROMPT": "0",
    }
    subprocess.run(
        ["git", "-C", str(repo), "read-tree", f"{finalization_commit}^{{tree}}"],
        check=True,
        env=replacement_environment,
        timeout=30,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "update-index",
            "--cacheinfo",
            f"100644,{forged_blob_sha},benchmarks/run-manifest.json",
        ],
        check=True,
        env=replacement_environment,
        timeout=30,
    )
    forged_tree = subprocess.run(
        ["git", "-C", str(repo), "write-tree"],
        check=True,
        capture_output=True,
        env=replacement_environment,
        timeout=30,
    ).stdout.decode("ascii").strip()
    parent_line = _git(repo, "rev-parse", f"{finalization_commit}^").decode("ascii").strip()
    _git(repo, "config", "user.email", "registry-test@example.invalid")
    _git(repo, "config", "user.name", "Registry Test")
    replacement_commit = _git(
        repo,
        "commit-tree",
        forged_tree,
        "-p",
        parent_line,
        input_bytes=b"forged finalization replacement\n",
    ).decode("ascii").strip()
    _git(repo, "replace", finalization_commit, replacement_commit)

    replaced_blob = _git(
        repo,
        "cat-file",
        "blob",
        f"{finalization_commit}:benchmarks/run-manifest.json",
    )
    literal_blob = _git(
        repo,
        "--no-replace-objects",
        "cat-file",
        "blob",
        f"{finalization_commit}:benchmarks/run-manifest.json",
    )
    assert replaced_blob == forged_manifest
    assert literal_blob == original_manifest

    malicious_global = tmp_path / "malicious.gitconfig"
    malicious_global.write_text(
        "[core]\n\thooksPath = malicious-hooks\n\tpager = false\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(malicious_global))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "malicious")
    monkeypatch.setenv("GIT_NO_REPLACE_OBJECTS", "0")
    with pytest.raises(RegistryError, match="replacement refs are refused"):
        validate_registry(registry_path, root=repo)


def test_registry_release_promotion_is_exact_and_byte_scoped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tools.evaluation.failure_registry as failure_registry

    repo = _clone_current_repo(tmp_path)
    registry_path = (
        repo / "evidence" / "failure-registry" / "synthetic-observations-v1.json"
    )
    registry = _load(registry_path)
    development_version = registry["benchmark_binding"]["engine_version"]
    assert isinstance(development_version, str)
    assert development_version.endswith(".dev0")
    stable_version = development_version.removesuffix(".dev0")
    current_version = failure_registry.__dict__["ENGINE_VERSION"]
    assert current_version in {development_version, stable_version}
    assert validate_registry(registry_path, root=repo) == 3

    version_path = repo / "evoom_guard" / "__init__.py"
    development_assignment = f'__version__ = "{development_version}"'
    stable_assignment = f'__version__ = "{stable_version}"'
    source = version_path.read_text(encoding="utf-8")
    current_assignment = f'__version__ = "{current_version}"'
    assert source.count(current_assignment) == 1
    development_source = source.replace(
        current_assignment,
        development_assignment,
        1,
    )
    version_path.write_text(development_source, encoding="utf-8", newline="\n")
    monkeypatch.setattr(failure_registry, "ENGINE_VERSION", development_version)
    assert validate_registry(registry_path, root=repo) == 3

    stable_source = development_source.replace(
        development_assignment,
        stable_assignment,
        1,
    )
    version_path.write_text(stable_source, encoding="utf-8", newline="\n")
    monkeypatch.setattr(failure_registry, "ENGINE_VERSION", stable_version)
    assert validate_registry(registry_path, root=repo) == 3

    version_path.write_text(
        stable_source + "# unrelated source drift\n",
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(RegistryError, match="source content drift"):
        validate_registry(registry_path, root=repo)

    invalid_version = f"{stable_version}.dev1"
    version_path.write_text(
        stable_source.replace(
            stable_assignment,
            f'__version__ = "{invalid_version}"',
            1,
        ),
        encoding="utf-8",
        newline="\n",
    )
    monkeypatch.setattr(failure_registry, "ENGINE_VERSION", invalid_version)
    with pytest.raises(RegistryError, match="exact dev0 release-promotion relation"):
        validate_registry(registry_path, root=repo)
