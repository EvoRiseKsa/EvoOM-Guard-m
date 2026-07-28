from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from evoom_guard.runners import registry
from tools.conformance import runner_kit
from tools.conformance.runner_kit import (
    CANONICAL_INNER_ORDER,
    CANONICAL_REGISTRY_ORDER,
    DEFAULT_MANIFEST,
    OWNER_SPECS,
    ManifestError,
    ResultVerificationError,
    load_manifest,
    load_result,
    run_conformance,
    validate_manifest,
    verify_result,
    write_result_create_only,
)
from tools.conformance.secure_io import ConformanceIOError

CONFORMANCE_DIR = DEFAULT_MANIFEST.parent
MANIFEST_SCHEMA = CONFORMANCE_DIR / "runner-manifest.schema.json"
RESULT_SCHEMA = CONFORMANCE_DIR / "runner-result.schema.json"


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _result_validator() -> Draft202012Validator:
    return Draft202012Validator(
        _load_json(RESULT_SCHEMA),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def _write_manifest(tmp_path: Path, manifest: dict[str, Any]) -> Path:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def test_schemas_are_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(_load_json(MANIFEST_SCHEMA))
    Draft202012Validator.check_schema(_load_json(RESULT_SCHEMA))


def test_checked_in_manifest_validates_against_schema_and_runtime_contract() -> None:
    manifest = _load_json(DEFAULT_MANIFEST)
    Draft202012Validator(_load_json(MANIFEST_SCHEMA)).validate(manifest)
    validate_manifest(manifest)


def test_manifest_covers_all_nine_owners_and_registry_order() -> None:
    manifest, _ = load_manifest()
    owner_ids = [owner["id"] for owner in manifest["owners"]]
    assert owner_ids == list(CANONICAL_REGISTRY_ORDER)
    assert manifest["registry_order"] == list(CANONICAL_REGISTRY_ORDER)
    assert manifest["inner_registry_order"] == list(CANONICAL_INNER_ORDER)
    assert len(owner_ids) == 9
    assert owner_ids[0] == "shell"


def test_manifest_has_required_case_categories_for_each_owner() -> None:
    manifest, _ = load_manifest()
    coverage = {
        owner: {case["category"] for case in manifest["cases"] if case["owner"] == owner}
        for owner in CANONICAL_REGISTRY_ORDER
    }
    for owner, categories in coverage.items():
        assert {"accept", "mismatch", "windows_path"} <= categories
        if owner != "pytest":
            assert "decline" in categories
    assert "shell" in coverage["shell"]


def test_offline_suite_passes_exact_argv_env_and_result_schema() -> None:
    result = run_conformance()
    _result_validator().validate(result)
    verify_result(result)
    assert result["status"] == "pass"
    assert result["status_basis"] == "offline_adapter_contract_only"
    assert result["summary"] == {
        "offline_checks": 51,
        "passed": 51,
        "failed": 0,
        "tool_versions_observed": 0,
        "tool_versions_unsupported": 0,
    }
    assert all(case["expected"] == case["observed"] for case in result["cases"])
    assert all(case["expected"] == case["observed"] for case in result["registry"]["cases"])


def test_expected_argv_mutation_is_detected(tmp_path: Path) -> None:
    manifest = copy.deepcopy(_load_json(DEFAULT_MANIFEST))
    manifest["cases"][0]["expected"]["argv"][-1] += " --mutated"
    result = run_conformance(manifest_path=_write_manifest(tmp_path, manifest))
    assert result["status"] == "fail"
    assert result["summary"]["failed"] == 1
    assert result["cases"][0]["mismatch_fields"] == ["argv"]


def test_registry_order_mutation_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "ADAPTERS", tuple(reversed(registry.ADAPTERS)))
    result = run_conformance()
    assert result["status"] == "fail"
    assert result["registry"]["order"]["status"] == "fail"
    assert "registry_order" in result["registry"]["order"]["mismatch_fields"]


def test_owner_identity_mutation_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(OWNER_SPECS[1].adapter_type, "name", "not-pytest")
    result = run_conformance()
    owner = next(item for item in result["owners"] if item["id"] == "pytest")
    assert result["status"] == "fail"
    assert owner["mismatch_fields"] == ["adapter_name"]


def test_manifest_rejects_noncanonical_owner_and_missing_coverage() -> None:
    wrong_owner = copy.deepcopy(_load_json(DEFAULT_MANIFEST))
    wrong_owner["owners"][0]["class"] = "ImpostorAdapter"
    with pytest.raises(ManifestError, match="canonical nine owners"):
        validate_manifest(wrong_owner)

    missing_case = copy.deepcopy(_load_json(DEFAULT_MANIFEST))
    missing_case["cases"] = [
        case
        for case in missing_case["cases"]
        if not (case["owner"] == "maven" and case["category"] == "windows_path")
    ]
    with pytest.raises(ManifestError, match="maven lacks categories"):
        validate_manifest(missing_case)


def test_discovery_is_observed_or_unsupported_and_never_gating(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unsupported(
        spec: runner_kit.OwnerSpec,
        timeout: float,
    ) -> dict[str, Any]:
        assert timeout > 0
        return {
            "owner": spec.owner_id,
            "argv": list(spec.discovery_argv),
            "status": "unsupported",
            "reason": "not_found",
        }

    monkeypatch.setattr(runner_kit, "_discover_one", unsupported)
    result = run_conformance(discover_tools=True)
    _result_validator().validate(result)
    assert result["status"] == "pass"
    discovery = result["live_tool_discovery"]
    assert discovery["non_gating"] is True
    assert discovery["proves_runner_execution"] is False
    assert {item["status"] for item in discovery["tools"]} == {"unsupported"}
    assert "pass" not in {item["status"] for item in discovery["tools"]}
    assert result["summary"]["tool_versions_unsupported"] == 9


def test_result_claims_do_not_promote_version_discovery_to_execution() -> None:
    result = run_conformance()
    assert result["claims"] == {
        "offline_adapter_contract_executed": True,
        "external_runner_suites_executed": False,
        "multi_os_real_runner_matrix_published": False,
    }
    assert result["live_tool_discovery"]["requested"] is False
    assert result["live_tool_discovery"]["tools"] == []


def test_result_contains_no_personal_absolute_execution_paths() -> None:
    serialized = json.dumps(run_conformance(), ensure_ascii=False).casefold()
    forbidden = {
        str(runner_kit.REPOSITORY_ROOT.resolve()).casefold(),
        str(Path.home().resolve()).casefold(),
        str(Path(sys.executable).resolve()).casefold(),
    }
    assert all(secret not in serialized for secret in forbidden)
    assert "tools/conformance/runner-manifest.json" in serialized
    assert '"python"' in serialized


def test_create_only_writer_never_replaces_existing_result(tmp_path: Path) -> None:
    destination = tmp_path / "runner-result.json"
    result = run_conformance()
    write_result_create_only(result, destination)
    first = destination.read_bytes()
    with pytest.raises(FileExistsError):
        write_result_create_only({"replacement": True}, destination)
    assert destination.read_bytes() == first
    _result_validator().validate(json.loads(first))


def test_semantic_verifier_rejects_fabricated_pass_and_source_digest() -> None:
    result = run_conformance()
    contradictory = copy.deepcopy(result)
    contradictory["cases"][0]["observed"]["argv"] = ["wrong"]
    with pytest.raises(ResultVerificationError, match="case results"):
        verify_result(contradictory)

    stale = copy.deepcopy(result)
    stale["source"]["files"][0]["sha256"] = "0" * 64
    with pytest.raises(ResultVerificationError, match="source.files"):
        verify_result(stale)

    extra = copy.deepcopy(result)
    extra["unexpected"] = True
    with pytest.raises(ResultVerificationError, match="keys differ"):
        verify_result(extra)


def test_result_loader_and_writer_reject_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "result-link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(
        ResultVerificationError,
        match="runner result must not be a link or reparse point",
    ) as caught:
        load_result(link)
    assert isinstance(caught.value.__cause__, ConformanceIOError)
    with pytest.raises(FileExistsError):
        write_result_create_only(run_conformance(), link)
    assert target.read_text(encoding="utf-8") == "{}"
