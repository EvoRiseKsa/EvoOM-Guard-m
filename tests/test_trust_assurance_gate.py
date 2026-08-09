"""Contracts for per-module branch ratchets and reviewed mutation declarations."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

from tools.ci import check_trust_assurance as gate

EXPECTED_MODULES = {
    "evoom_guard/workspace/__init__.py",
    "evoom_guard/runtime_identity.py",
    "evoom_guard/verifiers/fidelity.py",
    "evoom_guard/admission/release_artifact.py",
    "evoom_guard/admission/agent_change.py",
    "evoom_guard/finalizer/deployment.py",
    "evoom_guard/artifact_admission.py",
    "evoom_guard/release_source_producer_receipt.py",
    "evoom_guard/artifact_digest_admission.py",
    "evoom_guard/admission/release_source.py",
    "evoom_guard/release_source_finalizer.py",
    "evoom_guard/github_attestation.py",
}


def _manifest() -> dict[str, object]:
    return json.loads(gate.DEFAULT_MANIFEST.read_text(encoding="utf-8"))


def _coverage_at_floor(manifest: dict[str, object]) -> dict[str, object]:
    files: dict[str, object] = {}
    for entry in manifest["modules"]:  # type: ignore[index]
        floor = entry["branch_floor"]
        files[entry["path"]] = {
            "summary": {
                "covered_branches": floor["covered"],
                "num_branches": floor["total"],
            }
        }
    return {"meta": {"branch_coverage": True}, "files": files}


def test_manifest_pins_every_selected_weak_trust_module() -> None:
    manifest = _manifest()
    paths = {entry["path"] for entry in manifest["modules"]}  # type: ignore[index]

    assert paths == EXPECTED_MODULES
    assert gate.validate_manifest(manifest) == []


def test_manifest_reports_direct_mutation_truth_without_inference() -> None:
    manifest = _manifest()
    counts = gate.reviewed_mutation_counts()
    declarations = {
        entry["path"]: entry["mutation"]["status"]
        for entry in manifest["modules"]  # type: ignore[index]
    }

    assert declarations["evoom_guard/github_attestation.py"] == "reviewed"
    assert counts["evoom_guard/github_attestation.py"] >= 31
    assert set(declarations.values()) == {"reviewed"}
    for entry in manifest["modules"]:  # type: ignore[index]
        path = entry["path"]
        assert counts[path] >= entry["mutation"]["minimum_reviewed_mutants"]


def test_coverage_at_every_declared_floor_passes() -> None:
    manifest = _manifest()

    errors, observations = gate.validate_coverage(manifest, _coverage_at_floor(manifest))

    assert errors == []
    assert len(observations) == len(EXPECTED_MODULES)


def test_new_direct_mutant_for_a_gap_requires_a_manifest_update() -> None:
    manifest = _manifest()
    counts = Counter(gate.reviewed_mutation_counts())
    path = "evoom_guard/runtime_identity.py"
    entry = next(
        item
        for item in manifest["modules"]
        if item["path"] == path  # type: ignore[index]
    )
    entry["mutation"] = {
        "status": "gap",
        "gap": "Synthetic unreviewed state used to bind the gate contract.",
    }
    counts[path] = 1

    errors = gate.validate_manifest(manifest, mutation_counts=counts)

    assert (
        f"{path}: declared mutation gap now has 1 direct mutant(s); "
        "replace the gap with a reviewed minimum"
    ) in errors


def test_reviewed_mutant_count_is_a_downward_ratchet() -> None:
    manifest = _manifest()
    counts = Counter(gate.reviewed_mutation_counts())
    path = "evoom_guard/github_attestation.py"
    counts[path] = 30

    errors = gate.validate_manifest(manifest, mutation_counts=counts)

    assert f"{path}: reviewed mutation count 30 is below 31" in errors


def test_one_branch_ratio_regression_fails() -> None:
    manifest = _manifest()
    coverage = _coverage_at_floor(manifest)
    path = "evoom_guard/workspace/__init__.py"
    regressed = copy.deepcopy(coverage)
    regressed["files"][path]["summary"]["covered_branches"] -= 1  # type: ignore[index,operator]

    errors, _ = gate.validate_coverage(manifest, regressed)

    assert errors == [f"{path}: branch ratio 47/110 regressed below 48/110"]


def test_cli_fails_closed_when_coverage_file_is_missing(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"

    assert gate.main(["--coverage-json", str(missing)]) == 2


def test_direct_script_execution_uses_the_reviewed_inventory(tmp_path: Path) -> None:
    manifest = _manifest()
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(json.dumps(_coverage_at_floor(manifest)), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(gate.ROOT / "tools" / "ci" / "check_trust_assurance.py"),
            "--coverage-json",
            str(coverage_path),
        ],
        cwd=gate.ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "direct reviewed mutants=31 status=reviewed" in completed.stdout
