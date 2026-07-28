# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Characterize the offline, non-authoritative Release Ledger v2 assembler."""

from __future__ import annotations

import copy
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import types
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from evoom_guard.signing import generate_keypair
from tests.test_release_artifact_admission import _inputs as _artifact_inputs
from tests.test_release_artifact_admission import _seal as _seal_artifact
from tests.test_release_ledger_v2 import (
    _repository_control_observation,
    _valid_ledger,
)
from tools.ci import assemble_release_ledger_v2 as assembler
from tools.ci import validate_release_ledger_v2 as validator

ROOT = Path(__file__).resolve().parents[1]


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def test_assembler_bootstrap_ignores_and_restores_ambient_jsonschema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_path = tmp_path / "jsonschema.py"
    fake_path.write_text("raise AssertionError('must not execute')\n", encoding="utf-8")
    fake = types.ModuleType("jsonschema")
    fake.__file__ = str(fake_path)
    fake.__spec__ = importlib.machinery.ModuleSpec(
        "jsonschema",
        loader=None,
        origin=str(fake_path),
    )
    monkeypatch.setitem(sys.modules, "jsonschema", fake)

    module_name = "_evoguard_assembler_bootstrap_test"
    spec = importlib.util.spec_from_file_location(module_name, Path(assembler.__file__))
    assert spec is not None and spec.loader is not None
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = loaded
    try:
        spec.loader.exec_module(loaded)
        loaded.validator.validate_structure(_valid_ledger())
        assert sys.modules["jsonschema"] is fake
    finally:
        sys.modules.pop(module_name, None)


def _trusted_parent(
    tmp_path: Path,
    ledger: dict[str, Any],
    evidence_root: Path,
) -> Path:
    repository = tmp_path / "trusted-parent"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Ledger Assembler Test")
    _git(repository, "config", "user.email", "ledger@example.invalid")
    shutil.copytree(
        ROOT / "evoom_guard",
        repository / "evoom_guard",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    for source, relative in (
        (
            validator.DEFAULT_SCHEMA,
            validator.OFFICIAL_SCHEMA_REPOSITORY_PATH,
        ),
        (
            Path(validator.__file__),
            validator.VALIDATOR_REPOSITORY_PATH,
        ),
        (
            ROOT / validator.REPOSITORY_CONTROLS_COLLECTOR_REPOSITORY_PATH,
            validator.REPOSITORY_CONTROLS_COLLECTOR_REPOSITORY_PATH,
        ),
        *(
            (
                ROOT.joinpath(*PurePosixPath(relative).parts),
                relative,
            )
            for relative in validator.TRUSTED_BUILD_INPUT_PATHS.values()
        ),
    ):
        target = repository / Path(*PurePosixPath(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    anchor = (
        repository
        / "security"
        / "release-ledger-roots"
        / f"{ledger['release']['tag']}.pub.pem"
    )
    anchor.parent.mkdir(parents=True)
    retained_public = ledger["ledger_signature"]["public_key"]["path"]
    anchor.write_bytes(
        (evidence_root / Path(*PurePosixPath(retained_public).parts)).read_bytes()
    )
    _git(repository, "add", ".")
    _git(repository, "commit", "-q", "-m", "trusted parent")
    parent = _git(repository, "rev-parse", "HEAD")
    tree = _git(repository, "rev-parse", "HEAD^{tree}")
    ledger["source"]["parent_commit_sha"] = parent
    ledger["source"]["parent_tree_sha"] = tree
    ledger["toolchain"]["trusted_build_inputs"]["source_parent_sha"] = parent
    ledger["toolchain"]["trusted_build_inputs"]["source_parent_tree_sha"] = tree
    ledger["toolchain"]["trusted_build_inputs"].update(
        {
            field: _git(repository, "rev-parse", f"HEAD:{relative}")
            for field, relative in validator.TRUSTED_BUILD_INPUT_PATHS.items()
        }
    )
    return repository


def _remove_derived_claims(ledger: dict[str, Any]) -> None:
    for _label, descriptor in assembler._descriptor_slots(ledger):
        descriptor.pop("size_bytes", None)
        descriptor.pop("sha256", None)
        descriptor.pop("github_digest", None)
    contracts = ledger["schema_contracts"]
    contracts.pop("release_ledger")
    contracts.pop("validator")
    contracts.pop("repository_controls_collector")
    ledger["checksum_manifest"].pop("manifest_sha256")
    ledger["checksum_manifest"].pop("entries")
    ledger["artifact_admission"].pop("source_rsae_sha256")
    for subject in ledger["artifact_admission"]["subjects"]:
        subject.pop("artifact_sha256")
        subject.pop("artifact_size_bytes")
        subject["raae"].pop("key_id")
    ledger["source_admission"]["rsae"].pop("key_id")
    for name in (
        "source_producer",
        "build_provenance",
        "spdx_provenance",
        "sbom_provenance",
    ):
        ledger["attestations"][name].pop("subject_sha256")
    ledger["attestations"]["release"].pop("asset_subjects")
    for root in ledger["trust_roots"]:
        root.pop("key_id")
    ledger["ledger_signature"].pop("key_id")
    ledger["ledger_signature"].pop("trusted_parent_anchor")
    for field in validator.TRUSTED_BUILD_INPUT_PATHS:
        ledger["toolchain"]["trusted_build_inputs"].pop(field)


def _evidence_directory(
    tmp_path: Path,
    ledger: dict[str, Any],
) -> tuple[Path, dict[str, bytes]]:
    root = tmp_path / "evidence"
    root.mkdir()
    inventory = validator._collect_descriptors(ledger)
    contents = {relative: f"{relative}\n".encode() for relative in inventory}
    artifact_paths = {
        item["name"]: item["path"] for item in ledger["artifacts"]
    }
    contents[artifact_paths["SHA256SUMS"]] = "".join(
        f"{hashlib.sha256(contents[artifact_paths[name]]).hexdigest()}  {name}\n"
        for name in ("evo-guard.pyz", "evo-guard.spdx.json")
    ).encode("ascii")
    observation = ledger["repository_controls"]["observation_evidence"]["path"]
    contents[observation] = validator.canonical_json_bytes(
        _repository_control_observation(ledger)
    )

    key_workspace = tmp_path / "keys"
    key_workspace.mkdir()
    public_paths = [
        item["public_key"]["path"] for item in ledger["trust_roots"]
    ] + [ledger["ledger_signature"]["public_key"]["path"]]
    for index, relative in enumerate(public_paths):
        private = key_workspace / f"{index}.pem"
        public = key_workspace / f"{index}.pub.pem"
        generate_keypair(str(private), str(public))
        contents[relative] = public.read_bytes()

    for relative, data in contents.items():
        target = root / Path(*PurePosixPath(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return root, contents


def test_assembler_derives_descriptors_and_rejects_a_claimed_contradiction(
    tmp_path: Path,
) -> None:
    ledger = _valid_ledger()
    root, contents = _evidence_directory(tmp_path, ledger)
    _remove_derived_claims(ledger)

    retained = assembler._complete_file_descriptors(ledger, root)
    assert retained == contents
    readme = ledger["ledger_scope"]["readme"]
    assert readme == {
        "path": "README.md",
        "size_bytes": len(contents["README.md"]),
        "sha256": hashlib.sha256(contents["README.md"]).hexdigest(),
    }

    ledger["ledger_scope"]["readme"]["sha256"] = "0" * 64
    with pytest.raises(
        assembler.LedgerAssemblyError,
        match="contradicts retained evidence",
    ):
        assembler._complete_file_descriptors(ledger, root)


def test_repository_control_claims_are_derived_from_collector_bytes(
    tmp_path: Path,
) -> None:
    ledger = _valid_ledger()
    expected = copy.deepcopy(ledger["repository_controls"])
    root = tmp_path / "repository-controls"
    observation_path = root / Path(
        *PurePosixPath(expected["observation_evidence"]["path"]).parts
    )
    observation_path.parent.mkdir(parents=True)
    observation_path.write_bytes(
        validator.canonical_json_bytes(_repository_control_observation(ledger))
    )
    derived_keys = (
        "observed_utc",
        "main_branch",
        "tag_ruleset",
        "release_deploy_key",
        "immutable_releases",
        "actions",
        "environments",
        "repository_admission_secret_absence_after_publication",
        "admission_secret_absence_after_publication",
        "activation_flags_after_publication",
    )
    for key in derived_keys:
        ledger["repository_controls"].pop(key)

    facts = assembler._derive_repository_control_facts(ledger, root)

    for key in derived_keys:
        assert ledger["repository_controls"][key] == expected[key]
        assert facts[key] == expected[key]
    assert facts["observed_window"] == {
        "started_utc": "2030-01-01T00:23:00Z",
        "completed_utc": "2030-01-01T00:27:00Z",
    }

    ledger = _valid_ledger()
    ledger["repository_controls"]["actions"]["allowed_actions"] = "selected"
    with pytest.raises(
        assembler.LedgerAssemblyError,
        match="contradicts retained evidence",
    ):
        assembler._derive_repository_control_facts(ledger, root)


def test_assembler_rejects_hard_linked_evidence(tmp_path: Path) -> None:
    ledger = _valid_ledger()
    root, _contents = _evidence_directory(tmp_path, ledger)
    _remove_derived_claims(ledger)
    readme = root / "README.md"
    alias = tmp_path / "readme-alias"
    try:
        os.link(readme, alias)
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")
    with pytest.raises(
        assembler.LedgerAssemblyError,
        match="must not be a hard-linked file",
    ):
        assembler._complete_file_descriptors(ledger, root)


def test_assembler_extracts_real_rsae_and_raae_manifest_bindings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    producer = tmp_path / "producer"
    producer.mkdir()
    inputs = _artifact_inputs(producer, monkeypatch)
    sealed = _seal_artifact(inputs)
    root = tmp_path / "envelopes"
    source_target = root / "admission/source/source-allow.rsae"
    artifact_target = root / "admission/artifact/evo-guard.pyz.raae"
    source_target.parent.mkdir(parents=True)
    artifact_target.parent.mkdir(parents=True)
    source_target.write_bytes(inputs.release_source.output.read_bytes())
    artifact_target.write_bytes(Path(sealed.bundle_path).read_bytes())
    claims: dict[str, Any] = {
        "source_admission": {
            "rsae": {"path": "admission/source/source-allow.rsae"}
        },
        "artifact_admission": {
            "subjects": [
                {
                    "name": "evo-guard.pyz",
                    "raae": {
                        "path": "admission/artifact/evo-guard.pyz.raae"
                    },
                }
            ]
        },
        "control_evidence": {},
        "attestations": {},
    }
    monkeypatch.setattr(assembler, "_derive_attestation_facts", lambda *_: {})

    facts = assembler._derive_embedded_facts(claims, root)

    source_manifest = inputs.release_source.attested.verified.receipt.payload
    source = claims["source_admission"]
    assert source["format"] == "EVOGUARD_RELEASE_SOURCE_ADMISSION_V2"
    assert source["decision"] == "ALLOW"
    assert source["target_commit_sha"] == source_manifest["source"][
        "target_commit_sha"
    ]
    assert source["rsae"]["algorithm"] == "Ed25519"
    subject = claims["artifact_admission"]["subjects"][0]
    assert subject["artifact_sha256"] == hashlib.sha256(
        inputs.artifact.read_bytes()
    ).hexdigest()
    assert subject["artifact_size_bytes"] == inputs.artifact.stat().st_size
    assert subject["raae"]["algorithm"] == "Ed25519"
    assert facts["artifact_admission"][0]["embedded_rsae_sha256"] == hashlib.sha256(
        inputs.release_source.output.read_bytes()
    ).hexdigest()


def test_assembler_emits_canonical_unsigned_draft_and_provenance_without_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = _valid_ledger()
    root, _contents = _evidence_directory(tmp_path, ledger)
    trusted_parent = _trusted_parent(tmp_path, ledger, root)
    _remove_derived_claims(ledger)
    claims = tmp_path / "reviewed-claims.json"
    claims.write_text(json.dumps(ledger, indent=2), encoding="utf-8")
    output = tmp_path / "RELEASE_LEDGER.unsigned.json"
    provenance = tmp_path / "RELEASE_LEDGER.assembly-provenance.json"

    # The generic byte inventory, schema, trusted-parent, checksum, key, and
    # repository-observation checks remain active.  These three owners are
    # replaced because this compact fixture intentionally does not construct
    # real GitHub outputs or signed RSAE/RAAE bundles.
    monkeypatch.setattr(
        assembler.validator,
        "_validate_control_bytes",
        lambda *_: None,
    )
    monkeypatch.setattr(
        assembler.validator,
        "_validate_attestation_bytes",
        lambda *_: None,
    )
    monkeypatch.setattr(
        assembler.validator,
        "_validate_envelopes",
        lambda *_: None,
    )
    monkeypatch.setattr(
        assembler,
        "_derive_embedded_facts",
        lambda *_: {"fixture": "byte-specific owners tested separately"},
    )
    trusted_parent_context = assembler.validator._trusted_parent_first_party
    observed_blocked_roots: list[Path] = []

    def _observe_trusted_parent_context(
        contracts: Any,
        *,
        blocked_roots: tuple[Path, ...] = (),
    ) -> Any:
        observed_blocked_roots.extend(blocked_roots)
        return trusted_parent_context(contracts, blocked_roots=blocked_roots)

    monkeypatch.setattr(
        assembler.validator,
        "_trusted_parent_first_party",
        _observe_trusted_parent_context,
    )

    assembled, manifest = assembler.assemble(
        root,
        claims,
        output,
        provenance,
        trusted_parent,
    )
    assert output.read_bytes() == validator.canonical_json_bytes(assembled)
    assert provenance.read_bytes() == validator.canonical_json_bytes(manifest)
    assert manifest["authoritative"] is False
    assert manifest["network_access"] == "not-performed"
    assert manifest["signing"] == "not-performed"
    assert manifest["unsigned_draft"]["sha256"] == hashlib.sha256(
        output.read_bytes()
    ).hexdigest()
    assert len(manifest["retained_inputs"]) == len(
        validator._collect_descriptors(assembled)
    )
    assert root in observed_blocked_roots

    before = (output.read_bytes(), provenance.read_bytes())
    with pytest.raises(assembler.LedgerAssemblyError, match="refusing to overwrite"):
        assembler.assemble(
            root,
            claims,
            output,
            provenance,
            trusted_parent,
        )
    assert (output.read_bytes(), provenance.read_bytes()) == before


def test_cli_failure_does_not_create_outputs_for_claims_inside_evidence(
    tmp_path: Path,
) -> None:
    ledger = _valid_ledger()
    root, _contents = _evidence_directory(tmp_path, ledger)
    trusted_parent = _trusted_parent(tmp_path, ledger, root)
    claims = root / "claims.json"
    claims.write_text(json.dumps(ledger), encoding="utf-8")
    output = tmp_path / "draft.json"
    provenance = tmp_path / "provenance.json"
    assert (
        assembler.main(
            [
                str(root),
                str(claims),
                str(output),
                "--provenance",
                str(provenance),
                "--trusted-parent-repo",
                str(trusted_parent),
            ]
        )
        == 1
    )
    assert not output.exists()
    assert not provenance.exists()


def test_assembler_rejects_parent_missing_trusted_build_input(
    tmp_path: Path,
) -> None:
    ledger = _valid_ledger()
    root, _contents = _evidence_directory(tmp_path, ledger)
    trusted_parent = _trusted_parent(tmp_path, ledger, root)
    (trusted_parent / "tools" / "ci" / "verify_spdx_attestation.py").unlink()
    _git(trusted_parent, "add", ".")
    _git(trusted_parent, "commit", "-q", "-m", "remove trusted verifier")
    ledger["source"]["parent_commit_sha"] = _git(trusted_parent, "rev-parse", "HEAD")
    ledger["source"]["parent_tree_sha"] = _git(
        trusted_parent, "rev-parse", "HEAD^{tree}"
    )
    _remove_derived_claims(ledger)
    trusted_inputs = ledger["toolchain"]["trusted_build_inputs"]
    trusted_inputs.pop("source_parent_sha")
    trusted_inputs.pop("source_parent_tree_sha")

    with pytest.raises(
        assembler.LedgerAssemblyError,
        match=r"build input tools/ci/verify_spdx_attestation\.py",
    ):
        assembler._trusted_contracts(ledger, root, trusted_parent)
