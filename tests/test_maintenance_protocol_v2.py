from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from evoom_guard import release_source_finalizer as legacy_finalizer
from evoom_guard import release_source_producer_receipt as legacy_receipt
from evoom_guard.admission import release_artifact as legacy_artifact_admission
from evoom_guard.admission import release_artifact_v2 as release_artifact_v2_module
from evoom_guard.admission import release_source as legacy_source_admission
from evoom_guard.admission import release_source_v3 as release_source_v3_module
from evoom_guard.admission.release_artifact_v2 import (
    MAX_SOURCE_ADMISSION_BYTES,
    RELEASE_ARTIFACT_ADMISSION_FORMAT_V2,
    RELEASE_ARTIFACT_ADMISSION_SIGNATURE_DOMAIN_V2,
    RELEASE_ARTIFACT_ADMISSION_SIGNATURE_PURPOSE_V2,
    RELEASE_ARTIFACT_SOURCE_ADMISSION_PATH_V2,
    ReleaseArtifactAdmissionV2Error,
    bind_release_artifact_v2_to_source_admission,
    release_artifact_admission_v2_signature_message,
    validate_release_artifact_admission_v2,
)
from evoom_guard.admission.release_source_v3 import (
    MAX_PRODUCER_RECEIPT_BYTES_V2,
    RELEASE_SOURCE_ADMISSION_FORMAT_V3,
    RELEASE_SOURCE_ADMISSION_PRODUCER_RECEIPT_PATH_V3,
    RELEASE_SOURCE_ADMISSION_SIGNATURE_DOMAIN_V3,
    RELEASE_SOURCE_ADMISSION_SIGNATURE_PURPOSE_V3,
    ReleaseSourceAdmissionV3Error,
    bind_release_source_admission_v3_to_receipt,
    canonical_release_source_admission_v3_bytes,
    release_source_admission_v3_signature_message,
    validate_release_source_admission_v3,
)
from evoom_guard.evidence_bundle import canonical_json_bytes
from evoom_guard.maintenance_bindings import (
    RELEASE_SOURCE_BINDINGS_FORMAT_V2,
    RELEASE_SOURCE_CONTEXT_FORMAT_V2,
    RELEASE_SOURCE_FORMAT_V2,
    RELEASE_SOURCE_HANDOFF_FORMAT_V2,
    MaintenanceBindingError,
    canonical_validated_bytes,
    context_from_release_source_bindings_v2,
    require_canonical_bytes,
    validate_release_source_bindings_v2,
    validate_release_source_context_v2,
    validate_release_source_handoff_v2,
    validate_release_source_v2,
)
from evoom_guard.release_source_finalizer_v2 import (
    RELEASE_SOURCE_EVIDENCE_FORMAT_V2,
    RELEASE_SOURCE_FINALIZER_HANDOFF_PATH_V2,
    RELEASE_SOURCE_FINALIZER_RECORD_PATH_V2,
    RELEASE_SOURCE_FINALIZER_SIGNATURE_DOMAIN_V2,
    RELEASE_SOURCE_FINALIZER_SIGNATURE_PURPOSE_V2,
    release_source_finalizer_v2_signature_message,
    validate_release_source_finalizer_v2,
)
from evoom_guard.release_source_producer_receipt_v2 import (
    RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT_V2,
    RELEASE_SOURCE_PRODUCER_RUNTIME_FORMAT_V2,
    ReleaseSourceProducerReceiptV2Error,
    canonical_release_source_producer_receipt_v2_bytes,
    validate_release_source_producer_receipt_v2,
)


def _source() -> dict[str, Any]:
    return {
        "format": RELEASE_SOURCE_FORMAT_V2,
        "repository": "EvoRiseKsa/EvoOM-Guard-m",
        "repository_id": "123456789",
        "default_branch": "main",
        "trusted_workflow_ref": "refs/heads/main",
        "trusted_workflow_sha": "1" * 40,
        "trusted_workflow_tree": "2" * 40,
        "trusted_workflow_path": ".github/workflows/release-source-finalizer-v2.yml",
        "trusted_workflow_blob_sha": "3" * 40,
        "maintenance_base_ref": "refs/heads/maintenance/v4.5",
        "maintenance_base_sha": "4" * 40,
        "maintenance_base_tree": "5" * 40,
        "target_source_ref": "refs/heads/release/v4.5.1",
        "target_source_sha": "6" * 40,
        "target_source_tree": "7" * 40,
    }


def _trusted_inputs(source: dict[str, Any] | None = None) -> dict[str, Any]:
    selected = source or _source()
    return {
        "source_sha": selected["trusted_workflow_sha"],
        "source_tree": selected["trusted_workflow_tree"],
        "policy": {
            "path": ".evoguard.json",
            "blob_sha": "8" * 40,
            "sha256": "a" * 64,
        },
        "verifier_pack": {
            "root_path": "security/packs/release",
            "tree_sha": "9" * 40,
            "sha256": "b" * 64,
        },
        "control_tools": [
            {
                "path": ".github/workflows/release-artifact-admitter-v2.yml",
                "blob_sha": "d" * 40,
                "sha256": "0" * 64,
            },
            {
                "path": ".github/workflows/release-artifact-builder-v2.yml",
                "blob_sha": "c" * 40,
                "sha256": "1" * 64,
            },
            {
                "path": ".github/workflows/release-source-admitter-v3.yml",
                "blob_sha": "b" * 40,
                "sha256": "2" * 64,
            },
            {
                "path": ".github/workflows/release-source-finalizer-v2.yml",
                "blob_sha": "3" * 40,
                "sha256": "3" * 64,
            },
            {
                "path": ".github/workflows/release-source-producer-v2.yml",
                "blob_sha": "a" * 40,
                "sha256": "4" * 64,
            },
            {
                "path": "tools/ci/validate_maintenance_release.py",
                "blob_sha": "c" * 40,
                "sha256": "5" * 64,
            },
        ],
    }


def _run(run_id: str, attempt: int = 1) -> dict[str, Any]:
    return {"run_id": run_id, "run_attempt": attempt}


def _context() -> dict[str, Any]:
    source = _source()
    return {
        "format": RELEASE_SOURCE_CONTEXT_FORMAT_V2,
        "source": source,
        "evaluation": _run("100", 1),
        "trusted_inputs": _trusted_inputs(source),
        "candidate_sha256": "e" * 64,
    }


def _bindings() -> dict[str, Any]:
    source = _source()
    return {
        "format": RELEASE_SOURCE_BINDINGS_FORMAT_V2,
        "source": source,
        "trusted_inputs": _trusted_inputs(source),
        "candidate_sha256": "e" * 64,
    }


def _handoff() -> dict[str, Any]:
    return {
        "format": RELEASE_SOURCE_HANDOFF_FORMAT_V2,
        "source": _source(),
        "context": _context(),
        "upstream": _run("100", 1),
        "record": {"sha256": "f" * 64, "size": 4096},
    }


def _actor(
    *,
    workflow_id: str,
    path: str,
    blob: str,
    run_id: str,
    attempt: int,
    upstream_id: str,
    upstream_attempt: int,
    event: str = "workflow_run",
) -> dict[str, Any]:
    source = _source()
    return {
        "workflow_repository": source["repository"],
        "workflow_repository_id": source["repository_id"],
        "workflow_id": workflow_id,
        "workflow_path": path,
        "workflow_blob_sha": blob * 40,
        "workflow_run_id": run_id,
        "workflow_run_attempt": attempt,
        "workflow_event": event,
        "workflow_ref": "refs/heads/main",
        "workflow_commit_sha": source["trusted_workflow_sha"],
        "workflow_tree_sha": source["trusted_workflow_tree"],
        "upstream_run_id": upstream_id,
        "upstream_run_attempt": upstream_attempt,
        "runner_class": "github-hosted",
    }


def _producer() -> dict[str, Any]:
    return _actor(
        workflow_id="2000",
        path=".github/workflows/release-source-producer-v2.yml",
        blob="a",
        run_id="200",
        attempt=2,
        upstream_id="100",
        upstream_attempt=1,
    )


def _receipt() -> dict[str, Any]:
    return {
        "format": RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT_V2,
        "subject": _source(),
        "context": _context(),
        "upstream": _run("100", 1),
        "record": {"sha256": "f" * 64, "size": 4096},
        "handoff": {"sha256": "1" * 64, "size": 8192},
        "bootstrap": {
            "runtime_identity_format": RELEASE_SOURCE_PRODUCER_RUNTIME_FORMAT_V2,
            "guard_artifact_sha256": "2" * 64,
        },
        "execution": {
            "outcome": "PASS",
            "guard_exit_code": 0,
            "candidate_isolation": "gvisor",
            "network": "none",
            "report_integrity": "external_process_isolated",
            "overall_profile": "black_box_external_judge",
        },
        "producer": _producer(),
    }


def _descriptor(path: str, token: str, size: int) -> dict[str, Any]:
    return {"path": path, "sha256": token * 64, "size": size}


def _key_ids(names: list[str]) -> dict[str, str]:
    digits = "123456789abcdef"
    return {name: "sha256:" + digits[index] * 64 for index, name in enumerate(names)}


def _source_admission() -> dict[str, Any]:
    receipt_bytes = canonical_release_source_producer_receipt_v2_bytes(_receipt())
    receipt = {
        "path": RELEASE_SOURCE_ADMISSION_PRODUCER_RECEIPT_PATH_V3,
        "sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "size": len(receipt_bytes),
    }
    source = _source()
    producer = _producer()
    admitter = _actor(
        workflow_id="3000",
        path=".github/workflows/release-source-admitter-v3.yml",
        blob="b",
        run_id="300",
        attempt=1,
        upstream_id="200",
        upstream_attempt=2,
    )
    separation = _key_ids(
        [
            "trusted_finalizer",
            "artifact_admission_v1",
            "artifact_digest_admission_v2",
            "release_source_finalizer_v1",
            "release_source_admission_v2",
            "release_source_finalizer_v2",
        ]
    )
    return {
        "format": RELEASE_SOURCE_ADMISSION_FORMAT_V3,
        "decision": "ALLOW",
        "source": source,
        "context": _context(),
        "upstream": _run("100", 1),
        "producer": producer,
        "admitter": admitter,
        "producer_receipt": receipt,
        "provider": {
            "name": "github-artifact-attestations",
            "artifact": {"sha256": receipt["sha256"], "size": receipt["size"]},
            "policy": {
                "repository": source["repository"],
                "signer_workflow": f"{source['repository']}/{producer['workflow_path']}",
                "signer_digest": source["trusted_workflow_sha"],
                "source_ref": "refs/heads/main",
                "source_digest": source["trusted_workflow_sha"],
                "cert_oidc_issuer": "https://token.actions.githubusercontent.com",
                "predicate_type": "https://slsa.dev/provenance/v1",
                "deny_self_hosted_runners": True,
                "attestation_limit": 1,
            },
            "verified_attestation_count": 1,
            "receipt": _descriptor("provider/github-attestation-receipt.json", "3", 1024),
            "raw_output": _descriptor("provider/github-attestation-output.json", "4", 2048),
        },
        "toolchain": {
            "git_sha256": "5" * 64,
            "github_cli_sha256": "6" * 64,
            "provider_isolation": {"platform": "posix", "uid": 1001, "gid": 1001},
        },
        "replay": {
            "evaluation": _run("100", 1),
            "producer": _run("200", 2),
            "admitter": _run("300", 1),
        },
        "key_separation": separation,
        "authentication": {
            "algorithm": "Ed25519",
            "key_id": "sha256:" + "f" * 64,
            "purpose": RELEASE_SOURCE_ADMISSION_SIGNATURE_PURPOSE_V3,
            "key_domain": "release-source-admission-v3",
            "signature_path": "admission.sig",
        },
    }


def _artifact_admission() -> tuple[dict[str, Any], bytes]:
    source_admission = _source_admission()
    source_bytes = canonical_release_source_admission_v3_bytes(source_admission)
    source = _source()
    source_summary = {
        "format": RELEASE_SOURCE_ADMISSION_FORMAT_V3,
        "decision": "ALLOW",
        "bundle": {
            "path": RELEASE_ARTIFACT_SOURCE_ADMISSION_PATH_V2,
            "sha256": hashlib.sha256(source_bytes).hexdigest(),
            "size": len(source_bytes),
        },
        "key_id": source_admission["authentication"]["key_id"],
        "repository": source["repository"],
        "repository_id": source["repository_id"],
        "trusted_workflow_sha": source["trusted_workflow_sha"],
        "trusted_workflow_tree": source["trusted_workflow_tree"],
        "trusted_workflow_path": source["trusted_workflow_path"],
        "trusted_workflow_blob_sha": source["trusted_workflow_blob_sha"],
        "maintenance_base_sha": source["maintenance_base_sha"],
        "maintenance_base_tree": source["maintenance_base_tree"],
        "target_source_sha": source["target_source_sha"],
        "target_source_tree": source["target_source_tree"],
        "trusted_inputs": _trusted_inputs(source),
        "admission_run_id": "300",
        "admission_run_attempt": 1,
        "admission_workflow_id": source_admission["admitter"]["workflow_id"],
        "admission_workflow_path": source_admission["admitter"]["workflow_path"],
        "admission_workflow_blob_sha": source_admission["admitter"]["workflow_blob_sha"],
    }
    builder = _actor(
        workflow_id="4000",
        path=".github/workflows/release-artifact-builder-v2.yml",
        blob="c",
        run_id="400",
        attempt=1,
        upstream_id="300",
        upstream_attempt=1,
        event="workflow_dispatch",
    )
    admitter = _actor(
        workflow_id="5000",
        path=".github/workflows/release-artifact-admitter-v2.yml",
        blob="d",
        run_id="500",
        attempt=1,
        upstream_id="400",
        upstream_attempt=1,
    )
    artifact = {"kind": "file", "sha256": "7" * 64, "size": 12_345}
    separation = dict(source_admission["key_separation"])
    separation["release_source_admission_v3"] = source_admission["authentication"][
        "key_id"
    ]
    manifest = {
        "format": RELEASE_ARTIFACT_ADMISSION_FORMAT_V2,
        "decision": "ALLOW",
        "release_source": source_summary,
        "artifact": artifact,
        "builder": builder,
        "admitter": admitter,
        "provider": {
            "name": "github-artifact-attestations",
            "artifact": {"sha256": artifact["sha256"], "size": artifact["size"]},
            "policy": {
                "repository": source["repository"],
                "signer_workflow": f"{source['repository']}/{builder['workflow_path']}",
                "signer_digest": source["trusted_workflow_sha"],
                "source_ref": "refs/heads/main",
                "source_digest": source["trusted_workflow_sha"],
                "cert_oidc_issuer": "https://token.actions.githubusercontent.com",
                "predicate_type": "https://slsa.dev/provenance/v1",
                "deny_self_hosted_runners": True,
                "attestation_limit": 1,
            },
            "verified_attestation_count": 1,
            "receipt": _descriptor("provider/github-attestation-receipt.json", "8", 1024),
            "raw_output": _descriptor("provider/github-attestation-output.json", "9", 2048),
        },
        "toolchain": {
            "git_sha256": "a" * 64,
            "github_cli_sha256": "b" * 64,
            "provider_isolation": {"platform": "posix", "uid": 1001, "gid": 1001},
        },
        "replay": {
            "source_admitter": _run("300", 1),
            "builder": _run("400", 1),
            "artifact_admitter": _run("500", 1),
        },
        "key_separation": separation,
        "authentication": {
            "algorithm": "Ed25519",
            "key_id": "sha256:" + "e" * 64,
            "purpose": RELEASE_ARTIFACT_ADMISSION_SIGNATURE_PURPOSE_V2,
            "key_domain": "release-artifact-admission-v2",
            "signature_path": "admission.sig",
        },
    }
    return manifest, source_bytes


def _finalizer() -> dict[str, Any]:
    return {
        "format": RELEASE_SOURCE_EVIDENCE_FORMAT_V2,
        "decision": "DENY",
        "source": _source(),
        "context": _context(),
        "upstream": _run("100", 1),
        "record": _descriptor(RELEASE_SOURCE_FINALIZER_RECORD_PATH_V2, "a", 4096),
        "handoff": _descriptor(RELEASE_SOURCE_FINALIZER_HANDOFF_PATH_V2, "b", 8192),
        "authentication": {
            "algorithm": "Ed25519",
            "key_id": "sha256:" + "c" * 64,
            "purpose": RELEASE_SOURCE_FINALIZER_SIGNATURE_PURPOSE_V2,
            "key_domain": "release-source-finalizer-v2",
            "signature_path": "bundle.sig",
        },
    }


def test_protocol_v2_golden_canonical_digests() -> None:
    artifact, _source_bytes = _artifact_admission()
    values = {
        "source": (validate_release_source_v2, _source()),
        "context": (validate_release_source_context_v2, _context()),
        "bindings": (validate_release_source_bindings_v2, _bindings()),
        "handoff": (validate_release_source_handoff_v2, _handoff()),
        "finalizer": (validate_release_source_finalizer_v2, _finalizer()),
        "receipt": (validate_release_source_producer_receipt_v2, _receipt()),
        "source_admission": (validate_release_source_admission_v3, _source_admission()),
        "artifact_admission": (validate_release_artifact_admission_v2, artifact),
    }
    expected = {
        "source": "6e95ae92f7429e5510b9b59c57eeb5cf82fb9465acdc127989b97b290f92b4bb",
        "context": "151f78779664f9e2f96f2de820864477e51f49894ec8db7f9965a21a2d2f2d2a",
        "bindings": "a7fcce54f0dc89788552c06cc8601f969552721fef7a2974e2df063eec6ec8a7",
        "handoff": "ed7518063e4dd7b5ba617ca7b8371c48d1294921d0c9497a5420e37d315ae0d5",
        "finalizer": "3ae53609f5ea3d0ddcb35edba417f875f6fa3d2ecf07ede66255761fa98ba25b",
        "receipt": "bacbde0847f86f34255657674608325dc28585da6769e4b20a6c2731336419b4",
        "source_admission": "7d9090ceded966cf7f012cf6f0cff0c7e0279980d5450c153a8499bdf1903f5e",
        "artifact_admission": "cabdbb5a7ddee8dc2bf2a1995569b4a2d2ca513b3310511468e5cd63b0378716",
    }
    actual = {
        name: hashlib.sha256(canonical_validated_bytes(value, validator=validator)).hexdigest()
        for name, (validator, value) in values.items()
    }
    assert actual == expected


def test_context_is_derived_from_bindings_and_every_handoff_carries_upstream() -> None:
    context = context_from_release_source_bindings_v2(_bindings(), upstream=_run("100", 1))
    assert context == _context()
    assert validate_release_source_handoff_v2(_handoff())["upstream"] == _run("100", 1)
    assert validate_release_source_producer_receipt_v2(_receipt())["upstream"] == _run("100", 1)


def test_v2_schemas_accept_every_golden_contract() -> None:
    schema_dir = Path(__file__).parents[1] / "evoom_guard" / "schemas"
    names = [
        "release-source-2.schema.json",
        "release-source-context-2.schema.json",
        "release-source-git-bindings-2.schema.json",
        "release-source-handoff-2.schema.json",
        "release-source-producer-receipt-2.schema.json",
        "release-source-finalizer-2.schema.json",
        "release-source-admission-3.schema.json",
        "release-artifact-admission-2.schema.json",
    ]
    schemas = [json.loads((schema_dir / name).read_text(encoding="utf-8")) for name in names]
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema, default_specification=DRAFT202012))
        for schema in schemas
    )
    artifact, _source_bytes = _artifact_admission()
    values = [
        _source(),
        _context(),
        _bindings(),
        _handoff(),
        _receipt(),
        _finalizer(),
        _source_admission(),
        artifact,
    ]
    for schema, value in zip(schemas, values, strict=True):
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, registry=registry).validate(value)


def test_source_admission_binds_exact_receipt_and_keeps_target_out_of_provider_source() -> None:
    receipt = _receipt()
    receipt_bytes = canonical_release_source_producer_receipt_v2_bytes(receipt)
    admission = bind_release_source_admission_v3_to_receipt(
        _source_admission(), receipt, receipt_bytes=receipt_bytes
    )
    policy = admission["provider"]["policy"]
    assert policy["source_digest"] == admission["source"]["trusted_workflow_sha"]
    assert policy["source_digest"] != admission["source"]["target_source_sha"]
    checked_receipt = validate_release_source_producer_receipt_v2(_receipt())
    assert (
        checked_receipt["subject"]["target_source_sha"] == admission["source"]["target_source_sha"]
    )


def test_artifact_admission_binds_exact_source_admission_bytes() -> None:
    artifact, source_bytes = _artifact_admission()
    bound = bind_release_artifact_v2_to_source_admission(
        artifact, _source_admission(), source_admission_bytes=source_bytes
    )
    assert bound["release_source"]["target_source_sha"] == _source()["target_source_sha"]
    assert bound["provider"]["policy"]["source_digest"] == _source()["trusted_workflow_sha"]


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value["source"].__setitem__(
            "trusted_workflow_sha", value["source"]["target_source_sha"]
        ),
        lambda value: value["source"].__setitem__("trusted_workflow_tree", "f" * 40),
        lambda value: value["source"].__setitem__("trusted_workflow_blob_sha", "f" * 40),
        lambda value: value["source"].__setitem__(
            "trusted_workflow_path", ".github/workflows/other.yml"
        ),
        lambda value: value["context"]["trusted_inputs"].__setitem__(
            "source_sha", value["source"]["target_source_sha"]
        ),
        lambda value: value["context"]["trusted_inputs"].__setitem__(
            "source_tree", value["source"]["target_source_tree"]
        ),
        lambda value: value["replay"]["producer"].__setitem__("run_attempt", 1),
        lambda value: value["provider"]["policy"].__setitem__(
            "source_digest", value["source"]["target_source_sha"]
        ),
    ],
)
def test_source_admission_rejects_role_swap_blob_tree_policy_and_replay(
    mutator: Any,
) -> None:
    changed = copy.deepcopy(_source_admission())
    mutator(changed)
    with pytest.raises((ReleaseSourceAdmissionV3Error, ReleaseSourceProducerReceiptV2Error)):
        validate_release_source_admission_v3(changed)


def test_exact_keys_and_noncanonical_json_fail_closed() -> None:
    changed = _source()
    changed["candidate_selected_policy"] = True
    with pytest.raises(MaintenanceBindingError, match="keys are not exact"):
        validate_release_source_v2(changed)
    canonical = canonical_validated_bytes(_source(), validator=validate_release_source_v2)
    alternate = json.dumps(_source(), indent=2).encode("utf-8")
    assert alternate != canonical
    with pytest.raises(MaintenanceBindingError, match="not canonical"):
        require_canonical_bytes(
            alternate, validator=validate_release_source_v2, label="release source V2"
        )


def test_receipt_subject_target_and_receipt_bytes_cannot_be_substituted() -> None:
    changed_receipt = copy.deepcopy(_receipt())
    changed_receipt["subject"]["target_source_sha"] = "f" * 40
    with pytest.raises(ReleaseSourceProducerReceiptV2Error):
        validate_release_source_producer_receipt_v2(changed_receipt)

    changed_admission = copy.deepcopy(_source_admission())
    changed_admission["producer_receipt"]["sha256"] = "0" * 64
    changed_admission["provider"]["artifact"]["sha256"] = "0" * 64
    with pytest.raises(ReleaseSourceAdmissionV3Error, match="canonical receipt bytes"):
        receipt = _receipt()
        bind_release_source_admission_v3_to_receipt(
            changed_admission,
            receipt,
            receipt_bytes=canonical_release_source_producer_receipt_v2_bytes(receipt),
        )


def test_source_admission_binding_rejects_noncanonical_and_mixed_receipt_bytes() -> None:
    receipt = _receipt()
    canonical = canonical_release_source_producer_receipt_v2_bytes(receipt)
    noncanonical = json.dumps(receipt, indent=2).encode("utf-8")
    assert (len(canonical), len(noncanonical)) == (4701, 5645)

    with pytest.raises(ReleaseSourceAdmissionV3Error, match="not canonical JSON"):
        bind_release_source_admission_v3_to_receipt(
            _source_admission(), receipt, receipt_bytes=noncanonical
        )

    other_receipt = copy.deepcopy(receipt)
    other_receipt["record"]["sha256"] = "0" * 64
    other_bytes = canonical_release_source_producer_receipt_v2_bytes(other_receipt)
    with pytest.raises(ReleaseSourceAdmissionV3Error, match="mapping does not match"):
        bind_release_source_admission_v3_to_receipt(
            _source_admission(), receipt, receipt_bytes=other_bytes
        )

    with pytest.raises(ReleaseSourceAdmissionV3Error, match="immutable bytes"):
        bind_release_source_admission_v3_to_receipt(
            _source_admission(), receipt, receipt_bytes=bytearray(canonical)  # type: ignore[arg-type]
        )


def test_source_receipt_size_bound_precedes_parser_and_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admission = _source_admission()
    receipt = _receipt()

    def unexpected_work(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("receipt parsing or hashing ran before its byte-size bound")

    monkeypatch.setattr(release_source_v3_module, "require_canonical_bytes", unexpected_work)
    monkeypatch.setattr(release_source_v3_module.hashlib, "sha256", unexpected_work)

    for invalid in (b"", bytes(MAX_PRODUCER_RECEIPT_BYTES_V2 + 1)):
        with pytest.raises(ReleaseSourceAdmissionV3Error, match="size is outside bounds"):
            bind_release_source_admission_v3_to_receipt(
                admission, receipt, receipt_bytes=invalid
            )


def test_artifact_source_size_bound_precedes_parser_and_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact, _source_bytes = _artifact_admission()
    source_admission = _source_admission()

    def unexpected_work(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("source parsing or hashing ran before its byte-size bound")

    monkeypatch.setattr(release_artifact_v2_module, "require_canonical_bytes", unexpected_work)
    monkeypatch.setattr(release_artifact_v2_module.hashlib, "sha256", unexpected_work)

    oversized = bytes(MAX_SOURCE_ADMISSION_BYTES + 1)
    assert len(oversized) == 73_400_321
    for invalid in (b"", oversized):
        with pytest.raises(ReleaseArtifactAdmissionV2Error, match="size is outside bounds"):
            bind_release_artifact_v2_to_source_admission(
                artifact,
                source_admission,
                source_admission_bytes=invalid,
            )


def test_every_stage_workflow_path_and_blob_must_be_a_trusted_main_material() -> None:
    changed_receipt = copy.deepcopy(_receipt())
    changed_receipt["producer"]["workflow_blob_sha"] = "f" * 40
    with pytest.raises(ReleaseSourceProducerReceiptV2Error, match="trusted-main material"):
        validate_release_source_producer_receipt_v2(changed_receipt)

    changed_source = copy.deepcopy(_source_admission())
    changed_source["admitter"]["workflow_path"] = ".github/workflows/unbound.yml"
    with pytest.raises(ReleaseSourceAdmissionV3Error, match="trusted-main material"):
        validate_release_source_admission_v3(changed_source)

    changed_artifact, _source_bytes = _artifact_admission()
    changed_artifact["builder"]["workflow_blob_sha"] = "f" * 40
    with pytest.raises(ReleaseArtifactAdmissionV2Error, match="trusted-main material"):
        validate_release_artifact_admission_v2(changed_artifact)


def test_artifact_target_swap_and_source_bundle_replay_fail_closed() -> None:
    artifact, source_bytes = _artifact_admission()
    artifact["release_source"]["target_source_sha"] = "f" * 40
    with pytest.raises(ReleaseArtifactAdmissionV2Error, match="does not match"):
        bind_release_artifact_v2_to_source_admission(
            artifact, _source_admission(), source_admission_bytes=source_bytes
        )

    artifact, source_bytes = _artifact_admission()
    with pytest.raises(ReleaseArtifactAdmissionV2Error, match="canonical JSON"):
        bind_release_artifact_v2_to_source_admission(
            artifact, _source_admission(), source_admission_bytes=source_bytes + b"\n"
        )


def test_artifact_binding_rejects_mix_and_match_mapping_and_canonical_bytes() -> None:
    artifact, _source_bytes = _artifact_admission()
    other_admission = copy.deepcopy(_source_admission())
    other_admission["toolchain"]["git_sha256"] = "0" * 64
    other_bytes = canonical_release_source_admission_v3_bytes(other_admission)
    artifact["release_source"]["bundle"].update(
        sha256=hashlib.sha256(other_bytes).hexdigest(), size=len(other_bytes)
    )
    with pytest.raises(ReleaseArtifactAdmissionV2Error, match="mapping does not match"):
        bind_release_artifact_v2_to_source_admission(
            artifact,
            _source_admission(),
            source_admission_bytes=other_bytes,
        )


def test_artifact_standalone_requires_source_summary_key_registry_continuity() -> None:
    artifact, _source_bytes = _artifact_admission()
    artifact["key_separation"]["release_source_admission_v3"] = "sha256:" + "d" * 64
    with pytest.raises(ReleaseArtifactAdmissionV2Error, match="source summary"):
        validate_release_artifact_admission_v2(artifact)


@pytest.mark.parametrize(
    "domain",
    [
        "trusted_finalizer",
        "artifact_admission_v1",
        "artifact_digest_admission_v2",
        "release_source_finalizer_v1",
        "release_source_admission_v2",
        "release_source_finalizer_v2",
    ],
)
def test_artifact_binding_requires_each_inherited_source_registry_entry(domain: str) -> None:
    artifact, source_bytes = _artifact_admission()
    artifact["key_separation"][domain] = "sha256:" + "d" * 64
    validate_release_artifact_admission_v2(artifact)
    with pytest.raises(ReleaseArtifactAdmissionV2Error, match="inherited key registry"):
        bind_release_artifact_v2_to_source_admission(
            artifact,
            _source_admission(),
            source_admission_bytes=source_bytes,
        )


def test_artifact_false_registry_cannot_reuse_the_source_authentication_key() -> None:
    artifact, _source_bytes = _artifact_admission()
    artifact["key_separation"]["release_source_admission_v3"] = "sha256:" + "d" * 64
    artifact["authentication"]["key_id"] = artifact["release_source"]["key_id"]
    with pytest.raises(ReleaseArtifactAdmissionV2Error, match="source summary"):
        validate_release_artifact_admission_v2(artifact)


def test_artifact_binding_registry_tracks_the_exact_source_authentication_key() -> None:
    artifact, _source_bytes = _artifact_admission()
    other_source = copy.deepcopy(_source_admission())
    other_source["authentication"]["key_id"] = "sha256:" + "d" * 64
    other_bytes = canonical_release_source_admission_v3_bytes(other_source)
    artifact["release_source"]["bundle"].update(
        sha256=hashlib.sha256(other_bytes).hexdigest(), size=len(other_bytes)
    )
    validate_release_artifact_admission_v2(artifact)
    with pytest.raises(ReleaseArtifactAdmissionV2Error, match="exact source bytes"):
        bind_release_artifact_v2_to_source_admission(
            artifact,
            other_source,
            source_admission_bytes=other_bytes,
        )


def test_local_replay_and_workflow_role_collapse_fail_closed() -> None:
    source_admission = copy.deepcopy(_source_admission())
    source_admission["producer"]["workflow_run_id"] = "100"
    source_admission["admitter"]["upstream_run_id"] = "100"
    source_admission["replay"]["producer"]["run_id"] = "100"
    with pytest.raises(ReleaseSourceAdmissionV3Error, match="pairwise distinct"):
        validate_release_source_admission_v3(source_admission)

    source_admission = copy.deepcopy(_source_admission())
    source_admission["admitter"]["workflow_id"] = source_admission["producer"]["workflow_id"]
    with pytest.raises(ReleaseSourceAdmissionV3Error, match="roles must be distinct"):
        validate_release_source_admission_v3(source_admission)

    artifact, _source_bytes = _artifact_admission()
    artifact["builder"]["workflow_run_id"] = "300"
    artifact["admitter"]["upstream_run_id"] = "300"
    artifact["replay"]["builder"]["run_id"] = "300"
    with pytest.raises(ReleaseArtifactAdmissionV2Error, match="pairwise distinct"):
        validate_release_artifact_admission_v2(artifact)

    artifact, _source_bytes = _artifact_admission()
    artifact["builder"]["workflow_id"] = artifact["release_source"][
        "admission_workflow_id"
    ]
    with pytest.raises(ReleaseArtifactAdmissionV2Error, match="roles must be distinct"):
        validate_release_artifact_admission_v2(artifact)


def test_full_five_stage_cross_chain_replay_and_role_collapse_fail_closed() -> None:
    artifact, source_bytes = _artifact_admission()
    artifact["builder"]["workflow_run_id"] = "200"
    artifact["admitter"]["upstream_run_id"] = "200"
    artifact["replay"]["builder"]["run_id"] = "200"
    validate_release_artifact_admission_v2(artifact)
    with pytest.raises(ReleaseArtifactAdmissionV2Error, match="five-stage"):
        bind_release_artifact_v2_to_source_admission(
            artifact, _source_admission(), source_admission_bytes=source_bytes
        )

    artifact, source_bytes = _artifact_admission()
    artifact["builder"]["workflow_id"] = _source_admission()["producer"]["workflow_id"]
    validate_release_artifact_admission_v2(artifact)
    with pytest.raises(ReleaseArtifactAdmissionV2Error, match="workflow ID"):
        bind_release_artifact_v2_to_source_admission(
            artifact, _source_admission(), source_admission_bytes=source_bytes
        )

    artifact, source_bytes = _artifact_admission()
    producer = _source_admission()["producer"]
    artifact["builder"]["workflow_path"] = producer["workflow_path"]
    artifact["builder"]["workflow_blob_sha"] = producer["workflow_blob_sha"]
    artifact["provider"]["policy"]["signer_workflow"] = (
        f"{_source()['repository']}/{producer['workflow_path']}"
    )
    validate_release_artifact_admission_v2(artifact)
    with pytest.raises(ReleaseArtifactAdmissionV2Error, match="path/blob"):
        bind_release_artifact_v2_to_source_admission(
            artifact, _source_admission(), source_admission_bytes=source_bytes
        )


@pytest.mark.parametrize(
    ("factory", "validator", "mutator"),
    [
        (
            _source_admission,
            validate_release_source_admission_v3,
            lambda value: value["provider"].__setitem__("verified_attestation_count", True),
        ),
        (
            _source_admission,
            validate_release_source_admission_v3,
            lambda value: value["provider"]["policy"].__setitem__("attestation_limit", True),
        ),
        (
            _source_admission,
            validate_release_source_admission_v3,
            lambda value: value["provider"]["policy"].__setitem__(
                "deny_self_hosted_runners", 1
            ),
        ),
        (
            lambda: _artifact_admission()[0],
            validate_release_artifact_admission_v2,
            lambda value: value["provider"].__setitem__("verified_attestation_count", True),
        ),
        (
            lambda: _artifact_admission()[0],
            validate_release_artifact_admission_v2,
            lambda value: value["provider"]["policy"].__setitem__("attestation_limit", True),
        ),
        (
            lambda: _artifact_admission()[0],
            validate_release_artifact_admission_v2,
            lambda value: value["provider"]["policy"].__setitem__(
                "deny_self_hosted_runners", 1
            ),
        ),
        (
            lambda: _artifact_admission()[0],
            validate_release_artifact_admission_v2,
            lambda value: (
                value["artifact"].__setitem__("size", 1),
                value["provider"]["artifact"].__setitem__("size", True),
            ),
        ),
        (
            lambda: _artifact_admission()[0],
            validate_release_artifact_admission_v2,
            lambda value: (
                value["artifact"].__setitem__("size", True),
                value["provider"]["artifact"].__setitem__("size", True),
            ),
        ),
    ],
)
def test_boolean_integer_type_confusion_is_rejected(
    factory: Any, validator: Any, mutator: Any
) -> None:
    value = factory()
    mutator(value)
    with pytest.raises(MaintenanceBindingError):
        validator(value)


def test_trusted_material_collisions_overlap_and_finalizer_omission_fail_closed() -> None:
    context = _context()
    context["trusted_inputs"]["policy"]["path"] = context["trusted_inputs"][
        "control_tools"
    ][0]["path"]
    with pytest.raises(MaintenanceBindingError, match="collide or overlap"):
        validate_release_source_context_v2(context)

    context = _context()
    context["trusted_inputs"]["verifier_pack"]["root_path"] = ".github"
    with pytest.raises(MaintenanceBindingError, match="collides or overlaps"):
        validate_release_source_context_v2(context)

    context = _context()
    finalizer = next(
        item
        for item in context["trusted_inputs"]["control_tools"]
        if item["path"] == context["source"]["trusted_workflow_path"]
    )
    finalizer["blob_sha"] = "f" * 40
    with pytest.raises(MaintenanceBindingError, match="trusted-main material"):
        validate_release_source_context_v2(context)


def _maintenance_schema_validator(name: str) -> Draft202012Validator:
    schema_dir = Path(__file__).parents[1] / "evoom_guard" / "schemas"
    names = [
        "release-source-2.schema.json",
        "release-source-context-2.schema.json",
        "release-source-git-bindings-2.schema.json",
        "release-source-handoff-2.schema.json",
        "release-source-producer-receipt-2.schema.json",
        "release-source-finalizer-2.schema.json",
        "release-source-admission-3.schema.json",
        "release-artifact-admission-2.schema.json",
    ]
    schemas = {
        schema_name: json.loads((schema_dir / schema_name).read_text(encoding="utf-8"))
        for schema_name in names
    }
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema, default_specification=DRAFT202012))
        for schema in schemas.values()
    )
    return Draft202012Validator(schemas[name], registry=registry)


def test_runtime_and_schema_share_representative_non_numeric_boundaries() -> None:
    long_workflow = ".github/workflows/" + "a" * 235 + ".yml"
    assert len(long_workflow) == 257

    source_long_workflow = _source()
    source_long_workflow["trusted_workflow_path"] = long_workflow
    source_dot_ref = _source()
    source_dot_ref["maintenance_base_ref"] = "refs/heads/maintenance/.hidden"
    source_lock_ref = _source()
    source_lock_ref["maintenance_base_ref"] = "refs/heads/maintenance/release.lock"
    context_bool_run = _context()
    context_bool_run["evaluation"]["run_attempt"] = True
    context_long_material = _context()
    context_long_material["trusted_inputs"]["policy"]["path"] = "a" * 513
    receipt_bool_size = _receipt()
    receipt_bool_size["record"]["size"] = True
    admission_bool_count = _source_admission()
    admission_bool_count["provider"]["verified_attestation_count"] = True
    artifact_bool_size, _source_bytes = _artifact_admission()
    artifact_bool_size["artifact"]["size"] = True
    artifact_bool_size["provider"]["artifact"]["size"] = True

    cases = [
        ("release-source-2.schema.json", source_long_workflow, validate_release_source_v2),
        ("release-source-2.schema.json", source_dot_ref, validate_release_source_v2),
        ("release-source-2.schema.json", source_lock_ref, validate_release_source_v2),
        (
            "release-source-context-2.schema.json",
            context_bool_run,
            validate_release_source_context_v2,
        ),
        (
            "release-source-context-2.schema.json",
            context_long_material,
            validate_release_source_context_v2,
        ),
        (
            "release-source-producer-receipt-2.schema.json",
            receipt_bool_size,
            validate_release_source_producer_receipt_v2,
        ),
        (
            "release-source-admission-3.schema.json",
            admission_bool_count,
            validate_release_source_admission_v3,
        ),
        (
            "release-artifact-admission-2.schema.json",
            artifact_bool_size,
            validate_release_artifact_admission_v2,
        ),
    ]
    for schema_name, value, runtime_validator in cases:
        assert not _maintenance_schema_validator(schema_name).is_valid(value)
        with pytest.raises(MaintenanceBindingError):
            runtime_validator(value)


def _integer_leaf_paths(
    value: Any, prefix: tuple[str | int, ...] = ()
) -> list[tuple[tuple[str | int, ...], int]]:
    if type(value) is int:
        return [(prefix, value)]
    if isinstance(value, dict):
        return [
            item
            for key, child in value.items()
            for item in _integer_leaf_paths(child, (*prefix, key))
        ]
    if isinstance(value, list):
        return [
            item
            for index, child in enumerate(value)
            for item in _integer_leaf_paths(child, (*prefix, index))
        ]
    return []


def _replace_path(value: Any, path: tuple[str | int, ...], replacement: Any) -> None:
    cursor = value
    for component in path[:-1]:
        cursor = cursor[component]
    cursor[path[-1]] = replacement


def test_draft_2020_12_integral_float_gap_is_explicit_for_all_49_integer_leaves() -> None:
    artifact, _source_bytes = _artifact_admission()
    contracts: list[
        tuple[
            str,
            dict[str, Any],
            Callable[[Mapping[str, Any]], dict[str, Any]],
        ]
    ] = [
        ("release-source-2.schema.json", _source(), validate_release_source_v2),
        (
            "release-source-context-2.schema.json",
            _context(),
            validate_release_source_context_v2,
        ),
        (
            "release-source-git-bindings-2.schema.json",
            _bindings(),
            validate_release_source_bindings_v2,
        ),
        (
            "release-source-handoff-2.schema.json",
            _handoff(),
            validate_release_source_handoff_v2,
        ),
        (
            "release-source-producer-receipt-2.schema.json",
            _receipt(),
            validate_release_source_producer_receipt_v2,
        ),
        (
            "release-source-finalizer-2.schema.json",
            _finalizer(),
            validate_release_source_finalizer_v2,
        ),
        (
            "release-source-admission-3.schema.json",
            _source_admission(),
            validate_release_source_admission_v3,
        ),
        (
            "release-artifact-admission-2.schema.json",
            artifact,
            validate_release_artifact_admission_v2,
        ),
    ]

    characterized = 0
    for schema_name, value, runtime_validator in contracts:
        schema_validator = _maintenance_schema_validator(schema_name)
        for path, integer_value in _integer_leaf_paths(value):
            mutated = copy.deepcopy(value)
            _replace_path(mutated, path, float(integer_value))
            assert schema_validator.is_valid(mutated), (schema_name, path)
            with pytest.raises(MaintenanceBindingError):
                runtime_validator(mutated)
            characterized += 1

    assert characterized == 49


def test_runtime_canonical_parser_rejects_integral_float_lexeme() -> None:
    context = _context()
    context["evaluation"]["run_attempt"] = 1.0
    assert _maintenance_schema_validator("release-source-context-2.schema.json").is_valid(
        context
    )
    encoded = canonical_json_bytes(context)
    assert b'"run_attempt":1.0' in encoded
    with pytest.raises(MaintenanceBindingError):
        require_canonical_bytes(
            encoded,
            validator=validate_release_source_context_v2,
            label="release-source context V2",
        )


def test_cross_version_and_cross_domain_replay_is_rejected() -> None:
    with pytest.raises(MaintenanceBindingError):
        validate_release_source_v2(
            {
                "repository": "EvoRiseKsa/EvoOM-Guard-m",
                "repository_id": "123456789",
                "default_branch": "main",
                "workflow_run_id": "1",
                "workflow_run_attempt": 1,
                "protected_ref": "refs/heads/main",
                "target_commit_sha": "1" * 40,
                "target_tree_sha": "2" * 40,
            }
        )
    with pytest.raises(legacy_finalizer.ReleaseSourceFinalizerError):
        legacy_finalizer.validate_release_source(_source())
    with pytest.raises(legacy_receipt.ReleaseSourceProducerReceiptError):
        legacy_receipt.validate_release_source_producer_receipt(_receipt())
    with pytest.raises(legacy_source_admission.ReleaseSourceAdmissionError):
        legacy_source_admission._validate_manifest(_source_admission())
    artifact, _source_bytes = _artifact_admission()
    with pytest.raises(legacy_artifact_admission.ReleaseArtifactAdmissionError):
        legacy_artifact_admission._validate_manifest(artifact)

    assert (
        len(
            {
                legacy_finalizer.RELEASE_SOURCE_EVIDENCE_DOMAIN,
                legacy_source_admission.RELEASE_SOURCE_ADMISSION_SIGNATURE_DOMAIN,
                legacy_artifact_admission.RELEASE_ARTIFACT_ADMISSION_SIGNATURE_DOMAIN,
                RELEASE_SOURCE_FINALIZER_SIGNATURE_DOMAIN_V2,
                RELEASE_SOURCE_ADMISSION_SIGNATURE_DOMAIN_V3,
                RELEASE_ARTIFACT_ADMISSION_SIGNATURE_DOMAIN_V2,
            }
        )
        == 6
    )
    finalizer_message = release_source_finalizer_v2_signature_message(_finalizer())
    source_message = release_source_admission_v3_signature_message(_source_admission())
    artifact_message = release_artifact_admission_v2_signature_message(artifact)
    assert len({finalizer_message, source_message, artifact_message}) == 3
    assert finalizer_message.startswith(RELEASE_SOURCE_FINALIZER_SIGNATURE_DOMAIN_V2)
    assert source_message.startswith(RELEASE_SOURCE_ADMISSION_SIGNATURE_DOMAIN_V3)
    assert artifact_message.startswith(RELEASE_ARTIFACT_ADMISSION_SIGNATURE_DOMAIN_V2)


def test_legacy_v1_source_canonical_bytes_remain_accepted_byte_for_byte() -> None:
    legacy = {
        "repository": "EvoRiseKsa/EvoOM-Guard-m",
        "repository_id": "123456789",
        "default_branch": "main",
        "workflow_run_id": "99",
        "workflow_run_attempt": 1,
        "protected_ref": "refs/heads/main",
        "target_commit_sha": "1" * 40,
        "target_tree_sha": "2" * 40,
    }
    checked = legacy_finalizer.validate_release_source(legacy)
    encoded = canonical_json_bytes(checked)
    assert checked == legacy
    assert (
        hashlib.sha256(encoded).hexdigest()
        == "833b004bf88577833a0c19acc2b8665a9cb411cf667afbc7966c49e904ed70be"
    )
    assert encoded == canonical_json_bytes(legacy_finalizer.validate_release_source(legacy))
