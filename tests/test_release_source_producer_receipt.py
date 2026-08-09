from __future__ import annotations

import copy
import importlib
import json
from collections.abc import Mapping
from dataclasses import FrozenInstanceError, fields
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

# Reuse the release-source fixture's deliberately strong black-box record.  The
# producer-receipt contract is an extension of that exact source contract, not
# a second permissive record format.
from test_release_source_finalizer import _commit, _git, _make_raw_git_repository, _strong_record

from evoom_guard import (
    evidence_bundle,
    github_attestation,
    release_source_finalizer,
    release_source_producer_receipt,
)
from evoom_guard.cli import main as cli_main
from evoom_guard.finalizer_derivation import derive_raw_evaluation_bindings


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _receipt_inputs(tmp_path: Path, *, include_admitter: bool = False):
    repo, _baseline, parent, _baseline_tree, parent_tree = _make_raw_git_repository(tmp_path)
    workflow = repo / ".github" / "workflows" / "evoguard-produce-release-source-receipt.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "name: EvoGuard Produce Release Source Receipt\n"
        "on: workflow_run\n"
        "jobs:\n  receipt:\n    runs-on: ubuntu-latest\n    steps: []\n",
        encoding="utf-8",
        newline="\n",
    )
    trigger_workflow = repo / ".github" / "workflows" / "evoguard-release-source-reverify.yml"
    trigger_workflow.write_text(
        "name: EvoGuard Release Source Reverify\n"
        "on: workflow_dispatch\n"
        "jobs:\n  reverify:\n    runs-on: ubuntu-latest\n    steps: []\n",
        encoding="utf-8",
        newline="\n",
    )
    if include_admitter:
        admitter_workflow = (
            repo / ".github" / "workflows" / "evoguard-admit-release-source.yml"
        )
        admitter_workflow.write_text(
            "name: EvoGuard Admit Release Source\n"
            "on: workflow_run\n"
            "jobs:\n  admit:\n    runs-on: ubuntu-latest\n    steps: []\n",
            encoding="utf-8",
            newline="\n",
        )
    target = _commit(repo, "add protected receipt producer")
    target_tree = _git(repo, "rev-parse", f"{target}^{{tree}}")
    raw = derive_raw_evaluation_bindings(
        base_repo=str(repo),
        head_repo=str(repo),
        base_sha=parent,
        head_sha=target,
        base_tree_sha=parent_tree,
        head_tree_sha=target_tree,
    )
    record = _strong_record(
        parent=parent,
        target=target,
        parent_tree=parent_tree,
        target_tree=target_tree,
        raw=raw,
    )
    source = {
        "repository": "owner/project",
        "repository_id": "12345",
        "default_branch": "main",
        "workflow_run_id": "987654321",
        "workflow_run_attempt": 1,
        "protected_ref": "refs/heads/main",
        "target_commit_sha": target,
        "target_tree_sha": target_tree,
    }
    bindings = release_source_finalizer.derive_release_source_bindings(
        git_repository=str(repo), source=source
    )
    context = release_source_finalizer.context_from_release_source_bindings(bindings, record)
    verdict = tmp_path / "verdict.json"
    _write_json(verdict, record)
    handoff = tmp_path / "handoff.json"
    release_source_finalizer.create_release_source_handoff(
        str(verdict), str(handoff), source=source, context=context
    )
    producer = {
        "workflow_repository": "owner/project",
        "workflow_repository_id": "12345",
        "workflow_id": "55555",
        "workflow_path": ".github/workflows/evoguard-produce-release-source-receipt.yml",
        "workflow_blob_sha": _git(
            repo,
            "rev-parse",
            f"{target}:.github/workflows/evoguard-produce-release-source-receipt.yml",
        ),
        "workflow_run_id": "987654322",
        "workflow_run_attempt": 1,
        "workflow_event": "workflow_run",
        "workflow_ref": "refs/heads/main",
        "workflow_commit_sha": target,
        "trigger_workflow_id": "44444",
        "trigger_workflow_path": ".github/workflows/evoguard-release-source-reverify.yml",
        "trigger_workflow_blob_sha": _git(
            repo,
            "rev-parse",
            f"{target}:.github/workflows/evoguard-release-source-reverify.yml",
        ),
        "trigger_workflow_run_id": "987654321",
        "trigger_workflow_run_attempt": 1,
        "runner_class": "github-hosted",
    }
    return repo, verdict, handoff, source, context, producer, target


def test_release_source_finalizer_primitive_snapshot_is_exact_and_immutable() -> None:
    snapshot = release_source_finalizer.snapshot_release_source_finalizer_primitives()

    assert isinstance(
        snapshot,
        release_source_finalizer.ReleaseSourceFinalizerPrimitiveSnapshot,
    )
    assert tuple(field.name for field in fields(snapshot)) == (
        "publish_bytes",
        "record_snapshot",
        "validate_source_context",
    )
    assert snapshot.publish_bytes is release_source_finalizer._publish_bytes
    assert snapshot.record_snapshot is release_source_finalizer._record_snapshot
    assert snapshot.validate_source_context is release_source_finalizer._validate_source_context
    assert not hasattr(snapshot, "__dict__")
    with pytest.raises(FrozenInstanceError):
        snapshot.publish_bytes = release_source_finalizer._publish_bytes


def test_producer_finalizer_primitives_are_snapshotted_at_module_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, verdict, handoff, source, context, producer, _target = _receipt_inputs(tmp_path)
    owner = release_source_finalizer
    consumer = release_source_producer_receipt
    original_publish = owner._publish_bytes
    original_record_snapshot = owner._record_snapshot
    original_validate_source_context = owner._validate_source_context
    original_snapshot_provider = owner.snapshot_release_source_finalizer_primitives
    snapshot_calls: list[str] = []
    published: list[tuple[str, bytes, bool, str, str]] = []
    record_paths: list[str] = []
    validated_pairs: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    publish_failure: list[BaseException | None] = [None]
    validation_failure: list[BaseException | None] = [None]

    class ImportBoundFailure(BaseException):
        pass

    def import_publish(
        path: str,
        data: bytes,
        *,
        force: bool,
        prefix: str,
        label: str,
    ) -> str:
        published.append((path, data, force, prefix, label))
        if publish_failure[0] is not None:
            raise publish_failure[0]
        return str(Path(path).resolve())

    def import_record_snapshot(path: str) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
        record_paths.append(path)
        return original_record_snapshot(path)

    def import_validate_source_context(
        source_value: Mapping[str, Any],
        context_value: Mapping[str, Any],
    ) -> None:
        validated_pairs.append((source_value, context_value))
        if validation_failure[0] is not None:
            raise validation_failure[0]
        original_validate_source_context(source_value, context_value)

    def import_snapshot_provider() -> (
        release_source_finalizer.ReleaseSourceFinalizerPrimitiveSnapshot
    ):
        snapshot_calls.append("module-import")
        return original_snapshot_provider()

    monkeypatch.setattr(owner, "_publish_bytes", import_publish)
    monkeypatch.setattr(owner, "_record_snapshot", import_record_snapshot)
    monkeypatch.setattr(owner, "_validate_source_context", import_validate_source_context)
    monkeypatch.setattr(
        owner,
        "snapshot_release_source_finalizer_primitives",
        import_snapshot_provider,
    )

    try:
        consumer = importlib.reload(consumer)
        imported_snapshot = consumer._release_source_finalizer_primitives
        assert snapshot_calls == ["module-import"]
        assert imported_snapshot.publish_bytes is import_publish
        assert imported_snapshot.record_snapshot is import_record_snapshot
        assert imported_snapshot.validate_source_context is import_validate_source_context
        assert consumer._publish_bytes is import_publish
        assert consumer._validate_source_context is import_validate_source_context

        output = tmp_path / "producer-receipt.json"
        created = consumer.create_release_source_producer_receipt(
            str(verdict),
            str(handoff),
            str(output),
            source=source,
            context=context,
            bootstrap_guard_sha256="a" * 64,
            producer=producer,
            git_repository=str(repo),
        )
        assert snapshot_calls == ["module-import"]
        assert published == [
            (
                str(output),
                evidence_bundle.canonical_json_bytes(created),
                False,
                ".evoguard-release-source-producer-receipt-",
                "release-source producer receipt",
            )
        ]
        assert record_paths
        assert validated_pairs

        def late_publish(*args: object, **kwargs: object) -> str:
            raise AssertionError("late owner publish primitive must not be observed")

        def late_record_snapshot(
            path: str,
        ) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
            return original_record_snapshot(path)

        def late_validate_source_context(
            source_value: Mapping[str, Any], context_value: Mapping[str, Any]
        ) -> None:
            original_validate_source_context(source_value, context_value)

        monkeypatch.setattr(owner, "_publish_bytes", late_publish)
        monkeypatch.setattr(owner, "_record_snapshot", late_record_snapshot)
        monkeypatch.setattr(owner, "_validate_source_context", late_validate_source_context)
        assert consumer._release_source_finalizer_primitives is imported_snapshot
        assert consumer._publish_bytes is import_publish
        assert consumer._validate_source_context is import_validate_source_context

        expected_publish_failure = ImportBoundFailure("publish")
        publish_failure[0] = expected_publish_failure
        with pytest.raises(ImportBoundFailure) as caught_publish:
            consumer.create_release_source_producer_receipt(
                str(verdict),
                str(handoff),
                str(output),
                source=source,
                context=context,
                bootstrap_guard_sha256="a" * 64,
                producer=producer,
                git_repository=str(repo),
            )
        assert caught_publish.value is expected_publish_failure
        assert published[-1][1] == published[0][1]

        expected_validation_failure = ImportBoundFailure("validate")
        validation_failure[0] = expected_validation_failure
        with pytest.raises(ImportBoundFailure) as caught_validation:
            consumer.validate_release_source_context_producer_binding(source, context, producer)
        assert caught_validation.value is expected_validation_failure
        assert snapshot_calls == ["module-import"]
    finally:
        monkeypatch.setattr(owner, "_publish_bytes", original_publish)
        monkeypatch.setattr(owner, "_record_snapshot", original_record_snapshot)
        monkeypatch.setattr(
            owner,
            "_validate_source_context",
            original_validate_source_context,
        )
        monkeypatch.setattr(
            owner,
            "snapshot_release_source_finalizer_primitives",
            original_snapshot_provider,
        )
        importlib.reload(consumer)


def test_canonical_producer_receipt_rechecks_raw_git_and_exact_bytes(tmp_path: Path) -> None:
    repo, verdict, handoff, source, context, producer, _target = _receipt_inputs(tmp_path)
    receipt = tmp_path / "producer-receipt.json"

    created = release_source_producer_receipt.create_release_source_producer_receipt(
        str(verdict),
        str(handoff),
        str(receipt),
        source=source,
        context=context,
        bootstrap_guard_sha256="a" * 64,
        producer=producer,
        git_repository=str(repo),
    )

    inspected = release_source_producer_receipt.inspect_release_source_producer_receipt(str(receipt))
    assert inspected.payload == created
    schema_path = Path(__file__).parents[1] / "evoom_guard" / "schemas" / "release-source-producer-receipt-1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert list(Draft202012Validator(schema).iter_errors(created)) == []
    assert created["execution"] == {
        "outcome": "PASS",
        "guard_exit_code": 0,
        "candidate_isolation": "docker",
        "network": "none",
        "report_integrity": "external_process_isolated",
        "overall_profile": "black_box_external_judge",
    }
    verified = release_source_producer_receipt.verify_release_source_producer_receipt(
        str(receipt),
        str(handoff),
        str(verdict),
        expected_source=source,
        expected_context=context,
        expected_producer=producer,
        expected_bootstrap_guard_sha256="a" * 64,
        git_repository=str(repo),
    )
    assert verified.receipt.payload == created


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda producer: producer.__setitem__("workflow_blob_sha", "b" * 40), "blob"),
        (lambda producer: producer.__setitem__("workflow_id", "44444"), "workflow must be distinct"),
        (
            lambda producer: producer.__setitem__(
                "workflow_path", ".github/workflows/evoguard-release-source-reverify.yml"
            ),
            "workflow path must be distinct",
        ),
        (
            lambda producer: producer.__setitem__(
                "workflow_path", ".github/workflows/nested/producer.yml"
            ),
            "directly under",
        ),
        (
            lambda producer: producer.__setitem__(
                "workflow_path", ".github/workflows/producer signer.yml"
            ),
            "ASCII workflow filename",
        ),
        (
            lambda producer: producer.__setitem__(
                "workflow_path", ".github/workflows/منتج.yml"
            ),
            "ASCII workflow filename",
        ),
        (
            lambda producer: producer.__setitem__(
                "workflow_path", ".github/workflows/-producer.yml"
            ),
            "ASCII workflow filename",
        ),
        (lambda producer: producer.__setitem__("workflow_run_id", "987654321"), "distinct"),
        (lambda producer: producer.__setitem__("workflow_event", "workflow_dispatch"), "workflow_event"),
        (lambda producer: producer.__setitem__("runner_class", "self-hosted"), "runner_class"),
    ],
)
def test_producer_identity_rejects_unsafe_or_unbound_values(
    tmp_path: Path, mutator, message: str
) -> None:
    repo, verdict, handoff, source, context, producer, _target = _receipt_inputs(tmp_path)
    mutator(producer)
    with pytest.raises(release_source_producer_receipt.ReleaseSourceProducerReceiptError, match=message):
        release_source_producer_receipt.create_release_source_producer_receipt(
            str(verdict),
            str(handoff),
            str(tmp_path / "receipt.json"),
            source=source,
            context=context,
            bootstrap_guard_sha256="a" * 64,
            producer=producer,
            git_repository=str(repo),
        )


def test_receipt_rejects_noncanonical_bytes_and_external_mismatch(tmp_path: Path) -> None:
    repo, verdict, handoff, source, context, producer, _target = _receipt_inputs(tmp_path)
    receipt = tmp_path / "receipt.json"
    release_source_producer_receipt.create_release_source_producer_receipt(
        str(verdict),
        str(handoff),
        str(receipt),
        source=source,
        context=context,
        bootstrap_guard_sha256="a" * 64,
        producer=producer,
        git_repository=str(repo),
    )
    receipt.write_bytes(receipt.read_bytes() + b"\n")
    with pytest.raises(release_source_producer_receipt.ReleaseSourceProducerReceiptError, match="canonical"):
        release_source_producer_receipt.inspect_release_source_producer_receipt(str(receipt))

    release_source_producer_receipt.create_release_source_producer_receipt(
        str(verdict),
        str(handoff),
        str(receipt),
        source=source,
        context=context,
        bootstrap_guard_sha256="a" * 64,
        producer=producer,
        git_repository=str(repo),
        force=True,
    )
    bad_producer = copy.deepcopy(producer)
    bad_producer["workflow_id"] = "99999"
    with pytest.raises(release_source_producer_receipt.ReleaseSourceProducerReceiptError, match="exactly match"):
        release_source_producer_receipt.verify_release_source_producer_receipt(
            str(receipt),
            str(handoff),
            str(verdict),
            expected_source=source,
            expected_context=context,
            expected_producer=bad_producer,
            expected_bootstrap_guard_sha256="a" * 64,
            git_repository=str(repo),
        )


def test_fresh_provider_verification_is_after_local_and_raw_git_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, verdict, handoff, source, context, producer, target = _receipt_inputs(tmp_path)
    receipt = tmp_path / "receipt.json"
    release_source_producer_receipt.create_release_source_producer_receipt(
        str(verdict),
        str(handoff),
        str(receipt),
        source=source,
        context=context,
        bootstrap_guard_sha256="a" * 64,
        producer=producer,
        git_repository=str(repo),
    )
    calls: list[dict[str, object]] = []

    def fake_create(
        artifact_path: str,
        receipt_path: str,
        raw_output_path: str,
        **kwargs: Any,
    ) -> github_attestation.CreatedGitHubAttestationReceipt:
        calls.append({"artifact": artifact_path, **kwargs})
        policy = github_attestation.github_attestation_policy(
            kwargs["repository"],
            kwargs["signer_workflow"],
            kwargs["source_digest"],
            signer_digest=kwargs["signer_digest"],
            source_ref=kwargs["source_ref"],
            cert_oidc_issuer=kwargs["cert_oidc_issuer"],
        )
        return github_attestation.CreatedGitHubAttestationReceipt(
            receipt_path=receipt_path,
            raw_output_path=raw_output_path,
            artifact=github_attestation.GitHubAttestationArtifact(
                sha256="c" * 64, size=receipt.stat().st_size
            ),
            policy=policy,
            verified_attestation_count=1,
        )

    monkeypatch.setattr(
        release_source_producer_receipt, "create_github_attestation_receipt", fake_create
    )
    policy = {
        "repository": "owner/project",
        "signer_workflow": "owner/project/.github/workflows/evoguard-produce-release-source-receipt.yml",
        "signer_digest": target,
        "source_ref": "refs/heads/main",
        "source_digest": target,
        "cert_oidc_issuer": github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
    }
    provider_isolation = github_attestation.GitHubAttestationProviderIsolation(
        executable_path=str((tmp_path / "trusted-gh").resolve()),
        executable_sha256="d" * 64,
        uid=2001,
        gid=2002,
    )
    attested = release_source_producer_receipt.reverify_attested_release_source_producer_receipt(
        str(receipt),
        str(handoff),
        str(verdict),
        expected_source=source,
        expected_context=context,
        expected_producer=producer,
        expected_bootstrap_guard_sha256="a" * 64,
        expected_github_policy=policy,
        git_repository=str(repo),
        github_receipt_path=str(tmp_path / "github-receipt.json"),
        github_raw_output_path=str(tmp_path / "github-raw.json"),
        gh_executable=provider_isolation.executable_path,
        provider_isolation=provider_isolation,
    )
    assert attested.github_receipt.verified_attestation_count == 1
    assert calls == [
        {
            "artifact": str(receipt),
            **policy,
            "gh_executable": provider_isolation.executable_path,
            "timeout_seconds": 120,
            "expected_workflow_run_id": producer["workflow_run_id"],
            "expected_workflow_run_attempt": producer["workflow_run_attempt"],
            "provider_isolation": provider_isolation,
        }
    ]


def test_cli_nonadmitting_verification_fails_closed_without_explicit_archive_opt_in(
    tmp_path: Path,
) -> None:
    repo, verdict, handoff, source, context, producer, _target = _receipt_inputs(tmp_path)
    receipt = tmp_path / "receipt.json"
    release_source_producer_receipt.create_release_source_producer_receipt(
        str(verdict),
        str(handoff),
        str(receipt),
        source=source,
        context=context,
        bootstrap_guard_sha256="a" * 64,
        producer=producer,
        git_repository=str(repo),
    )
    source_path = tmp_path / "source.json"
    context_path = tmp_path / "context.json"
    producer_path = tmp_path / "producer.json"
    _write_json(source_path, source)
    _write_json(context_path, context)
    _write_json(producer_path, producer)
    command = [
        "verify-release-source-producer-receipt",
        str(receipt),
        str(handoff),
        str(verdict),
        "--source",
        str(source_path),
        "--context",
        str(context_path),
        "--producer",
        str(producer_path),
        "--bootstrap-guard-sha",
        "a" * 64,
        "--git-repository",
        str(repo),
    ]
    assert cli_main(command) == 1
    assert cli_main([*command, "--allow-nonadmitting-evidence"]) == 0
