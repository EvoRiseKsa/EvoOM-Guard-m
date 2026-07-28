from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest

from evoom_guard.policy import effective_policy_sha256
from evoom_guard.signing import generate_keypair, public_key_id, sign_bytes
from tools.evaluation.blind_protocol import (
    ProtocolError,
    _read_regular_bytes,
    commit_labels,
    freeze_predictions,
    main,
    score_reveal,
)

BASELINE_RECORDS = Path(__file__).parent / "baseline" / "v4.0.1" / "evidence"
PASS_CANDIDATE_SHA256 = (
    "e12f32b54c5d0d671849574807d2157e5b6c2b47e596cf69eb52096f90d59409"
)
FAIL_CANDIDATE_SHA256 = (
    "76b2b97b6d21e9a6ca6ac44635a8a4dc38945c2eaad1d7be332cf880a470bc72"
)


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def _fixture(tmp_path: Path) -> dict[str, Path]:
    case_root = tmp_path / "case-bundles"
    case_root.mkdir()
    bundles: dict[str, bytes] = {
        "attack-detected": b"real project archive A",
        "attack-missed": b"real project archive B",
        "legitimate-accepted": b"real project archive C",
        "legitimate-blocked": b"real project archive D",
        "attack-abstained": b"real project archive E",
    }
    candidate_sha_by_case = {
        "attack-detected": FAIL_CANDIDATE_SHA256,
        "attack-missed": PASS_CANDIDATE_SHA256,
        "legitimate-accepted": PASS_CANDIDATE_SHA256,
        "legitimate-blocked": FAIL_CANDIDATE_SHA256,
        "attack-abstained": hashlib.sha256(
            b"candidate that timed out before a verdict"
        ).hexdigest(),
    }
    cases: list[dict[str, object]] = []
    for index, (case_id, payload) in enumerate(bundles.items()):
        bundle_file = f"{case_id}.tar.zst"
        (case_root / bundle_file).write_bytes(payload)
        cases.append(
            {
                "id": case_id,
                "ecosystem": ("python", "node", "java", "go", "rust")[index],
                "source_repository": f"https://example.invalid/{case_id}",
                "base_commit": f"{index + 1:040x}",
                "head_commit": f"{index + 101:040x}",
                "candidate_sha256": candidate_sha_by_case[case_id],
                "bundle_file": bundle_file,
                "bundle_sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    case_manifest = tmp_path / "cases.json"
    _write_json(
        case_manifest,
        {
            "schema_version": "evoguard-blind-case-manifest-v1",
            "evaluation_id": "external-round-1",
            "cases": cases,
        },
    )
    labels = tmp_path / "labels.jsonl"
    _write_jsonl(
        labels,
        [
            {"id": "attack-detected", "truth": "block"},
            {"id": "attack-missed", "truth": "block"},
            {"id": "legitimate-accepted", "truth": "accept"},
            {"id": "legitimate-blocked", "truth": "accept"},
            {"id": "attack-abstained", "truth": "block"},
        ],
    )
    salt = tmp_path / "labels.salt"
    salt.write_bytes(bytes(range(32)))
    label_private_key = tmp_path / "label-authority.pem"
    label_public_key = tmp_path / "label-authority.pub"
    verdict_private_key = tmp_path / "verdict-finalizer.pem"
    verdict_public_key = tmp_path / "verdict-finalizer.pub"
    execution_private_key = tmp_path / "execution-freezer.pem"
    execution_public_key = tmp_path / "execution-freezer.pub"
    generate_keypair(str(label_private_key), str(label_public_key))
    generate_keypair(str(verdict_private_key), str(verdict_public_key))
    generate_keypair(str(execution_private_key), str(execution_public_key))

    pass_record = json.loads(
        (BASELINE_RECORDS / "record-pass-repo.json").read_text(encoding="utf-8")
    )
    fail_record = json.loads(
        (BASELINE_RECORDS / "record-fail-repo.json").read_text(encoding="utf-8")
    )
    effective_policy = pass_record["attestation"]["effective_policy"]
    effective_policy["operating_profile"] = "local"
    policy_digest = effective_policy_sha256(effective_policy)
    for record in (pass_record, fail_record):
        record["schema_version"] = "1.12"
        record["attestation"]["effective_policy"] = effective_policy
        record["attestation"]["policy_sha256"] = policy_digest

    verdict_dir = tmp_path / "verdicts"
    verdict_dir.mkdir()
    verdicts: dict[str, dict[str, object]] = {
        "attack-detected": fail_record,
        "attack-missed": pass_record,
        "legitimate-accepted": pass_record,
        "legitimate-blocked": fail_record,
    }
    baseline_exit_codes = {
        "attack-detected": 1,
        "attack-missed": 1,
        "legitimate-accepted": 0,
        "legitimate-blocked": 0,
        "attack-abstained": None,
    }
    predictions: list[dict[str, object]] = []
    case_by_id = {str(case["id"]): case for case in cases}
    for case_id, record_template in verdicts.items():
        record = json.loads(json.dumps(record_template))
        case = case_by_id[case_id]
        record["attestation"]["base_sha"] = case["base_commit"]
        record["attestation"]["head_sha"] = case["head_commit"]
        verdict_path = verdict_dir / f"{case_id}.json"
        _write_json(verdict_path, record)
        signature_path = verdict_path.with_suffix(".json.sig")
        signature_path.write_bytes(
            base64.b64encode(
                sign_bytes(verdict_path.read_bytes(), str(verdict_private_key))
            )
            + b"\n"
        )
        baseline_path = tmp_path / f"{case_id}-baseline.json"
        _write_json(
            baseline_path,
            {
                "schema_version": "evoguard-ordinary-ci-result-v2",
                "case_id": case_id,
                "case_bundle_sha256": case["bundle_sha256"],
                "command_sha256": hashlib.sha256(b"pytest -q").hexdigest(),
                "environment_sha256": hashlib.sha256(b"sanitized-env-v1").hexdigest(),
                "toolchain_sha256": hashlib.sha256(b"python-3.12").hexdigest(),
                "timeout_seconds": 300,
                "execution_binding_status": "declaration_not_runtime_attestation",
                "exit_code": baseline_exit_codes[case_id],
                "execution_error_code": None,
            },
        )
        predictions.append(
            {
                "id": case_id,
                "verdict_file": str(verdict_path),
                "verdict_signature_file": str(signature_path),
                "execution_error_code": None,
                "baseline_result_file": str(baseline_path),
            }
        )
    abstained_baseline = tmp_path / "attack-abstained-baseline.json"
    _write_json(
        abstained_baseline,
        {
            "schema_version": "evoguard-ordinary-ci-result-v2",
            "case_id": "attack-abstained",
            "case_bundle_sha256": case_by_id["attack-abstained"]["bundle_sha256"],
            "command_sha256": hashlib.sha256(b"pytest -q").hexdigest(),
            "environment_sha256": hashlib.sha256(b"sanitized-env-v1").hexdigest(),
            "toolchain_sha256": hashlib.sha256(b"python-3.12").hexdigest(),
            "timeout_seconds": 300,
            "execution_binding_status": "declaration_not_runtime_attestation",
            "exit_code": None,
            "execution_error_code": "runner_timeout",
        },
    )
    predictions.append(
        {
            "id": "attack-abstained",
            "verdict_file": None,
            "verdict_signature_file": None,
            "execution_error_code": "runner_timeout",
            "baseline_result_file": str(abstained_baseline),
        }
    )
    prediction_path = tmp_path / "predictions.jsonl"
    _write_jsonl(prediction_path, predictions)
    guard_artifact = tmp_path / "evo-guard.pyz"
    guard_artifact.write_bytes(b"exact guard artifact")
    policy = tmp_path / "policy.json"
    _write_json(policy, effective_policy)
    return {
        "cases": case_manifest,
        "labels": labels,
        "salt": salt,
        "label_private_key": label_private_key,
        "label_public_key": label_public_key,
        "case_root": case_root,
        "predictions": prediction_path,
        "guard_artifact": guard_artifact,
        "policy": policy,
        "verdict_private_key": verdict_private_key,
        "verdict_public_key": verdict_public_key,
        "execution_private_key": execution_private_key,
        "execution_public_key": execution_public_key,
    }


def _signed_commitment(
    tmp_path: Path,
    paths: dict[str, Path],
    *,
    cases: Path | None = None,
    stem: str = "commitment",
) -> tuple[Path, Path]:
    commitment = tmp_path / f"{stem}.json"
    signature = tmp_path / f"{stem}.json.sig"
    commit_labels(
        cases or paths["cases"],
        paths["labels"],
        paths["salt"],
        commitment,
        label_authority="Independent Lab",
        conflict_disclosure="No conflict declared.",
        label_private_key_path=paths["label_private_key"],
        signature_output_path=signature,
    )
    return commitment, signature


def _run_protocol(tmp_path: Path) -> tuple[dict[str, object], dict[str, Path]]:
    paths = _fixture(tmp_path)
    commitment = tmp_path / "commitment.json"
    commitment_signature = tmp_path / "commitment.json.sig"
    frozen = tmp_path / "frozen.json"
    frozen_signature = tmp_path / "frozen.json.sig"
    report = tmp_path / "report.json"
    commit_labels(
        paths["cases"],
        paths["labels"],
        paths["salt"],
        commitment,
        label_authority="Independent Lab",
        conflict_disclosure="No funding or authorship relationship declared.",
        label_private_key_path=paths["label_private_key"],
        signature_output_path=commitment_signature,
    )
    freeze_predictions(
        paths["cases"],
        commitment,
        commitment_signature,
        paths["predictions"],
        paths["case_root"],
        paths["guard_artifact"],
        paths["policy"],
        frozen,
        profile="local",
        baseline_id="ordinary-ci-exit-v1",
        execution_authority="Execution Lab",
        label_public_key_path=paths["label_public_key"],
        verdict_public_key_path=paths["verdict_public_key"],
        execution_private_key_path=paths["execution_private_key"],
        signature_output_path=frozen_signature,
    )
    result = score_reveal(
        paths["cases"],
        commitment,
        commitment_signature,
        frozen,
        frozen_signature,
        paths["execution_public_key"],
        paths["label_public_key"],
        paths["verdict_public_key"],
        paths["labels"],
        paths["salt"],
        report,
    )
    paths.update(
        {
            "commitment": commitment,
            "commitment_signature": commitment_signature,
            "frozen": frozen,
            "frozen_signature": frozen_signature,
            "report": report,
        }
    )
    return result, paths


def test_blind_protocol_commits_freezes_and_scores_without_private_field_leakage(
    tmp_path: Path,
) -> None:
    report, paths = _run_protocol(tmp_path)

    guard = report["guard_metrics"]
    assert isinstance(guard, dict)
    assert guard["tp"] == 1
    assert guard["fn"] == 1
    assert guard["tn"] == 1
    assert guard["fp"] == 1
    assert guard["abstain_block"] == 1
    assert guard["coverage"] == 0.8
    baseline = report["baseline_metrics"]
    assert isinstance(baseline, dict)
    assert baseline["tp"] == 2
    assert baseline["fp"] == 0
    assert baseline["abstain_block"] == 1
    assert report["independence_status"] == "externally_declared_not_verified_by_tool"
    assert (
        report["key_separation_status"]
        == "distinct_keys_verified_organizational_separation_unverified"
    )
    assert (
        report["execution_binding_status"]
        == "signed_execution_authority_declaration_not_runtime_attestation"
    )
    frozen = json.loads(paths["frozen"].read_text(encoding="utf-8"))
    assert frozen["label_commitment"]["sha256"] == hashlib.sha256(
        paths["commitment"].read_bytes()
    ).hexdigest()
    assert (
        frozen["label_commitment"]["size"]
        == paths["commitment"].stat().st_size
    )

    frozen_text = paths["frozen"].read_text(encoding="utf-8")
    report_text = paths["report"].read_text(encoding="utf-8")
    for forbidden in (
        "SECRET-DIAGNOSTIC-MUST-NOT-LEAK",
        "C:/private/customer/repository",
        str(tmp_path),
    ):
        assert forbidden not in frozen_text
        assert forbidden not in report_text


def test_revealed_label_mutation_fails_commitment_check(tmp_path: Path) -> None:
    _, paths = _run_protocol(tmp_path)
    rows = [
        json.loads(line)
        for line in paths["labels"].read_text(encoding="utf-8").splitlines()
    ]
    rows[0]["truth"] = "accept"
    mutated = tmp_path / "mutated-labels.jsonl"
    _write_jsonl(mutated, rows)

    with pytest.raises(ProtocolError, match="do not match the pre-run commitment"):
        score_reveal(
            paths["cases"],
            paths["commitment"],
            paths["commitment_signature"],
            paths["frozen"],
            paths["frozen_signature"],
            paths["execution_public_key"],
            paths["label_public_key"],
            paths["verdict_public_key"],
            mutated,
            paths["salt"],
            tmp_path / "mutated-report.json",
        )


def test_freeze_rejects_case_bundle_digest_mismatch(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    commitment, commitment_sig = _signed_commitment(tmp_path, paths)
    (paths["case_root"] / "attack-detected.tar.zst").write_bytes(b"tampered")

    with pytest.raises(ProtocolError, match="bundle digest mismatch"):
        freeze_predictions(
            paths["cases"],
            commitment,
            commitment_sig,
            paths["predictions"],
            paths["case_root"],
            paths["guard_artifact"],
            paths["policy"],
            tmp_path / "frozen.json",
            profile="local",
            baseline_id="ordinary-ci-exit-v1",
            execution_authority="Execution Lab",
            label_public_key_path=paths["label_public_key"],
            verdict_public_key_path=paths["verdict_public_key"],
            execution_private_key_path=paths["execution_private_key"],
            signature_output_path=tmp_path / "frozen.json.sig",
        )


def test_commit_rejects_short_salt_duplicate_labels_and_overwrite(
    tmp_path: Path,
) -> None:
    paths = _fixture(tmp_path)
    short_salt = tmp_path / "short.salt"
    short_salt.write_bytes(b"predictable")
    output = tmp_path / "commitment.json"
    with pytest.raises(ProtocolError, match="at least 32"):
        commit_labels(
            paths["cases"],
            paths["labels"],
            short_salt,
            output,
            label_authority="Lab",
            conflict_disclosure="None declared",
            label_private_key_path=paths["label_private_key"],
            signature_output_path=tmp_path / "short-commitment.json.sig",
        )

    duplicate = tmp_path / "duplicate-labels.jsonl"
    rows = [
        json.loads(line)
        for line in paths["labels"].read_text(encoding="utf-8").splitlines()
    ]
    _write_jsonl(duplicate, rows + [rows[0]])
    with pytest.raises(ProtocolError, match="duplicate label"):
        commit_labels(
            paths["cases"],
            duplicate,
            paths["salt"],
            output,
            label_authority="Lab",
            conflict_disclosure="None declared",
            label_private_key_path=paths["label_private_key"],
            signature_output_path=tmp_path / "duplicate-commitment.json.sig",
        )

    commit_labels(
        paths["cases"],
        paths["labels"],
        paths["salt"],
        output,
        label_authority="Lab",
        conflict_disclosure="None declared",
        label_private_key_path=paths["label_private_key"],
        signature_output_path=tmp_path / "commitment.json.sig",
    )
    with pytest.raises(ProtocolError, match="refusing to overwrite"):
        commit_labels(
            paths["cases"],
            paths["labels"],
            paths["salt"],
            output,
            label_authority="Lab",
            conflict_disclosure="None declared",
            label_private_key_path=paths["label_private_key"],
            signature_output_path=tmp_path / "other-commitment.json.sig",
        )


def test_freeze_rejects_unsafe_case_bundle_path(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    manifest = json.loads(paths["cases"].read_text(encoding="utf-8"))
    manifest["cases"][0]["bundle_file"] = "../outside.tar"
    unsafe_manifest = tmp_path / "unsafe-cases.json"
    _write_json(unsafe_manifest, manifest)
    commitment, commitment_sig = _signed_commitment(
        tmp_path,
        paths,
        cases=unsafe_manifest,
        stem="unsafe-commitment",
    )

    with pytest.raises(ProtocolError, match="unsafe"):
        freeze_predictions(
            unsafe_manifest,
            commitment,
            commitment_sig,
            paths["predictions"],
            paths["case_root"],
            paths["guard_artifact"],
            paths["policy"],
            tmp_path / "frozen.json",
            profile="local",
            baseline_id="ordinary-ci-exit-v1",
            execution_authority="Execution Lab",
            label_public_key_path=paths["label_public_key"],
            verdict_public_key_path=paths["verdict_public_key"],
            execution_private_key_path=paths["execution_private_key"],
            signature_output_path=tmp_path / "frozen.json.sig",
        )


def test_score_rejects_frozen_verdict_prediction_contradiction(tmp_path: Path) -> None:
    _, paths = _run_protocol(tmp_path)
    frozen = json.loads(paths["frozen"].read_text(encoding="utf-8"))
    frozen["predictions"][0]["prediction"] = (
        "accept"
        if frozen["predictions"][0]["prediction"] == "block"
        else "block"
    )
    tampered = tmp_path / "tampered-frozen.json"
    _write_json(tampered, frozen)
    tampered_signature = tmp_path / "tampered-frozen.json.sig"
    tampered_signature.write_bytes(
        base64.b64encode(
            sign_bytes(
                tampered.read_bytes(),
                str(paths["execution_private_key"]),
            )
        )
        + b"\n"
    )

    with pytest.raises(ProtocolError, match="verdict and prediction contradict"):
        score_reveal(
            paths["cases"],
            paths["commitment"],
            paths["commitment_signature"],
            tampered,
            tampered_signature,
            paths["execution_public_key"],
            paths["label_public_key"],
            paths["verdict_public_key"],
            paths["labels"],
            paths["salt"],
            tmp_path / "tampered-report.json",
        )


def test_freeze_rejects_free_form_execution_error_that_could_leak(
    tmp_path: Path,
) -> None:
    paths = _fixture(tmp_path)
    commitment, commitment_sig = _signed_commitment(tmp_path, paths)
    rows = [
        json.loads(line)
        for line in paths["predictions"].read_text(encoding="utf-8").splitlines()
    ]
    rows[-1]["execution_error_code"] = "C:/private/customer/SECRET"
    unsafe = tmp_path / "unsafe-predictions.jsonl"
    _write_jsonl(unsafe, rows)

    with pytest.raises(ProtocolError, match="execution_error_code must be one of"):
        freeze_predictions(
            paths["cases"],
            commitment,
            commitment_sig,
            unsafe,
            paths["case_root"],
            paths["guard_artifact"],
            paths["policy"],
            tmp_path / "frozen.json",
            profile="local",
            baseline_id="ordinary-ci-exit-v1",
            execution_authority="Execution Lab",
            label_public_key_path=paths["label_public_key"],
            verdict_public_key_path=paths["verdict_public_key"],
            execution_private_key_path=paths["execution_private_key"],
            signature_output_path=tmp_path / "frozen.json.sig",
        )


def test_freeze_rejects_signed_but_semantically_incomplete_verdict(
    tmp_path: Path,
) -> None:
    paths = _fixture(tmp_path)
    commitment, commitment_sig = _signed_commitment(tmp_path, paths)
    rows = [
        json.loads(line)
        for line in paths["predictions"].read_text(encoding="utf-8").splitlines()
    ]
    verdict_path = Path(str(rows[0]["verdict_file"]))
    signature_path = Path(str(rows[0]["verdict_signature_file"]))
    _write_json(verdict_path, {"verdict": "PASS", "reason_code": "tests_passed"})
    signature_path.write_bytes(
        base64.b64encode(
            sign_bytes(verdict_path.read_bytes(), str(paths["verdict_private_key"]))
        )
        + b"\n"
    )

    with pytest.raises(ProtocolError, match="fails verify-record semantics"):
        freeze_predictions(
            paths["cases"],
            commitment,
            commitment_sig,
            paths["predictions"],
            paths["case_root"],
            paths["guard_artifact"],
            paths["policy"],
            tmp_path / "frozen.json",
            profile="local",
            baseline_id="ordinary-ci-exit-v1",
            execution_authority="Execution Lab",
            label_public_key_path=paths["label_public_key"],
            verdict_public_key_path=paths["verdict_public_key"],
            execution_private_key_path=paths["execution_private_key"],
            signature_output_path=tmp_path / "frozen.json.sig",
        )


def test_freeze_rejects_invalid_verdict_signature(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    commitment, commitment_sig = _signed_commitment(tmp_path, paths)
    rows = [
        json.loads(line)
        for line in paths["predictions"].read_text(encoding="utf-8").splitlines()
    ]
    signature_path = Path(str(rows[0]["verdict_signature_file"]))
    signature_path.write_bytes(base64.b64encode(b"\0" * 64) + b"\n")

    with pytest.raises(ProtocolError, match="verdict signature is invalid"):
        freeze_predictions(
            paths["cases"],
            commitment,
            commitment_sig,
            paths["predictions"],
            paths["case_root"],
            paths["guard_artifact"],
            paths["policy"],
            tmp_path / "frozen.json",
            profile="local",
            baseline_id="ordinary-ci-exit-v1",
            execution_authority="Execution Lab",
            label_public_key_path=paths["label_public_key"],
            verdict_public_key_path=paths["verdict_public_key"],
            execution_private_key_path=paths["execution_private_key"],
            signature_output_path=tmp_path / "frozen.json.sig",
        )


def test_freeze_binds_verdict_attestation_to_the_exact_case(
    tmp_path: Path,
) -> None:
    paths = _fixture(tmp_path)
    manifest = json.loads(paths["cases"].read_text(encoding="utf-8"))
    manifest["cases"][0]["candidate_sha256"] = "f" * 64
    mismatched = tmp_path / "mismatched-case.json"
    _write_json(mismatched, manifest)
    commitment, commitment_sig = _signed_commitment(
        tmp_path,
        paths,
        cases=mismatched,
        stem="mismatched-commitment",
    )

    with pytest.raises(ProtocolError, match="candidate_sha256 differs"):
        freeze_predictions(
            mismatched,
            commitment,
            commitment_sig,
            paths["predictions"],
            paths["case_root"],
            paths["guard_artifact"],
            paths["policy"],
            tmp_path / "frozen.json",
            profile="local",
            baseline_id="ordinary-ci-exit-v1",
            execution_authority="Execution Lab",
            label_public_key_path=paths["label_public_key"],
            verdict_public_key_path=paths["verdict_public_key"],
            execution_private_key_path=paths["execution_private_key"],
            signature_output_path=tmp_path / "frozen.json.sig",
        )


def test_freeze_derives_baseline_prediction_from_bounded_evidence(
    tmp_path: Path,
) -> None:
    paths = _fixture(tmp_path)
    commitment, commitment_sig = _signed_commitment(tmp_path, paths)
    rows = [
        json.loads(line)
        for line in paths["predictions"].read_text(encoding="utf-8").splitlines()
    ]
    rows[0]["baseline_prediction"] = "accept"
    invalid_predictions = tmp_path / "manual-baseline-prediction.jsonl"
    _write_jsonl(invalid_predictions, rows)

    with pytest.raises(ProtocolError, match="predictions row 1 keys differ"):
        freeze_predictions(
            paths["cases"],
            commitment,
            commitment_sig,
            invalid_predictions,
            paths["case_root"],
            paths["guard_artifact"],
            paths["policy"],
            tmp_path / "frozen.json",
            profile="local",
            baseline_id="ordinary-ci-exit-v1",
            execution_authority="Execution Lab",
            label_public_key_path=paths["label_public_key"],
            verdict_public_key_path=paths["verdict_public_key"],
            execution_private_key_path=paths["execution_private_key"],
            signature_output_path=tmp_path / "frozen.json.sig",
        )


def test_score_rejects_frozen_file_not_signed_by_execution_authority(
    tmp_path: Path,
) -> None:
    _, paths = _run_protocol(tmp_path)
    paths["frozen_signature"].write_bytes(base64.b64encode(b"\0" * 64) + b"\n")

    with pytest.raises(ProtocolError, match="frozen predictions signature is invalid"):
        score_reveal(
            paths["cases"],
            paths["commitment"],
            paths["commitment_signature"],
            paths["frozen"],
            paths["frozen_signature"],
            paths["execution_public_key"],
            paths["label_public_key"],
            paths["verdict_public_key"],
            paths["labels"],
            paths["salt"],
            tmp_path / "unsigned-report.json",
        )


def test_score_rejects_invented_verdict_key_id_in_execution_signed_freeze(
    tmp_path: Path,
) -> None:
    _, paths = _run_protocol(tmp_path)
    frozen = json.loads(paths["frozen"].read_text(encoding="utf-8"))
    frozen["verdict_signing_key_id"] = "sha256:" + ("a" * 64)
    tampered = tmp_path / "invented-verdict-key-frozen.json"
    _write_json(tampered, frozen)
    tampered_signature = tmp_path / "invented-verdict-key-frozen.json.sig"
    tampered_signature.write_bytes(
        base64.b64encode(
            sign_bytes(
                tampered.read_bytes(),
                str(paths["execution_private_key"]),
            )
        )
        + b"\n"
    )

    with pytest.raises(
        ProtocolError,
        match="verdict signing key differs from the externally trusted key",
    ):
        score_reveal(
            paths["cases"],
            paths["commitment"],
            paths["commitment_signature"],
            tampered,
            tampered_signature,
            paths["execution_public_key"],
            paths["label_public_key"],
            paths["verdict_public_key"],
            paths["labels"],
            paths["salt"],
            tmp_path / "invented-verdict-key-report.json",
        )


@pytest.mark.parametrize(
    "colliding_public_key",
    ["label_public_key", "execution_public_key"],
)  # type: ignore[untyped-decorator]
def test_score_rejects_trusted_verdict_key_collision(
    tmp_path: Path,
    colliding_public_key: str,
) -> None:
    _, paths = _run_protocol(tmp_path)
    frozen = json.loads(paths["frozen"].read_text(encoding="utf-8"))
    frozen["verdict_signing_key_id"] = public_key_id(
        str(paths[colliding_public_key])
    )
    tampered = tmp_path / f"{colliding_public_key}-collision-frozen.json"
    _write_json(tampered, frozen)
    tampered_signature = tampered.with_suffix(".json.sig")
    tampered_signature.write_bytes(
        base64.b64encode(
            sign_bytes(
                tampered.read_bytes(),
                str(paths["execution_private_key"]),
            )
        )
        + b"\n"
    )

    with pytest.raises(ProtocolError, match="are not distinct"):
        score_reveal(
            paths["cases"],
            paths["commitment"],
            paths["commitment_signature"],
            tampered,
            tampered_signature,
            paths["execution_public_key"],
            paths["label_public_key"],
            paths[colliding_public_key],
            paths["labels"],
            paths["salt"],
            tmp_path / f"{colliding_public_key}-collision-report.json",
        )


def test_score_rejects_a_different_fully_signed_commitment_created_after_freeze(
    tmp_path: Path,
) -> None:
    _, paths = _run_protocol(tmp_path)
    alternate_labels = tmp_path / "alternate-labels.jsonl"
    rows = [
        json.loads(line)
        for line in paths["labels"].read_text(encoding="utf-8").splitlines()
    ]
    rows[0]["truth"] = "accept"
    _write_jsonl(alternate_labels, rows)
    alternate_salt = tmp_path / "alternate.salt"
    alternate_salt.write_bytes(b"a" * 32)
    alternate_commitment = tmp_path / "alternate-commitment.json"
    alternate_signature = tmp_path / "alternate-commitment.json.sig"
    commit_labels(
        paths["cases"],
        alternate_labels,
        alternate_salt,
        alternate_commitment,
        label_authority="Independent Lab",
        conflict_disclosure="No conflict declared.",
        label_private_key_path=paths["label_private_key"],
        signature_output_path=alternate_signature,
    )

    with pytest.raises(ProtocolError, match="descriptor does not match"):
        score_reveal(
            paths["cases"],
            alternate_commitment,
            alternate_signature,
            paths["frozen"],
            paths["frozen_signature"],
            paths["execution_public_key"],
            paths["label_public_key"],
            paths["verdict_public_key"],
            alternate_labels,
            alternate_salt,
            tmp_path / "alternate-report.json",
        )


def test_freeze_rejects_invalid_label_authority_signature(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    commitment, commitment_sig = _signed_commitment(tmp_path, paths)
    commitment_sig.write_bytes(base64.b64encode(b"\0" * 64) + b"\n")

    with pytest.raises(ProtocolError, match="commitment signature is invalid"):
        freeze_predictions(
            paths["cases"],
            commitment,
            commitment_sig,
            paths["predictions"],
            paths["case_root"],
            paths["guard_artifact"],
            paths["policy"],
            tmp_path / "frozen.json",
            profile="local",
            baseline_id="ordinary-ci-exit-v1",
            execution_authority="Execution Lab",
            label_public_key_path=paths["label_public_key"],
            verdict_public_key_path=paths["verdict_public_key"],
            execution_private_key_path=paths["execution_private_key"],
            signature_output_path=tmp_path / "frozen.json.sig",
        )


def test_score_rechecks_label_authority_signature(tmp_path: Path) -> None:
    _, paths = _run_protocol(tmp_path)
    paths["commitment_signature"].write_bytes(
        base64.b64encode(b"\0" * 64) + b"\n"
    )

    with pytest.raises(ProtocolError, match="commitment signature is invalid"):
        score_reveal(
            paths["cases"],
            paths["commitment"],
            paths["commitment_signature"],
            paths["frozen"],
            paths["frozen_signature"],
            paths["execution_public_key"],
            paths["label_public_key"],
            paths["verdict_public_key"],
            paths["labels"],
            paths["salt"],
            tmp_path / "invalid-label-signature-report.json",
        )


@pytest.mark.parametrize(
    ("label_key", "label_public", "execution_key"),
    [
        ("verdict_private_key", "verdict_public_key", "execution_private_key"),
        ("execution_private_key", "execution_public_key", "execution_private_key"),
        ("label_private_key", "label_public_key", "verdict_private_key"),
    ],
)  # type: ignore[untyped-decorator]
def test_freeze_requires_three_distinct_signing_keys(
    tmp_path: Path,
    label_key: str,
    label_public: str,
    execution_key: str,
) -> None:
    paths = _fixture(tmp_path)
    commitment = tmp_path / "collision-commitment.json"
    commitment_sig = tmp_path / "collision-commitment.json.sig"
    commit_labels(
        paths["cases"],
        paths["labels"],
        paths["salt"],
        commitment,
        label_authority="Independent Lab",
        conflict_disclosure="No conflict declared.",
        label_private_key_path=paths[label_key],
        signature_output_path=commitment_sig,
    )

    with pytest.raises(ProtocolError, match="must be distinct"):
        freeze_predictions(
            paths["cases"],
            commitment,
            commitment_sig,
            paths["predictions"],
            paths["case_root"],
            paths["guard_artifact"],
            paths["policy"],
            tmp_path / "collision-frozen.json",
            profile="local",
            baseline_id="ordinary-ci-exit-v1",
            execution_authority="Execution Lab",
            label_public_key_path=paths[label_public],
            verdict_public_key_path=paths["verdict_public_key"],
            execution_private_key_path=paths[execution_key],
            signature_output_path=tmp_path / "collision-frozen.json.sig",
        )


def test_commitment_pair_reserves_payload_when_signature_path_exists(
    tmp_path: Path,
) -> None:
    paths = _fixture(tmp_path)
    commitment = tmp_path / "reserved-commitment.json"
    signature = tmp_path / "reserved-commitment.json.sig"
    signature.write_bytes(b"existing")

    with pytest.raises(ProtocolError, match="refusing to overwrite"):
        commit_labels(
            paths["cases"],
            paths["labels"],
            paths["salt"],
            commitment,
            label_authority="Independent Lab",
            conflict_disclosure="No conflict declared.",
            label_private_key_path=paths["label_private_key"],
            signature_output_path=signature,
        )

    assert commitment.read_bytes() == b""
    assert signature.read_bytes() == b"existing"


def test_commitment_pair_retains_reservations_after_partial_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _fixture(tmp_path)
    commitment = tmp_path / "partial-commitment.json"
    signature = tmp_path / "partial-commitment.json.sig"
    original_write = os.write
    calls = 0

    def failing_write(descriptor: int, payload: bytes | memoryview) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            prefix = bytes(payload[: max(1, len(payload) // 2)])
            return original_write(descriptor, prefix)
        raise OSError("injected write failure")

    monkeypatch.setattr("tools.evaluation.blind_protocol.os.write", failing_write)
    with pytest.raises(OSError, match="injected write failure"):
        commit_labels(
            paths["cases"],
            paths["labels"],
            paths["salt"],
            commitment,
            label_authority="Independent Lab",
            conflict_disclosure="No conflict declared.",
            label_private_key_path=paths["label_private_key"],
            signature_output_path=signature,
        )

    assert commitment.stat().st_size > 0
    assert signature.read_bytes() == b""


def test_freeze_pair_reserves_payload_when_signature_path_exists(
    tmp_path: Path,
) -> None:
    paths = _fixture(tmp_path)
    commitment, commitment_sig = _signed_commitment(tmp_path, paths)
    frozen = tmp_path / "reserved-frozen.json"
    signature = tmp_path / "reserved-frozen.json.sig"
    signature.write_bytes(b"existing")

    with pytest.raises(ProtocolError, match="refusing to overwrite"):
        freeze_predictions(
            paths["cases"],
            commitment,
            commitment_sig,
            paths["predictions"],
            paths["case_root"],
            paths["guard_artifact"],
            paths["policy"],
            frozen,
            profile="local",
            baseline_id="ordinary-ci-exit-v1",
            execution_authority="Execution Lab",
            label_public_key_path=paths["label_public_key"],
            verdict_public_key_path=paths["verdict_public_key"],
            execution_private_key_path=paths["execution_private_key"],
            signature_output_path=signature,
        )

    assert frozen.read_bytes() == b""
    assert signature.read_bytes() == b"existing"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("case_id", "another-case", "case_id is inconsistent"),
        ("case_bundle_sha256", "0" * 64, "bundle digest is inconsistent"),
        ("timeout_seconds", 0, "timeout_seconds is invalid"),
        ("unexpected", "field", "keys differ"),
    ],
)  # type: ignore[untyped-decorator]
def test_freeze_rejects_inconsistent_or_extra_baseline_evidence(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    paths = _fixture(tmp_path)
    commitment, commitment_sig = _signed_commitment(tmp_path, paths)
    predictions = [
        json.loads(line)
        for line in paths["predictions"].read_text(encoding="utf-8").splitlines()
    ]
    baseline_path = Path(str(predictions[0]["baseline_result_file"]))
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline[field] = value
    _write_json(baseline_path, baseline)

    with pytest.raises(ProtocolError, match=message):
        freeze_predictions(
            paths["cases"],
            commitment,
            commitment_sig,
            paths["predictions"],
            paths["case_root"],
            paths["guard_artifact"],
            paths["policy"],
            tmp_path / "baseline-frozen.json",
            profile="local",
            baseline_id="ordinary-ci-exit-v1",
            execution_authority="Execution Lab",
            label_public_key_path=paths["label_public_key"],
            verdict_public_key_path=paths["verdict_public_key"],
            execution_private_key_path=paths["execution_private_key"],
            signature_output_path=tmp_path / "baseline-frozen.json.sig",
        )


def test_regular_reader_rejects_in_place_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "changing.bin"
    source.write_bytes(b"a" * (2 * 1024 * 1024))
    original_read = os.read
    mutated = False

    def mutating_read(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        chunk = original_read(descriptor, size)
        if not mutated:
            mutated = True
            source.write_bytes(b"changed")
        return chunk

    monkeypatch.setattr("tools.evaluation.blind_protocol.os.read", mutating_read)
    with pytest.raises(ProtocolError, match="changed while it was read"):
        _read_regular_bytes(source, limit=4 * 1024 * 1024, label="changing input")


def test_regular_reader_rejects_path_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "swapped.bin"
    source.write_bytes(b"original")
    original_open = os.open
    swapped = False

    def swapping_open(
        path: str | os.PathLike[str],
        flags: int,
        mode: int = 0o777,
    ) -> int:
        nonlocal swapped
        if not swapped and Path(path) == source:
            swapped = True
            source.rename(tmp_path / "old.bin")
            source.write_bytes(b"replacement")
        return original_open(path, flags, mode)

    monkeypatch.setattr("tools.evaluation.blind_protocol.os.open", swapping_open)
    with pytest.raises(ProtocolError, match="changed while it was opened"):
        _read_regular_bytes(source, limit=1024, label="swapped input")


def test_regular_reader_rejects_symbolic_link(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    link = tmp_path / "link.bin"
    source.write_bytes(b"evidence")
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("symbolic-link creation is unavailable")
    with pytest.raises(ProtocolError, match="regular non-link"):
        _read_regular_bytes(link, limit=1024, label="linked input")


def test_regular_reader_rejects_reparse_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "reparse-like.bin"
    source.write_bytes(b"evidence")
    monkeypatch.setattr(
        "tools.evaluation.blind_protocol._is_reparse_point",
        lambda _metadata: True,
    )
    with pytest.raises(ProtocolError, match="regular non-link"):
        _read_regular_bytes(source, limit=1024, label="reparse input")


def test_cli_returns_two_for_a_failed_reveal(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, paths = _run_protocol(tmp_path)
    wrong_salt = tmp_path / "wrong.salt"
    wrong_salt.write_bytes(b"x" * 32)

    code = main(
        [
            "score-reveal",
            "--cases",
            str(paths["cases"]),
            "--commitment",
            str(paths["commitment"]),
            "--commitment-sig",
            str(paths["commitment_signature"]),
            "--label-pub",
            str(paths["label_public_key"]),
            "--verdict-pub",
            str(paths["verdict_public_key"]),
            "--frozen",
            str(paths["frozen"]),
            "--frozen-sig",
            str(paths["frozen_signature"]),
            "--execution-pub",
            str(paths["execution_public_key"]),
            "--labels",
            str(paths["labels"]),
            "--salt",
            str(wrong_salt),
            "--out",
            str(tmp_path / "other-report.json"),
        ]
    )

    assert code == 2
    assert "revealed salt does not match" in capsys.readouterr().err
