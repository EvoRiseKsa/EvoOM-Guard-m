from __future__ import annotations

import io
import json
import subprocess
import threading
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from evoom_guard import github_attestation
from evoom_guard.cli import main as cli_main
from evoom_guard.guard import guard
from evoom_guard.signing import generate_keypair
from evoom_guard.trusted_finalizer import create_finalizer_handoff, seal_finalizer_bundle


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _keys(tmp_path: Path, name: str) -> tuple[Path, Path]:
    private = tmp_path / f"{name}.private.pem"
    public = tmp_path / f"{name}.public.pem"
    generate_keypair(str(private), str(public))
    return private, public


def _finalized_allow(tmp_path: Path):
    repo = tmp_path / "repo"
    tests = repo / "tests"
    tests.mkdir(parents=True)
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tests / "test_app.py").write_text(
        "from app import VALUE\n\n\ndef test_value():\n    assert VALUE == 2\n",
        encoding="utf-8",
    )
    record = guard(
        str(repo),
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        base_sha="a" * 40,
        head_sha="b" * 40,
        base_tree_sha="c" * 40,
        head_tree_sha="d" * 40,
    ).to_dict()
    attestation = record["attestation"]
    source = {
        "pull_request_number": 42,
        "workflow_run_id": "123456",
        "workflow_run_attempt": 1,
        "base_sha": attestation["base_sha"],
        "head_sha": attestation["head_sha"],
    }
    context = {
        "repository": "owner/project",
        "repository_id": "12345",
        "run_id": "123456",
        "run_attempt": 1,
        "base_sha": attestation["base_sha"],
        "head_sha": attestation["head_sha"],
        "base_tree_sha": attestation["base_tree_sha"],
        "head_tree_sha": attestation["head_tree_sha"],
        "candidate_sha256": attestation["candidate_sha256"],
        "policy_sha256": attestation["policy_sha256"],
        "verifier_pack_sha256": attestation["verifier_pack_sha256"],
        "guard_artifact_sha256": "e" * 64,
    }
    verdict = tmp_path / "verdict.json"
    _write_json(verdict, record)
    handoff = tmp_path / "handoff.json"
    create_finalizer_handoff(str(verdict), str(handoff), source=source, context=context)
    finalizer_private, finalizer_public = _keys(tmp_path, "finalizer")
    bundle = tmp_path / "finalized.evb"
    seal_finalizer_bundle(
        str(handoff),
        str(verdict),
        str(bundle),
        expected_source=source,
        expected_context=context,
        private_key_path=str(finalizer_private),
    )
    return bundle, finalizer_public, source, context


def _successful_gh(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []
    real_popen = github_attestation.subprocess.Popen

    class FakePopen:
        def __init__(self, command: list[str], **kwargs: object) -> None:
            calls.append(command)
            assert kwargs["shell"] is False
            assert kwargs["stdin"] is subprocess.DEVNULL
            assert kwargs["stdout"] is subprocess.PIPE
            assert kwargs["stderr"] is subprocess.PIPE
            self.returncode = 0
            self.stdout = io.BytesIO(
                b'[{"attestation":{"opaque":"candidate-controlled"},'
                b'"verificationResult":{"statement":{"predicate":{"untrusted":true}}}}]'
            )
            self.stderr = io.BytesIO()
            assert "--repo" in command
            assert "--signer-workflow" in command
            assert "--signer-digest" in command
            assert "--source-ref" in command
            assert "--source-digest" in command
            assert "--cert-oidc-issuer" in command
            assert command[command.index("--repo") + 1] == "owner/project"
            assert command[command.index("--signer-workflow") + 1] == (
                "owner/project/.github/workflows/build.yml"
            )
            assert command[command.index("--signer-digest") + 1] == "c" * 40
            assert command[command.index("--source-ref") + 1] == "refs/heads/main"
            assert command[command.index("--source-digest") + 1] == "b" * 40
            assert command[command.index("--cert-oidc-issuer") + 1] == (
                github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER
            )
            assert "--deny-self-hosted-runners" in command
            assert command[command.index("--limit") + 1] == "1"

        def wait(self, timeout: int | None = None) -> int:
            return self.returncode

        def kill(self) -> None:
            self.returncode = -9

    def fake_popen(command: list[str], **kwargs: object) -> object:
        if command[1:3] == ["attestation", "verify"]:
            return FakePopen(command, **kwargs)
        return real_popen(command, **kwargs)

    monkeypatch.setattr(github_attestation.subprocess, "Popen", fake_popen)
    return calls


def _receipt_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    artifact = tmp_path / "product.bin"
    artifact.write_bytes(b"immutable-product-bytes\n")
    return artifact, tmp_path / "receipt.json", tmp_path / "raw.json"


def _policy_kwargs(*, source_digest: str = "b" * 40, **overrides: str) -> dict[str, str]:
    policy = {
        "repository": "owner/project",
        "signer_workflow": "owner/project/.github/workflows/build.yml",
        "signer_digest": "c" * 40,
        "source_ref": "refs/heads/main",
        "source_digest": source_digest,
        "cert_oidc_issuer": github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
    }
    policy.update(overrides)
    return policy


def test_gh_environment_keeps_only_documented_authentication_variables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GH_TOKEN", "protected-gh-token")
    monkeypatch.setenv("GITHUB_TOKEN", "protected-github-token")
    monkeypatch.setenv("GH_CONFIG_DIR", "candidate-config")
    monkeypatch.setenv("GH_REPO", "other/repository")
    monkeypatch.setenv("GH_DEBUG", "api")
    monkeypatch.setenv("GH_PAGER", "candidate-pager")
    environment = github_attestation._gh_environment(str(tmp_path))
    assert environment["GH_TOKEN"] == "protected-gh-token"
    assert environment["GITHUB_TOKEN"] == "protected-github-token"
    assert environment["GH_CONFIG_DIR"] == str(tmp_path / "gh-config")
    assert all(name not in environment for name in ("GH_REPO", "GH_DEBUG", "GH_PAGER"))


def test_create_receipt_runs_strict_gh_policy_and_preserves_exact_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _successful_gh(monkeypatch)
    artifact, receipt_path, raw_path = _receipt_inputs(tmp_path)
    policy = _policy_kwargs()

    created = github_attestation.create_github_attestation_receipt(
        str(artifact),
        str(receipt_path),
        str(raw_path),
        **policy,
        gh_executable="trusted-gh",
    )

    assert calls[0][0] == "trusted-gh"
    assert calls[0][1:3] == ["attestation", "verify"]
    assert calls[0][calls[0].index("--predicate-type") + 1] == (
        github_attestation.GITHUB_ATTESTATION_PREDICATE_TYPE
    )
    assert created.artifact.sha256 == "af7558bfc74ab85958c7808ec808d51a1c8fc66774c97bedde7a65acbd598aa1"
    assert created.artifact.size == len(b"immutable-product-bytes\n")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["verification_policy"] == {
        "attestation_limit": 1,
        "deny_self_hosted_runners": True,
        "predicate_type": "https://slsa.dev/provenance/v1",
        "repository": "owner/project",
        "cert_oidc_issuer": github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
        "signer_digest": "c" * 40,
        "signer_workflow": "owner/project/.github/workflows/build.yml",
        "source_ref": "refs/heads/main",
        "source_digest": policy["source_digest"],
    }
    assert receipt["verification_output"]["verified_attestation_count"] == 1
    assert b"candidate-controlled" in raw_path.read_bytes()


def test_receipt_recheck_requires_artifact_output_and_policy_to_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _successful_gh(monkeypatch)
    artifact, receipt_path, raw_path = _receipt_inputs(tmp_path)
    kwargs = _policy_kwargs()
    github_attestation.create_github_attestation_receipt(
        str(artifact), str(receipt_path), str(raw_path), **kwargs
    )

    verified = github_attestation.verify_github_attestation_receipt(
        str(receipt_path), str(artifact), str(raw_path), **kwargs
    )
    assert verified.artifact.sha256 == "af7558bfc74ab85958c7808ec808d51a1c8fc66774c97bedde7a65acbd598aa1"

    artifact.write_bytes(b"changed\n")
    with pytest.raises(github_attestation.GitHubAttestationError, match="artifact"):
        github_attestation.verify_github_attestation_receipt(
            str(receipt_path), str(artifact), str(raw_path), **kwargs
        )

    artifact.write_bytes(b"immutable-product-bytes\n")
    raw_path.write_bytes(b"[]")
    with pytest.raises(github_attestation.GitHubAttestationError, match="exactly one"):
        github_attestation.verify_github_attestation_receipt(
            str(receipt_path), str(artifact), str(raw_path), **kwargs
        )


def test_receipt_recheck_rejects_a_valid_but_substituted_trust_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _successful_gh(monkeypatch)
    artifact, receipt_path, raw_path = _receipt_inputs(tmp_path)
    kwargs = _policy_kwargs()
    github_attestation.create_github_attestation_receipt(
        str(artifact), str(receipt_path), str(raw_path), **kwargs
    )

    substituted = json.loads(receipt_path.read_text(encoding="utf-8"))
    substituted["verification_policy"]["source_ref"] = "refs/heads/release"
    receipt_path.write_bytes(
        (json.dumps(substituted, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    )

    with pytest.raises(github_attestation.GitHubAttestationError, match="exactly match"):
        github_attestation.verify_github_attestation_receipt(
            str(receipt_path), str(artifact), str(raw_path), **kwargs
        )


def test_receipt_can_be_freshly_reverified_without_reusing_historic_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _successful_gh(monkeypatch)
    artifact, receipt_path, raw_path = _receipt_inputs(tmp_path)
    kwargs = _policy_kwargs()
    github_attestation.create_github_attestation_receipt(
        str(artifact), str(receipt_path), str(raw_path), **kwargs
    )

    fresh = github_attestation.reverify_github_attestation_receipt(
        str(receipt_path), str(artifact), gh_executable="trusted-gh", **kwargs
    )
    assert len(calls) == 2
    assert fresh.verified_attestation_count == 1
    assert fresh.artifact.sha256 == "af7558bfc74ab85958c7808ec808d51a1c8fc66774c97bedde7a65acbd598aa1"


def test_verifier_output_is_capped_while_the_child_is_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kills: list[bool] = []

    class OversizedPopen:
        def __init__(self, command: list[str], **kwargs: object) -> None:
            assert kwargs["stdout"] is subprocess.PIPE
            assert kwargs["stderr"] is subprocess.PIPE
            self.returncode = 0
            self.killed = False
            self.stdout = io.BytesIO(b"x" * (github_attestation.MAX_GITHUB_ATTESTATION_OUTPUT_BYTES + 1))
            self.stderr = io.BytesIO()

        def wait(self, timeout: float | None = None) -> int:
            return self.returncode

        def kill(self) -> None:
            self.killed = True
            self.returncode = -9
            kills.append(True)

    monkeypatch.setattr(github_attestation.subprocess, "Popen", OversizedPopen)
    artifact, receipt_path, raw_path = _receipt_inputs(tmp_path)
    with pytest.raises(github_attestation.GitHubAttestationError, match="bounded standard-output"):
        github_attestation.create_github_attestation_receipt(
            str(artifact), str(receipt_path), str(raw_path), **_policy_kwargs()
        )
    assert kills == [True]
    assert not receipt_path.exists()
    assert not raw_path.exists()


def test_nonzero_gh_exit_without_stderr_is_reported_not_a_name_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FailedPopen:
        def __init__(self, command: list[str], **kwargs: object) -> None:
            self.returncode = 7
            self.stdout = io.BytesIO(b"[]")
            self.stderr = io.BytesIO()

        def wait(self, timeout: float | None = None) -> int:
            return self.returncode

        def kill(self) -> None:
            self.returncode = -9

    monkeypatch.setattr(github_attestation.subprocess, "Popen", FailedPopen)
    artifact, receipt_path, raw_path = _receipt_inputs(tmp_path)
    with pytest.raises(github_attestation.GitHubAttestationError, match=r"exit 7"):
        github_attestation.create_github_attestation_receipt(
            str(artifact), str(receipt_path), str(raw_path), **_policy_kwargs()
        )


def test_verifier_fails_closed_when_a_descendant_holds_an_output_pipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class HeldPipe:
        def __init__(self) -> None:
            self.closed = threading.Event()

        def read(self, size: int) -> bytes:
            self.closed.wait()
            return b""

        def close(self) -> None:
            self.closed.set()

    class HeldPipePopen:
        def __init__(self, command: list[str], **kwargs: object) -> None:
            self.returncode = 0
            self.stdout = HeldPipe()
            self.stderr = io.BytesIO()

        def wait(self, timeout: float | None = None) -> int:
            return self.returncode

        def kill(self) -> None:
            self.returncode = -9

    monkeypatch.setattr(github_attestation.subprocess, "Popen", HeldPipePopen)
    artifact, receipt_path, raw_path = _receipt_inputs(tmp_path)
    with pytest.raises(github_attestation.GitHubAttestationError, match="left output pipes open"):
        github_attestation.create_github_attestation_receipt(
            str(artifact),
            str(receipt_path),
            str(raw_path),
            timeout_seconds=1,
            **_policy_kwargs(),
        )


def test_receipt_rejects_noncanonical_or_weakened_policy(tmp_path: Path) -> None:
    artifact, receipt_path, raw_path = _receipt_inputs(tmp_path)
    raw_path.write_bytes(b"[{}]")
    receipt_path.write_text(
        json.dumps(
            {
                "format": github_attestation.GITHUB_ATTESTATION_RECEIPT_FORMAT,
                "artifact": {
                    "sha256": "0" * 64,
                    "size": artifact.stat().st_size,
                },
                "verification_policy": {
                    "repository": "owner/project",
                    "signer_workflow": "owner/project/.github/workflows/build.yml",
                    "signer_digest": "c" * 40,
                    "source_ref": "refs/heads/main",
                    "source_digest": "b" * 40,
                    "cert_oidc_issuer": github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
                    "predicate_type": github_attestation.GITHUB_ATTESTATION_PREDICATE_TYPE,
                    "deny_self_hosted_runners": False,
                    "attestation_limit": 1,
                },
                "verification_output": {
                    "sha256": "0" * 64,
                    "size": 4,
                    "verified_attestation_count": 1,
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(github_attestation.GitHubAttestationError, match="deny_self_hosted"):
        github_attestation.verify_github_attestation_receipt(
            str(receipt_path),
            str(artifact),
            str(raw_path),
            **_policy_kwargs(),
        )


def test_sealed_admission_binds_receipt_and_requires_finalizer_head_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _successful_gh(monkeypatch)
    bundle, finalizer_public, source, context = _finalized_allow(tmp_path)
    binding_private, binding_public = _keys(tmp_path, "admission")
    artifact, receipt_path, raw_path = _receipt_inputs(tmp_path)
    kwargs = _policy_kwargs(source_digest=context["head_sha"])
    sealed = github_attestation.seal_github_attestation_admission(
        str(artifact),
        str(receipt_path),
        str(raw_path),
        str(bundle),
        str(tmp_path / "admission.eab"),
        trusted_finalizer_public_key_path=str(finalizer_public),
        expected_finalizer_source=source,
        expected_finalizer_context=context,
        private_key_path=str(binding_private),
        **kwargs,
    )
    assert sealed.admission.subject.kind == "artifact-sha256"
    assert sealed.admission.subject.digest == f"sha256:{sealed.receipt.artifact.sha256}"

    verified = github_attestation.verify_github_attestation_admission(
        sealed.admission.binding_path,
        str(artifact),
        str(receipt_path),
        str(raw_path),
        str(bundle),
        trusted_public_key_path=str(binding_public),
        trusted_finalizer_public_key_path=str(finalizer_public),
        expected_finalizer_source=source,
        expected_finalizer_context=context,
        **kwargs,
    )
    assert verified.admission.subject == sealed.admission.subject

    with pytest.raises(github_attestation.GitHubAttestationError, match="context.head_sha"):
        github_attestation.seal_github_attestation_admission(
            str(artifact),
            str(tmp_path / "second-receipt.json"),
            str(tmp_path / "second-raw.json"),
            str(bundle),
            str(tmp_path / "second.eab"),
            **_policy_kwargs(source_digest="a" * 40),
            trusted_finalizer_public_key_path=str(finalizer_public),
            expected_finalizer_source=source,
            expected_finalizer_context=context,
            private_key_path=str(binding_private),
        )


@pytest.mark.parametrize(
    ("repository", "workflow", "signer_digest", "source_ref", "source_digest", "issuer"),
    [
        (
            "owner/project/tag",
            "owner/project/.github/workflows/build.yml",
            "c" * 40,
            "refs/heads/main",
            "b" * 40,
            github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
        ),
        (
            "owner/project",
            "other/project/.github/workflows/build.yml",
            "c" * 40,
            "refs/heads/main",
            "b" * 40,
            github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
        ),
        (
            "owner/project",
            "owner/project/.github/workflows/build.yml",
            "C" * 40,
            "refs/heads/main",
            "b" * 40,
            github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
        ),
        (
            "owner/project",
            "owner/project/.github/workflows/build.yml",
            "c" * 40,
            "refs/heads/release/../main",
            "b" * 40,
            github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
        ),
        (
            "owner/project",
            "owner/project/.github/workflows/build.yml",
            "c" * 40,
            "refs/tags/v1.0.0",
            "b" * 40,
            "https://evil.example.invalid",
        ),
    ],
)
def test_policy_rejects_ambiguous_or_mutable_inputs(
    repository: str,
    workflow: str,
    signer_digest: str,
    source_ref: str,
    source_digest: str,
    issuer: str,
) -> None:
    with pytest.raises(github_attestation.GitHubAttestationError):
        github_attestation.github_attestation_policy(
            repository,
            workflow,
            source_digest,
            signer_digest=signer_digest,
            source_ref=source_ref,
            cert_oidc_issuer=issuer,
        )


def test_policy_accepts_a_same_repository_canonical_github_url() -> None:
    policy = github_attestation.github_attestation_policy(
        "owner/project",
        "https://github.com/owner/project/.github/workflows/build.yml",
        "b" * 40,
        signer_digest="c" * 40,
        source_ref="refs/tags/v1.2.3",
        cert_oidc_issuer=github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
    )
    assert policy.signer_workflow == "owner/project/.github/workflows/build.yml"
    assert github_attestation.github_attestation_provenance_identity(policy) != (
        github_attestation.github_attestation_provenance_identity(
            github_attestation.github_attestation_policy(
                "owner/project",
                "owner/project/.github/workflows/build.yml",
                "b" * 40,
                signer_digest="c" * 40,
                source_ref="refs/heads/release",
                cert_oidc_issuer=github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
            )
        )
    )


def test_receipt_schema_matches_the_strict_adapter_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _successful_gh(monkeypatch)
    artifact, receipt_path, raw_path = _receipt_inputs(tmp_path)
    github_attestation.create_github_attestation_receipt(
        str(artifact),
        str(receipt_path),
        str(raw_path),
        **_policy_kwargs(),
    )
    root = Path(__file__).resolve().parents[1]
    schema = json.loads(
        (root / "evoom_guard" / "schemas" / "github-attestation-receipt-1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(schema)
    assert schema["$id"] == "urn:evoguard:github-attestation-receipt:1"
    validator = Draft202012Validator(schema)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    validator.validate(receipt)
    for unsafe_ref in ("refs/heads/a//b", "refs/heads/a/../b", "refs/heads/a/.", "refs/heads/a/"):
        invalid = json.loads(json.dumps(receipt))
        invalid["verification_policy"]["source_ref"] = unsafe_ref
        assert list(validator.iter_errors(invalid))


def test_cli_receipt_and_rechecks_require_all_policy_pins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _successful_gh(monkeypatch)
    artifact, receipt_path, raw_path = _receipt_inputs(tmp_path)
    policy = _policy_kwargs()
    policy_flags = [
        "--repo",
        policy["repository"],
        "--signer-workflow",
        policy["signer_workflow"],
        "--signer-digest",
        policy["signer_digest"],
        "--source-ref",
        policy["source_ref"],
        "--source-digest",
        policy["source_digest"],
        "--cert-oidc-issuer",
        policy["cert_oidc_issuer"],
    ]
    url_policy_flags = list(policy_flags)
    url_policy_flags[url_policy_flags.index("--signer-workflow") + 1] = (
        "https://github.com/owner/project/.github/workflows/build.yml"
    )
    assert cli_main(
        [
            "github-attestation-receipt",
            str(artifact),
            "--receipt-out",
            str(receipt_path),
            "--raw-output-out",
            str(raw_path),
            "--gh-executable",
            "trusted-gh",
            *url_policy_flags,
        ]
    ) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "PROVIDER_VERIFIED"
    assert report["verification_scope"] == "fresh-provider-gh-attestation-verify"
    assert report["verification_policy"] == github_attestation.github_attestation_policy(
        policy["repository"],
        policy["signer_workflow"],
        policy["source_digest"],
        signer_digest=policy["signer_digest"],
        source_ref=policy["source_ref"],
        cert_oidc_issuer=policy["cert_oidc_issuer"],
    ).as_dict()

    assert cli_main(
        [
            "verify-github-attestation-receipt",
            str(receipt_path),
            str(artifact),
            str(raw_path),
            *policy_flags,
        ]
    ) == 0
    retained_report = json.loads(capsys.readouterr().out)
    assert retained_report["status"] == "RETAINED_RECEIPT_VERIFIED"
    assert retained_report["verification_scope"] == "retained-byte-continuity-only"
    assert retained_report["live_provider_reverification"] is False

    assert cli_main(
        [
            "reverify-github-attestation-receipt",
            str(receipt_path),
            str(artifact),
            "--gh-executable",
            "trusted-gh",
            *policy_flags,
        ]
    ) == 0
    reverified_report = json.loads(capsys.readouterr().out)
    assert reverified_report["status"] == "FRESH_PROVIDER_REVERIFIED"
    assert reverified_report["reverification"] == "fresh-gh-attestation-verify"

    unsafe_ref_flags = list(policy_flags)
    unsafe_ref_flags[unsafe_ref_flags.index("--source-ref") + 1] = "refs/heads/../main"
    assert cli_main(
        [
            "github-attestation-receipt",
            str(artifact),
            "--receipt-out",
            str(tmp_path / "rejected-receipt.json"),
            "--raw-output-out",
            str(tmp_path / "rejected-raw.json"),
            *unsafe_ref_flags,
        ]
    ) == 1
    rejected_report = json.loads(capsys.readouterr().out)
    assert rejected_report["status"] == "REJECTED"
    assert "source ref" in rejected_report["error"]
