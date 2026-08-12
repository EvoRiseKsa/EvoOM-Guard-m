from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import jsonschema  # type: ignore[import-untyped]
import pytest

import evoom_guard.finalizer.deployment as finalizer_deployment
from evoom_guard.finalizer.deployment import (
    DEPLOYMENT_MANIFEST_PATH,
    FinalizerDeploymentError,
    inspect_finalizer_deployment,
    install_finalizer_deployment,
    load_finalizer_kit,
)
from evoom_guard.pack_manifest import pack_digest

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "evoom_guard" / "templates" / "trusted-finalizer" / "v4.5.0"
PUBLIC_KEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n"
    "-----END PUBLIC KEY-----\n"
)


def _public_key(tmp_path: Path) -> Path:
    path = tmp_path / "input-public.pem"
    path.write_text(PUBLIC_KEY, encoding="ascii", newline="\n")
    return path


def _install(tmp_path: Path, name: str = "consumer") -> Path:
    root = tmp_path / name
    root.mkdir()
    install_finalizer_deployment(str(root), str(_public_key(tmp_path)))
    return root


def _write_safe_policy(root: Path) -> None:
    pack = root / "judge" / "pack"
    pack.mkdir(parents=True)
    (pack / "test_contract.py").write_text(
        "def test_contract():\n    assert True\n", encoding="utf-8", newline="\n"
    )
    policy = {
        "blackbox": True,
        "blackbox_only": True,
        "docker_image": "python:3.12@sha256:" + "1" * 64,
        "docker_network": "none",
        "expect_verifier_pack_sha256": pack_digest(str(pack)),
        "isolation": "docker",
        "require_candidate_isolation": "docker",
        "require_report_integrity": "external_process_isolated",
        "trust_setup_on_host": False,
        "verifier_pack": "judge/pack",
    }
    (root / ".evoguard.json").write_text(
        json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _installed_bytes(root: Path) -> dict[str, bytes]:
    paths = (
        ".github/workflows/evoguard-reverify.yml",
        ".github/workflows/evoguard-seal.yml",
        "security/evoguard-finalizer.pub.pem",
        DEPLOYMENT_MANIFEST_PATH,
    )
    return {path: (root / path).read_bytes() for path in paths}


def test_finalizer_init_is_deterministic_and_manifest_bound(tmp_path: Path) -> None:
    key = _public_key(tmp_path)
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()

    first_result = install_finalizer_deployment(str(first), str(key))
    install_finalizer_deployment(str(second), str(key))

    assert _installed_bytes(first) == _installed_bytes(second)
    assert first_result["public_key_id"].startswith("sha256:")
    manifest_bytes = (first / DEPLOYMENT_MANIFEST_PATH).read_bytes()
    manifest = json.loads(manifest_bytes)
    assert manifest_bytes == (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    assert manifest["runtime"]["release"] == "v4.5.0"
    assert manifest["runtime"]["source_commit"] == (
        "6bb4c328e56661b661e50532886802c6ba36a997"
    )
    assert manifest["runtime"]["release_ledger_sha256"] == (
        "9ee6c49e7a3c93d611c34e208f5e3936f147bf0ed0b8ff2c41b3e53b891da239"
    )
    assert manifest["public_key"]["sha256"] == hashlib.sha256(
        PUBLIC_KEY.encode("ascii")
    ).hexdigest()


def test_finalizer_init_refuses_every_overwrite_before_writing(tmp_path: Path) -> None:
    root = tmp_path / "consumer"
    workflow = root / ".github" / "workflows" / "evoguard-reverify.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("user-owned\n", encoding="utf-8")

    with pytest.raises(FinalizerDeploymentError, match="refusing to overwrite"):
        install_finalizer_deployment(str(root), str(_public_key(tmp_path)))

    assert workflow.read_text(encoding="utf-8") == "user-owned\n"
    assert not (root / ".github/workflows/evoguard-seal.yml").exists()
    assert not (root / "security/evoguard-finalizer.pub.pem").exists()
    assert not (root / DEPLOYMENT_MANIFEST_PATH).exists()


def test_finalizer_init_refuses_a_private_key(tmp_path: Path) -> None:
    root = tmp_path / "consumer"
    root.mkdir()
    private = tmp_path / "private.pem"
    private.write_text(
        "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
        encoding="ascii",
    )

    with pytest.raises(FinalizerDeploymentError, match="private keys are never accepted"):
        install_finalizer_deployment(str(root), str(private))
    assert not (root / ".github").exists()


def test_finalizer_init_rolls_back_files_after_a_later_failure(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "consumer"
    root.mkdir()
    key = _public_key(tmp_path)
    real_write = finalizer_deployment._exclusive_write
    calls = 0

    def fail_second(path: str, data: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise FinalizerDeploymentError("synthetic write failure")
        real_write(path, data)

    monkeypatch.setattr(finalizer_deployment, "_exclusive_write", fail_second)
    with pytest.raises(FinalizerDeploymentError, match="synthetic write failure"):
        install_finalizer_deployment(str(root), str(key))

    assert not (root / ".github/workflows/evoguard-reverify.yml").exists()
    assert not (root / ".github/workflows/evoguard-seal.yml").exists()
    assert not (root / "security/evoguard-finalizer.pub.pem").exists()
    assert not (root / DEPLOYMENT_MANIFEST_PATH).exists()


def test_finalizer_init_refuses_a_symlinked_deployment_parent(tmp_path: Path) -> None:
    root = tmp_path / "consumer"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        os.symlink(outside, root / ".github", target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symbolic links are unavailable: {exc}")

    with pytest.raises(FinalizerDeploymentError, match="non-link directory"):
        install_finalizer_deployment(str(root), str(_public_key(tmp_path)))
    assert not list(outside.iterdir())


@pytest.mark.skipif(os.name != "nt", reason="Windows junction/reparse-point contract")
def test_finalizer_init_refuses_a_windows_reparse_parent(tmp_path: Path) -> None:
    root = tmp_path / "consumer"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    junction = root / ".github"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if created.returncode != 0:
        pytest.skip(f"junction creation is unavailable: {created.stdout}{created.stderr}")
    try:
        with pytest.raises(FinalizerDeploymentError, match="non-link directory"):
            install_finalizer_deployment(str(root), str(_public_key(tmp_path)))
        assert not list(outside.iterdir())
    finally:
        os.rmdir(junction)


def test_packaged_templates_are_exact_current_workflows_and_manifest_contract() -> None:
    kit = load_finalizer_kit()
    by_resource = {entry["resource"]: entry for entry in kit["templates"]}
    pairs = {
        "reverify.yml": ROOT / ".github/workflows/evoguard-reverify.yml",
        "seal.yml": ROOT / ".github/workflows/evoguard-seal.yml",
    }
    for resource, workflow in pairs.items():
        template_bytes = (TEMPLATES / resource).read_bytes()
        assert template_bytes == workflow.read_bytes()
        assert hashlib.sha256(template_bytes).hexdigest() == by_resource[resource]["sha256"]

    reverify = (TEMPLATES / "reverify.yml").read_text(encoding="utf-8")
    seal = (TEMPLATES / "seal.yml").read_text(encoding="utf-8")
    secret = kit["github"]["private_key_secret"]
    assert secret == "EVOGUARD_FINALIZER_KEY"
    assert f"secrets.{secret}" in seal
    assert f"secrets.{secret}" not in reverify
    assert kit["github"]["guard_digest_variable"] in reverify
    assert kit["github"]["guard_digest_variable"] in seal
    assert kit["github"]["reverify_workflow_id_variable"] in seal
    assert f"environment: {kit['github']['environment']}" in seal
    assert kit["runtime"]["source_commit"] == (
        "6bb4c328e56661b661e50532886802c6ba36a997"
    )
    ledger = ROOT / "evidence/release-ledgers/v4.5.0/RELEASE_LEDGER.json"
    assert hashlib.sha256(ledger.read_bytes()).hexdigest() == (
        kit["runtime"]["release_ledger_sha256"]
    )


def test_finalizer_doctor_passes_static_files_policy_pack_and_key(tmp_path: Path) -> None:
    root = _install(tmp_path)
    _write_safe_policy(root)

    report = inspect_finalizer_deployment(str(root))

    assert report["static_ready"] is True
    assert report["scope"] == "static"
    assert report["github_controls_checked"] is False
    assert report["enforcement_ready"] is False
    assert all(check["status"] == "PASS" for check in report["checks"])
    assert report["required_live_controls"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("blackbox_only", False),
        ("docker_network", "bridge"),
        ("trust_setup_on_host", True),
        ("require_candidate_isolation", "gvisor"),
        ("docker_image", "python:3.12"),
        ("docker_image", "python:3.12@sha256:" + "A" * 64),
    ],
)
def test_finalizer_doctor_fails_weak_policy(
    tmp_path: Path, field: str, value: object
) -> None:
    root = _install(tmp_path)
    _write_safe_policy(root)
    policy_path = root / ".evoguard.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy[field] = value
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    report = inspect_finalizer_deployment(str(root))

    assert report["static_ready"] is False
    policy_check = next(check for check in report["checks"] if check["id"] == "policy-safety")
    assert policy_check["status"] == "FAIL"


def test_finalizer_doctor_detects_pack_and_public_key_drift(tmp_path: Path) -> None:
    root = _install(tmp_path)
    _write_safe_policy(root)
    (root / "judge/pack/test_contract.py").write_text(
        "def test_contract():\n    assert False\n", encoding="utf-8"
    )
    (root / "security/evoguard-finalizer.pub.pem").write_text(
        PUBLIC_KEY.replace("11qY", "21qY"), encoding="ascii"
    )

    report = inspect_finalizer_deployment(str(root))

    failed = {check["id"] for check in report["checks"] if check["status"] == "FAIL"}
    assert "public-key" in failed or "manifest-bindings" in failed
    assert "verifier-pack" in failed
    assert report["static_ready"] is False


def test_deployment_and_report_validate_against_published_schemas(tmp_path: Path) -> None:
    root = _install(tmp_path)
    _write_safe_policy(root)
    deployment = json.loads((root / DEPLOYMENT_MANIFEST_PATH).read_text(encoding="utf-8"))
    report = inspect_finalizer_deployment(str(root))
    deployment_schema = json.loads(
        (ROOT / "evoom_guard/schemas/finalizer-deployment-1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    report_schema = json.loads(
        (ROOT / "evoom_guard/schemas/finalizer-deployment-report-1.schema.json").read_text(
            encoding="utf-8"
        )
    )

    jsonschema.Draft202012Validator.check_schema(deployment_schema)
    jsonschema.Draft202012Validator.check_schema(report_schema)
    jsonschema.Draft202012Validator(
        deployment_schema, format_checker=jsonschema.FormatChecker()
    ).validate(deployment)
    jsonschema.Draft202012Validator(report_schema).validate(report)


def test_wheel_contains_finalizer_templates_and_schemas(tmp_path: Path) -> None:
    wheel_directory = tmp_path / "wheel"
    wheel_directory.mkdir()
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            ".",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheel_directory),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    wheels = list(wheel_directory.glob("*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
    assert {
        "evoom_guard/candidate/identity.py",
        "evoom_guard/schemas/agent-change-proposal-2.schema.json",
        "evoom_guard/schemas/agent-change-git-bindings-2.schema.json",
        "evoom_guard/schemas/admission-decision-envelope-2.schema.json",
        "evoom_guard/schemas/finalizer-deployment-1.schema.json",
        "evoom_guard/schemas/finalizer-deployment-report-1.schema.json",
        "evoom_guard/templates/trusted-finalizer/v4.5.0/manifest.json",
        "evoom_guard/templates/trusted-finalizer/v4.5.0/reverify.yml",
        "evoom_guard/templates/trusted-finalizer/v4.5.0/seal.yml",
    } <= names
