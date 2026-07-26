"""Contracts for the reproducible isolation conformance kit."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jsonschema  # type: ignore[import-untyped]
import pytest

from evoom_guard.isolation.docker import DockerContainerCleanupResult
from tools.conformance import isolation_kit
from tools.conformance.secure_io import read_stable_regular_file

_IMAGE_ID = "sha256:" + ("a" * 64)


def _manifest() -> dict[str, Any]:
    return isolation_kit.load_manifest()


def _probe_payload(*, uid: int = 1000, gid: int = 1000) -> dict[str, Any]:
    forbidden = _manifest()["forbidden_paths"]
    return {
        "schema_version": isolation_kit.PROBE_VERSION,
        "identity": {"uid": uid, "gid": gid, "groups": [gid]},
        "kernel": {
            "system": "Linux",
            "node": "container",
            "release": "test",
            "version": "test",
            "machine": "x86_64",
        },
        "attempts": {
            "network_connect": {"blocked": True},
            "candidate_mount_write": {"blocked": True},
            "root_filesystem_write": {"blocked": True},
            "forbidden_path_read": {path: {"blocked": True} for path in forbidden},
        },
    }


def _inspect(*, user: str = "1000:1000", runtime: str = "runc") -> dict[str, Any]:
    return {
        "Id": "container-id",
        "Image": "sha256:" + ("a" * 64),
        "Config": {"User": user},
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Runtime": runtime,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {"/tmp": "rw,exec"},
            "PidsLimit": 256,
            "NanoCpus": 1_000_000_000,
            "Ulimits": [{"Name": "nofile", "Soft": 1024, "Hard": 1024}],
        },
        "Mounts": [{"Type": "bind", "Destination": "/candidate", "RW": False}],
    }


def _cleaned() -> DockerContainerCleanupResult:
    return DockerContainerCleanupResult(
        name="case",
        removals=(),
        observations=(),
        proven_absent=True,
    )


def _schema(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _unavailable_docker() -> dict[str, Any]:
    return {
        "available": False,
        "executable": "docker.exe" if os.name == "nt" else "docker",
        "error": "daemon unavailable",
        "client": None,
        "server": None,
        "info": None,
        "available_runtimes": [],
    }


def _available_docker(*, runtimes: tuple[str, ...] = ("runc",)) -> dict[str, Any]:
    return {
        "available": True,
        "executable": "docker.exe" if os.name == "nt" else "docker",
        "error": None,
        "client": {"Version": "test"},
        "server": {"Version": "test"},
        "info": {"default_runtime": "runc"},
        "available_runtimes": list(runtimes),
    }


def _resolved_image(requested: str) -> dict[str, Any]:
    return {
        "requested": requested,
        "image_id": _IMAGE_ID,
        "repo_digests": [],
        "pull_attempted": False,
        "error": None,
    }


def _validate_result_schema(result: dict[str, Any]) -> None:
    jsonschema.Draft202012Validator(
        _schema(isolation_kit.RESULT_SCHEMA),
        format_checker=jsonschema.FormatChecker(),
    ).validate(result)


def _assert_no_container_probe_tampering_is_rejected(
    result: dict[str, Any],
) -> None:
    mutations = {
        "id": "network_none",
        "required": not result["profiles"][0]["probes"][0]["required"],
        "status": "pass",
        "expected": {"forged": True},
        "observed": {"forged": True},
        "detail": "forged detail",
    }
    for field, value in mutations.items():
        forged = deepcopy(result)
        forged["profiles"][0]["probes"][0][field] = value
        with pytest.raises(
            isolation_kit.ResultVerificationError,
            match="no-container state evidence mismatch",
        ):
            isolation_kit.verify_result(forged)


def _synthetic_available_profile(
    manifest: dict[str, Any],
    profile: dict[str, Any],
    *,
    inspected: dict[str, Any],
    available_runtimes: list[str],
) -> dict[str, Any]:
    expected_user = isolation_kit.expected_container_user(manifest)
    if expected_user is None:
        payload = _probe_payload()
    else:
        payload = _probe_payload(uid=expected_user[0], gid=expected_user[1])
        inspected["Config"]["User"] = f"{expected_user[0]}:{expected_user[1]}"
    probes = isolation_kit.evaluate_isolation_probes(
        manifest,
        profile,
        payload=payload,
        inspected=inspected,
        expected_user=expected_user,
        cleanup=_cleaned(),
    )
    timeout_command = isolation_kit.build_container_command(
        manifest,
        profile,
        image_id=_IMAGE_ID,
        candidate_dir="/judge/candidate",
        name="timeout-case",
        payload_command=["python", "-c", "pass"],
        user=expected_user,
    )
    probes.append(
        isolation_kit._probe(  # noqa: SLF001 - semantic verifier fixture
            "timeout_cleanup",
            required=True,
            status="pass",
            expected={
                "timeout_raised": True,
                "container_started": True,
                "cleanup_proven_absent": True,
            },
            observed={
                "timeout_raised": True,
                "container_started": True,
                "returned_code": None,
                "cleanup": isolation_kit.cleanup_evidence(_cleaned()),
                "command_template": isolation_kit.command_template(
                    timeout_command,
                    candidate_dir="/judge/candidate",
                    container_name="timeout-case",
                ),
            },
        )
    )
    command = isolation_kit.build_container_command(
        manifest,
        profile,
        image_id=_IMAGE_ID,
        candidate_dir="/judge/candidate",
        name="case",
        payload_command=["python", "/candidate/isolation_probe.py"],
        user=expected_user,
    )
    status = isolation_kit.profile_status(probes)
    return {
        "id": profile["id"],
        "required": profile["required"],
        "requested_runtime": profile.get("runtime"),
        "status": status,
        "reason": None if status == "pass" else "one or more probes did not pass",
        "runtime": {
            "requested": profile.get("runtime"),
            "available": True,
            "available_runtimes": available_runtimes,
            "observed": inspected["HostConfig"]["Runtime"],
        },
        "container": {
            "command_template": isolation_kit.command_template(
                command,
                candidate_dir="/judge/candidate",
                container_name="case",
            ),
            "returncode": 0,
            "stderr": "",
            "inspect": isolation_kit.extract_container_metadata(inspected),
            "probe_payload": payload,
        },
        "probes": probes,
    }


def test_checked_in_manifest_matches_its_schema() -> None:
    schema = _schema(isolation_kit.CONFORMANCE_DIR / "isolation-manifest.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(_manifest())


def test_manifest_rejects_unknown_duplicate_or_missing_required_probes() -> None:
    manifest = _manifest()
    manifest["required_probes"] = ["typo"]
    with pytest.raises(isolation_kit.ManifestError, match="exact mandatory"):
        isolation_kit.validate_manifest(manifest)

    manifest = _manifest()
    manifest["required_probes"][-1] = manifest["required_probes"][0]
    with pytest.raises(isolation_kit.ManifestError, match="duplicates"):
        isolation_kit.validate_manifest(manifest)

    manifest = _manifest()
    manifest["required_probes"].pop()
    with pytest.raises(isolation_kit.ManifestError, match="exact mandatory"):
        isolation_kit.validate_manifest(manifest)


def test_result_schema_is_valid_json_schema() -> None:
    schema = _schema(isolation_kit.RESULT_SCHEMA)
    jsonschema.Draft202012Validator.check_schema(schema)


def test_result_uses_logical_paths_and_does_not_leak_local_roots(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        isolation_kit,
        "collect_docker_metadata",
        lambda _timeout: {
            "available": False,
            "executable": "docker.exe" if os.name == "nt" else "docker",
            "error": "daemon unavailable",
            "client": None,
            "server": None,
            "info": None,
            "available_runtimes": [],
        },
    )

    result = isolation_kit.run_conformance(
        pull=False,
        output_path=tmp_path / "private-result.json",
    )
    schema = _schema(isolation_kit.RESULT_SCHEMA)
    jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(result)

    assert result["$schema"] == "tools/conformance/isolation-result.schema.json"
    assert result["manifest"]["path"] == "tools/conformance/isolation-manifest.json"
    assert result["probe_source"]["path"] == ("tools/conformance/probe/isolation_probe.py")
    assert "python_executable" not in result["environment"]["host"]
    assert result["reproduce"]["argv"][:3] == [
        "python",
        "-m",
        "tools.conformance.run_isolation_conformance",
    ]
    assert result["reproduce"]["argv"][-1] == "<result.json>"

    serialized = json.dumps(result, ensure_ascii=False).casefold()
    forbidden = {
        str(isolation_kit.REPOSITORY_ROOT.resolve()).casefold(),
        str(Path.home().resolve()).casefold(),
        str(Path(sys.executable).resolve()).casefold(),
        str(tmp_path.resolve()).casefold(),
    }
    assert all(path not in serialized for path in forbidden)


def test_docker_metadata_records_only_executable_basename(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    executable_name = "docker.exe" if os.name == "nt" else "docker"
    executable = tmp_path / "private" / executable_name
    responses = iter(
        (
            {"Client": {"Version": "1"}, "Server": {"Version": "1"}},
            {
                "Runtimes": {"runc": {}},
                "ServerVersion": "1",
                "DockerRootDir": str(tmp_path / "private-root"),
                "Name": "private-hostname",
            },
        )
    )
    monkeypatch.setattr(isolation_kit.shutil, "which", lambda _name: str(executable))
    monkeypatch.setattr(
        isolation_kit,
        "_json_control",
        lambda _command, *, timeout: next(responses),
    )

    metadata = isolation_kit.collect_docker_metadata(1)

    assert metadata["executable"] == executable_name
    assert "docker_root_dir" not in metadata["info"]
    assert "name" not in metadata["info"]
    assert str(tmp_path) not in json.dumps(metadata)


def test_command_contains_every_manifest_isolation_control() -> None:
    manifest = _manifest()
    profile = next(profile for profile in manifest["profiles"] if profile["id"] == "gvisor")
    image_id = "sha256:" + ("a" * 64)

    command = isolation_kit.build_container_command(
        manifest,
        profile,
        image_id=image_id,
        candidate_dir="/judge/candidate",
        name="case",
        payload_command=["python", "/candidate/isolation_probe.py"],
        environment={"PROBE": "1"},
        user=(1000, 1001),
    )

    assert command[:4] == ["docker", "run", "--name", "case"]
    assert command[command.index("--network") + 1] == "none"
    assert "--read-only" in command
    assert command[command.index("--user") + 1] == "1000:1001"
    assert command[command.index("--runtime") + 1] == "runsc"
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert command[command.index("--security-opt") + 1] == "no-new-privileges"
    assert "/judge/candidate:/candidate:ro" in command
    assert image_id in command


def test_evaluator_requires_active_attempts_and_daemon_configuration() -> None:
    manifest = _manifest()
    profile = next(profile for profile in manifest["profiles"] if profile["id"] == "docker")

    probes = isolation_kit.evaluate_isolation_probes(
        manifest,
        profile,
        payload=_probe_payload(),
        inspected=_inspect(),
        expected_user=(1000, 1000),
        cleanup=_cleaned(),
    )

    assert probes
    assert all(probe["status"] == "pass" for probe in probes)
    assert isolation_kit.profile_status(probes) == "pass"


@pytest.mark.parametrize(
    ("inspect_field", "tampered_value", "normalized_field"),
    (
        ("CapDrop", [], "cap_drop"),
        ("SecurityOpt", ["no-new-privileges:false"], "security_opt"),
        ("Tmpfs", {"/tmp": "rw"}, "tmpfs"),
        ("PidsLimit", 255, "pids_limit"),
        ("NanoCpus", 999_999_999, "nano_cpus"),
        (
            "Ulimits",
            [{"Name": "nofile", "Soft": 2048, "Hard": 2048}],
            "ulimits",
        ),
    ),
)
def test_security_profile_fails_each_exact_resource_control_tamper(
    inspect_field: str,
    tampered_value: object,
    normalized_field: str,
) -> None:
    manifest = _manifest()
    profile = next(profile for profile in manifest["profiles"] if profile["id"] == "docker")
    inspected = _inspect()
    inspected["HostConfig"][inspect_field] = tampered_value

    probes = isolation_kit.evaluate_isolation_probes(
        manifest,
        profile,
        payload=_probe_payload(),
        inspected=inspected,
        expected_user=(1000, 1000),
        cleanup=_cleaned(),
    )

    security = next(probe for probe in probes if probe["id"] == "security_profile")
    assert security["status"] == "fail"
    assert security["observed"][normalized_field] != security["expected"][normalized_field]
    assert isolation_kit.profile_status(probes) == "fail"


def test_security_profile_normalizes_equivalent_docker_option_order_and_spelling() -> None:
    manifest = _manifest()
    profile = next(profile for profile in manifest["profiles"] if profile["id"] == "docker")
    inspected = _inspect()
    inspected["HostConfig"]["CapDrop"] = ["all"]
    inspected["HostConfig"]["SecurityOpt"] = ["NO-NEW-PRIVILEGES:TRUE"]
    inspected["HostConfig"]["Tmpfs"] = {"/tmp": "exec,rw"}

    probes = isolation_kit.evaluate_isolation_probes(
        manifest,
        profile,
        payload=_probe_payload(),
        inspected=inspected,
        expected_user=(1000, 1000),
        cleanup=_cleaned(),
    )

    security = next(probe for probe in probes if probe["id"] == "security_profile")
    assert security["status"] == "pass"
    assert security["observed"] == security["expected"]


def test_user_identity_is_truthfully_skipped_when_host_contract_does_not_apply() -> None:
    manifest = _manifest()
    profile = next(profile for profile in manifest["profiles"] if profile["id"] == "docker")

    probes = isolation_kit.evaluate_isolation_probes(
        manifest,
        profile,
        payload=_probe_payload(uid=0, gid=0),
        inspected=_inspect(user=""),
        expected_user=None,
        cleanup=_cleaned(),
    )

    identity = next(probe for probe in probes if probe["id"] == "user_identity")
    assert identity["required"] is False
    assert identity["status"] == "skip"
    assert identity["observed"]["uid"] == 0


def test_forbidden_path_probe_rejects_a_covering_mount_even_when_read_fails() -> None:
    manifest = _manifest()
    profile = next(profile for profile in manifest["profiles"] if profile["id"] == "docker")
    inspected = _inspect()
    inspected["Mounts"].append({"Type": "bind", "Destination": "/out", "RW": False})

    probes = isolation_kit.evaluate_isolation_probes(
        manifest,
        profile,
        payload=_probe_payload(),
        inspected=inspected,
        expected_user=(1000, 1000),
        cleanup=_cleaned(),
    )

    forbidden = next(probe for probe in probes if probe["id"] == "forbidden_path_read")
    assert forbidden["status"] == "fail"
    assert forbidden["observed"]["/out/conformance-secret.txt"]["covering_mounts"] == ["/out"]


def test_available_but_root_host_identity_fails_non_root_contract() -> None:
    manifest = _manifest()
    profile = next(profile for profile in manifest["profiles"] if profile["id"] == "docker")

    probes = isolation_kit.evaluate_isolation_probes(
        manifest,
        profile,
        payload=_probe_payload(uid=0, gid=0),
        inspected=_inspect(user="0:0"),
        expected_user=(0, 0),
        cleanup=_cleaned(),
    )

    identity = next(probe for probe in probes if probe["id"] == "user_identity")
    assert identity["required"] is True
    assert identity["status"] == "fail"
    assert isolation_kit.profile_status(probes) == "fail"


def test_missing_runsc_is_unsupported_and_never_pass() -> None:
    profile = {"id": "gvisor", "runtime": "runsc", "required": False}

    result = isolation_kit.unsupported_profile(profile, ["runc"])

    assert result["status"] == "unsupported"
    assert result["probes"][0]["status"] == "unsupported"
    assert isolation_kit.overall_status([result]) == "unsupported"


def test_no_pull_does_not_mutate_daemon_when_image_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        isolation_kit,
        "inspect_docker_image",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["docker", "image", "inspect"],
            1,
            stdout="",
            stderr="missing",
        ),
    )
    monkeypatch.setattr(
        isolation_kit,
        "resolve_docker_image",
        lambda *_args, **_kwargs: pytest.fail("image pull path was called"),
    )

    result = isolation_kit.resolve_image_metadata(
        "missing:never",
        control_timeout=1,
        pull_timeout=1,
        pull=False,
    )

    assert result["image_id"] is None
    assert result["pull_attempted"] is False
    assert result["error"] == "missing"


def test_optional_unsupported_runtime_does_not_erase_docker_pass() -> None:
    docker = {"id": "docker", "required": True, "status": "pass", "probes": []}
    gvisor = {
        "id": "gvisor",
        "required": False,
        "status": "unsupported",
        "probes": [],
    }

    assert isolation_kit.overall_status([docker, gvisor]) == "pass"


def test_require_gvisor_promotes_missing_runtime_to_required_unsupported() -> None:
    manifest = _manifest()
    selected = isolation_kit._select_profiles(  # noqa: SLF001 - contract test
        manifest,
        ["gvisor"],
        require_gvisor=True,
    )
    result = isolation_kit.unsupported_profile(selected[0], ["runc"])

    assert result["required"] is True
    assert result["status"] == "unsupported"
    assert isolation_kit.exit_code(isolation_kit.overall_status([result])) == 2


def test_live_docker_profiles_emit_schema_valid_truthful_evidence(
    tmp_path: Path,
) -> None:
    if os.environ.get("EVOGUARD_RUN_ISOLATION_CONFORMANCE") != "1":
        pytest.skip("set EVOGUARD_RUN_ISOLATION_CONFORMANCE=1 for the live daemon probe")
    image = os.environ.get("EVOGUARD_E2E_IMAGE")
    if image is None or "@sha256:" not in image:
        pytest.fail(
            "live isolation conformance requires pinned EVOGUARD_E2E_IMAGE (name@sha256:digest)"
        )
    manifest = _manifest()
    docker = isolation_kit.collect_docker_metadata(float(manifest["control_timeout_seconds"]))
    if docker["available"] is not True:
        pytest.skip(str(docker.get("error") or "Docker unavailable"))

    result = isolation_kit.run_conformance(
        image=image,
        pull=False,
        output_path=tmp_path / "result.json",
    )

    schema = _schema(isolation_kit.RESULT_SCHEMA)
    jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(result)
    docker_profile = next(profile for profile in result["profiles"] if profile["id"] == "docker")
    assert docker_profile["status"] == "pass"
    assert result["environment"]["image"]["image_id"].startswith("sha256:")
    assert result["environment"]["image"]["image_id"] in result["reproduce"]["argv"]
    assert {probe["id"]: probe["status"] for probe in docker_profile["probes"]}[
        "timeout_cleanup"
    ] == "pass"

    gvisor = next(profile for profile in result["profiles"] if profile["id"] == "gvisor")
    runtimes = result["environment"]["docker"]["available_runtimes"]
    if "runsc" not in runtimes:
        assert gvisor["status"] == "unsupported"
        assert gvisor["probes"][0]["status"] == "unsupported"


def test_semantic_verifier_rejects_empty_profiles_status_and_source_forgery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(isolation_kit, "collect_docker_metadata", lambda _timeout: _unavailable_docker())
    result = isolation_kit.run_conformance(pull=False)
    isolation_kit.verify_result(result)

    empty = json.loads(json.dumps(result))
    empty["profiles"] = []
    empty["status"] = "pass"
    empty["summary"] = {
        "profiles": {"pass": 0, "fail": 0, "error": 0, "skip": 0, "unsupported": 0},
        "probes": {"pass": 0, "fail": 0, "error": 0, "skip": 0, "unsupported": 0},
    }
    with pytest.raises(isolation_kit.ResultVerificationError, match="must not be empty"):
        isolation_kit.verify_result(empty)

    contradictory = json.loads(json.dumps(result))
    contradictory["status"] = "pass"
    with pytest.raises(isolation_kit.ResultVerificationError, match="aggregate"):
        isolation_kit.verify_result(contradictory)

    stale = json.loads(json.dumps(result))
    stale["source"]["files"][0]["sha256"] = "0" * 64
    with pytest.raises(isolation_kit.ResultVerificationError, match="source inventory"):
        isolation_kit.verify_result(stale)


def test_verifier_exactly_rederives_docker_unavailable_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        isolation_kit,
        "collect_docker_metadata",
        lambda _timeout: _unavailable_docker(),
    )

    result = isolation_kit.run_conformance(
        selected_profiles=["docker"],
        pull=False,
    )

    _validate_result_schema(result)
    isolation_kit.verify_result(result)
    assert result["profiles"][0]["probes"][0]["id"] == "docker_available"
    _assert_no_container_probe_tampering_is_rejected(result)


def test_verifier_exactly_rederives_image_resolution_error_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        isolation_kit,
        "collect_docker_metadata",
        lambda _timeout: _available_docker(),
    )
    monkeypatch.setattr(
        isolation_kit,
        "resolve_image_metadata",
        lambda requested, **_kwargs: {
            "requested": requested,
            "image_id": None,
            "repo_digests": [],
            "pull_attempted": False,
            "error": "image missing",
        },
    )

    result = isolation_kit.run_conformance(
        image="missing:test",
        selected_profiles=["docker"],
        pull=False,
    )

    _validate_result_schema(result)
    isolation_kit.verify_result(result)
    assert result["profiles"][0]["probes"][0]["id"] == "image_available"
    _assert_no_container_probe_tampering_is_rejected(result)


def test_verifier_exactly_rederives_missing_runtime_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        isolation_kit,
        "collect_docker_metadata",
        lambda _timeout: _available_docker(),
    )
    monkeypatch.setattr(
        isolation_kit,
        "resolve_image_metadata",
        lambda requested, **_kwargs: _resolved_image(requested),
    )

    result = isolation_kit.run_conformance(
        image="reviewed:test",
        selected_profiles=["gvisor"],
        pull=False,
    )

    _validate_result_schema(result)
    isolation_kit.verify_result(result)
    assert result["profiles"][0]["probes"][0]["id"] == "runtime_available"
    _assert_no_container_probe_tampering_is_rejected(result)


def test_verifier_exactly_rederives_harness_exception_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        isolation_kit,
        "collect_docker_metadata",
        lambda _timeout: _available_docker(),
    )
    monkeypatch.setattr(
        isolation_kit,
        "resolve_image_metadata",
        lambda requested, **_kwargs: _resolved_image(requested),
    )

    def raise_harness_error(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("harness boom")

    monkeypatch.setattr(isolation_kit, "_execute_main_probe", raise_harness_error)

    result = isolation_kit.run_conformance(
        image="reviewed:test",
        selected_profiles=["docker"],
        pull=False,
    )

    _validate_result_schema(result)
    isolation_kit.verify_result(result)
    assert result["profiles"][0]["probes"][0]["id"] == "harness_execution"
    _assert_no_container_probe_tampering_is_rejected(result)


def test_verifier_rejects_raw_inspect_security_tampering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest()
    monkeypatch.setattr(
        isolation_kit,
        "collect_docker_metadata",
        lambda _timeout: _available_docker(),
    )
    monkeypatch.setattr(
        isolation_kit,
        "resolve_image_metadata",
        lambda requested, **_kwargs: _resolved_image(requested),
    )

    def synthetic_execute(
        passed_manifest: dict[str, Any],
        profile: dict[str, Any],
        *,
        image_id: str,
        available_runtimes: list[str],
        probe_source_bytes: bytes,
    ) -> dict[str, Any]:
        assert passed_manifest == manifest
        assert image_id == _IMAGE_ID
        assert probe_source_bytes
        return _synthetic_available_profile(
            passed_manifest,
            profile,
            inspected=_inspect(),
            available_runtimes=available_runtimes,
        )

    monkeypatch.setattr(isolation_kit, "execute_profile", synthetic_execute)
    result = isolation_kit.run_conformance(
        image="reviewed:test",
        selected_profiles=["docker"],
        pull=False,
    )

    _validate_result_schema(result)
    isolation_kit.verify_result(result)
    tampered_values = {
        "cap_drop": [],
        "security_opt": ["no-new-privileges:false"],
        "tmpfs": {"/tmp": "rw"},
        "pids_limit": 255,
        "nano_cpus": 999_999_999,
        "ulimits": [{"Name": "nofile", "Soft": 2048, "Hard": 2048}],
    }
    for field, value in tampered_values.items():
        forged = deepcopy(result)
        forged["profiles"][0]["container"]["inspect"][field] = value
        with pytest.raises(
            isolation_kit.ResultVerificationError,
            match="contradicts container inspect",
        ):
            isolation_kit.verify_result(forged)


def test_isolation_writer_and_loader_reject_existing_symlink(tmp_path: Path) -> None:
    result = {"status": "unsupported"}
    destination = tmp_path / "result.json"
    isolation_kit.write_result(result, destination)
    first = destination.read_bytes()
    with pytest.raises(FileExistsError):
        isolation_kit.write_result({"status": "pass"}, destination)
    assert destination.read_bytes() == first

    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "result-link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(OSError):
        isolation_kit.load_result(link)
    with pytest.raises(FileExistsError):
        isolation_kit.write_result(result, link)
    assert target.read_text(encoding="utf-8") == "{}"


def test_isolation_source_inventory_binds_evaluator_and_helpers() -> None:
    source = isolation_kit.collect_source_metadata()
    paths = {item["path"] for item in source["files"]}
    assert {
        "tools/conformance/isolation_kit.py",
        "tools/conformance/secure_io.py",
        "evoom_guard/isolation/docker.py",
        "evoom_guard/execution/process.py",
        "tools/conformance/probe/isolation_probe.py",
    } <= paths


def test_stable_reader_rejects_windows_reparse_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if not marker:
        pytest.skip("reparse metadata is Windows-specific")
    source = tmp_path / "source.json"
    source.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda _self: SimpleNamespace(
            st_mode=stat.S_IFREG,
            st_file_attributes=marker,
        ),
    )
    with pytest.raises(OSError, match="reparse"):
        read_stable_regular_file(source, label="test input")
