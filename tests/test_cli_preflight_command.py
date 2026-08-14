"""CLI-owner tests for static repository preflight."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from evoom_guard.cli import main
from evoom_guard.cli.preflight_commands import PreflightServices, execute_preflight
from evoom_guard.policy.preflight import analyze_preflight, normalize_test_command


class _ConfigError(ValueError):
    pass


def _args(repo: Path, **overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "repo": str(repo),
        "config": None,
        "no_config": False,
        "test_command": None,
        "isolation": None,
        "verifier_pack": None,
        "expect_verifier_pack_sha256": None,
        "blackbox": None,
        "blackbox_only": None,
        "docker_image": None,
        "preflight_json": False,
        "strict": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _services(
    config: dict[str, object] | Exception,
    *,
    pack_report: dict[str, object] | None = None,
) -> PreflightServices:
    def load_config(_path: str, **_kwargs: object) -> dict[str, object]:
        if isinstance(config, Exception):
            raise config
        return dict(config)

    return PreflightServices(
        load_config=load_config,
        config_error_type=lambda: _ConfigError,
        normalize_command=normalize_test_command,
        analyze=lambda **kwargs: analyze_preflight(**kwargs),
        validate_pack=lambda _path: (
            dict(pack_report)
            if pack_report is not None
            else {
                "ok": True,
                "problems": [],
                "pack_sha256": "a" * 64,
            }
        ),
        is_pack_sha256=lambda value: (
            isinstance(value, str)
            and len(value) == 64
            and all(character in "0123456789abcdefABCDEF" for character in value)
        ),
        locate_executable=lambda executable, _cwd: f"/trusted/{executable}",
        operating_profile_violations=lambda *_args, **_kwargs: (),
    )


def test_json_preflight_reads_policy_without_executing(tmp_path: Path) -> None:
    output: list[str] = []
    result = execute_preflight(
        _args(tmp_path, preflight_json=True),
        services=_services(
            {
                "test_command": [
                    "python",
                    "-m",
                    "pytest",
                    "-p",
                    "no:cacheprovider",
                ],
                "verifier_pack": "judge-pack",
            }
        ),
        out=output.append,
    )

    assert result == 0
    payload = json.loads(output[0])
    assert payload["schema_version"] == "evoguard/preflight/v1"
    assert payload["ready"] is True
    assert payload["verifier_pack_configured"] is True


def test_strict_mode_makes_unresolved_warnings_nonzero(tmp_path: Path) -> None:
    result = execute_preflight(
        _args(
            tmp_path,
            no_config=True,
            strict=True,
            test_command="custom-runner",
            verifier_pack="judge-pack",
        ),
        services=_services({}),
        out=lambda _line: None,
    )

    assert result == 1


def test_explicit_broken_config_is_usage_error(tmp_path: Path) -> None:
    output: list[str] = []
    result = execute_preflight(
        _args(tmp_path, config="policy.json"),
        services=_services(_ConfigError("bad policy")),
        out=output.append,
    )

    assert result == 2
    assert output == ["config error (fail-closed): bad policy"]


def test_text_output_contains_actionable_codes(tmp_path: Path) -> None:
    output: list[str] = []
    result = execute_preflight(
        _args(tmp_path),
        services=_services(
            {
                "test_command": "python -I -c __import__('click')",
                "verifier_pack": "judge-pack",
            }
        ),
        out=output.append,
    )

    assert result == 1
    text = "\n".join(output)
    assert "runtime_write.python_environment_ignored" in text
    assert "add the explicit -B" in text


def test_missing_verifier_pack_is_not_ready(tmp_path: Path) -> None:
    output: list[str] = []
    result = execute_preflight(
        _args(tmp_path, verifier_pack="missing-pack", preflight_json=True),
        services=_services(
            {},
            pack_report={"ok": False, "problems": ["not a directory"]},
        ),
        out=output.append,
    )

    assert result == 1
    payload = json.loads(output[0])
    assert payload["ready"] is False
    assert any(
        check["code"] == "verifier_pack.valid"
        and check["status"] == "error"
        for check in payload["checks"]
    )


def test_invalid_blackbox_and_container_combinations_are_not_ready(
    tmp_path: Path,
) -> None:
    output: list[str] = []
    result = execute_preflight(
        _args(
            tmp_path,
            no_config=True,
            blackbox_only=True,
            isolation="docker",
            preflight_json=True,
        ),
        services=_services({}),
        out=output.append,
    )

    assert result == 1
    payload = json.loads(output[0])
    codes = {
        check["code"]
        for check in payload["checks"]
        if check["status"] == "error"
    }
    assert "policy.blackbox_only_requires_blackbox" in codes
    assert "policy.container_requires_image" in codes


def test_container_default_command_matches_guard_image_command(tmp_path: Path) -> None:
    output: list[str] = []
    result = execute_preflight(
        _args(
            tmp_path,
            no_config=True,
            isolation="docker",
            docker_image="python:3.12@sha256:" + "a" * 64,
            preflight_json=True,
        ),
        services=_services({}),
        out=output.append,
    )

    assert result == 0
    payload = json.loads(output[0])
    assert payload["test_command"][0] == "python"


def test_empty_policy_command_falls_back_to_guard_default(tmp_path: Path) -> None:
    output: list[str] = []
    result = execute_preflight(
        _args(tmp_path, preflight_json=True),
        services=_services({"test_command": []}),
        out=output.append,
    )

    assert result == 0
    payload = json.loads(output[0])
    assert payload["test_command"][1:] == [
        "-m",
        "pytest",
        "-q",
        "--color=no",
        "-p",
        "no:cacheprovider",
    ]


def test_pack_pin_without_pack_matches_guard_usage_failure(tmp_path: Path) -> None:
    output: list[str] = []
    result = execute_preflight(
        _args(
            tmp_path,
            no_config=True,
            expect_verifier_pack_sha256="a" * 64,
            preflight_json=True,
        ),
        services=_services({}),
        out=output.append,
    )

    assert result == 1
    payload = json.loads(output[0])
    assert any(
        check["code"] == "verifier_pack.pin_without_pack"
        and check["status"] == "error"
        for check in payload["checks"]
    )


def test_config_relative_pack_uses_policy_directory_but_override_uses_cwd(
    tmp_path: Path,
    monkeypatch,
) -> None:
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir()
    monkeypatch.chdir(tmp_path)
    observed: list[str] = []
    services = _services({"verifier_pack": "judge-pack"})
    services = PreflightServices(
        load_config=services.load_config,
        config_error_type=services.config_error_type,
        normalize_command=services.normalize_command,
        analyze=services.analyze,
        validate_pack=lambda path: (
            observed.append(path)
            or {"ok": True, "problems": [], "pack_sha256": "a" * 64}
        ),
        is_pack_sha256=services.is_pack_sha256,
        locate_executable=services.locate_executable,
        operating_profile_violations=services.operating_profile_violations,
    )

    assert execute_preflight(
        _args(tmp_path, config="policy/.evoguard.json"),
        services=services,
        out=lambda _line: None,
    ) == 0
    assert Path(observed.pop()) == policy_dir / "judge-pack"

    assert execute_preflight(
        _args(
            tmp_path,
            config="policy/.evoguard.json",
            verifier_pack="override-pack",
        ),
        services=services,
        out=lambda _line: None,
    ) == 0
    assert Path(observed.pop()) == tmp_path / "override-pack"


def test_public_cli_dispatches_preflight_as_json(
    tmp_path: Path,
    capsys,
) -> None:
    result = main(["preflight", str(tmp_path), "--no-config", "--json"])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "evoguard/preflight/v1"
    assert payload["ready"] is True
    assert payload["repository"] == str(tmp_path.resolve())


def test_unsupported_policy_requirements_and_profile_overrides_fail_closed(
    tmp_path: Path,
) -> None:
    output: list[str] = []
    services = _services(
        {
            "blackbox": True,
            "setup_command": ["python", "setup.py"],
            "verifier_pack": "judge-pack",
            "expect_verifier_pack_sha256": "a" * 64,
            "operating_profile": "protected",
            "isolation": "docker",
            "docker_image": "python@sha256:" + "b" * 64,
            "docker_network": "none",
            "blackbox_only": True,
            "require_report_integrity": "external_process_isolated",
            "require_candidate_isolation": "docker",
        }
    )
    services = PreflightServices(
        load_config=services.load_config,
        config_error_type=services.config_error_type,
        normalize_command=services.normalize_command,
        analyze=services.analyze,
        validate_pack=services.validate_pack,
        is_pack_sha256=services.is_pack_sha256,
        locate_executable=services.locate_executable,
        operating_profile_violations=lambda *_args, **kwargs: (
            ("requires isolation='docker' or 'gvisor'",)
            if kwargs["isolation"] == "subprocess"
            else ()
        ),
    )

    result = execute_preflight(
        _args(
            tmp_path,
            isolation="subprocess",
            preflight_json=True,
        ),
        services=services,
        out=output.append,
    )

    assert result == 1
    payload = json.loads(output[0])
    error_codes = {
        check["code"]
        for check in payload["checks"]
        if check["status"] == "error"
    }
    assert "policy.requirement_unsupported" in error_codes
    assert "policy.operating_profile_violation" in error_codes


def test_strict_digest_pinned_container_can_be_green(tmp_path: Path) -> None:
    result = execute_preflight(
        _args(
            tmp_path,
            no_config=True,
            isolation="docker",
            docker_image="python@sha256:" + "b" * 64,
            verifier_pack="judge-pack",
            expect_verifier_pack_sha256="a" * 64,
            strict=True,
        ),
        services=_services({}),
        out=lambda _line: None,
    )

    assert result == 0
