from __future__ import annotations

import argparse
import hashlib
import os
import stat
from pathlib import Path

import pytest

from evoom_guard import cli as cli_module
from evoom_guard import github_attestation


def _executable(tmp_path: Path) -> tuple[Path, str]:
    executable = (tmp_path / "trusted-gh").resolve()
    data = b"reviewed-provider-executable\n"
    executable.write_bytes(data)
    executable.chmod(0o755)
    return executable, hashlib.sha256(data).hexdigest()


def _isolation(
    tmp_path: Path,
    *,
    uid: int = 2001,
    gid: int = 2002,
    digest: str | None = None,
) -> github_attestation.GitHubAttestationProviderIsolation:
    executable, actual_digest = _executable(tmp_path)
    return github_attestation.github_attestation_provider_isolation(
        str(executable),
        actual_digest if digest is None else digest,
        uid=uid,
        gid=gid,
    )


def _policy() -> github_attestation.GitHubAttestationPolicy:
    return github_attestation.github_attestation_policy(
        "owner/project",
        "owner/project/.github/workflows/build.yml",
        "b" * 40,
        signer_digest="c" * 40,
        source_ref="refs/heads/main",
        cert_oidc_issuer=github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
    )


def _workspace(tmp_path: Path) -> tuple[Path, Path]:
    directory = tmp_path / "provider-workspace"
    directory.mkdir()
    snapshot = directory / "artifact-snapshot"
    snapshot.write_bytes(b"artifact\n")
    return directory, snapshot


def test_provider_isolation_rejects_path_lookup_and_root_uid(tmp_path: Path) -> None:
    with pytest.raises(
        github_attestation.GitHubAttestationError,
        match="absolute path",
    ):
        github_attestation.github_attestation_provider_isolation(
            "gh", "0" * 64, uid=2001, gid=2002
        )

    executable, digest = _executable(tmp_path)
    with pytest.raises(
        github_attestation.GitHubAttestationError,
        match="non-root",
    ):
        github_attestation.github_attestation_provider_isolation(
            str(executable), digest, uid=0, gid=2002
        )


def test_provider_isolation_rejects_wrong_executable_digest_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    isolation = _isolation(tmp_path, digest="0" * 64)
    directory, snapshot = _workspace(tmp_path)
    monkeypatch.setattr(github_attestation, "_provider_posix_identity", lambda: (0, 0))
    monkeypatch.setattr(
        github_attestation,
        "_execute_gh_attestation_command",
        lambda *_args, **_kwargs: pytest.fail("provider launched with a mismatched digest"),
    )

    with pytest.raises(
        github_attestation.GitHubAttestationError,
        match="does not match the pinned digest",
    ):
        github_attestation._run_gh_attestation_verify(
            str(snapshot),
            _policy(),
            gh_executable=isolation.executable_path,
            timeout_seconds=1,
            directory=str(directory),
            provider_isolation=isolation,
        )
    assert not (directory / "gh-pinned").exists()


def test_provider_isolation_rejects_same_caller_gid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    isolation = _isolation(tmp_path, gid=2002)
    directory, snapshot = _workspace(tmp_path)
    monkeypatch.setattr(
        github_attestation,
        "_provider_posix_identity",
        lambda: (0, 2002),
    )

    with pytest.raises(
        github_attestation.GitHubAttestationError,
        match="must both differ",
    ):
        github_attestation._prepare_provider_isolation(
            isolation,
            gh_executable=isolation.executable_path,
            snapshot_path=str(snapshot),
            directory=str(directory),
        )


def test_isolated_environment_inherits_only_provider_tokens(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    isolation = _isolation(tmp_path)
    directory, _snapshot = _workspace(tmp_path)
    monkeypatch.setenv("GH_TOKEN", "gh-secret")
    monkeypatch.setenv("GITHUB_TOKEN", "github-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-leak")
    monkeypatch.setenv("DATABASE_URL", "must-not-leak")
    monkeypatch.setenv("PATH", "candidate-path")
    monkeypatch.setenv("HOME", "candidate-home")
    monkeypatch.setattr(
        github_attestation,
        "_set_provider_path_access",
        lambda *_args, **_kwargs: None,
    )

    environment = github_attestation._isolated_gh_environment(
        str(directory), isolation
    )

    assert environment["GH_TOKEN"] == "gh-secret"
    assert environment["GITHUB_TOKEN"] == "github-secret"
    assert set(environment) == {
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_CONFIG_DIR",
        "HOME",
        "TMPDIR",
        "NO_COLOR",
        "CLICOLOR",
        "GIT_TERMINAL_PROMPT",
    }
    assert "must-not-leak" not in environment.values()
    assert environment["HOME"] == environment["GH_CONFIG_DIR"]
    assert environment["TMPDIR"] == environment["GH_CONFIG_DIR"]


def test_prepare_isolation_exposes_snapshot_and_config_to_only_lower_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    isolation = _isolation(tmp_path)
    directory, snapshot = _workspace(tmp_path)
    access: list[tuple[str, int, int, int, str]] = []
    monkeypatch.setattr(github_attestation, "_provider_posix_identity", lambda: (0, 0))

    def record_access(
        path: str,
        *,
        uid: int,
        gid: int,
        mode: int,
        label: str,
    ) -> None:
        access.append((path, uid, gid, mode, label))

    monkeypatch.setattr(github_attestation, "_set_provider_path_access", record_access)
    pinned, environment, launch = github_attestation._prepare_provider_isolation(
        isolation,
        gh_executable=isolation.executable_path,
        snapshot_path=str(snapshot),
        directory=str(directory),
    )
    try:
        assert (str(snapshot), isolation.uid, isolation.gid, 0o400) in {
            (path, uid, gid, mode) for path, uid, gid, mode, _label in access
        }
        assert (
            environment["GH_CONFIG_DIR"],
            isolation.uid,
            isolation.gid,
            0o700,
        ) in {(path, uid, gid, mode) for path, uid, gid, mode, _label in access}
        assert (str(directory), 0, isolation.gid, 0o710) in {
            (path, uid, gid, mode) for path, uid, gid, mode, _label in access
        }
        assert (pinned, 0, 0, 0o555) in {
            (path, uid, gid, mode) for path, uid, gid, mode, _label in access
        }
        assert launch == {
            "user": isolation.uid,
            "group": isolation.gid,
            "extra_groups": (),
            "umask": 0o077,
        }
    finally:
        github_attestation._remove_provider_snapshot(pinned)


def test_pinned_executable_is_removed_when_provider_launch_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    isolation = _isolation(tmp_path)
    directory, snapshot = _workspace(tmp_path)
    observed: dict[str, object] = {}
    monkeypatch.setattr(github_attestation, "_provider_posix_identity", lambda: (0, 0))
    monkeypatch.setattr(
        github_attestation,
        "_set_provider_path_access",
        lambda *_args, **_kwargs: None,
    )

    def fail_launch(command: list[str], **kwargs: object) -> bytes:
        observed["command"] = command
        observed.update(kwargs)
        raise github_attestation.GitHubAttestationError("simulated provider failure")

    monkeypatch.setattr(
        github_attestation, "_execute_gh_attestation_command", fail_launch
    )
    with pytest.raises(
        github_attestation.GitHubAttestationError,
        match="simulated provider failure",
    ):
        github_attestation._run_gh_attestation_verify(
            str(snapshot),
            _policy(),
            gh_executable=isolation.executable_path,
            timeout_seconds=1,
            directory=str(directory),
            provider_isolation=isolation,
        )
    command = observed["command"]
    assert isinstance(command, list)
    assert not Path(command[0]).exists()
    environment = observed["environment"]
    assert isinstance(environment, dict)
    assert "PATH" not in environment
    assert observed["provider_launch_kwargs"] == {
        "user": isolation.uid,
        "group": isolation.gid,
        "extra_groups": (),
        "umask": 0o077,
    }


def _metadata(mode: int, *, uid: int = 0, gid: int = 0) -> os.stat_result:
    return os.stat_result((mode, 1, 1, 1, uid, gid, 0, 0, 0, 0))


def test_signing_key_metadata_proof_does_not_open_key_and_rejects_writable_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    isolation = _isolation(tmp_path)
    key = (tmp_path / "admission.key").resolve()
    key.write_bytes(b"never-opened-by-metadata-proof")
    key.chmod(0o600)
    parents: list[str] = []
    parent = os.path.dirname(str(key))
    while True:
        parents.append(parent)
        next_parent = os.path.dirname(parent)
        if next_parent == parent:
            break
        parent = next_parent

    real_lstat = os.lstat
    directory_modes = {path: _metadata(stat.S_IFDIR | 0o755) for path in parents}

    def metadata(path: str | bytes | os.PathLike[str] | os.PathLike[bytes]) -> os.stat_result:
        normalized = os.fspath(path)
        if isinstance(normalized, bytes):
            normalized = os.fsdecode(normalized)
        if normalized == str(key):
            return _metadata(stat.S_IFREG | 0o600)
        if normalized in directory_modes:
            return directory_modes[normalized]
        return real_lstat(path)

    monkeypatch.setattr(github_attestation, "_provider_posix_identity", lambda: (0, 0))
    monkeypatch.setattr(github_attestation.os, "lstat", metadata)
    monkeypatch.setattr(
        github_attestation.os,
        "open",
        lambda *_args, **_kwargs: pytest.fail("signing-key contents were opened"),
    )
    assert (
        github_attestation.validate_provider_isolated_signing_key_path(
            str(key), isolation
        )
        == str(key)
    )

    directory_modes[parents[0]] = _metadata(
        stat.S_IFDIR | 0o770,
        gid=isolation.gid,
    )
    with pytest.raises(
        github_attestation.GitHubAttestationError,
        match="writable by the lowered identity",
    ):
        github_attestation.validate_provider_isolated_signing_key_path(
            str(key), isolation
        )


def test_cli_provider_isolation_is_all_or_nothing(tmp_path: Path) -> None:
    executable, digest = _executable(tmp_path)
    assert (
        cli_module._github_attestation_provider_isolation(
            argparse.Namespace(
                gh_executable=str(executable),
                gh_executable_sha256=None,
                provider_isolation_uid=None,
                provider_isolation_gid=None,
            )
        )
        is None
    )
    with pytest.raises(ValueError, match="must be supplied together"):
        cli_module._github_attestation_provider_isolation(
            argparse.Namespace(
                gh_executable=str(executable),
                gh_executable_sha256=digest,
                provider_isolation_uid=2001,
                provider_isolation_gid=None,
            )
        )
