from __future__ import annotations

import hashlib
import io
import os
import shutil
import subprocess
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from evoom_guard import finalizer_derivation
from evoom_guard.finalizer_derivation import (
    FinalizerDerivationError,
    GitExecutablePin,
    _git_command,
    _GitReader,
    derive_finalizer_bindings,
    derive_raw_evaluation_bindings,
    derive_raw_ref_parent_pair,
    git_executable_pin,
    resolve_raw_git_regular_blob,
)


def _enable_posix_snapshot_seam(
    monkeypatch: pytest.MonkeyPatch,
    *,
    snapshot_root: Path | None = None,
) -> None:
    monkeypatch.setattr(
        finalizer_derivation,
        "_git_executable_pinning_supported",
        lambda: True,
    )
    if snapshot_root is not None:
        temporary_directory = finalizer_derivation.tempfile.TemporaryDirectory
        canonical_root = str(snapshot_root.resolve())
        monkeypatch.setattr(
            finalizer_derivation.tempfile,
            "TemporaryDirectory",
            lambda *, prefix: temporary_directory(prefix=prefix, dir=canonical_root),
        )


def _fake_executable(tmp_path: Path, payload: bytes = b"reviewed-git-executable\n") -> Path:
    executable = tmp_path / ("reviewed-git.exe" if os.name == "nt" else "reviewed-git")
    executable.write_bytes(payload)
    executable.chmod(0o700)
    return executable.resolve()


def _pin(path: Path) -> GitExecutablePin:
    return git_executable_pin(
        str(path),
        hashlib.sha256(path.read_bytes()).hexdigest(),
    )


class _FinishedGit:
    def __init__(self, output: bytes = b"literal-output\n") -> None:
        self.stdout = io.BytesIO(output)
        self.stderr = io.BytesIO()
        self.returncode = 0

    def poll(self) -> int:
        return 0

    def wait(self, *, timeout: float | None = None) -> int:
        assert timeout == finalizer_derivation._GIT_KILL_REAP_SECONDS
        return 0


def _mock_successful_git(
    monkeypatch: pytest.MonkeyPatch,
    observed: list[list[str]],
) -> None:
    def fake_popen(command: list[str], **_kwargs: object) -> _FinishedGit:
        observed.append(command)
        executable = Path(command[0])
        assert executable.is_absolute()
        assert executable.is_file()
        assert executable.read_bytes() == b"reviewed-git-executable\n"
        return _FinishedGit()

    monkeypatch.setattr(finalizer_derivation.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(finalizer_derivation, "terminate_process_tree", lambda *_args: True)


def test_git_executable_pin_fails_closed_without_posix_snapshot_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = _fake_executable(tmp_path)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    monkeypatch.setattr(
        finalizer_derivation,
        "_git_executable_pinning_supported",
        lambda: False,
    )

    with pytest.raises(FinalizerDerivationError, match="requires POSIX stable-snapshot"):
        git_executable_pin(str(executable), digest)


def test_git_executable_pin_validates_path_type_digest_and_frozen_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_posix_snapshot_seam(monkeypatch, snapshot_root=tmp_path)
    executable = _fake_executable(tmp_path)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()

    pin = GitExecutablePin(str(executable), digest)
    assert git_executable_pin(str(executable), digest) == pin
    with pytest.raises(FrozenInstanceError):
        pin.executable_path = "git"  # type: ignore[misc]
    with pytest.raises(FinalizerDerivationError, match="absolute path"):
        git_executable_pin("git", digest)
    noncanonical = str(executable.parent) + os.sep + "." + os.sep + executable.name
    with pytest.raises(FinalizerDerivationError, match="canonical"):
        git_executable_pin(noncanonical, digest)
    with pytest.raises(FinalizerDerivationError, match="lowercase 64-hex"):
        git_executable_pin(str(executable), digest.upper())
    with pytest.raises(FinalizerDerivationError, match="does not match"):
        git_executable_pin(str(executable), "0" * 64)
    with pytest.raises(FinalizerDerivationError, match="regular non-symlink"):
        git_executable_pin(str(tmp_path.resolve()), digest)


def test_git_executable_pin_rejects_symlink_non_executable_and_oversize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_posix_snapshot_seam(monkeypatch, snapshot_root=tmp_path)
    executable = _fake_executable(tmp_path)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    link = tmp_path / "git-link"
    try:
        link.symlink_to(executable)
    except OSError:
        link = None
    if link is not None:
        with pytest.raises(FinalizerDerivationError, match="must not traverse symlinks"):
            git_executable_pin(str(link.resolve(strict=False).parent / link.name), digest)

    executable.chmod(0o600)
    if os.name == "posix":
        with pytest.raises(FinalizerDerivationError, match="not executable"):
            git_executable_pin(str(executable), digest)
    executable.chmod(0o700)
    monkeypatch.setattr(
        finalizer_derivation,
        "MAX_GIT_EXECUTABLE_BYTES",
        len(executable.read_bytes()) - 1,
    )
    with pytest.raises(FinalizerDerivationError, match="bounded size"):
        git_executable_pin(str(executable), digest)


def test_raw_git_command_executes_private_pinned_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_posix_snapshot_seam(monkeypatch, snapshot_root=tmp_path)
    executable = _fake_executable(tmp_path)
    pin = _pin(executable)
    observed: list[list[str]] = []
    _mock_successful_git(monkeypatch, observed)

    output = _git_command(
        str(tmp_path),
        ["rev-parse", "HEAD"],
        bare=False,
        git_executable=pin,
    )

    assert output == b"literal-output\n"
    assert len(observed) == 1
    snapshot = Path(observed[0][0])
    assert snapshot != executable
    assert snapshot.name == ("git.exe" if os.name == "nt" else "git")
    assert not snapshot.exists()
    assert observed[0][1:] == [
        "--no-replace-objects",
        "-C",
        str(tmp_path),
        "rev-parse",
        "HEAD",
    ]


def test_pinned_git_uses_closed_loader_and_configuration_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_posix_snapshot_seam(monkeypatch, snapshot_root=tmp_path)
    executable = _fake_executable(tmp_path)
    pin = _pin(executable)
    for name in (
        "LD_PRELOAD",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "PATH",
        "HOME",
        "XDG_CONFIG_HOME",
        "PYTHONPATH",
    ):
        monkeypatch.setenv(name, "candidate-controlled")
    observed: dict[str, object] = {}

    def fake_popen(command: list[str], **kwargs: object) -> _FinishedGit:
        observed["command"] = command
        observed["environment"] = kwargs["env"]
        return _FinishedGit()

    monkeypatch.setattr(finalizer_derivation.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(finalizer_derivation, "terminate_process_tree", lambda *_args: True)

    assert (
        _git_command(
            str(tmp_path),
            ["rev-parse", "HEAD"],
            bare=False,
            git_executable=pin,
        )
        == b"literal-output\n"
    )
    environment = observed["environment"]
    assert isinstance(environment, dict)
    expected_names = {
        "GIT_OPTIONAL_LOCKS",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_ATTR_NOSYSTEM",
        "GIT_TERMINAL_PROMPT",
        "LC_ALL",
        "LANG",
    }
    if os.name == "nt":
        expected_names.update(
            name for name in ("SYSTEMROOT", "WINDIR") if name in os.environ
        )
    assert set(environment) == expected_names
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_GLOBAL"] == os.devnull
    assert environment["LC_ALL"] == "C"


def test_raw_git_reader_reuses_one_snapshot_and_never_falls_back_after_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_posix_snapshot_seam(monkeypatch, snapshot_root=tmp_path)
    executable = _fake_executable(tmp_path)
    pin = _pin(executable)
    repository = tmp_path / "repository"
    repository.mkdir()
    observed: list[list[str]] = []
    _mock_successful_git(monkeypatch, observed)

    with _GitReader(str(repository), bare=False, git_executable=pin) as reader:
        reader.command(["rev-parse", "HEAD"])
        reader.command(["rev-parse", "HEAD"])
        snapshot = Path(observed[0][0])
        assert snapshot.exists()
        assert [command[0] for command in observed] == [str(snapshot), str(snapshot)]

    assert not snapshot.exists()
    with pytest.raises(FinalizerDerivationError, match="reader is closed"):
        reader.command(["rev-parse", "HEAD"])


def test_mutation_after_pin_is_rejected_before_git_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_posix_snapshot_seam(monkeypatch, snapshot_root=tmp_path)
    executable = _fake_executable(tmp_path)
    pin = _pin(executable)
    executable.write_bytes(b"unreviewed-git-executable\n")
    executable.chmod(0o700)

    def must_not_launch(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("unpinned executable bytes must not launch")

    monkeypatch.setattr(finalizer_derivation.subprocess, "Popen", must_not_launch)
    with pytest.raises(FinalizerDerivationError, match="does not match"):
        _git_command(
            str(tmp_path),
            ["rev-parse", "HEAD"],
            bare=False,
            git_executable=pin,
        )


def _git(directory: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(directory), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@pytest.mark.skipif(os.name != "posix", reason="pinned execution requires POSIX snapshots")
def test_public_raw_derivation_functions_propagate_real_git_pin(tmp_path: Path) -> None:
    discovered = shutil.which("git")
    if discovered is None:  # pragma: no cover - suite already requires Git
        pytest.skip("Git is unavailable")
    executable = Path(discovered).resolve()
    pin = _pin(executable)
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    (repository / ".evoguard.json").write_text("{}\n", encoding="utf-8")
    (repository / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(repository, "add", "--all")
    _git(
        repository,
        "-c",
        "user.name=EvoGuard Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        "base",
    )
    base = _git(repository, "rev-parse", "HEAD")
    (repository / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    _git(repository, "add", "--all")
    _git(
        repository,
        "-c",
        "user.name=EvoGuard Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        "head",
    )
    head = _git(repository, "rev-parse", "HEAD")
    base_tree = _git(repository, "rev-parse", f"{base}^{{tree}}")
    head_tree = _git(repository, "rev-parse", f"{head}^{{tree}}")
    ref = _git(repository, "symbolic-ref", "HEAD")

    pair = derive_raw_ref_parent_pair(
        repository=str(repository),
        ref=ref,
        git_executable=pin,
    )
    workflow_blob = resolve_raw_git_regular_blob(
        repository=str(repository),
        treeish=head_tree,
        path="app.py",
        git_executable=pin,
    )
    raw = derive_raw_evaluation_bindings(
        base_repo=str(repository),
        head_repo=str(repository),
        base_sha=base,
        head_sha=head,
        base_tree_sha=base_tree,
        head_tree_sha=head_tree,
        git_executable=pin,
    )
    bindings = derive_finalizer_bindings(
        base_repo=str(repository),
        head_repo=str(repository),
        base_sha=base,
        head_sha=head,
        base_tree_sha=base_tree,
        head_tree_sha=head_tree,
        source={
            "pull_request_number": 1,
            "workflow_run_id": "1",
            "workflow_run_attempt": 1,
            "base_sha": base,
            "head_sha": head,
        },
        repository="owner/repository",
        repository_id="1",
        guard_artifact_sha256="a" * 64,
        git_executable=pin,
    )

    assert pair == (head, head_tree, base, base_tree)
    assert workflow_blob == _git(repository, "rev-parse", f"{head}:app.py")
    assert bindings.candidate_sha256 == raw["candidate_sha256"]
