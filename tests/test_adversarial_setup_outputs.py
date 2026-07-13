# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Adversarial setup-output continuity across repo-suite and pack phases."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import evoom_guard.verifiers.repo_verifier as repo_verifier_module
from evoom_guard.guard import guard
from evoom_guard.runtime_identity import (
    RUNTIME_DIGEST_FORMAT,
    RuntimeIdentityError,
    capture_runtime_identity,
    verify_runtime_identity,
)
from evoom_guard.verifiers.fidelity import (
    _setup_fidelity_changes,
    _setup_fidelity_snapshot,
)
from evoom_guard.verifiers.repo_verifier import RepoVerifier


@pytest.mark.parametrize(
    ("output_dir", "member"),
    (
        ("node_modules", "pkg/index.js"),
        (".venv", "lib/site.py"),
    ),
)
def test_setup_created_default_output_is_bound_after_setup(
    tmp_path, output_dir: str, member: str
) -> None:
    """Setup may create conventional outputs, but later phases may not drift them."""
    (tmp_path / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    pre_setup = _setup_fidelity_snapshot(str(tmp_path))

    runtime_file = tmp_path / output_dir / member
    runtime_file.parent.mkdir(parents=True)
    runtime_file.write_text("trusted setup bytes\n", encoding="utf-8")

    # Setup fidelity still permits a newly created conventional output.
    post_setup = _setup_fidelity_snapshot(str(tmp_path), baseline=pre_setup)
    assert _setup_fidelity_changes(pre_setup, post_setup) == []
    assert all(
        path != output_dir and not path.startswith(output_dir + "/")
        for path in post_setup
    )

    # The separate post-setup runtime identity is deliberately full.
    accepted_runtime = capture_runtime_identity(str(tmp_path))
    assert f"{output_dir}/{member}" in {
        record.path for record in accepted_runtime.records
    }
    runtime_file.write_text("suite-mutated bytes\n", encoding="utf-8")
    _observed, changes = verify_runtime_identity(str(tmp_path), accepted_runtime)
    assert changes == [f"{output_dir}/{member}"]


def test_preexisting_default_output_remains_bound_during_setup(tmp_path) -> None:
    runtime_file = tmp_path / "node_modules" / "pkg" / "index.js"
    runtime_file.parent.mkdir(parents=True)
    runtime_file.write_text("checked-in bytes\n", encoding="utf-8")

    before = _setup_fidelity_snapshot(str(tmp_path))
    runtime_file.write_text("setup-mutated bytes\n", encoding="utf-8")
    after = _setup_fidelity_snapshot(str(tmp_path), baseline=before)
    assert _setup_fidelity_changes(before, after) == ["node_modules/pkg/index.js"]


def test_setup_output_glob_does_not_weaken_runtime_continuity(tmp_path) -> None:
    """Trusted setup exclusions end when the accepted runtime identity is taken."""
    generated = tmp_path / "generated" / "runtime.bin"
    generated.parent.mkdir()
    generated.write_bytes(b"initial")
    output_globs = ("generated/**",)

    setup_before = _setup_fidelity_snapshot(str(tmp_path), output_globs)
    generated.write_bytes(b"created by setup")
    setup_after = _setup_fidelity_snapshot(
        str(tmp_path), output_globs, baseline=setup_before
    )
    assert _setup_fidelity_changes(setup_before, setup_after) == []

    accepted_runtime = capture_runtime_identity(str(tmp_path))
    generated.write_bytes(b"suite mutation")
    _observed, changes = verify_runtime_identity(str(tmp_path), accepted_runtime)
    assert changes == ["generated/runtime.bin"]


def _make_repo_and_pack(tmp_path: Path, pack_body: str) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "test_runtime.py").write_text(pack_body, encoding="utf-8")
    return repo, pack


def _setup_command() -> list[str]:
    return [
        sys.executable,
        "-c",
        (
            "from pathlib import Path; "
            "p=Path('node_modules/pkg/runtime.txt'); "
            "p.parent.mkdir(parents=True); p.write_text('trusted\\n')"
        ),
    ]


def _candidate() -> str:
    return "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>"


def test_suite_runtime_drift_blocks_pack_before_it_runs(tmp_path) -> None:
    sentinel = tmp_path / "pack-ran"
    repo, pack = _make_repo_and_pack(
        tmp_path,
        (
            "from pathlib import Path\n"
            "def test_runtime():\n"
            f"    Path({str(sentinel)!r}).write_text('ran')\n"
            "    assert Path('node_modules/pkg/runtime.txt').read_text() == 'trusted\\n'\n"
        ),
    )
    suite_mutation = [
        sys.executable,
        "-c",
        "open('node_modules/pkg/runtime.txt','w').write('mutated\\n')",
    ]

    result = RepoVerifier(
        setup_command=_setup_command(),
        test_command=suite_mutation,
        mem_limit_mb=0,
    ).verify(_candidate(), {"repo_path": str(repo), "verifier_pack": str(pack)})

    assert not result.passed
    assert result.artifact["outcome"] == "candidate_tree_changed"
    assert result.artifact["tamper"] is True
    assert result.artifact["candidate_fidelity_changes"] == [
        "node_modules/pkg/runtime.txt"
    ]
    assert result.artifact["runtime_continuity"] == "verification_failed"
    assert not sentinel.exists(), "pack must not run after pre-pack runtime drift"


def test_unchanged_setup_runtime_passes_repo_and_pack(tmp_path) -> None:
    repo, pack = _make_repo_and_pack(
        tmp_path,
        (
            "from pathlib import Path\n"
            "def test_runtime():\n"
            "    assert Path('node_modules/pkg/runtime.txt').read_text() == 'trusted\\n'\n"
        ),
    )
    result = RepoVerifier(
        setup_command=_setup_command(),
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        mem_limit_mb=0,
    ).verify(_candidate(), {"repo_path": str(repo), "verifier_pack": str(pack)})

    assert result.passed, result.diagnostics
    assert result.artifact["runtime_tree_sha256"]
    assert result.artifact["runtime_tree_digest_format"] == RUNTIME_DIGEST_FORMAT
    assert result.artifact["runtime_tree_entries"] >= 5
    assert result.artifact["runtime_tree_bytes"] > 0
    assert result.artifact["runtime_identity_elapsed_ms"] > 0
    assert result.artifact["runtime_continuity"] == "snapshot_boundary_checked"


def test_pack_runtime_mutation_is_detected_after_pack(tmp_path) -> None:
    repo, pack = _make_repo_and_pack(
        tmp_path,
        (
            "from pathlib import Path\n"
            "def test_runtime():\n"
            "    p=Path('node_modules/pkg/runtime.txt')\n"
            "    assert p.read_text() == 'trusted\\n'\n"
            "    p.write_text('pack mutation\\n')\n"
        ),
    )
    result = RepoVerifier(
        setup_command=_setup_command(),
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        mem_limit_mb=0,
    ).verify(_candidate(), {"repo_path": str(repo), "verifier_pack": str(pack)})

    assert not result.passed
    assert result.artifact["outcome"] == "candidate_tree_changed"
    assert result.artifact["tamper"] is True
    assert result.artifact["candidate_fidelity_changes"] == [
        "node_modules/pkg/runtime.txt"
    ]
    assert result.artifact["runtime_continuity"] == "verification_failed"


def test_runtime_capture_failure_is_not_claimed_as_delivered(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, pack = _make_repo_and_pack(tmp_path, "def test_pack():\n    assert True\n")

    def fail_capture(_root: str):
        raise RuntimeIdentityError("controlled capture failure")

    monkeypatch.setattr(repo_verifier_module, "capture_runtime_identity", fail_capture)
    result = RepoVerifier(
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        mem_limit_mb=0,
    ).verify(_candidate(), {"repo_path": str(repo), "verifier_pack": str(pack)})

    assert not result.passed
    assert result.artifact["outcome"] == "runtime_identity_unavailable"
    assert result.artifact["runtime_tree_sha256"] is None
    assert result.artifact["runtime_continuity"] == "unavailable"

    guarded = guard(
        str(repo),
        _candidate(),
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        verifier_pack=str(pack),
        mem_limit_mb=0,
    )
    assert guarded.verdict == "ERROR"
    assert guarded.reason_code == "assurance_requirement_not_met"
    assert guarded.attestation is not None
    assert guarded.attestation["runtime_continuity"] == "unavailable"
    assert guarded.assurance is not None
    assert guarded.assurance["runtime_continuity"] == "unavailable"


def test_suite_timeout_preserves_incomplete_runtime_evidence(tmp_path) -> None:
    repo, pack = _make_repo_and_pack(tmp_path, "def test_pack():\n    assert True\n")
    result = RepoVerifier(
        test_command=[sys.executable, "-c", "import time; time.sleep(5)"],
        timeout=1,
        mem_limit_mb=0,
    ).verify(_candidate(), {"repo_path": str(repo), "verifier_pack": str(pack)})

    assert not result.passed
    assert result.artifact["outcome"] == "test_timeout"
    assert result.artifact["runtime_tree_sha256"]
    assert result.artifact["runtime_continuity"] == "incomplete"


def test_runtime_continuity_is_not_applicable_without_a_pack(tmp_path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    result = RepoVerifier(
        setup_command=_setup_command(),
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        mem_limit_mb=0,
    ).verify(_candidate(), {"repo_path": str(repo)})

    assert result.passed, result.diagnostics
    assert result.artifact["runtime_continuity"] == "not_applicable"
    assert result.artifact["runtime_tree_sha256"] is None
    assert result.artifact["runtime_tree_digest_format"] is None
    assert result.artifact["runtime_tree_entries"] is None
    assert result.artifact["runtime_tree_bytes"] is None
    assert result.artifact["runtime_identity_elapsed_ms"] == 0.0


def test_guard_attests_the_delivered_runtime_continuity(tmp_path) -> None:
    repo, pack = _make_repo_and_pack(
        tmp_path,
        "def test_runtime_contract():\n    assert True\n",
    )

    result = guard(
        str(repo),
        _candidate(),
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        verifier_pack=str(pack),
        mem_limit_mb=0,
    )

    assert result.passed, result.reason
    assert result.attestation is not None
    assert result.attestation["runtime_tree_sha256"]
    assert (
        result.attestation["runtime_tree_digest_format"]
        == RUNTIME_DIGEST_FORMAT
    )
    assert result.attestation["runtime_tree_entries"] >= 2
    assert result.attestation["runtime_tree_bytes"] > 0
    assert result.attestation["runtime_identity_elapsed_ms"] > 0
    assert result.attestation["runtime_continuity"] == "snapshot_boundary_checked"
    assert result.assurance is not None
    assert result.assurance["runtime_continuity"] == "snapshot_boundary_checked"
