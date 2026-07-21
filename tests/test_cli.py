# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""CLI surface tests — `evo-guard guard` / `doctor` / `version`.

Exercises the command dispatch, the three guard input modes wired through the
parser, stdin reading (`-`), and the report/JSON output paths. The end-to-end
paths that run the repo's suite are skipped when pytest is unavailable, matching
the convention in ``test_guard.py``.
"""

import difflib
import importlib.util
import io
import json
import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard import __version__, cli
from evoom_guard.pack_manifest import pack_digest

HAS_PYTEST = importlib.util.find_spec("pytest") is not None
needs_pytest = pytest.mark.skipif(not HAS_PYTEST, reason="needs pytest to run the suite")

# A buggy package + a visible test that wants dbl(3) == 6 (matches test_guard.py).
_BUG = "def dbl(x):\n    return x + x + 1\n"
_FIXED = "def dbl(x):\n    return x + x\n"
_TEST = "from pkg.m import dbl\n\n\ndef test_dbl():\n    assert dbl(3) == 6\n"
FIX_BLOCK = "<<<FILE: pkg/m.py>>>\ndef dbl(x):\n    return x + x\n<<<END FILE>>>"


def _make_repo(root: str, *, m_body: str = _BUG) -> None:
    os.makedirs(os.path.join(root, "pkg"))
    os.makedirs(os.path.join(root, "tests"))
    open(os.path.join(root, "pkg", "__init__.py"), "w").close()
    with open(os.path.join(root, "pkg", "m.py"), "w", encoding="utf-8") as f:
        f.write(m_body)
    with open(os.path.join(root, "tests", "test_m.py"), "w", encoding="utf-8") as f:
        f.write(_TEST)


# ───────────────────────────── helpers / dispatch ───────────────────────────
def test_read_text_stdin(monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("from-stdin"))
    assert cli._read_text("-") == "from-stdin"


def test_read_text_file(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("on-disk", encoding="utf-8")
    assert cli._read_text(str(p)) == "on-disk"


def test_version_command(capsys):
    assert cli.main(["version"]) == 0
    assert __version__ in capsys.readouterr().out


def test_doctor_text(capsys):
    rc = cli.main(["doctor"])
    out = capsys.readouterr().out
    assert "evoguard" in out
    assert rc in (0, 1)  # 0 when git/patch present


def test_doctor_json(capsys):
    assert cli.main(["doctor", "--json"]) in (0, 1)
    info = json.loads(capsys.readouterr().out)
    assert info["tool"] == "evoguard"
    assert "supported" in info


def test_guard_missing_args_is_usage(capsys):
    assert cli.main(["guard"]) == 2
    assert "usage" in capsys.readouterr().out.lower()


def test_guard_parser_accepts_docker_network():
    # ``None`` means "defer to trusted policy"; cmd_guard supplies the safe
    # ``none`` fallback only after that policy has been loaded.
    args = cli.build_parser().parse_args(["guard", ".", "--patch", "-"])
    assert args.docker_network is None
    args = cli.build_parser().parse_args(
        ["guard", ".", "--patch", "-", "--docker-network", "mynet"]
    )
    assert args.docker_network == "mynet"


def test_trusted_config_forwards_full_runtime_policy_to_guard(tmp_path, monkeypatch):
    """Policy knobs omitted from CLI flags still reach the trusted judge call."""
    from evoom_guard.guard import PASS, GuardResult

    repo = tmp_path / "repo"
    repo.mkdir()
    patch = tmp_path / "candidate.txt"
    patch.write_text("<<<FILE: app.py>>>\nvalue = 2\n<<<END FILE>>>", encoding="utf-8")
    (repo / ".evoguard.json").write_text(
        json.dumps(
            {
                "strict_harness": True,
                "isolation": "docker",
                "docker_image": "judge:latest",
                "docker_network": "none",
                "blackbox": True,
                "blackbox_only": True,
                "diff_coverage": True,
                "baseline_evidence": True,
                "require_demonstrated_fix": True,
            }
        ),
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    def fake_guard(_repo, _candidate, **kwargs):
        captured.update(kwargs)
        return GuardResult(
            PASS, True, "stub", ["app.py"], [], "low", 0.0,
            verdict_source="exit",
        )

    monkeypatch.setattr("evoom_guard.guard.guard", fake_guard)
    args = cli.build_parser().parse_args(["guard", str(repo), "--patch", str(patch)])

    assert cli.cmd_guard(args, out=lambda _message: None) == 0
    assert {
        key: captured[key]
        for key in (
            "strict_harness",
            "isolation",
            "docker_image",
            "docker_network",
            "blackbox",
            "blackbox_only",
            "diff_coverage",
            "baseline_evidence",
            "require_demonstrated_fix",
        )
    } == {
        "strict_harness": True,
        "isolation": "docker",
        "docker_image": "judge:latest",
        "docker_network": "none",
        "blackbox": True,
        "blackbox_only": True,
        "diff_coverage": True,
        "baseline_evidence": True,
        "require_demonstrated_fix": True,
    }


def test_guard_docker_isolation_requires_image(capsys):
    # --isolation docker without --docker-image is a usage error (exit 2).
    assert cli.main(["guard", ".", "--patch", "-", "--isolation", "docker"]) == 2
    assert "docker-image" in capsys.readouterr().out


def test_blackbox_only_requires_blackbox(capsys):
    assert cli.main(["guard", ".", "--patch", "-", "--blackbox-only"]) == 2
    assert "--blackbox-only requires --blackbox" in capsys.readouterr().out


# ───────────────────────────── guard input modes ────────────────────────────
@needs_pytest
def test_guard_patch_via_stdin(tmp_path, monkeypatch, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    _make_repo(str(repo))
    monkeypatch.setattr(sys, "stdin", io.StringIO(FIX_BLOCK))
    assert cli.main(["guard", str(repo), "--patch", "-"]) == 0
    assert "PASS" in capsys.readouterr().out


@needs_pytest
def test_guard_base_head_mode(tmp_path, capsys):
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    _make_repo(str(base), m_body=_BUG)     # base fails the visible test
    _make_repo(str(head), m_body=_FIXED)   # head fixes it
    assert cli.main(["guard", "--base", str(base), "--head", str(head)]) == 0
    out = capsys.readouterr().out
    assert "PASS" in out and "base/head" in out


def test_base_head_rejects_a_candidate_controlled_verifier_pack(tmp_path):
    """The CLI must not snapshot a verifier from the untrusted head checkout."""
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    _make_repo(str(base), m_body=_BUG)
    shutil.copytree(base, head)
    (head / "pkg" / "m.py").write_text(_FIXED, encoding="utf-8")
    pack = head / "judge-pack"
    pack.mkdir()
    (pack / "test_invariant.py").write_text(
        "def test_invariant():\n    assert True\n", encoding="utf-8"
    )
    verdict = tmp_path / "verdict.json"

    assert (
        cli.main(
            [
                "guard",
                "--base", str(base),
                "--head", str(head),
                "--verifier-pack", str(pack),
                "--expect-verifier-pack-sha256", "0" * 64,
                "--json", str(verdict),
            ]
        )
        == 1
    )
    record = json.loads(verdict.read_text(encoding="utf-8"))
    assert record["verdict"] == "ERROR"
    assert record["reason_code"] == "verifier_pack_invalid"
    assert record["source"] == "base/head"
    assert record["test_command_ran"] is False


@needs_pytest
def test_base_head_uses_a_pack_resolved_from_the_trusted_base_policy(tmp_path):
    """A relative policy pack resolves from base, not from the untrusted head."""
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    _make_repo(str(base), m_body=_BUG)
    pack = base / "security" / "judge-pack"
    pack.mkdir(parents=True)
    (pack / "test_invariant.py").write_text(
        "def test_independent_invariant():\n    assert True\n", encoding="utf-8"
    )
    (base / ".evoguard.json").write_text(
        json.dumps(
            {
                "verifier_pack": "security/judge-pack",
                "expect_verifier_pack_sha256": pack_digest(str(pack)),
            }
        ),
        encoding="utf-8",
    )
    shutil.copytree(base, head)
    (head / "pkg" / "m.py").write_text(_FIXED, encoding="utf-8")
    verdict = tmp_path / "verdict.json"

    assert cli.main(["guard", "--base", str(base), "--head", str(head),
                     "--json", str(verdict)]) == 0
    record = json.loads(verdict.read_text(encoding="utf-8"))
    assert record["verdict"] == "PASS"
    assert record["attestation"]["verifier_pack_sha256"] == pack_digest(str(pack))
    assert record["verdict_source"] == "composite:repo+verifier-pack"


@needs_pytest
def test_base_head_uses_baseline_policy_and_rejects_candidate_self_amendment(tmp_path):
    """A candidate policy cannot replace the baseline's judge command or allowlist."""
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    _make_repo(str(base), m_body=_FIXED)
    base_policy = {
        "test_command": [sys.executable, "-m", "pytest", "-q"],
    }
    (base / ".evoguard.json").write_text(json.dumps(base_policy), encoding="utf-8")
    shutil.copytree(base, head)
    (head / "pkg" / "m.py").write_text(_BUG, encoding="utf-8")
    (head / ".evoguard.json").write_text(
        json.dumps(
            {
                "allow": [".evoguard.json", "tests/*"],
                "test_command": [sys.executable, "-c", "raise SystemExit(0)"],
            }
        ),
        encoding="utf-8",
    )
    verdict = tmp_path / "verdict.json"

    assert (
        cli.main(
            [
                "guard",
                "--base",
                str(base),
                "--head",
                str(head),
                "--json",
                str(verdict),
            ]
        )
        == 1
    )
    record = json.loads(verdict.read_text(encoding="utf-8"))
    assert record["verdict"] == "REJECTED"
    assert record["test_command_ran"] is False
    assert ".evoguard.json" in record["protected_violations"]


@needs_pytest
def test_patch_mode_reads_policy_from_repo_not_current_working_directory(tmp_path, monkeypatch):
    """The text-patch form has a base repo too; cwd must not supply its policy."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _make_repo(str(repo), m_body=_FIXED)
    (repo / ".evoguard.json").write_text(
        json.dumps({"test_command": [sys.executable, "-m", "pytest", "-q"]}),
        encoding="utf-8",
    )
    candidate_cwd = tmp_path / "candidate-cwd"
    candidate_cwd.mkdir()
    (candidate_cwd / ".evoguard.json").write_text(
        json.dumps({"test_command": [sys.executable, "-c", "raise SystemExit(0)"]}),
        encoding="utf-8",
    )
    patch = tmp_path / "candidate.patch"
    patch.write_text(
        "<<<FILE: pkg/m.py>>>\ndef dbl(x):\n    return 999\n<<<END FILE>>>",
        encoding="utf-8",
    )
    monkeypatch.chdir(candidate_cwd)

    assert cli.main(["guard", str(repo), "--patch", str(patch)]) == 1


def test_diff_requires_trusted_config_or_explicit_no_config(tmp_path, capsys):
    head = tmp_path / "head"
    head.mkdir()
    diff = tmp_path / "change.diff"
    diff.write_text("diff --git a/x.py b/x.py\n", encoding="utf-8")
    assert cli.main(["guard", str(head), "--diff", str(diff)]) == 2
    assert "--diff requires" in capsys.readouterr().out


@needs_pytest
def test_diff_uses_external_trusted_policy_and_rejects_candidate_policy_change(tmp_path):
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    _make_repo(str(base), m_body=_FIXED)
    trusted = json.dumps({"test_command": [sys.executable, "-m", "pytest", "-q"]}) + "\n"
    (base / ".evoguard.json").write_text(trusted, encoding="utf-8")
    shutil.copytree(base, head)
    (head / "pkg" / "m.py").write_text(_BUG, encoding="utf-8")
    forged = json.dumps(
        {
            "allow": [".evoguard.json", "tests/*"],
            "test_command": [sys.executable, "-c", "raise SystemExit(0)"],
        }
    ) + "\n"
    (head / ".evoguard.json").write_text(forged, encoding="utf-8")
    diff = "".join(
        (
            "".join(
                difflib.unified_diff(
                    _FIXED.splitlines(True),
                    _BUG.splitlines(True),
                    fromfile="a/pkg/m.py",
                    tofile="b/pkg/m.py",
                )
            ),
            "".join(
                difflib.unified_diff(
                    trusted.splitlines(True),
                    forged.splitlines(True),
                    fromfile="a/.evoguard.json",
                    tofile="b/.evoguard.json",
                )
            ),
        )
    )
    patch = tmp_path / "change.diff"
    patch.write_text(diff, encoding="utf-8")
    trusted_config = tmp_path / "trusted-base-policy.json"
    trusted_config.write_text(trusted, encoding="utf-8")
    verdict = tmp_path / "verdict.json"

    assert (
        cli.main(
            [
                "guard",
                str(head),
                "--diff",
                str(patch),
                "--config",
                str(trusted_config),
                "--json",
                str(verdict),
            ]
        )
        == 1
    )
    record = json.loads(verdict.read_text(encoding="utf-8"))
    assert record["verdict"] == "REJECTED"
    assert record["test_command_ran"] is False
    assert ".evoguard.json" in record["protected_violations"]


def test_explicit_missing_config_fails_closed(tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    patch = tmp_path / "candidate.patch"
    patch.write_text("<<<FILE: app.py>>>\nx = 1\n<<<END FILE>>>", encoding="utf-8")
    missing = tmp_path / "missing-policy.json"
    assert cli.main(["guard", str(repo), "--patch", str(patch), "--config", str(missing)]) == 2
    assert "trusted policy file does not exist" in capsys.readouterr().out


def test_diff_rejects_an_explicit_config_inside_candidate_checkout(tmp_path, capsys):
    head = tmp_path / "head"
    head.mkdir()
    candidate_config = head / ".evoguard.json"
    candidate_config.write_text("{}", encoding="utf-8")
    diff = tmp_path / "change.diff"
    diff.write_text("diff --git a/x.py b/x.py\n", encoding="utf-8")
    assert (
        cli.main(
            [
                "guard",
                str(head),
                "--diff",
                str(diff),
                "--config",
                str(candidate_config),
            ]
        )
        == 2
    )
    assert "candidate checkout" in capsys.readouterr().out


def test_default_baseline_config_cannot_escape_through_a_symlink(tmp_path):
    """A trusted baseline policy may not be redirected into another tree."""
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    external = tmp_path / "external-policy.json"
    external.write_text("{}", encoding="utf-8")
    try:
        os.symlink(external, base / ".evoguard.json", target_is_directory=False)
    except OSError:
        pytest.skip("this Windows environment does not permit test symlinks")

    args = cli.build_parser().parse_args(
        ["guard", "--base", str(base), "--head", str(head)]
    )
    with pytest.raises(cli.ConfigError, match="must resolve inside"):
        cli._config_path_for_guard(args)


@needs_pytest
def test_guard_writes_report_and_json(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _make_repo(str(repo))
    patch = tmp_path / "cand.patch"
    patch.write_text(FIX_BLOCK, encoding="utf-8")
    report = tmp_path / "out.md"
    verdict = tmp_path / "out.json"
    rc = cli.main(
        ["guard", str(repo), "--patch", str(patch),
         "--report", str(report), "--json", str(verdict)]
    )
    assert rc == 0
    assert report.exists() and "PASS" in report.read_text(encoding="utf-8")
    payload = json.loads(verdict.read_text(encoding="utf-8"))
    assert payload["verdict"] == "PASS"
    assert payload["exit_code"] == 0


# ───────────────────────────── init (workflow scaffold) ─────────────────────
def test_init_writes_workflow(tmp_path, capsys):
    wf = tmp_path / ".github" / "workflows" / "evoguard.yml"
    rc = cli.main(["init", "--path", str(wf), "--test-command", "pytest -q app/", "--ref", "v9.9.9"])
    assert rc == 0
    body = wf.read_text(encoding="utf-8")
    assert "name: EvoGuard" in body
    assert "on:\n  pull_request:" in body
    assert "EvoOM-Guard-m@v9.9.9" in body                 # ref pinned as requested
    assert "test-command:" not in body
    policy = tmp_path / ".evoguard.json"
    assert json.loads(policy.read_text(encoding="utf-8")) == {
        "test_command": "pytest -q app/"
    }
    output = capsys.readouterr().out
    assert "wrote" in output and str(policy) in output


def test_init_requires_an_explicit_immutable_ref(tmp_path, capsys):
    wf = tmp_path / "wf.yml"
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["init", "--path", str(wf)])
    assert excinfo.value.code == 2
    assert "--ref" in capsys.readouterr().err


def test_init_refuses_moving_or_partial_refs(tmp_path):
    for ref in ("main", "v4", "8e11021"):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["init", "--path", str(tmp_path / f"{ref}.yml"), "--ref", ref])
        assert excinfo.value.code == 2


def test_init_accepts_a_full_commit_sha(tmp_path):
    ref = "a" * 40
    wf = tmp_path / "wf.yml"
    assert cli.main(["init", "--path", str(wf), "--ref", ref]) == 0
    assert f"EvoOM-Guard-m@{ref}" in wf.read_text(encoding="utf-8")


def test_init_refuses_to_overwrite_without_force(tmp_path, capsys):
    wf = tmp_path / "wf.yml"
    wf.write_text("keep me", encoding="utf-8")
    rc = cli.main(["init", "--path", str(wf), "--ref", "v9.9.9"])
    assert rc == 1
    assert wf.read_text(encoding="utf-8") == "keep me"   # untouched
    assert "refusing to overwrite" in capsys.readouterr().out


def test_init_force_overwrites(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text("old", encoding="utf-8")
    assert cli.main(["init", "--path", str(wf), "--force", "--ref", "v9.9.9"]) == 0
    assert "name: EvoGuard" in wf.read_text(encoding="utf-8")


def test_init_stdout_does_not_write(tmp_path, capsys):
    wf = tmp_path / "nope.yml"
    assert cli.main(["init", "--path", str(wf), "--stdout", "--ref", "v9.9.9"]) == 0
    assert not wf.exists()                                # nothing written
    assert not (tmp_path / ".evoguard.json").exists()
    assert "name: EvoGuard" in capsys.readouterr().out


def test_init_private_evoguard_generates_pip_workflow(tmp_path, capsys):
    wf = tmp_path / "evoguard.yml"
    rc = cli.main([
        "init", "--path", str(wf),
        "--private-evoguard",
        "--test-command", "pytest -q",
        "--ref", "v1.3.0",
    ])
    assert rc == 0
    body = wf.read_text(encoding="utf-8")
    assert "name: EvoGuard" in body
    assert "pip install" in body
    assert "EVOGUARD_TOKEN" in body
    assert "v1.3.0" in body
    assert "EvoOM-Guard-m@" not in body  # action-based ref NOT present in private mode
    assert 'BASE="${{ github.event.pull_request.base.sha }}"' in body
    assert 'git show "$BASE:.evoguard.json" > "$BASE_POLICY_CONFIG"' in body
    assert 'evo-guard guard . --diff - --config "$BASE_POLICY_CONFIG"' in body
    assert "--no-config" not in body
    assert (
        "github.event.pull_request.head.repo.full_name == github.repository" in body
    )
    assert "github.event.pull_request.user.login != 'dependabot[bot]'" in body
    assert "continue-on-error: true" in body
    assert (
        "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3"
        in body
    )
    assert "actions/github-script@v" not in body
    assert json.loads((tmp_path / ".evoguard.json").read_text(encoding="utf-8")) == {
        "test_command": "pytest -q"
    }


def test_init_preserves_an_existing_policy(tmp_path, capsys):
    wf = tmp_path / ".github" / "workflows" / "evoguard.yml"
    policy = tmp_path / ".evoguard.json"
    policy.write_text('{"test_command": ["custom", "suite"]}\n', encoding="utf-8")

    assert cli.main(["init", "--path", str(wf), "--test-command", "ignored", "--ref", "v9.9.9"]) == 0

    assert json.loads(policy.read_text(encoding="utf-8")) == {
        "test_command": ["custom", "suite"]
    }
    assert "kept existing trusted policy" in capsys.readouterr().out


def test_init_private_custom_secret_name(tmp_path):
    wf = tmp_path / "evoguard.yml"
    cli.main([
        "init", "--path", str(wf),
        "--private-evoguard",
        "--evoguard-token-secret", "MY_PAT", "--ref", "v9.9.9",
    ])
    body = wf.read_text(encoding="utf-8")
    assert "MY_PAT" in body
    assert "EVOGUARD_TOKEN" not in body


@pytest.mark.parametrize("credential_key", ("bad-name", "A B", "${{ x }}", "GITHUB_TOKEN"))
def test_init_private_rejects_an_unsafe_credential_reference(
    tmp_path, capsys, credential_key
):
    wf = tmp_path / "evoguard.yml"

    rc = cli.main([
        "init", "--path", str(wf), "--private-evoguard",
        "--evoguard-token-secret", credential_key, "--ref", "v9.9.9",
    ])

    assert rc == 2
    assert not wf.exists()
    assert "usage: --evoguard-token-secret" in capsys.readouterr().out


# ───────────────────────────── config (.evoguard.json) ──────────────────────
_QUIET = lambda *_a, **_k: None  # noqa: E731 - swallow warnings in unit tests


def test_cli_config_names_are_exact_compatibility_aliases():
    from evoom_guard.policy.config import ConfigError, load_config

    assert cli.ConfigError is ConfigError
    assert cli._load_config is load_config
    assert not hasattr(cli, "load_config")


def test_load_config_retains_unused_output_callback_until_after_read(tmp_path):
    policy = tmp_path / ".evoguard.json"
    policy.write_text('{"timeout": 7}', encoding="utf-8")

    class DeletePolicyWhenReleased:
        def __call__(self, _message: str) -> None:
            pass

        def __del__(self) -> None:
            policy.unlink(missing_ok=True)

    assert cli._load_config(
        str(policy), out=DeletePolicyWhenReleased()
    ) == {"timeout": 7}


def test_load_config_reads_known_keys(tmp_path):
    p = tmp_path / ".evoguard.json"
    p.write_text(json.dumps({
        "test_command": "pytest -q -x", "protected": ["a/*", "b/*"],
        "timeout": 30, "mem_limit": 512,
    }), encoding="utf-8")
    assert cli._load_config(str(p), out=_QUIET) == {
        "test_command": "pytest -q -x", "protected": ["a/*", "b/*"],
        "timeout": 30, "mem_limit": 512,
    }


def test_load_config_missing_file_is_empty(tmp_path):
    assert cli._load_config(str(tmp_path / "nope.json")) == {}


# The config file is protected harness policy: a broken file must STOP the run
# (fail-closed), never silently degrade to weaker defaults (external review).

def test_load_config_invalid_json_is_fail_closed(tmp_path):
    p = tmp_path / ".evoguard.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(cli.ConfigError):
        cli._load_config(str(p), out=_QUIET)


def test_load_config_non_object_is_fail_closed(tmp_path):
    p = tmp_path / ".evoguard.json"
    p.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(cli.ConfigError):
        cli._load_config(str(p), out=_QUIET)


def test_load_config_unknown_key_is_fail_closed(tmp_path):
    # The classic policy typo: the misspelled floor must never be ignored while
    # Guard keeps running WITHOUT the floor the owner believes is enforced.
    p = tmp_path / ".evoguard.json"
    p.write_text(json.dumps({"require_report_isolation": "external"}), encoding="utf-8")
    with pytest.raises(cli.ConfigError, match="unknown key"):
        cli._load_config(str(p), out=_QUIET)


def test_load_config_wrong_typed_keys_are_fail_closed(tmp_path):
    for payload in ({"timeout": "30"}, {"protected": "a/*"}, {"mem_limit": True}):
        p = tmp_path / ".evoguard.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(cli.ConfigError):
            cli._load_config(str(p), out=_QUIET)


def test_load_config_invalid_runtime_ranges_are_fail_closed(tmp_path):
    for payload in ({"timeout": 0}, {"timeout": -1}, {"mem_limit": -1}):
        p = tmp_path / ".evoguard.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(cli.ConfigError):
            cli._load_config(str(p), out=_QUIET)


@pytest.mark.parametrize(
    "flag,value,message",
    [
        ("--timeout", "0", "positive integer"),
        ("--timeout", "-1", "positive integer"),
        ("--mem-limit", "-1", "non-negative integer"),
    ],
)
def test_cmd_guard_rejects_invalid_runtime_ranges(
    tmp_path, capsys, flag, value, message
):
    patch = tmp_path / "candidate.patch"
    patch.write_text("<<<FILE: app.py>>>\nx = 1\n<<<END FILE>>>", encoding="utf-8")
    assert cli.main(["guard", str(tmp_path), "--patch", str(patch), flag, value]) == 2
    assert message in capsys.readouterr().out


@pytest.mark.parametrize("value", ["-1", "100.1", "nan", "inf"])
def test_cmd_guard_rejects_invalid_coverage_floor(tmp_path, capsys, value) -> None:
    patch = tmp_path / "candidate.patch"
    patch.write_text("<<<FILE: app.py>>>\nx = 1\n<<<END FILE>>>", encoding="utf-8")

    code = cli.main(
        [
            "guard",
            str(tmp_path),
            "--patch",
            str(patch),
            "--min-diff-coverage",
            value,
        ]
    )

    assert code == 2
    assert "finite number between 0 and 100" in capsys.readouterr().out


def test_load_config_reads_policy_contract_keys(tmp_path):
    p = tmp_path / ".evoguard.json"
    p.write_text(json.dumps({
        "policy_id": "org/production-strong", "policy_version": "1",
        "require_report_integrity": "external_process_isolated",
        "require_candidate_isolation": "docker",
        "min_diff_coverage": 80,
    }), encoding="utf-8")
    cfg = cli._load_config(str(p), out=_QUIET)
    assert cfg["policy_id"] == "org/production-strong"
    assert cfg["require_report_integrity"] == "external_process_isolated"
    assert cfg["require_candidate_isolation"] == "docker"
    assert cfg["min_diff_coverage"] == 80.0


def test_load_config_invalid_policy_values_are_fail_closed(tmp_path):
    for payload in (
        {"require_report_integrity": "unbreakable"},
        {"require_candidate_isolation": "vm"},
        {"min_diff_coverage": 150},
        {"policy_id": ""},
    ):
        p = tmp_path / ".evoguard.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(cli.ConfigError):
            cli._load_config(str(p), out=_QUIET)


def test_cmd_guard_exits_2_on_broken_config(tmp_path):
    # End-to-end: a broken config stops the RUN, before any judging.
    p = tmp_path / ".evoguard.json"
    p.write_text("{broken", encoding="utf-8")
    patch = tmp_path / "cand.txt"
    patch.write_text("<<<FILE: app.py>>>\nx = 1\n<<<END FILE>>>", encoding="utf-8")
    code = cli.main(["guard", str(tmp_path), "--patch", str(patch),
                     "--config", str(p)])
    assert code == 2


def test_load_config_reads_setup_command(tmp_path):
    p = tmp_path / ".evoguard.json"
    p.write_text(json.dumps({
        "setup_command": ["pnpm", "install", "--frozen-lockfile"],
        "test_command": ["vitest", "run"],
    }), encoding="utf-8")
    cfg = cli._load_config(str(p), out=_QUIET)
    assert cfg["setup_command"] == ["pnpm", "install", "--frozen-lockfile"]
    assert cfg["test_command"] == ["vitest", "run"]


def test_load_config_reads_setup_boundary_and_output_contract(tmp_path):
    p = tmp_path / ".evoguard.json"
    p.write_text(
        json.dumps(
            {
                "trust_setup_on_host": True,
                "setup_output_globs": ["generated/**", "tool-cache/*"],
                "verifier_pack": "security/org-pack",
                "expect_verifier_pack_sha256": "A" * 64,
            }
        ),
        encoding="utf-8",
    )
    cfg = cli._load_config(str(p), out=_QUIET)
    assert cfg["trust_setup_on_host"] is True
    assert cfg["setup_output_globs"] == ["generated/**", "tool-cache/*"]
    assert cfg["verifier_pack"] == "security/org-pack"
    assert cfg["expect_verifier_pack_sha256"] == "a" * 64


def test_load_config_invalid_setup_policy_types_are_fail_closed(tmp_path):
    for payload in (
        {"trust_setup_on_host": "true"},
        {"setup_output_globs": "generated/**"},
        {"setup_output_globs": ["generated/**", 1]},
        {"verifier_pack": ""},
        {"verifier_pack": []},
        {"expect_verifier_pack_sha256": "not-a-digest"},
    ):
        p = tmp_path / ".evoguard.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(cli.ConfigError):
            cli._load_config(str(p), out=_QUIET)


def test_cli_rejects_malformed_expected_pack_digest(tmp_path, capsys):
    patch = tmp_path / "candidate.txt"
    patch.write_text("<<<FILE: app.py>>>\nx = 1\n<<<END FILE>>>", encoding="utf-8")
    code = cli.main(
        [
            "guard",
            str(tmp_path),
            "--patch",
            str(patch),
            "--expect-verifier-pack-sha256",
            "abc",
        ]
    )
    assert code == 2
    assert "64 hex" in capsys.readouterr().out


def test_cli_can_override_host_setup_trust_in_both_directions():
    parser = cli.build_parser()
    trusted = parser.parse_args(["guard", "--trust-setup-on-host"])
    contained = parser.parse_args(["guard", "--no-trust-setup-on-host"])
    inherited = parser.parse_args(["guard"])
    assert trusted.trust_setup_on_host is True
    assert contained.trust_setup_on_host is False
    assert inherited.trust_setup_on_host is None


def test_load_config_setup_command_as_string_is_fail_closed(tmp_path):
    # A shell-string setup_command was previously silently dropped; splitting on
    # spaces is unsafe for paths, so it is now an explicit config error.
    p = tmp_path / ".evoguard.json"
    p.write_text(json.dumps({"setup_command": "pnpm install"}), encoding="utf-8")
    with pytest.raises(cli.ConfigError):
        cli._load_config(str(p), out=_QUIET)


_CFG_REPO_TEST = "from app import x\n\n\ndef test_x():\n    assert x == 1\n"
PATCH_SECRET = "<<<FILE: secret/x.py>>>\nprint('hi')\n<<<END FILE>>>"


def _config_repo(root: str) -> None:
    with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as f:
        f.write("x = 1\n")
    with open(os.path.join(root, "test_app.py"), "w", encoding="utf-8") as f:
        f.write(_CFG_REPO_TEST)


def test_config_protected_glob_is_applied(tmp_path, capsys):
    # protected from .evoguard.json rejects a patch that touches it — before any run.
    repo = tmp_path / "repo"
    repo.mkdir()
    _config_repo(str(repo))
    cfg = tmp_path / ".evoguard.json"
    cfg.write_text(json.dumps({"protected": ["secret/*"]}), encoding="utf-8")
    patch = tmp_path / "c.patch"
    patch.write_text(PATCH_SECRET, encoding="utf-8")
    assert cli.main(["guard", str(repo), "--patch", str(patch), "--config", str(cfg)]) == 1
    assert "REJECTED" in capsys.readouterr().out


@needs_pytest
def test_cli_protected_overrides_config(tmp_path):
    # An explicit --protected replaces the config list (not merged): secret/* is no
    # longer protected, so the same patch is not rejected for it.
    repo = tmp_path / "repo"
    repo.mkdir()
    _config_repo(str(repo))
    cfg = tmp_path / ".evoguard.json"
    cfg.write_text(json.dumps({"protected": ["secret/*"]}), encoding="utf-8")
    patch = tmp_path / "c.patch"
    patch.write_text(PATCH_SECRET, encoding="utf-8")
    out = tmp_path / "v.json"
    cli.main(["guard", str(repo), "--patch", str(patch), "--config", str(cfg),
              "--protected", "other/*", "--json", str(out)])
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert "secret/x.py" not in payload["protected_violations"]
