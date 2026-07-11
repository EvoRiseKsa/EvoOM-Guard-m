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

import importlib.util
import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard import __version__, cli

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
    # the flag parses and defaults to the safe 'none'.
    args = cli.build_parser().parse_args(["guard", ".", "--patch", "-"])
    assert args.docker_network == "none"
    args = cli.build_parser().parse_args(
        ["guard", ".", "--patch", "-", "--docker-network", "mynet"]
    )
    assert args.docker_network == "mynet"


def test_guard_docker_isolation_requires_image(capsys):
    # --isolation docker without --docker-image is a usage error (exit 2).
    assert cli.main(["guard", ".", "--patch", "-", "--isolation", "docker"]) == 2
    assert "docker-image" in capsys.readouterr().out


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
    assert 'test-command: "pytest -q app/"' in body  # custom command embedded
    assert "wrote" in capsys.readouterr().out


def test_init_default_ref_is_current_version(tmp_path):
    wf = tmp_path / "wf.yml"
    assert cli.main(["init", "--path", str(wf)]) == 0
    assert f"EvoOM-Guard-m@v{__version__}" in wf.read_text(encoding="utf-8")


def test_init_refuses_to_overwrite_without_force(tmp_path, capsys):
    wf = tmp_path / "wf.yml"
    wf.write_text("keep me", encoding="utf-8")
    rc = cli.main(["init", "--path", str(wf)])
    assert rc == 1
    assert wf.read_text(encoding="utf-8") == "keep me"   # untouched
    assert "refusing to overwrite" in capsys.readouterr().out


def test_init_force_overwrites(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text("old", encoding="utf-8")
    assert cli.main(["init", "--path", str(wf), "--force"]) == 0
    assert "name: EvoGuard" in wf.read_text(encoding="utf-8")


def test_init_stdout_does_not_write(tmp_path, capsys):
    wf = tmp_path / "nope.yml"
    assert cli.main(["init", "--path", str(wf), "--stdout"]) == 0
    assert not wf.exists()                                # nothing written
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


def test_init_private_custom_secret_name(tmp_path):
    wf = tmp_path / "evoguard.yml"
    cli.main([
        "init", "--path", str(wf),
        "--private-evoguard",
        "--evoguard-token-secret", "MY_PAT",
    ])
    body = wf.read_text(encoding="utf-8")
    assert "MY_PAT" in body
    assert "EVOGUARD_TOKEN" not in body


# ───────────────────────────── config (.evoguard.json) ──────────────────────
_QUIET = lambda *_a, **_k: None  # noqa: E731 - swallow warnings in unit tests


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
