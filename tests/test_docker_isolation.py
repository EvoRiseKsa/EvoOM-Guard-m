# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Sole owner & author: Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""The optional docker-isolated judge (`--isolation docker`).

Pure unit tests for the command wiring + the misconfiguration guards always run.
The end-to-end run (a real `docker run` of `node --test` in `node:22-slim`,
network-less and read-only) is skipped unless a docker daemon is reachable — so
CI without docker stays green; the default subprocess judge is unaffected.
"""

import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard.cli import main as cli_main
from evoom_guard.guard import ERROR, FAIL, PASS, guard
from evoom_guard.verifiers.repo_verifier import RepoVerifier


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


needs_docker = pytest.mark.skipif(not _docker_ok(), reason="needs a reachable docker daemon")


def _gvisor_ok() -> bool:
    if not _docker_ok():
        return False
    try:
        r = subprocess.run(
            ["docker", "info", "--format", "{{.Runtimes}}"],
            capture_output=True, text=True, timeout=20,
        )
        return "runsc" in r.stdout
    except (OSError, subprocess.SubprocessError):
        return False


needs_gvisor = pytest.mark.skipif(
    not _gvisor_ok(), reason="needs docker with the runsc (gVisor) runtime"
)


# ───────────────────────────── command wiring (no docker) ───────────────────
def test_docker_command_is_isolated_and_mounts_report_separately():
    v = RepoVerifier(mem_limit_mb=512, isolation="docker", docker_image="node:22-slim")
    dc = v._docker_command(["node", "--test", "x.mjs"], "/copy", "/out", "evoguard_job")
    assert dc[:3] == ["docker", "run", "--rm"]
    # isolation flags
    assert "--network" in dc and dc[dc.index("--network") + 1] == "none"
    assert "--read-only" in dc and "--pids-limit" in dc
    assert "--memory" in dc and dc[dc.index("--memory") + 1] == "512m"
    # the repo copy and the judge-owned report dir are separate bind mounts
    assert "-v" in dc and "/copy:/work" in dc and "/out:/out" in dc
    # image then the command, in order
    assert dc[-4:] == ["node:22-slim", "node", "--test", "x.mjs"]


def test_docker_command_omits_memory_when_uncapped():
    v = RepoVerifier(mem_limit_mb=0, isolation="docker", docker_image="node:22-slim")
    assert "--memory" not in v._docker_command(["node", "--test"], "/c", "/o", "n")


def test_docker_command_injects_reporter_env():
    # A runner whose report path comes from the environment (jest-junit) gets it
    # passed into the container as a -e flag so the judge-owned mount receives it.
    v = RepoVerifier(mem_limit_mb=0, isolation="docker", docker_image="node:22-slim")
    dc = v._docker_command(
        ["jest"], "/c", "/o", "n",
        {"JEST_JUNIT_OUTPUT_FILE": "/out/judge-result.xml"},
    )
    assert "-e" in dc
    assert "JEST_JUNIT_OUTPUT_FILE=/out/judge-result.xml" in dc


def test_verify_docker_without_image_is_a_clear_error(tmp_path):
    # Defensive: the RepoVerifier never shells out to docker without an image.
    (tmp_path / "m.py").write_text("x = 1\n", encoding="utf-8")
    v = RepoVerifier(isolation="docker", docker_image=None)
    res = v.verify("<<<FILE: m.py>>>\nx = 2\n<<<END FILE>>>", {"repo_path": str(tmp_path)})
    assert res.passed is False
    assert "docker" in res.diagnostics.lower() and "image" in res.diagnostics.lower()


def test_cli_docker_without_image_is_usage_error(tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "m.py").write_text("x = 1\n", encoding="utf-8")
    patch = tmp_path / "c.patch"
    patch.write_text("<<<FILE: m.py>>>\nx = 2\n<<<END FILE>>>", encoding="utf-8")
    rc = cli_main(["guard", str(repo), "--patch", str(patch), "--isolation", "docker"])
    assert rc == 2
    assert "--docker-image" in capsys.readouterr().out


# ───────────────────────────── gVisor (runsc) wiring ────────────────────────
def test_gvisor_isolation_uses_runsc_runtime():
    # gVisor is the container judge through the runsc OCI runtime — a user-space
    # guest kernel, no /dev/kvm. It inherits the same network-less/read-only flags.
    v = RepoVerifier(isolation="gvisor", docker_image="node:22-slim")
    assert v.docker_runtime == "runsc"
    dc = v._docker_command(["node", "--test"], "/c", "/o", "n")
    assert "--runtime" in dc and dc[dc.index("--runtime") + 1] == "runsc"
    assert "--network" in dc and dc[dc.index("--network") + 1] == "none"
    assert "--read-only" in dc


def test_docker_isolation_has_no_runtime_flag():
    v = RepoVerifier(isolation="docker", docker_image="node:22-slim")
    assert v.docker_runtime is None
    assert "--runtime" not in v._docker_command(["node", "--test"], "/c", "/o", "n")


def test_verify_gvisor_without_image_is_a_clear_error(tmp_path):
    (tmp_path / "m.py").write_text("x = 1\n", encoding="utf-8")
    v = RepoVerifier(isolation="gvisor", docker_image=None)
    res = v.verify("<<<FILE: m.py>>>\nx = 2\n<<<END FILE>>>", {"repo_path": str(tmp_path)})
    assert res.passed is False
    assert "gvisor" in res.diagnostics.lower() and "image" in res.diagnostics.lower()


def test_cli_gvisor_without_image_is_usage_error(tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "m.py").write_text("x = 1\n", encoding="utf-8")
    patch = tmp_path / "c.patch"
    patch.write_text("<<<FILE: m.py>>>\nx = 2\n<<<END FILE>>>", encoding="utf-8")
    rc = cli_main(["guard", str(repo), "--patch", str(patch), "--isolation", "gvisor"])
    assert rc == 2
    assert "--docker-image" in capsys.readouterr().out


# ───────────────────────────── end-to-end (needs docker) ────────────────────
def _node_repo(root):
    (root / "test").mkdir()
    (root / "src.mjs").write_text("export const add = (a, b) => a - b;\n", encoding="utf-8")  # bug
    (root / "test" / "c.test.mjs").write_text(
        "import { test } from 'node:test';\n"
        "import assert from 'node:assert';\n"
        "import { add } from '../src.mjs';\n"
        "test('add', () => assert.strictEqual(add(2, 3), 5));\n"
        "test('zero', () => assert.strictEqual(add(0, 0), 0));\n",
        encoding="utf-8",
    )


@needs_docker
def test_docker_judge_honest_fix_pass(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _node_repo(repo)
    cand = "<<<FILE: src.mjs>>>\nexport const add = (a, b) => a + b;\n<<<END FILE>>>"
    res = guard(str(repo), cand, test_command=["node", "--test", "test/c.test.mjs"],
                mem_limit_mb=0, isolation="docker", docker_image="node:22-slim")
    assert res.verdict == PASS
    assert res.verdict_source == "junit+exit"
    assert (res.tests_passed, res.tests_total) == (2, 2)


@needs_gvisor
def test_gvisor_judge_honest_fix_pass(tmp_path):
    # Same verdict as the docker judge, but under the runsc guest kernel.
    repo = tmp_path / "repo"
    repo.mkdir()
    _node_repo(repo)
    cand = "<<<FILE: src.mjs>>>\nexport const add = (a, b) => a + b;\n<<<END FILE>>>"
    res = guard(str(repo), cand, test_command=["node", "--test", "test/c.test.mjs"],
                mem_limit_mb=0, isolation="gvisor", docker_image="node:22-slim")
    assert res.verdict == PASS
    assert res.verdict_source == "junit+exit"


@needs_docker
def test_docker_judge_broken_fix_fail(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _node_repo(repo)
    cand = "<<<FILE: src.mjs>>>\nexport const add = (a, b) => a + b + 1;\n<<<END FILE>>>"  # still wrong
    res = guard(str(repo), cand, test_command=["node", "--test", "test/c.test.mjs"],
                mem_limit_mb=0, isolation="docker", docker_image="node:22-slim")
    assert res.verdict == FAIL
    assert res.verdict_source == "junit+exit"


@needs_docker
def test_docker_judge_rejects_protected_edit(tmp_path):
    # The reward-hack gate runs before any container starts.
    repo = tmp_path / "repo"
    repo.mkdir()
    _node_repo(repo)
    cand = "<<<FILE: test/c.test.mjs>>>\nimport { test } from 'node:test';\ntest('noop', () => {});\n<<<END FILE>>>"
    res = guard(str(repo), cand, test_command=["node", "--test", "test/c.test.mjs"],
                mem_limit_mb=0, isolation="docker", docker_image="node:22-slim")
    assert res.verdict == "REJECTED"
    assert res.verdict != ERROR
