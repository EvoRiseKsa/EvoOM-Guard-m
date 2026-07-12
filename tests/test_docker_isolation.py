# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
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

import evoom_guard.verifiers.repo_verifier as repo_verifier_module
from evoom_guard.cli import main as cli_main
from evoom_guard.guard import ERROR, FAIL, PASS, guard
from evoom_guard.pack_manifest import pack_digest
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
    assert dc[dc.index("--cap-drop") + 1] == "ALL"
    assert dc[dc.index("--security-opt") + 1] == "no-new-privileges"
    if hasattr(os, "getuid"):
        assert dc[dc.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    assert "--memory" in dc and dc[dc.index("--memory") + 1] == "512m"
    # the repo copy and the judge-owned report dir are separate bind mounts
    assert "-v" in dc and "/copy:/work:ro" in dc and "/out:/out:rw" in dc
    # image then the command, in order
    assert dc[-4:] == ["node:22-slim", "node", "--test", "x.mjs"]


def test_docker_command_omits_memory_when_uncapped():
    v = RepoVerifier(mem_limit_mb=0, isolation="docker", docker_image="node:22-slim")
    assert "--memory" not in v._docker_command(["node", "--test"], "/c", "/o", "n")


def test_default_container_command_never_uses_the_host_python_path():
    v = RepoVerifier(isolation="docker", docker_image="python:3.12-slim")
    assert v._command({"repo_path": "/repo"})[:3] == ["python", "-m", "pytest"]


def test_concurrent_container_names_are_unique_and_docker_safe():
    first = repo_verifier_module._docker_container_name("pack phase")
    second = repo_verifier_module._docker_container_name("pack phase")
    assert first != second
    assert first.startswith("evoguard_pack-phase_")
    assert all(char.isalnum() or char in "_.-" for char in first)


def test_setup_mount_is_writable_but_suite_and_pack_are_read_only():
    v = RepoVerifier(mem_limit_mb=0, isolation="docker", docker_image="python:3.12-slim")
    setup = v._docker_command(
        ["python", "setup.py"], "/copy", None, "setup", work_writable=True
    )
    suite = v._docker_command(["python", "-m", "pytest"], "/copy", "/out", "suite")
    pack = v._docker_command(
        ["python", "-m", "pytest", "/verifier-pack"],
        "/copy",
        "/out",
        "pack",
        pack_dir="/host/pack",
    )
    assert "/copy:/work:rw" in setup
    assert not any(mount.endswith(":/out:rw") for mount in setup)
    assert "/copy:/work:ro" in suite
    assert "/copy:/work:ro" in pack
    assert "/host/pack:/verifier-pack:ro" in pack


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


def test_setup_runs_inside_requested_container_by_default(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    seen = []

    def fake_run(cmd, **_kwargs):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 3, "", "setup failed")

    verifier = RepoVerifier(
        isolation="docker", docker_image="python:3.12-slim",
        setup_command=["python", "-c", "print('x; touch PWNED')"],
    )
    monkeypatch.setattr(verifier, "_resolve_docker_image", lambda: "sha256:fixed")
    monkeypatch.setattr(repo_verifier_module.subprocess, "run", fake_run)
    result = verifier.verify(
        "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>", {"repo_path": str(tmp_path)}
    )
    assert not result.passed
    assert result.artifact["setup_isolation"] == "docker"
    command = seen[0]
    assert command[:3] == ["docker", "run", "--rm"]
    assert "--network" in command and command[command.index("--network") + 1] == "none"
    assert command[-3:] == ["python", "-c", "print('x; touch PWNED')"]
    assert command.count("print('x; touch PWNED')") == 1


def test_setup_container_exit_125_is_isolation_unavailable(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    verifier = RepoVerifier(
        isolation="docker",
        docker_image="python:3.12-slim",
        setup_command=["python", "-c", "pass"],
    )
    monkeypatch.setattr(verifier, "_resolve_docker_image", lambda: "sha256:fixed")
    monkeypatch.setattr(
        repo_verifier_module.subprocess,
        "run",
        lambda cmd, **_kwargs: subprocess.CompletedProcess(cmd, 125, "", "daemon error"),
    )
    result = verifier.verify(
        "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>", {"repo_path": str(tmp_path)}
    )
    assert not result.passed
    assert result.artifact["outcome"] == "isolation_unavailable"
    assert result.artifact["setup_isolation"] == "unavailable"


def test_suite_container_exit_125_is_isolation_unavailable(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    verifier = RepoVerifier(isolation="docker", docker_image="python:3.12-slim")
    monkeypatch.setattr(verifier, "_resolve_docker_image", lambda: "sha256:fixed")
    monkeypatch.setattr(
        repo_verifier_module.subprocess,
        "run",
        lambda cmd, **_kwargs: subprocess.CompletedProcess(cmd, 125, "", "daemon error"),
    )
    result = verifier.verify(
        "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>", {"repo_path": str(tmp_path)}
    )
    assert not result.passed
    assert result.artifact["outcome"] == "isolation_unavailable"


def test_host_setup_requires_explicit_opt_in_and_is_recorded(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    seen = []

    def fake_run(cmd, **_kwargs):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 3, "", "setup failed")

    verifier = RepoVerifier(
        isolation="docker", docker_image="python:3.12-slim",
        setup_command=["trusted-setup", "--offline"], trust_setup_on_host=True,
    )
    monkeypatch.setattr(verifier, "_resolve_docker_image", lambda: "sha256:fixed")
    monkeypatch.setattr(repo_verifier_module.subprocess, "run", fake_run)
    result = verifier.verify(
        "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>", {"repo_path": str(tmp_path)}
    )
    assert not result.passed
    assert seen[0] == ["trusted-setup", "--offline"]
    assert result.artifact["setup_isolation"] == "subprocess_host_opt_in"


def test_setup_suite_and_pack_share_one_resolved_image_id(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "test_contract.py").write_text(
        "def test_contract():\n    assert True\n", encoding="utf-8"
    )
    docker_commands = []
    resolve_calls = 0

    verifier = RepoVerifier(
        isolation="docker",
        docker_image="python:mutable",
        setup_command=["python", "-c", "pass"],
        test_command=["python", "-c", "raise SystemExit(0)"],
        mem_limit_mb=0,
    )

    def resolve_once():
        nonlocal resolve_calls
        resolve_calls += 1
        return "sha256:fixed-image"

    def fake_run(cmd, **_kwargs):
        docker_commands.append(cmd)
        for token in cmd:
            if isinstance(token, str) and token.endswith(":/out:rw"):
                outdir = token.removesuffix(":/out:rw")
                os.makedirs(outdir, exist_ok=True)
                with open(
                    os.path.join(outdir, "judge-result.xml"), "w", encoding="utf-8"
                ) as stream:
                    stream.write(
                        '<testsuite tests="1" failures="0" errors="0">'
                        '<testcase classname="x" name="ok"/></testsuite>'
                    )
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(verifier, "_resolve_docker_image", resolve_once)
    monkeypatch.setattr(repo_verifier_module.subprocess, "run", fake_run)
    result = verifier.verify(
        "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>",
        {"repo_path": str(repo), "verifier_pack": str(pack)},
    )

    assert result.passed, result.diagnostics
    assert resolve_calls == 1
    assert len(docker_commands) == 3
    assert all("sha256:fixed-image" in command for command in docker_commands)
    assert all("python:mutable" not in command for command in docker_commands)
    assert result.artifact["image_digest"] == "sha256:fixed-image"


def test_setup_cannot_mutate_source_after_pre_gate(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    verifier = RepoVerifier(
        setup_command=[
            sys.executable, "-c", "open('app.py','w').write('x = 999\\n')",
        ],
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        mem_limit_mb=0,
    )
    result = verifier.verify(
        "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>", {"repo_path": str(tmp_path)}
    )
    assert not result.passed
    assert "tree different from the candidate" in result.diagnostics
    assert result.artifact["setup_fidelity_changes"] == ["app.py"]


def test_setup_can_create_a_conventional_dependency_output(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    create_dependency = (
        "import os; os.makedirs('node_modules/pkg'); "
        "open('node_modules/pkg/index.js', 'w').write('ok')"
    )
    result = RepoVerifier(
        setup_command=[sys.executable, "-c", create_dependency],
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        mem_limit_mb=0,
    ).verify(
        "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>", {"repo_path": str(tmp_path)}
    )
    assert result.passed, result.diagnostics
    assert result.artifact["setup_fidelity"] == "verified"


def test_setup_cannot_rewrite_preexisting_content_under_vendor(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "tracked.py").write_text("SAFE = True\n", encoding="utf-8")
    result = RepoVerifier(
        setup_command=[
            sys.executable,
            "-c",
            "open('vendor/tracked.py', 'w').write('SAFE = False\\n')",
        ],
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        mem_limit_mb=0,
    ).verify(
        "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>", {"repo_path": str(tmp_path)}
    )
    assert not result.passed
    assert result.artifact["setup_fidelity_changes"] == ["vendor/tracked.py"]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_setup_created_symlink_is_detected(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    result = RepoVerifier(
        setup_command=[
            sys.executable,
            "-c",
            "import os; os.symlink('app.py', 'candidate_link')",
        ],
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        mem_limit_mb=0,
    ).verify(
        "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>", {"repo_path": str(tmp_path)}
    )
    if sys.platform == "win32" and "setup command failed" in result.diagnostics:
        pytest.skip("Windows symlink privilege unavailable")
    assert not result.passed
    assert result.artifact["setup_fidelity_changes"] == ["candidate_link"]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
def test_setup_created_fifo_is_detected_without_opening_it(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    result = RepoVerifier(
        setup_command=[sys.executable, "-c", "import os; os.mkfifo('candidate_pipe')"],
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        mem_limit_mb=0,
    ).verify(
        "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>", {"repo_path": str(tmp_path)}
    )
    assert not result.passed
    assert result.artifact["setup_fidelity_changes"] == ["candidate_pipe"]


@needs_docker
@pytest.mark.skipif(
    not os.environ.get("EVOGUARD_E2E_PYTEST_IMAGE"),
    reason="needs the CI-built pytest image",
)
def test_docker_setup_suite_and_pack_e2e(tmp_path):
    image = os.environ["EVOGUARD_E2E_PYTEST_IMAGE"]
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "test_app.py").write_text(
        "import app\n"
        "def test_repo():\n"
        "    assert app.x == 2\n",
        encoding="utf-8",
    )
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "test_contract.py").write_text(
        "import os, app\n"
        "def test_pack():\n"
        "    assert app.x == 2\n"
        "    assert os.path.exists('.evoguard-setup/ready')\n",
        encoding="utf-8",
    )
    setup = [
        "python",
        "-c",
        (
            "import os; os.makedirs('.evoguard-setup'); "
            "open('.evoguard-setup/ready', 'w').write('ready')"
        ),
    ]
    result = guard(
        str(repo),
        "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>",
        setup_command=setup,
        isolation="docker",
        docker_image=image,
        verifier_pack=str(pack),
        expect_verifier_pack_sha256=pack_digest(str(pack)),
        mem_limit_mb=0,
        timeout=120,
    )
    assert result.verdict == PASS, result.reason
    assert (result.tests_passed, result.tests_total) == (2, 2)
    assert result.assurance["setup_isolation"] == "docker"
    assert result.attestation["verifier_pack_sha256"] == pack_digest(str(pack))


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
