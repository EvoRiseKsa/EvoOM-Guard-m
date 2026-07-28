"""Regression checks for the Marketplace composite action's trust boundary."""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ACTION = Path(__file__).parents[1] / "action.yml"
CFLITE_WORKFLOW = (
    Path(__file__).parents[1] / ".github" / "workflows" / "cflite_pr.yml"
)
ACTIVE_NODE_WORKFLOWS = (
    Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml",
    Path(__file__).parents[1] / ".github" / "workflows" / "windows.yml",
)
REVERIFY_WORKFLOW = (
    Path(__file__).parents[1] / ".github" / "workflows" / "evoguard-reverify.yml"
)
SEAL_WORKFLOW = (
    Path(__file__).parents[1] / ".github" / "workflows" / "evoguard-seal.yml"
)
SCORECARD_WORKFLOW = (
    Path(__file__).parents[1] / ".github" / "workflows" / "scorecard.yml"
)
GUARD_CALL = 'python -I "$RUNNER_TEMP/evo-guard.pyz" "${ARGS[@]}"'


def _run_blocks(text: str) -> list[str]:
    """Extract literal ``run: |`` bodies without needing a YAML dependency."""
    lines = text.splitlines()
    blocks: list[str] = []
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)run:\s*\|\s*$", line)
        if not match:
            continue
        indent = len(match.group(1))
        body: list[str] = []
        for candidate in lines[index + 1 :]:
            if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= indent:
                break
            body.append(candidate)
        blocks.append("\n".join(body))
    return blocks


def _working_bash() -> str | None:
    candidates: list[Path] = []
    discovered = shutil.which("bash")
    if discovered:
        candidates.append(Path(discovered))
    git = shutil.which("git")
    if os.name == "nt" and git:
        git_root = Path(git).resolve().parents[1]
        candidates.extend((git_root / "bin" / "bash.exe", git_root / "usr" / "bin" / "bash.exe"))
    for candidate in dict.fromkeys(candidates):
        try:
            probe = subprocess.run(
                [str(candidate), "-c", "exit 0"],
                check=False,
                capture_output=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return str(candidate)
    return None


def _run_credential_preflight(
    *,
    remote_names: str = "",
    remote_list_status: int = 0,
    origin_fetch: str = "https://github.com/example/project.git",
    origin_fetch_status: int = 0,
    origin_push: str = "https://github.com/example/project.git",
    origin_push_status: int = 0,
    mirror_fetch: str = "https://github.com/example/project.git",
    mirror_fetch_status: int = 0,
    mirror_push: str = "https://github.com/example/project.git",
    mirror_push_status: int = 0,
) -> subprocess.CompletedProcess[str]:
    bash = _working_bash()
    if bash is None:
        pytest.skip("a working Bash is required to execute the composite preflight")

    block = next(
        candidate
        for candidate in _run_blocks(ACTION.read_text(encoding="utf-8"))
        if "inspect_git_config_for_credentials()" in candidate
    )
    fake_git = r"""
git() {
  case "$1" in
    rev-parse)
      return 0
      ;;
    config)
      return 1
      ;;
    remote)
      shift
      if [ "$#" -eq 0 ]; then
        printf '%b' "$FAKE_REMOTE_NAMES"
        return "$FAKE_REMOTE_LIST_STATUS"
      fi
      case "$*" in
        "get-url --all origin")
          printf '%s\n' "$FAKE_ORIGIN_FETCH"
          return "$FAKE_ORIGIN_FETCH_STATUS"
          ;;
        "get-url --push --all origin")
          printf '%s\n' "$FAKE_ORIGIN_PUSH"
          return "$FAKE_ORIGIN_PUSH_STATUS"
          ;;
        "get-url --all mirror")
          printf '%s\n' "$FAKE_MIRROR_FETCH"
          return "$FAKE_MIRROR_FETCH_STATUS"
          ;;
        "get-url --push --all mirror")
          printf '%s\n' "$FAKE_MIRROR_PUSH"
          return "$FAKE_MIRROR_PUSH_STATUS"
          ;;
        *)
          return 2
          ;;
      esac
      ;;
    *)
      return 2
      ;;
  esac
}
"""
    env = {
        key: value
        for key, value in os.environ.items()
        if key
        not in {
            "BASH_ENV",
            "ENV",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "GIT_ASKPASS",
            "SSH_ASKPASS",
            "SSH_AUTH_SOCK",
        }
    }
    env.update(
        {
            "FAKE_REMOTE_NAMES": remote_names,
            "FAKE_REMOTE_LIST_STATUS": str(remote_list_status),
            "FAKE_ORIGIN_FETCH": origin_fetch,
            "FAKE_ORIGIN_FETCH_STATUS": str(origin_fetch_status),
            "FAKE_ORIGIN_PUSH": origin_push,
            "FAKE_ORIGIN_PUSH_STATUS": str(origin_push_status),
            "FAKE_MIRROR_FETCH": mirror_fetch,
            "FAKE_MIRROR_FETCH_STATUS": str(mirror_fetch_status),
            "FAKE_MIRROR_PUSH": mirror_push,
            "FAKE_MIRROR_PUSH_STATUS": str(mirror_push_status),
        }
    )
    return subprocess.run(
        [bash, "-s"],
        input=f"{fake_git}\n{block}\n",
        text=True,
        capture_output=True,
        cwd=ACTION.parent,
        env=env,
        check=False,
        timeout=10,
    )


def test_action_inputs_are_not_interpolated_into_shell_scripts() -> None:
    blocks = _run_blocks(ACTION.read_text(encoding="utf-8"))
    assert blocks
    for block in blocks:
        assert "${{ inputs." not in block


def test_candidate_execution_block_enables_full_bash_strict_mode() -> None:
    blocks = _run_blocks(ACTION.read_text(encoding="utf-8"))
    candidate = next(block for block in blocks if GUARD_CALL in block)
    assert candidate.lstrip().startswith("set -euo pipefail\n")


def test_action_never_uses_pull_request_target() -> None:
    """The composite action must not recommend a privileged untrusted-code event."""
    assert "pull_request_target" not in ACTION.read_text(encoding="utf-8")


def test_third_party_actions_are_pinned_to_full_commit_shas() -> None:
    text = ACTION.read_text(encoding="utf-8")
    uses = re.findall(r"^\s*uses:\s*([^\s#]+)", text, flags=re.MULTILINE)
    assert uses
    for target in uses:
        if target.startswith("./") or target.startswith("docker://"):
            continue
        assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", target), target


def test_base_resolution_fails_fast_with_named_causes() -> None:
    """A missing/unreachable diff base must stop the step BEFORE the guard runs,
    with a stable named cause — never surface later as a confusing empty-diff
    verdict (external-review finding §6.1)."""
    text = ACTION.read_text(encoding="utf-8")
    # The two named setup-failure causes.
    assert "base_ref_unavailable" in text
    assert "base_diff_failed" in text
    # The authoritative check: the base must resolve to a commit in this checkout.
    assert re.search(r"git rev-parse --verify --quiet .*commit", text)
    # The best-effort fetch surfaces a ::warning:: instead of being silenced
    # (no more `2>/dev/null || true` swallowing the diagnosis).
    assert "::warning::" in text
    assert "2>/dev/null || true" not in text
    # Fail-fast ordering: both named causes appear before the guard invocation.
    guard_call = text.index(GUARD_CALL)
    assert text.index("base_ref_unavailable") < guard_call
    assert text.index("base_diff_failed") < guard_call
    conditional_check = text.index(
        'if ! git rev-parse --verify --quiet "${BASE}^{commit}"'
    )
    fetch = text.index('git fetch --no-tags --depth=1 origin "$BASE"', conditional_check)
    conditional_end = text.index("        fi", fetch)
    authoritative_check = text.index(
        'git rev-parse --verify --quiet "${BASE}^{commit}"',
        conditional_end,
    )
    assert conditional_check < fetch < conditional_end < authoritative_check < guard_call


def test_action_uses_a_verified_base_policy_not_candidate_workspace() -> None:
    text = ACTION.read_text(encoding="utf-8")
    base_check = text.index('git rev-parse --verify --quiet "${BASE}^{commit}"')
    materialize = text.index('git show "${BASE}:.evoguard.json"')
    guard_call = text.index(GUARD_CALL)
    assert base_check < materialize < guard_call
    assert 'BASE_POLICY_CONFIG="$RUNNER_TEMP/evoguard-base-policy.json"' in text
    assert 'ARGS=(guard --diff - --config "$BASE_POLICY_CONFIG"' in text
    assert "base_policy_config_unavailable" in text


def test_pr_action_inputs_cannot_weaken_the_base_or_failure_policy() -> None:
    text = ACTION.read_text(encoding="utf-8")
    assert 'BASE="$PR_BASE_SHA"' in text
    assert "untrusted_base_ref_override" in text
    assert "untrusted_fail_on_override" in text
    # The PR guards must execute before resolving the diff and before Guard.
    base_guard = text.index("untrusted_base_ref_override")
    diff = text.index('git diff "$BASE...HEAD"')
    guard_call = text.index(GUARD_CALL)
    assert base_guard < diff < guard_call


def test_fail_on_documents_the_pr_safety_boundary() -> None:
    """'rejected-only' turns FAIL/TAMPERED/ERROR green; the input description
    must say so loudly (external-review finding §6.4)."""
    text = ACTION.read_text(encoding="utf-8")
    fail_on = text.index("fail-on:")
    desc_end = text.index("isolation:", fail_on)
    desc = text[fail_on:desc_end]
    for token in ("PR", "any-non-pass", "rejected-only", "trusted non-PR"):
        assert token in desc, f"fail-on description must warn about {token}"


def test_host_setup_escape_hatch_is_explicitly_forwarded_only_for_trusted_runs() -> None:
    text = ACTION.read_text(encoding="utf-8")
    assert "trust-setup-on-host:" in text
    assert "INPUT_TRUST_SETUP_ON_HOST: ${{ inputs.trust-setup-on-host }}" in text
    assert 'ARGS+=(--trust-setup-on-host)' in text
    assert 'ARGS+=(--no-trust-setup-on-host)' in text
    overrides = text[
        text.index("# BEGIN NON_PR_WORKFLOW_OVERRIDES") : text.index(
            "# END NON_PR_WORKFLOW_OVERRIDES"
        )
    ]
    assert 'if [ "$IS_PR" != "true" ]; then' in overrides
    assert "INPUT_TRUST_SETUP_ON_HOST" in overrides
    description = text[text.index("trust-setup-on-host:") : text.index("diff-coverage:")]
    assert "weakens" in description
    assert "subprocess" in description


def test_operating_profile_is_forwarded_only_for_trusted_non_pr_runs() -> None:
    text = ACTION.read_text(encoding="utf-8")
    description = text[
        text.index("operating-profile:") : text.index("strict-harness:")
    ]
    assert "local" in description
    assert "protected" in description
    assert "hostile" in description
    assert "verified base .evoguard.json policy" in description
    assert (
        "INPUT_OPERATING_PROFILE: ${{ inputs.operating-profile }}"
        in text
    )

    overrides_start = text.index("# BEGIN NON_PR_WORKFLOW_OVERRIDES")
    overrides_end = text.index("# END NON_PR_WORKFLOW_OVERRIDES", overrides_start)
    overrides = text[overrides_start:overrides_end]
    assert 'if [ "$IS_PR" != "true" ]; then' in overrides
    assert (
        'ARGS+=(--operating-profile "$INPUT_OPERATING_PROFILE")'
        in overrides
    )

    pr_policy_start = text.index('if [ "$IS_PR" = "true" ]; then')
    pr_policy_end = text.index("set +e", pr_policy_start)
    pr_policy = text[pr_policy_start:pr_policy_end]
    assert '[ -n "$INPUT_OPERATING_PROFILE" ]' in pr_policy
    assert "--operating-profile" not in pr_policy


@pytest.mark.parametrize(
    ("http_status", "helper_status", "expected_status", "expected_error"),
    (
        (1, 1, 0, None),
        (0, 1, 2, "checkout credentials are reachable"),
        (1, 0, 2, "checkout credentials are reachable"),
        (2, 1, 2, "could not safely inspect Git config"),
        (1, 128, 2, "could not safely inspect Git config"),
    ),
)
def test_credential_preflight_interprets_git_config_statuses_fail_closed(
    http_status: int,
    helper_status: int,
    expected_status: int,
    expected_error: str | None,
) -> None:
    bash = _working_bash()
    if bash is None:
        pytest.skip("a working Bash is required to execute the composite preflight")

    block = next(
        candidate
        for candidate in _run_blocks(ACTION.read_text(encoding="utf-8"))
        if "inspect_git_config_for_credentials()" in candidate
    )
    fake_git = r"""
git() {
  case "$1" in
    rev-parse)
      return 0
      ;;
    config)
      case "$*" in
        *extraheader*) return "$FAKE_HTTP_STATUS" ;;
        *) return "$FAKE_HELPER_STATUS" ;;
      esac
      ;;
    remote)
      return 0
      ;;
    *)
      return 2
      ;;
  esac
}
"""
    env = {
        key: value
        for key, value in os.environ.items()
        if key
        not in {
            "BASH_ENV",
            "ENV",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "GIT_ASKPASS",
            "SSH_ASKPASS",
            "SSH_AUTH_SOCK",
        }
    }
    env["FAKE_HTTP_STATUS"] = str(http_status)
    env["FAKE_HELPER_STATUS"] = str(helper_status)
    completed = subprocess.run(
        [bash, "-s"],
        input=f"{fake_git}\n{block}\n",
        text=True,
        capture_output=True,
        cwd=ACTION.parent,
        env=env,
        check=False,
        timeout=10,
    )

    assert completed.returncode == expected_status, completed.stderr
    if expected_error is None:
        assert "::error::" not in completed.stdout
    else:
        assert expected_error in completed.stdout


def test_credential_preflight_accepts_a_repository_with_no_remotes() -> None:
    completed = _run_credential_preflight(remote_names="", remote_list_status=0)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "::error::" not in completed.stdout


@pytest.mark.parametrize(
    ("remote_commands", "secret_url"),
    (
        (
            (
                ("remote", "add", "origin", "https://example.invalid/repo.git"),
                (
                    "remote",
                    "set-url",
                    "--push",
                    "origin",
                    "https://oauth2:push-secret@example.invalid/repo.git",
                ),
            ),
            "https://oauth2:push-secret@example.invalid/repo.git",
        ),
        (
            (
                ("remote", "add", "origin", "https://example.invalid/repo.git"),
                (
                    "remote",
                    "add",
                    "mirror",
                    "https://mirror-token@example.invalid/repo.git",
                ),
            ),
            "https://mirror-token@example.invalid/repo.git",
        ),
    ),
)
def test_credential_preflight_enumerates_real_git_fetch_and_push_urls(
    tmp_path: Path,
    remote_commands: tuple[tuple[str, ...], ...],
    secret_url: str,
) -> None:
    bash = _working_bash()
    git = shutil.which("git")
    if bash is None or git is None:
        pytest.skip("working Bash and Git executables are required")

    repository = tmp_path / "repository"
    subprocess.run(
        [git, "init", "--quiet", str(repository)],
        check=True,
        capture_output=True,
        timeout=10,
    )
    for command in remote_commands:
        subprocess.run(
            [git, "-C", str(repository), *command],
            check=True,
            capture_output=True,
            timeout=10,
        )

    empty_global_config = tmp_path / "empty-global.gitconfig"
    empty_global_config.write_text("", encoding="utf-8")
    env = {
        key: value
        for key, value in os.environ.items()
        if key
        not in {
            "BASH_ENV",
            "ENV",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "GIT_ASKPASS",
            "SSH_ASKPASS",
            "SSH_AUTH_SOCK",
        }
        and not key.startswith("GIT_CONFIG_")
    }
    env.update(
        {
            "GIT_CONFIG_GLOBAL": str(empty_global_config),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    block = next(
        candidate
        for candidate in _run_blocks(ACTION.read_text(encoding="utf-8"))
        if "inspect_git_config_for_credentials()" in candidate
    )
    completed = subprocess.run(
        [bash, "-s"],
        input=block,
        text=True,
        capture_output=True,
        cwd=repository,
        env=env,
        check=False,
        timeout=10,
    )

    assert completed.returncode == 2
    assert "checkout credentials are reachable" in completed.stdout
    assert secret_url not in completed.stdout
    assert secret_url not in completed.stderr


@pytest.mark.parametrize(
    ("kwargs", "expected_status"),
    (
        ({"remote_list_status": 2}, "2"),
        ({"remote_names": "origin\n", "origin_fetch_status": 2}, "2"),
        ({"remote_names": "origin\n", "origin_push_status": 128}, "128"),
    ),
)
def test_credential_preflight_fails_closed_when_remote_enumeration_fails(
    kwargs: dict[str, object],
    expected_status: str,
) -> None:
    completed = _run_credential_preflight(**kwargs)

    assert completed.returncode == 2
    assert "could not safely enumerate every Git remote fetch/push URL" in (
        completed.stdout
    )
    assert f"git exited {expected_status}" in completed.stdout


@pytest.mark.parametrize(
    ("kwargs", "secret_url"),
    (
        (
            {
                "remote_names": "origin\n",
                "origin_push": "https://oauth2:push-secret@example.invalid/repo.git",
            },
            "https://oauth2:push-secret@example.invalid/repo.git",
        ),
        (
            {
                "remote_names": "origin\nmirror\n",
                "mirror_fetch": "https://mirror-token@example.invalid/repo.git",
            },
            "https://mirror-token@example.invalid/repo.git",
        ),
        (
            {
                "remote_names": "origin\n",
                "origin_fetch": "HTTPS://upper-token@example.invalid/repo.git",
            },
            "HTTPS://upper-token@example.invalid/repo.git",
        ),
        (
            {
                "remote_names": "origin\n",
                "origin_fetch": "ssh://git:ssh-secret@example.invalid/repo.git",
            },
            "ssh://git:ssh-secret@example.invalid/repo.git",
        ),
        (
            {
                "remote_names": "origin\n",
                "origin_fetch": "//user:secret@example.invalid/repo.git",
            },
            "//user:secret@example.invalid/repo.git",
        ),
    ),
)
def test_credential_preflight_rejects_credentials_in_every_remote_url_without_leak(
    kwargs: dict[str, object],
    secret_url: str,
) -> None:
    completed = _run_credential_preflight(**kwargs)

    assert completed.returncode == 2
    assert "checkout credentials are reachable" in completed.stdout
    assert secret_url not in completed.stdout
    assert secret_url not in completed.stderr


@pytest.mark.parametrize(
    "url",
    (
        "ssh://git@example.invalid/org/repo.git",
        "git@example.invalid:org/repo.git",
    ),
)
def test_credential_preflight_allows_username_only_ssh_remotes(url: str) -> None:
    completed = _run_credential_preflight(
        remote_names="origin\n",
        origin_fetch=url,
        origin_push=url,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_verifier_pack_identity_pin_is_forwarded_without_shell_interpolation() -> None:
    text = ACTION.read_text(encoding="utf-8")
    assert "expect-verifier-pack-sha256:" in text
    assert (
        "INPUT_EXPECT_VERIFIER_PACK_SHA256: "
        "${{ inputs.expect-verifier-pack-sha256 }}"
    ) in text
    assert (
        'ARGS+=(--expect-verifier-pack-sha256 '
        '"$EFFECTIVE_EXPECT_VERIFIER_PACK_SHA256")'
    ) in text


def test_pr_verifier_pack_is_materialized_from_the_verified_base() -> None:
    text = ACTION.read_text(encoding="utf-8")
    assert 'read_base_policy_string verifier_pack' in text
    assert 'read_base_policy_string expect_verifier_pack_sha256' in text
    assert 'EFFECTIVE_VERIFIER_PACK="$TRUSTED_POLICY_VERIFIER_PACK"' in text
    assert (
        'EFFECTIVE_EXPECT_VERIFIER_PACK_SHA256='
        '"$TRUSTED_POLICY_EXPECT_VERIFIER_PACK_SHA256"'
    ) in text
    assert 'git archive --format=tar "$BASE" -- "$EFFECTIVE_VERIFIER_PACK"' in text
    assert 'TRUSTED_VERIFIER_PACK="$PACK_ROOT/$EFFECTIVE_VERIFIER_PACK"' in text
    assert 'ARGS+=(--verifier-pack "$TRUSTED_VERIFIER_PACK")' in text
    assert "untrusted_verifier_pack_path" in text
    assert "untrusted_verifier_pack_override" in text
    assert 'ARGS+=(--verifier-pack "$INPUT_VERIFIER_PACK")' not in text


def test_pr_mode_never_forwards_candidate_judge_inputs() -> None:
    """Workflow ``with:`` values are candidate-controlled in pull_request.

    Keep every action-input override in the named trusted-only block, rather
    than relying on a future editor to remember which individual options can
    weaken the judge.
    """
    text = ACTION.read_text(encoding="utf-8")
    args_start = text.index('ARGS=(guard --diff - --config "$BASE_POLICY_CONFIG"')
    overrides_start = text.index("# BEGIN NON_PR_WORKFLOW_OVERRIDES", args_start)
    overrides_end = text.index("# END NON_PR_WORKFLOW_OVERRIDES", overrides_start)
    args_end = text.index("# Exact-revision binding", overrides_end)
    overrides = text[overrides_start:overrides_end]
    outside_overrides = text[args_start:overrides_start] + text[overrides_end:args_end]

    assert 'if [ "$IS_PR" != "true" ]; then' in overrides
    for input_name in (
        "INPUT_TEST_COMMAND",
        "INPUT_PROTECTED",
        "INPUT_ALLOW",
        "INPUT_ALLOW_NEW_TESTS",
        "INPUT_ISOLATION",
        "INPUT_DOCKER_IMAGE",
        "INPUT_DOCKER_NETWORK",
        "INPUT_OPERATING_PROFILE",
        "INPUT_STRICT_HARNESS",
        "INPUT_TIMEOUT",
        "INPUT_MEM_LIMIT",
        "INPUT_SARIF",
        "INPUT_BLACKBOX",
        "INPUT_BLACKBOX_ONLY",
        "INPUT_REQUIRE_REPORT_INTEGRITY",
        "INPUT_REQUIRE_CANDIDATE_ISOLATION",
        "INPUT_TRUST_SETUP_ON_HOST",
        "INPUT_DIFF_COVERAGE",
        "INPUT_MIN_DIFF_COVERAGE",
        "INPUT_BASELINE_EVIDENCE",
        "INPUT_REQUIRE_DEMONSTRATED_FIX",
    ):
        assert input_name in overrides
        assert input_name not in outside_overrides

    assert "candidate workflow overrides were ignored" in text
    assert "pull_request ignores workflow inputs that shape the judge" in text


def test_action_bootstraps_a_local_zipapp_without_a_package_resolver() -> None:
    text = ACTION.read_text(encoding="utf-8")
    build_start = text.index("- name: Build EvoGuard archive")
    run_start = text.index("- name: Run EvoGuard", build_start)
    bootstrap = text[build_start:run_start]
    assert "EVOGUARD_ACTION_PATH: ${{ github.action_path }}" in bootstrap
    assert (
        'python -I "$EVOGUARD_ACTION_PATH/ops/build_pyz.py" \\\n'
        '          -o "$RUNNER_TEMP/evo-guard.pyz"'
    ) in bootstrap
    assert 'python -I "$RUNNER_TEMP/evo-guard.pyz" version' in bootstrap
    assert "pip install" not in text
    assert GUARD_CALL in text


def test_action_run_blocks_do_not_invoke_package_tools_or_a_path_command() -> None:
    blocks = _run_blocks(ACTION.read_text(encoding="utf-8"))
    commands = "\n".join(
        line
        for block in blocks
        for line in block.splitlines()
        if not line.lstrip().startswith("#")
    )
    for pattern in (
        r"(?m)^\s*(?:pip|pip3|pipx|poetry|pdm)\b",
        r"\bpython(?:3)?\s+-m\s+pip\b",
        r"\buv\s+pip\b",
    ):
        assert re.search(pattern, commands) is None, pattern
    assert re.search(r"(?m)^\s*evo-guard\b", commands) is None


def test_action_uses_only_preprovisioned_optional_coverage() -> None:
    text = ACTION.read_text(encoding="utf-8")
    description = text[text.index("diff-coverage:") : text.index("min-diff-coverage:")]
    assert "must already provide coverage.py" in description
    assert "[cov]" not in text


def test_windows_temp_paths_are_passed_to_python_as_argv() -> None:
    text = ACTION.read_text(encoding="utf-8")
    assert 'open(sys.argv[1], encoding="utf-8")' in text
    assert "'$RUNNER_TEMP/guard.json'" not in text


def test_fuzz_candidate_processes_receive_no_github_credentials() -> None:
    text = CFLITE_WORKFLOW.read_text(encoding="utf-8")
    for forbidden in (
        "github.token",
        "github-token",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "secrets.",
    ):
        assert forbidden not in text
    assert "persist-credentials: false" in text
    assert "--network none" in text


def test_fuzz_container_copies_do_not_require_chown_capability() -> None:
    text = CFLITE_WORKFLOW.read_text(encoding="utf-8")
    assert "cp -a" not in text
    assert text.count("cp -R --no-preserve=ownership") == 2


def test_fuzz_outputs_use_run_scoped_docker_volumes() -> None:
    text = CFLITE_WORKFLOW.read_text(encoding="utf-8")
    assert "$RUNNER_TEMP/fuzz-out" not in text
    assert "$RUNNER_TEMP/fuzz-work" not in text
    assert "github.run_id" in text
    assert "github.run_attempt" in text
    assert '"$FUZZ_OUT_VOLUME" >/dev/null' in text
    assert text.count("source=$FUZZ_OUT_VOLUME") == 2
    assert text.count("volume-nocopy") == 2
    assert "type=volume,target=/work,volume-nocopy" in text
    assert "chmod 777" not in text
    assert "volume prune" not in text
    assert "if: always()" in text
    assert 'docker volume inspect "$FUZZ_OUT_VOLUME"' in text
    assert 'docker volume rm "$FUZZ_OUT_VOLUME"' in text


def test_fuzz_workflow_runs_on_main_and_pull_requests() -> None:
    text = CFLITE_WORKFLOW.read_text(encoding="utf-8")
    assert "push:\n    branches: [main]" in text
    assert "pull_request:" in text
    assert "workflow_dispatch:" in text


def test_ci_verifies_and_retains_conformance_results() -> None:
    text = ACTIVE_NODE_WORKFLOWS[0].read_text(encoding="utf-8")
    upload = (
        "actions/upload-artifact@"
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
    )
    assert text.count(upload) == 2
    for filename, module in (
        ("runner-conformance.json", "run_runner_conformance"),
        ("isolation-conformance.json", "run_isolation_conformance"),
    ):
        create = text.index(f'--output "${{RUNNER_TEMP}}/{filename}"')
        verify = text.index(f'--verify "${{RUNNER_TEMP}}/{filename}"')
        retained = text.index(f"path: ${{{{ runner.temp }}}}/{filename}")
        assert create < verify < retained
        assert text.count(f"tools.conformance.{module}") >= 2
    assert '--image "$EVOGUARD_E2E_IMAGE"' in text
    assert "--no-pull" in text
    assert text.count("if-no-files-found: error") >= 2


def test_fuzz_workflow_uses_an_immutable_builder_without_wrapper_actions() -> None:
    text = CFLITE_WORKFLOW.read_text(encoding="utf-8")
    assert re.search(
        r"gcr\.io/oss-fuzz-base/base-builder-python@sha256:[0-9a-f]{64}",
        text,
    )
    assert "google/clusterfuzzlite/actions/" not in text
    uses = re.findall(r"^\s*uses:\s*([^\s#]+)", text, flags=re.MULTILINE)
    assert uses
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", target) for target in uses)


def test_fuzz_execution_is_bounded_and_source_is_read_only() -> None:
    text = CFLITE_WORKFLOW.read_text(encoding="utf-8")
    for control in (
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--pids-limit 512",
        "--memory",
        "--cpus",
        "$GITHUB_WORKSPACE:/input/evoom-guard:ro",
        "$GITHUB_WORKSPACE:/src/evoom-guard:ro",
        "source=$FUZZ_OUT_VOLUME,target=/out,readonly",
        "--read-only",
        '"/tmp/corpus/$TARGET"',
        "-artifact_prefix=/tmp/artifacts/",
    ):
        assert control in text


def test_active_candidate_workflows_disable_setup_node_automatic_cache() -> None:
    """Untrusted PR metadata must not silently enable setup-node's npm cache."""

    for workflow in ACTIVE_NODE_WORKFLOWS:
        lines = workflow.read_text(encoding="utf-8").splitlines()
        setup_lines = [
            index
            for index, line in enumerate(lines)
            if "uses: actions/setup-node@" in line
        ]
        assert setup_lines, workflow
        for index in setup_lines:
            block = "\n".join(lines[index : index + 10])
            assert "package-manager-cache: false" in block, workflow


def test_write_permissions_are_scoped_to_metadata_only_jobs() -> None:
    reverify = REVERIFY_WORKFLOW.read_text(encoding="utf-8")
    reverify_top, reverify_jobs = reverify.split("\njobs:\n", 1)
    metadata, candidate = reverify_jobs.split("\n  reverify:\n", 1)
    assert re.search(r"(?m)^\s+checks: write\s*$", reverify_top) is None
    assert re.search(r"(?m)^\s+checks: write\s*$", metadata)
    assert re.search(r"(?m)^\s+checks: write\s*$", candidate) is None

    seal = SEAL_WORKFLOW.read_text(encoding="utf-8")
    seal_top, seal_jobs = seal.split("\njobs:\n", 1)
    reconcile, privileged_seal = seal_jobs.split("\n  seal:\n", 1)
    assert re.search(r"(?m)^\s+checks: write\s*$", seal_top) is None
    assert re.search(r"(?m)^\s+checks: write\s*$", reconcile)
    assert re.search(r"(?m)^\s+checks: write\s*$", privileged_seal)

    scorecard_top = SCORECARD_WORKFLOW.read_text(encoding="utf-8").split(
        "\njobs:\n", 1
    )[0]
    assert "permissions: read-all" not in scorecard_top
    assert "contents: read" in scorecard_top
