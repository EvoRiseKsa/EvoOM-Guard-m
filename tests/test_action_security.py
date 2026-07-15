"""Regression checks for the Marketplace composite action's trust boundary."""

import re
from pathlib import Path

ACTION = Path(__file__).parents[1] / "action.yml"


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


def test_action_inputs_are_not_interpolated_into_shell_scripts() -> None:
    blocks = _run_blocks(ACTION.read_text(encoding="utf-8"))
    assert blocks
    for block in blocks:
        assert "${{ inputs." not in block


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
    guard_call = text.index('evo-guard "${ARGS[@]}"')
    assert text.index("base_ref_unavailable") < guard_call
    assert text.index("base_diff_failed") < guard_call


def test_action_uses_a_verified_base_policy_not_candidate_workspace() -> None:
    text = ACTION.read_text(encoding="utf-8")
    base_check = text.index('git rev-parse --verify --quiet "${BASE}^{commit}"')
    materialize = text.index('git show "${BASE}:.evoguard.json"')
    guard_call = text.index('evo-guard "${ARGS[@]}"')
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
    guard_call = text.index('evo-guard "${ARGS[@]}"')
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


def test_pr_mode_installs_coverage_without_trusting_candidate_coverage_inputs() -> None:
    text = ACTION.read_text(encoding="utf-8")
    install_start = text.index("- name: Install EvoGuard")
    run_start = text.index("- name: Run EvoGuard", install_start)
    install = text[install_start:run_start]
    assert "PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}" in install
    assert 'if [ -n "$PR_BASE_SHA" ]; then' in install
    assert 'pip install -q "${{ github.action_path }}[cov]"' in install
