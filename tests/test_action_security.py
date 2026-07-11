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


def test_fail_on_documents_the_rejected_only_footgun() -> None:
    """'rejected-only' turns FAIL/TAMPERED/ERROR green; the input description
    must say so loudly (external-review finding §6.4)."""
    text = ACTION.read_text(encoding="utf-8")
    fail_on = text.index("fail-on:")
    desc_end = text.index("isolation:", fail_on)
    desc = text[fail_on:desc_end]
    for token in ("FAIL", "TAMPERED", "ERROR", "GREEN"):
        assert token in desc, f"fail-on description must warn about {token}"
