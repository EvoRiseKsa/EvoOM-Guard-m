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
