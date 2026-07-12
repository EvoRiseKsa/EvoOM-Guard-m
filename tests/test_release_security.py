"""Supply-chain invariants for release workflows."""

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
CI = ROOT / ".github" / "workflows" / "ci.yml"


def test_release_assets_are_immutable_and_bound_to_the_tag_commit() -> None:
    for workflow in (RELEASE, CI):
        text = workflow.read_text(encoding="utf-8")
        assert "--clobber" not in text
        assert "release_tag_target_mismatch" in text
        assert "release_asset_immutable" in text
        assert "commits/$" in text
        assert "cmp -s" in text


def test_release_workflow_actions_are_pinned_to_commit_shas() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    uses = re.findall(r"^\s*-\s+uses:\s*([^\s#]+)", text, flags=re.MULTILINE)
    assert uses
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", target) for target in uses)
