# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Regression gate for maintained Markdown navigation."""

from pathlib import Path

from tools.ci.check_markdown_links import check_markdown_links


def test_live_markdown_local_links_and_anchors_are_valid() -> None:
    assert check_markdown_links() == []


def test_images_nested_links_parentheses_and_references_are_checked(
    tmp_path: Path,
) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (tmp_path / "image.png").write_bytes(b"image")
    (docs / "file_(draft).md").write_text("# Draft\n", encoding="utf-8")
    (docs / "guide.md").write_text("# Intro\n", encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "\n".join(
            (
                "# Index",
                "![missing image](missing.png)",
                "[![existing image](image.png)](missing-wrapper.md)",
                "[balanced destination](docs/file_(draft).md)",
                "[reference target][guide]",
                "[guide]: docs/guide.md#intro",
            )
        ),
        encoding="utf-8",
    )

    errors = check_markdown_links(tmp_path)

    assert len(errors) == 2
    assert any("missing.png" in error for error in errors)
    assert any("missing-wrapper.md" in error for error in errors)


def test_fenced_examples_are_ignored_and_heading_anchors_are_checked(
    tmp_path: Path,
) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "guide.md").write_text("# Real heading\n", encoding="utf-8")
    (docs / "escaped_(draft).md").write_text(
        "## [Install](https://example.test)\n",
        encoding="utf-8",
    )
    readme = tmp_path / "README.md"
    readme.write_text(
        "\n".join(
            (
                "# Index",
                "```markdown",
                "[illustrative missing link](ignored.md)",
                "```",
                "`[inline-code example](ignored-inline.md)`",
                "[valid anchor](docs/guide.md#real-heading)",
                r"[escaped parentheses](docs/escaped_\(draft\).md#install)",
            )
        ),
        encoding="utf-8",
    )
    assert check_markdown_links(tmp_path) == []

    readme.write_text("[bad anchor](docs/guide.md#missing)\n", encoding="utf-8")
    errors = check_markdown_links(tmp_path)
    assert len(errors) == 1
    assert "missing heading #missing" in errors[0]
