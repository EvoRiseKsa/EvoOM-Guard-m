# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Fail when live Markdown documentation contains a broken local link.

The check is deliberately offline. External URLs are not fetched because
availability is not reproducible in CI; local files and GitHub-style heading
anchors are checked against the exact source tree instead.
"""

from __future__ import annotations

import argparse
import re
import sys
import unicodedata
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]

_REFERENCE_LINK_RE = re.compile(
    r"^\s{0,3}\[[^\]\n]+\]:\s*(?P<target><[^>\n]+>|[^\s\n]+)",
    re.MULTILINE,
)
_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(?P<title>.+?)\s*#*\s*$")
_FENCE_RE = re.compile(r"^\s*(```|~~~)")
_EXTERNAL_SCHEMES = (
    "http:",
    "https:",
    "mailto:",
    "tel:",
    "data:",
)


def documentation_files(root: Path = ROOT) -> tuple[Path, ...]:
    """Return maintained Markdown surfaces, excluding immutable baselines."""

    top_level = (
        "README.md",
        "CHANGELOG.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "GOVERNANCE.md",
        "LICENSE_HISTORY.md",
        "LICENSE_ARABIC_SUMMARY.md",
        "COMMERCIAL-LICENSING.md",
        "THIRD_PARTY.md",
    )
    paths = [root / name for name in top_level if (root / name).is_file()]
    paths.extend(sorted((root / "docs").rglob("*.md")))
    paths.extend(sorted((root / "examples").rglob("*.md")))
    return tuple(dict.fromkeys(paths))


def _without_fenced_code(text: str) -> str:
    lines: list[str] = []
    in_fence = False
    fence = ""
    for line in text.splitlines():
        match = _FENCE_RE.match(line)
        if match:
            marker = match.group(1)
            if not in_fence:
                in_fence = True
                fence = marker
            elif marker == fence:
                in_fence = False
                fence = ""
            lines.append("")
            continue
        lines.append("" if in_fence else line)
    return "\n".join(lines)


def _without_inline_code(text: str) -> str:
    characters = list(text)
    index = 0
    while index < len(text):
        if text[index] != "`" or _is_escaped(text, index):
            index += 1
            continue
        run_end = index
        while run_end < len(text) and text[run_end] == "`":
            run_end += 1
        marker = text[index:run_end]
        closing = text.find(marker, run_end)
        if closing < 0:
            index = run_end
            continue
        for cursor in range(index, closing + len(marker)):
            if characters[cursor] != "\n":
                characters[cursor] = " "
        index = closing + len(marker)
    return "".join(characters)


def _slug_text(value: str) -> str:
    value = re.sub(r"<[^>]+>", "", value)
    value = re.sub(r"!?\[([^\]]+)\]\([^)]*\)", r"\1", value)
    value = re.sub(r"\[([^\]]+)\]\[[^\]]*\]", r"\1", value)
    value = re.sub(r"[`*_~]", "", value).strip().lower()
    retained: list[str] = []
    for character in value:
        category = unicodedata.category(character)
        if category[0] in {"L", "N"} or character in {" ", "-", "_"}:
            retained.append(character)
    return re.sub(r"[\s-]+", "-", "".join(retained)).strip("-")


def _anchors(path: Path) -> set[str]:
    counts: defaultdict[str, int] = defaultdict(int)
    anchors: set[str] = set()
    text = _without_fenced_code(path.read_text(encoding="utf-8"))
    for line in text.splitlines():
        match = _HEADING_RE.match(line)
        if match is None:
            continue
        base = _slug_text(match.group("title"))
        if not base:
            continue
        suffix = counts[base]
        counts[base] += 1
        anchors.add(base if suffix == 0 else f"{base}-{suffix}")
    return anchors


def _is_escaped(text: str, index: int) -> bool:
    backslashes = 0
    cursor = index - 1
    while cursor >= 0 and text[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes % 2 == 1


def _closing_square_bracket(text: str, start: int) -> int | None:
    depth = 0
    for index in range(start, len(text)):
        if _is_escaped(text, index):
            continue
        if text[index] == "[":
            depth += 1
        elif text[index] == "]":
            depth -= 1
            if depth == 0:
                return index
    return None


def _inline_targets(text: str) -> list[tuple[int, str]]:
    """Parse inline link and image destinations with balanced parentheses."""

    targets: list[tuple[int, str]] = []
    for index, character in enumerate(text):
        if character != "[" or _is_escaped(text, index):
            continue
        label_end = _closing_square_bracket(text, index)
        if label_end is None or label_end + 1 >= len(text) or text[label_end + 1] != "(":
            continue
        cursor = label_end + 2
        while cursor < len(text) and text[cursor] in {" ", "\t"}:
            cursor += 1
        if cursor >= len(text):
            continue
        target_start = cursor
        if text[cursor] == "<":
            target_start += 1
            cursor += 1
            while cursor < len(text):
                if text[cursor] == ">" and not _is_escaped(text, cursor):
                    targets.append(
                        (
                            text.count("\n", 0, index) + 1,
                            text[target_start:cursor],
                        )
                    )
                    break
                cursor += 1
            continue

        parenthesis_depth = 0
        while cursor < len(text):
            current = text[cursor]
            if _is_escaped(text, cursor):
                cursor += 1
                continue
            if current == "(":
                parenthesis_depth += 1
            elif current == ")":
                if parenthesis_depth == 0:
                    break
                parenthesis_depth -= 1
            elif current.isspace() and parenthesis_depth == 0:
                break
            cursor += 1
        if cursor > target_start:
            targets.append(
                (
                    text.count("\n", 0, index) + 1,
                    text[target_start:cursor],
                )
            )
    return targets


def _targets(text: str) -> list[tuple[int, str]]:
    clean = _without_inline_code(_without_fenced_code(text))
    targets = _inline_targets(clean)
    for match in _REFERENCE_LINK_RE.finditer(clean):
        target = match.group("target")
        if target.startswith("<") and target.endswith(">"):
            target = target[1:-1]
        lineno = clean.count("\n", 0, match.start()) + 1
        targets.append((lineno, target))
    return [
        (
            lineno,
            re.sub(r"\\([!\"#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~])", r"\1", target),
        )
        for lineno, target in targets
    ]


def check_markdown_links(root: Path = ROOT) -> list[str]:
    """Return deterministic local-link failures for maintained documentation."""

    errors: list[str] = []
    anchor_cache: dict[Path, set[str]] = {}
    root = root.resolve()
    for source in documentation_files(root):
        relative_source = source.relative_to(root).as_posix()
        for lineno, raw_target in _targets(source.read_text(encoding="utf-8")):
            target = unquote(raw_target)
            lowered = target.lower()
            if not target or lowered.startswith(_EXTERNAL_SCHEMES):
                continue
            if target.startswith("/") or target.startswith("//"):
                continue

            path_text, separator, fragment = target.partition("#")
            path_text = path_text.split("?", 1)[0]
            destination = source if not path_text else source.parent / path_text
            resolved = destination.resolve()
            try:
                resolved.relative_to(root)
            except ValueError:
                errors.append(
                    f"{relative_source}:{lineno}: local link escapes the repository: "
                    f"{raw_target}"
                )
                continue
            if not resolved.exists():
                errors.append(
                    f"{relative_source}:{lineno}: missing local target: {raw_target}"
                )
                continue
            if separator and fragment and resolved.is_file() and resolved.suffix.lower() == ".md":
                expected = _slug_text(fragment)
                anchors = anchor_cache.setdefault(resolved, _anchors(resolved))
                if expected not in anchors:
                    errors.append(
                        f"{relative_source}:{lineno}: missing heading #{fragment} in "
                        f"{resolved.relative_to(root).as_posix()}"
                    )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="repository root (defaults to the checker source tree)",
    )
    args = parser.parse_args(argv)
    errors = check_markdown_links(args.root)
    if errors:
        print("Markdown link check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("Markdown local links and anchors are consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
