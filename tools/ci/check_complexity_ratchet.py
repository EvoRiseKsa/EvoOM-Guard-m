# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Reject new or increased cyclomatic-complexity debt.

The baseline is deliberately keyed by source path and function name rather than
line number, so unrelated edits cannot hide or manufacture a finding. Existing
findings are reviewed debt, not a target and not evidence of a defect. A lower
or removed finding makes the baseline stale and fails the gate until the
reviewed ceiling is lowered, so removed complexity cannot be regained later.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASELINE = Path(__file__).with_name("complexity_baseline.json")
BASELINE_FORMAT = "evoom-guard-complexity-baseline-1"
RUFF_RULE = "C901"
MESSAGE_PATTERN = re.compile(
    r"^`(?P<symbol>[^`]+)` is too complex "
    r"\((?P<complexity>[0-9]+) > (?P<threshold>[0-9]+)\)$"
)


@dataclass(frozen=True, order=True)
class ComplexityFinding:
    """One stable Ruff C901 observation."""

    path: str
    symbol: str
    complexity: int
    threshold: int

    @property
    def key(self) -> tuple[str, str]:
        return self.path, self.symbol


def _relative_source_path(filename: str, *, root: Path) -> str:
    try:
        path = Path(filename).resolve().relative_to(root.resolve())
    except (OSError, ValueError) as exc:
        raise ValueError(f"Ruff reported a source outside the repository: {filename}") from exc
    return path.as_posix()


def parse_ruff_findings(document: Any, *, root: Path = ROOT) -> tuple[ComplexityFinding, ...]:
    """Parse Ruff JSON without silently accepting an unknown result shape."""

    if not isinstance(document, list):
        raise ValueError("Ruff output must be a JSON array")
    findings: list[ComplexityFinding] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(document):
        if not isinstance(item, dict):
            raise ValueError(f"Ruff finding {index} must be an object")
        if item.get("code") != RUFF_RULE:
            raise ValueError(f"Ruff finding {index} has unexpected rule {item.get('code')!r}")
        filename = item.get("filename")
        message = item.get("message")
        if not isinstance(filename, str) or not isinstance(message, str):
            raise ValueError(f"Ruff finding {index} is missing filename or message")
        match = MESSAGE_PATTERN.fullmatch(message)
        if match is None:
            raise ValueError(f"Ruff finding {index} has an unknown C901 message: {message!r}")
        finding = ComplexityFinding(
            path=_relative_source_path(filename, root=root),
            symbol=match.group("symbol"),
            complexity=int(match.group("complexity")),
            threshold=int(match.group("threshold")),
        )
        if finding.key in seen:
            raise ValueError(
                "Ruff produced an ambiguous duplicate path/function key: "
                f"{finding.path}:{finding.symbol}"
            )
        seen.add(finding.key)
        findings.append(finding)
    return tuple(sorted(findings))


def collect_findings(*, root: Path = ROOT) -> tuple[ComplexityFinding, ...]:
    """Run the repository's installed Ruff version and return C901 findings."""

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "evoom_guard",
            "--select",
            RUFF_RULE,
            "--output-format",
            "json",
            "--exit-zero",
        ],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"Ruff complexity collection failed: {detail}")
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Ruff returned invalid JSON: {exc}") from exc
    return parse_ruff_findings(document, root=root)


def baseline_document(findings: Iterable[ComplexityFinding]) -> dict[str, Any]:
    """Build the deterministic reviewed-ceiling document."""

    entries = [
        {
            "path": finding.path,
            "symbol": finding.symbol,
            "max_complexity": finding.complexity,
        }
        for finding in sorted(findings)
    ]
    return {
        "format": BASELINE_FORMAT,
        "rule": RUFF_RULE,
        "entries": entries,
    }


def parse_baseline(document: Any) -> dict[tuple[str, str], int]:
    """Validate a baseline and return its ceilings keyed by path/function."""

    if not isinstance(document, dict):
        raise ValueError("complexity baseline must be a JSON object")
    if document.get("format") != BASELINE_FORMAT:
        raise ValueError(f"complexity baseline format must be {BASELINE_FORMAT!r}")
    if document.get("rule") != RUFF_RULE:
        raise ValueError(f"complexity baseline rule must be {RUFF_RULE!r}")
    entries = document.get("entries")
    if not isinstance(entries, list):
        raise ValueError("complexity baseline entries must be an array")
    baseline: dict[tuple[str, str], int] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"baseline entry {index} must be an object")
        path = entry.get("path")
        symbol = entry.get("symbol")
        ceiling = entry.get("max_complexity")
        if not isinstance(path, str) or not path.startswith("evoom_guard/") or "\\" in path:
            raise ValueError(f"baseline entry {index} has an invalid source path")
        if not isinstance(symbol, str) or not symbol:
            raise ValueError(f"baseline entry {index} has an invalid symbol")
        if isinstance(ceiling, bool) or not isinstance(ceiling, int) or ceiling <= 10:
            raise ValueError(f"baseline entry {index} has an invalid complexity ceiling")
        key = (path, symbol)
        if key in baseline:
            raise ValueError(f"duplicate complexity baseline key: {path}:{symbol}")
        baseline[key] = ceiling
    return baseline


def compare_findings(
    findings: Iterable[ComplexityFinding], baseline: dict[tuple[str, str], int]
) -> tuple[list[str], list[str]]:
    """Return (regressions, improvements) relative to reviewed ceilings."""

    regressions: list[str] = []
    improvements: list[str] = []
    current = {finding.key: finding for finding in findings}
    for key, finding in sorted(current.items()):
        ceiling = baseline.get(key)
        label = f"{finding.path}:{finding.symbol}"
        if ceiling is None:
            regressions.append(f"new C901 hotspot {label} has complexity {finding.complexity}")
        elif finding.complexity > ceiling:
            regressions.append(
                f"C901 hotspot {label} increased from ceiling {ceiling} "
                f"to {finding.complexity}"
            )
        elif finding.complexity < ceiling:
            improvements.append(
                f"C901 hotspot {label} decreased from ceiling {ceiling} "
                f"to {finding.complexity}; lower the baseline"
            )
    for key, ceiling in sorted(baseline.items()):
        if key not in current:
            improvements.append(
                f"C901 hotspot {key[0]}:{key[1]} no longer exceeds the threshold "
                f"(old ceiling {ceiling}); remove it from the baseline"
            )
    return regressions, improvements


def _load_json(path: Path, *, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {label} {path}: {exc}") from exc


def check_complexity_ratchet(
    *, baseline_path: Path = DEFAULT_BASELINE, root: Path = ROOT
) -> tuple[list[str], list[str]]:
    findings = collect_findings(root=root)
    baseline = parse_baseline(_load_json(baseline_path, label="complexity baseline"))
    return compare_findings(findings, baseline)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="replace the reviewed baseline with the current deterministic findings",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        findings = collect_findings()
        if args.update_baseline:
            args.baseline.write_text(
                json.dumps(baseline_document(findings), indent=2) + "\n",
                encoding="utf-8",
            )
            print(f"wrote {len(findings)} reviewed C901 ceilings to {args.baseline}")
            return 0
        baseline = parse_baseline(_load_json(args.baseline, label="complexity baseline"))
        regressions, improvements = compare_findings(findings, baseline)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"complexity ratchet error: {exc}", file=sys.stderr)
        return 2

    for improvement in improvements:
        print(f"STALE BASELINE: {improvement}", file=sys.stderr)
    if regressions:
        for regression in regressions:
            print(f"REGRESSION: {regression}", file=sys.stderr)
        return 1
    if improvements:
        print(
            "complexity baseline must be updated to retain every measured improvement",
            file=sys.stderr,
        )
        return 1
    print(
        f"complexity ratchet passed: {len(findings)} C901 findings, "
        f"{len(improvements)} improvement(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
