"""Ratchet branch coverage and expose mutation gaps for weak trust modules.

The coverage baseline is intentionally separate from the global coverage floor.
It prevents a well-covered module from hiding a regression in one of the named
trust-boundary owners.  Mutation declarations are checked against the reviewed
mutations in ``run_security_mutation_gate.py``; a declaration of ``reviewed``
means only that the listed minimum number of explicit mutants targets the file.
It is not a whole-module mutation score.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = Path(__file__).with_name("trust_assurance_baseline.json")


def _normalized_path(value: str) -> str:
    return value.replace("\\", "/").removeprefix("./")


def _read_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return value


def reviewed_mutation_counts() -> Counter[str]:
    """Return direct per-file counts from the deterministic reviewed gate."""

    root_text = str(ROOT)
    if root_text not in sys.path:
        # Direct ``python tools/ci/...`` execution starts with tools/ci rather
        # than the repository root on sys.path.  Import only the reviewed,
        # repository-owned mutation inventory from the frozen root above.
        sys.path.insert(0, root_text)
    from tools.ci.run_security_mutation_gate import MUTATIONS

    return Counter(_normalized_path(mutation.path) for mutation in MUTATIONS)


def _positive_int(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def validate_manifest(
    manifest: dict[str, Any],
    *,
    mutation_counts: Counter[str] | None = None,
    require_sources: bool = True,
) -> list[str]:
    """Return declaration errors without making coverage claims."""

    errors: list[str] = []
    if manifest.get("schema_version") != 1:
        errors.append("manifest schema_version must be 1")
    modules = manifest.get("modules")
    if not isinstance(modules, list) or not modules:
        return errors + ["manifest modules must be a non-empty list"]

    counts = mutation_counts if mutation_counts is not None else reviewed_mutation_counts()
    seen: set[str] = set()
    for index, entry in enumerate(modules):
        prefix = f"modules[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{prefix} must be an object")
            continue
        raw_path = entry.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            errors.append(f"{prefix}.path must be a non-empty string")
            continue
        path = _normalized_path(raw_path)
        if path in seen:
            errors.append(f"duplicate module path: {path}")
        seen.add(path)
        if require_sources and not (ROOT / path).is_file():
            errors.append(f"module source does not exist: {path}")
        if not isinstance(entry.get("trust_boundary"), str) or not entry["trust_boundary"].strip():
            errors.append(f"{path}: trust_boundary must be non-empty")

        floor = entry.get("branch_floor")
        try:
            if not isinstance(floor, dict):
                raise ValueError("branch_floor must be an object")
            floor_covered = _positive_int(floor.get("covered"), label="covered")
            floor_total = _positive_int(floor.get("total"), label="total")
            if floor_covered > floor_total:
                raise ValueError("covered cannot exceed total")

            report = entry.get("baseline_report")
            if not isinstance(report, dict):
                raise ValueError("baseline_report must be an object")
            statements = _positive_int(report.get("statements"), label="statements")
            missing = _nonnegative_int(
                report.get("missing_statements"), label="missing_statements"
            )
            branches = _positive_int(report.get("branches"), label="branches")
            combined = _nonnegative_int(
                report.get("combined_percent"), label="combined_percent"
            )
            if missing > statements:
                raise ValueError("missing_statements cannot exceed statements")
            if combined > 100:
                raise ValueError("combined_percent cannot exceed 100")
            if floor_total != branches:
                raise ValueError("branch floor total must equal baseline branches")
            # coverage.py reported zero-decimal combined coverage at the frozen
            # run.  This is the smallest integral branch count that can reach
            # the lower edge of that rounded percentage bucket.
            total_opportunities = statements + branches
            minimum_covered_total = (
                (2 * combined - 1) * total_opportunities + 199
            ) // 200
            implied_branch_floor = max(
                0, minimum_covered_total - (statements - missing)
            )
            if floor_covered != implied_branch_floor:
                raise ValueError(
                    "covered does not equal the conservative floor implied by "
                    "baseline_report"
                )
        except ValueError as exc:
            errors.append(f"{path}: invalid branch_floor: {exc}")

        mutation = entry.get("mutation")
        if not isinstance(mutation, dict):
            errors.append(f"{path}: mutation must be an object")
            continue
        status = mutation.get("status")
        actual = counts[path]
        if status == "reviewed":
            try:
                minimum = _positive_int(
                    mutation.get("minimum_reviewed_mutants"),
                    label="minimum_reviewed_mutants",
                )
            except ValueError as exc:
                errors.append(f"{path}: {exc}")
            else:
                if actual < minimum:
                    errors.append(
                        f"{path}: reviewed mutation count {actual} is below {minimum}"
                    )
        elif status == "gap":
            gap = mutation.get("gap")
            if not isinstance(gap, str) or not gap.strip():
                errors.append(f"{path}: mutation gap must explain the missing coverage")
            if actual:
                errors.append(
                    f"{path}: declared mutation gap now has {actual} direct mutant(s); "
                    "replace the gap with a reviewed minimum"
                )
        else:
            errors.append(f"{path}: mutation.status must be 'reviewed' or 'gap'")
    return errors


def validate_coverage(
    manifest: dict[str, Any], coverage_document: dict[str, Any]
) -> tuple[list[str], list[str]]:
    """Validate branch ratios and return (errors, printable observations)."""

    errors: list[str] = []
    observations: list[str] = []
    meta = coverage_document.get("meta")
    if not isinstance(meta, dict) or meta.get("branch_coverage") is not True:
        return ["coverage JSON must report branch_coverage=true"], observations
    files = coverage_document.get("files")
    if not isinstance(files, dict):
        return ["coverage JSON files must be an object"], observations
    indexed = {
        _normalized_path(path): value
        for path, value in files.items()
        if isinstance(path, str)
    }

    for entry in manifest["modules"]:
        path = _normalized_path(entry["path"])
        record = indexed.get(path)
        if not isinstance(record, dict):
            errors.append(f"{path}: missing from coverage JSON")
            continue
        summary = record.get("summary")
        if not isinstance(summary, dict):
            errors.append(f"{path}: coverage summary is missing")
            continue
        covered = summary.get("covered_branches")
        total = summary.get("num_branches")
        if (
            isinstance(covered, bool)
            or not isinstance(covered, int)
            or covered < 0
            or isinstance(total, bool)
            or not isinstance(total, int)
            or total <= 0
            or covered > total
        ):
            errors.append(f"{path}: invalid branch counts covered={covered!r} total={total!r}")
            continue
        floor = entry["branch_floor"]
        floor_covered = floor["covered"]
        floor_total = floor["total"]
        observations.append(
            f"{path}: branches {covered}/{total}; floor {floor_covered}/{floor_total}"
        )
        if covered * floor_total < floor_covered * total:
            errors.append(
                f"{path}: branch ratio {covered}/{total} regressed below "
                f"{floor_covered}/{floor_total}"
            )
    return errors, observations


def mutation_observations(
    manifest: dict[str, Any], counts: Counter[str]
) -> Iterable[str]:
    for entry in manifest["modules"]:
        path = _normalized_path(entry["path"])
        status = entry["mutation"]["status"]
        yield f"{path}: direct reviewed mutants={counts[path]} status={status}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--coverage-json",
        type=Path,
        required=True,
        help="coverage.py JSON output produced with branch coverage enabled",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help=f"trust assurance manifest (default: {DEFAULT_MANIFEST})",
    )
    args = parser.parse_args(argv)

    try:
        manifest = _read_json(args.manifest, label="manifest")
        coverage_document = _read_json(args.coverage_json, label="coverage JSON")
        counts = reviewed_mutation_counts()
        errors = validate_manifest(manifest, mutation_counts=counts)
        if errors:
            print(
                "Trust assurance manifest failed:\n- " + "\n- ".join(errors),
                file=sys.stderr,
            )
            return 1
        coverage_errors, observations = validate_coverage(manifest, coverage_document)
    except ValueError as exc:
        print(f"trust assurance gate failed: {exc}", file=sys.stderr)
        return 2

    for observation in observations:
        print(f"COVERAGE {observation}")
    for observation in mutation_observations(manifest, counts):
        print(f"MUTATION {observation}")
    if coverage_errors:
        print(
            "\nTrust assurance gate failed:\n- " + "\n- ".join(coverage_errors),
            file=sys.stderr,
        )
        return 1
    print("\nTrust assurance branch ratchets and mutation declarations verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
