"""Run a deterministic, bounded mutation gate over assurance-sensitive logic.

This is intentionally smaller than a general mutation framework.  Every mutant
models a reviewed security regression, must apply exactly once, and is executed
against one focused test in an isolated package overlay.  A mutant is killed
only by a normal pytest assertion failure (exit 1); collection errors, timeouts,
and infrastructure failures fail the gate instead of becoming false positives.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Mutation:
    name: str
    path: str
    before: str
    after: str
    test: str


MUTATIONS = (
    Mutation(
        name="protected-edit-preflight-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before="        if rejection is not None:\n            return rejection\n",
        after="        if False and rejection is not None:\n            return rejection\n",
        test=(
            "tests/test_repo_verifier_characterization.py::"
            "test_frozen_repo_verifier_behavior_and_evidence[protected_test_edit]"
        ),
    ),
    Mutation(
        name="protected-deletion-preflight-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "            if del_rejection is not None:\n"
            "                return del_rejection\n"
        ),
        after=(
            "            if False and del_rejection is not None:\n"
            "                return del_rejection\n"
        ),
        test=(
            "tests/test_repo_verifier_characterization.py::"
            "test_frozen_repo_verifier_behavior_and_evidence[deleted_protected_test]"
        ),
    ),
    Mutation(
        name="strict-harness-exit-only-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before="            if strict_harness and (junit is None or junit.total <= 0):\n",
        after="            if False and strict_harness and (junit is None or junit.total <= 0):\n",
        test=(
            "tests/test_repo_verifier_characterization.py::"
            "test_frozen_repo_verifier_behavior_and_evidence[strict_exit_only_rejected]"
        ),
    ),
    Mutation(
        name="junit-exit-disagreement-bypass",
        path="evoom_guard/verifiers/junit_oracle.py",
        before="    if has_failures and returncode == 0:\n        return True\n",
        after="    if False and has_failures and returncode == 0:\n        return True\n",
        test=(
            "tests/test_repo_verifier_characterization.py::"
            "test_frozen_repo_verifier_behavior_and_evidence[junit_tamper]"
        ),
    ),
    Mutation(
        name="junit-doctype-filter-bypass",
        path="evoom_guard/verifiers/junit_oracle.py",
        before='    if "<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text:\n        return None\n',
        after=(
            '    if False and ("<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text):\n'
            "        return None\n"
        ),
        test="tests/test_junit_hardening.py::test_rejects_doctype_billion_laughs_without_expanding",
    ),
    Mutation(
        name="subprocess-output-cap-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before="                self._exceeded = True\n",
        after="                self._exceeded = False\n",
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_bounded_output_marks_any_truncated_bytes_as_exceeded"
        ),
    ),
)


def _apply_mutation(overlay: Path, mutation: Mutation) -> None:
    target = overlay / mutation.path
    source = target.read_text(encoding="utf-8")
    count = source.count(mutation.before)
    if count != 1:
        raise RuntimeError(
            f"{mutation.name}: expected one mutation site in {mutation.path}, found {count}"
        )
    target.write_text(
        source.replace(mutation.before, mutation.after, 1),
        encoding="utf-8",
        newline="\n",
    )


def _run_mutant(mutation: Mutation, timeout: float) -> tuple[str, str]:
    with tempfile.TemporaryDirectory(prefix="evoguard-mutant-") as temp:
        overlay = Path(temp)
        shutil.copytree(
            ROOT / "evoom_guard",
            overlay / "evoom_guard",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        _apply_mutation(overlay, mutation)

        # Pre-import from the overlay before pytest discovers the repository
        # root.  sys.modules then prevents a test's path setup from replacing the
        # mutated package with the working-tree package.
        bootstrap = (
            "import sys; "
            f"sys.path.insert(0, {str(overlay)!r}); "
            "import evoom_guard.verifiers.repo_verifier as repo_verifier; "
            f"assert repo_verifier.__file__.startswith({str(overlay)!r}); "
            "import evoom_guard.verifiers.junit_oracle; "
            "import pytest; "
            f"raise SystemExit(pytest.main([{mutation.test!r}, '-q']))"
        )
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONHASHSEED="0")
        try:
            completed = subprocess.run(
                [sys.executable, "-c", bootstrap],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return "infrastructure-error", f"exceeded {timeout:g}s"

    output = (completed.stdout + "\n" + completed.stderr).strip()
    if completed.returncode == 1:
        return "killed", output
    if completed.returncode == 0:
        return "survived", output
    return "infrastructure-error", f"pytest exit {completed.returncode}\n{output}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="per-mutant timeout in seconds (default: 20)",
    )
    parser.add_argument(
        "--mutation",
        action="append",
        default=[],
        help="run only this mutation name (repeatable)",
    )
    args = parser.parse_args()
    if not 1 <= args.timeout <= 120:
        parser.error("--timeout must be between 1 and 120 seconds")

    requested = set(args.mutation)
    known = {mutation.name for mutation in MUTATIONS}
    unknown = requested - known
    if unknown:
        parser.error("unknown mutation(s): " + ", ".join(sorted(unknown)))
    selected = [m for m in MUTATIONS if not requested or m.name in requested]

    failures: list[str] = []
    for mutation in selected:
        try:
            status, detail = _run_mutant(mutation, args.timeout)
        except (OSError, RuntimeError) as exc:
            status, detail = "infrastructure-error", str(exc)
        print(f"{status.upper():20} {mutation.name}")
        if status != "killed":
            failures.append(f"{mutation.name}: {status}\n{detail}")

    if failures:
        print("\nMutation gate failed:\n" + "\n\n".join(failures), file=sys.stderr)
        return 1
    print(f"\nSecurity mutation score: {len(selected)}/{len(selected)} killed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
