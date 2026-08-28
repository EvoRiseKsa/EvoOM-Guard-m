#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""One command for the benchmark re-seal ritual — same trust model, no toil.

Changing any file in the benchmark source inventory (``evoom_guard/**/*.py|json``
or the fixed ``benchmarks/{evaluate,run_live,run_manifest}.py`` /
``pyproject.toml`` / ``requirements/ci.lock`` set) invalidates the manifest's
source digest, which by design forces a three-commit re-seal:

1. ``bench(results): re-measure live corpus`` — a fresh ``benchmarks/results.jsonl``
   from real ``guard()`` runs, committed *without* the manifest so it can be the
   evidence commit.
2. ``bench(manifest): finalize provenance binding`` — the finalized
   ``benchmarks/run-manifest.json`` binding that evidence commit.
3. ``evidence(registry): re-bind failure registry`` — the derived
   ``evidence/failure-registry/synthetic-observations-v1.json``.

The three distinct, linearly-ancestral commits are **not ceremony**: the signed
release lane's Gate A verifies exactly that ``source -> evidence -> finalization``
ancestry chain (``docs/RELEASE_GATE_CHECKLIST.md``). This tool therefore does not
change the trust model at all — it runs the exact same commands, in the exact
same order, producing the exact same three-commit shape, so a human stops doing
it by hand.

The one human judgment it deliberately does **not** automate away is the
reviewed-disposition pin. ``tools/evaluation/failure_registry.py`` keys each
reviewed disposition (a "known gap" / "deliberate tradeoff" ruling) to the exact
``(source_inventory_sha256, corpus_sha256)`` that produced it, precisely so a
source change *expires* those rulings to ``unresolved`` and forces a re-review.
When the source digest changes, this tool stops and asks you to confirm the
known boundaries still hold; only ``--repin`` (your confirmation) re-pins them.

Usage::

    # After committing your source change (HEAD is the source commit):
    python -I tools/ci/reseal.py "my change summary"
    # If the source digest changed, review the reported dispositions, then:
    python -I tools/ci/reseal.py "my change summary" --repin

    python -I tools/ci/reseal.py "my change summary" --dry-run   # print the plan only
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "benchmarks" / "results.jsonl"
MANIFEST = ROOT / "benchmarks" / "run-manifest.json"
REGISTRY = ROOT / "evidence" / "failure-registry" / "synthetic-observations-v1.json"
FAILURE_REGISTRY_SRC = ROOT / "tools" / "evaluation" / "failure_registry.py"
FAILURE_REGISTRY_TEST = ROOT / "tests" / "test_synthetic_failure_registry.py"

# 64 lowercase hex — the source-inventory digest pinned in the reviewed
# dispositions (three occurrences) and in the disposition-binding test (one).
_SHA_RE = re.compile(r"\b[0-9a-f]{64}\b")


class ReSealError(RuntimeError):
    """A re-seal step failed or a precondition was not met."""


def _run(args: list[str], *, root: Path = ROOT) -> str:
    """Run a subprocess, raising ReSealError with captured output on failure."""
    completed = subprocess.run(
        args,
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ReSealError(
            f"command failed ({completed.returncode}): {' '.join(args)}\n"
            f"{completed.stdout}\n{completed.stderr}".strip()
        )
    return completed.stdout


def _git(args: list[str], *, root: Path = ROOT) -> str:
    return _run(["git", *args], root=root)


def _require_clean_worktree(root: Path = ROOT) -> None:
    """The source change must already be committed; HEAD is the source commit."""
    status = _git(["status", "--porcelain"], root=root).strip()
    if status:
        raise ReSealError(
            "working tree is not clean. Commit your source change first — the "
            "current HEAD becomes the bound source commit — then re-run.\n"
            f"outstanding:\n{status}"
        )


def _manifest_source_sha256(manifest_path: Path = MANIFEST) -> str:
    """The source-inventory digest recorded in a finalized manifest."""
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    source = data.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("sha256"), str):
        raise ReSealError(f"{manifest_path} has no source.sha256")
    sha = source["sha256"]
    if not _SHA_RE.fullmatch(sha):
        raise ReSealError(f"{manifest_path} source.sha256 is not a 64-hex digest")
    return sha


def _pinned_source_sha256(src: Path = FAILURE_REGISTRY_SRC) -> str:
    """The single source digest the reviewed dispositions are pinned to.

    Read from the real ``REVIEWED_DISPOSITIONS`` structure — a mapping whose keys
    are ``(source_inventory_sha256, corpus_sha256, case_id, failure_class)`` — so
    the source pin is unambiguously the first tuple element, never a regex guess.
    """
    dispositions = _load_reviewed_dispositions(src)
    if not dispositions:
        raise ReSealError(f"no reviewed dispositions found in {src}")
    source_pins = {key[0] for key in dispositions}
    if len(source_pins) != 1:
        raise ReSealError(
            f"reviewed dispositions in {src} pin differing source digests: {source_pins}"
        )
    (pin,) = source_pins
    if not _SHA_RE.fullmatch(pin):
        raise ReSealError(f"reviewed-disposition source pin is not a 64-hex digest: {pin}")
    return pin


def _load_reviewed_dispositions(src: Path = FAILURE_REGISTRY_SRC) -> dict[tuple[str, ...], str]:
    """Import ``REVIEWED_DISPOSITIONS`` from the registry module by file path."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("_evoguard_failure_registry", src)
    if spec is None or spec.loader is None:
        raise ReSealError(f"cannot load {src}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    dispositions = getattr(module, "REVIEWED_DISPOSITIONS", None)
    if not isinstance(dispositions, dict):
        raise ReSealError(f"{src} has no REVIEWED_DISPOSITIONS mapping")
    return dispositions


def _repin(new_sha: str, old_sha: str) -> list[Path]:
    """Replace the pinned source digest across the source + its test. Returns edited paths."""
    edited: list[Path] = []
    for path in (FAILURE_REGISTRY_SRC, FAILURE_REGISTRY_TEST):
        text = path.read_text(encoding="utf-8")
        if old_sha in text:
            path.write_text(text.replace(old_sha, new_sha), encoding="utf-8")
            edited.append(path)
    return edited


def _commit(files: list[Path], message: str, *, root: Path = ROOT) -> str:
    rels = [str(f.relative_to(root)) for f in files]
    _git(["add", "--", *rels], root=root)
    staged = _git(["diff", "--cached", "--name-only"], root=root).strip()
    if not staged:
        raise ReSealError(
            f"nothing staged for commit '{message}' — expected changes in {rels}"
        )
    _git(["commit", "-m", message], root=root)
    return _git(["rev-parse", "HEAD"], root=root).strip()


def re_seal(subject: str, *, repin: bool, dry_run: bool, root: Path = ROOT) -> int:
    """Run the three-commit re-seal ritual. Returns a process exit code."""
    py = [sys.executable, "-I"]
    run_live = str(root / "benchmarks" / "run_live.py")
    registry_tool = str(root / "tools" / "evaluation" / "failure_registry.py")

    plan = [
        f"1. {' '.join([*py, run_live, '--replace'])}  ->  commit results.jsonl",
        f"2. {' '.join([*py, run_live, '--finalize-provenance', str(MANIFEST), '--replace'])}"
        "  ->  commit run-manifest.json",
        f"3. {' '.join([*py, registry_tool, '--generate', '--finalization-commit <manifest-commit>', '--replace'])}"
        "  ->  commit registry",
        f"4. {' '.join([*py, registry_tool])}  &&  "
        f"{' '.join([*py, run_live, '--verify-manifest', str(MANIFEST)])}  ->  validate",
    ]
    if dry_run:
        print("re-seal plan (no changes will be made):")
        for step in plan:
            print(f"  {step}")
        print(f"  commit subject suffix: 'after {subject}'")
        return 0

    _require_clean_worktree(root)
    old_pin = _pinned_source_sha256()

    # Step 1 — re-measure, commit results only (this is the evidence commit).
    _run([*py, run_live, "--replace"], root=root)
    _commit([RESULTS], f"bench(results): re-measure live corpus after {subject}", root=root)

    # Step 2 — finalize provenance, then reconcile the disposition pin.
    _run([*py, run_live, "--finalize-provenance", str(MANIFEST), "--replace"], root=root)
    new_pin = _manifest_source_sha256()

    repinned: list[Path] = []
    if new_pin != old_pin:
        if not repin:
            _git(["reset", "--hard", "HEAD~1"], root=root)  # undo the results commit
            raise ReSealError(
                "the source-inventory digest changed, so the reviewed dispositions\n"
                f"  old: {old_pin}\n  new: {new_pin}\n"
                "have expired to 'unresolved' by design. Confirm the known "
                "boundaries in REVIEWED_DISPOSITIONS still hold (same-process JUnit "
                "forgery false-accept; the two legit-dependency-bump false-rejects), "
                "then re-run with --repin to re-pin them to the new source. "
                "(The results commit has been rolled back; nothing is left behind.)"
            )
        repinned = _repin(new_pin, old_pin)

    _commit([MANIFEST], f"bench(manifest): finalize provenance binding after {subject}", root=root)
    manifest_commit = _git(["rev-parse", "HEAD"], root=root).strip()

    # Step 3 — derive and commit the registry (with the repin, if any).
    _run(
        [*py, registry_tool, "--generate", "--finalization-commit", manifest_commit, "--replace"],
        root=root,
    )
    _commit(
        [REGISTRY, *repinned],
        f"evidence(registry): re-bind failure registry after {subject}",
        root=root,
    )

    # Step 4 — validate exactly what CI validates.
    _run([*py, registry_tool], root=root)
    _run([*py, run_live, "--verify-manifest", str(MANIFEST)], root=root)

    print("re-seal complete — three commits created and validated:")
    print(_git(["log", "--oneline", "-3"], root=root).strip())
    if repinned:
        print(f"reviewed dispositions re-pinned to {new_pin} (you confirmed with --repin).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="reseal",
        description="Run the benchmark re-seal ritual as one command (same trust model).",
    )
    parser.add_argument(
        "subject",
        help="short summary of the source change; used as the 'after <subject>' commit suffix",
    )
    parser.add_argument(
        "--repin",
        action="store_true",
        help="confirm the reviewed dispositions still hold and re-pin them to the new source digest",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the exact commands and commit plan without changing anything",
    )
    args = parser.parse_args(argv)
    try:
        return re_seal(args.subject, repin=args.repin, dry_run=args.dry_run)
    except ReSealError as exc:
        print(f"reseal: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
