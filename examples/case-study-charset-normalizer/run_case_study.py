#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""One-command reproduction of docs/CASE-STUDY.md (charset-normalizer #537).

Downloads the byte-pinned charset-normalizer 3.3.2 sdist from PyPI (the only
network step; a previously downloaded archive is reused), commits the upstream
regression test into its suite the way the maintainer workflow prescribes, and
judges the three shipped candidates with the real Guard CLI under the exact
policy documented in the case study:

    python examples/case-study-charset-normalizer/run_case_study.py

Every raw verdict is written to ``work/verdicts/``, checked against the
published expectations (PASS/tests_passed, REJECTED/protected_harness_edit,
FAIL/tests_failed), required to share one policy fingerprint, and validated
with ``verify_record`` — the same universality invariant the reason corpus
enforces.  When the ``cryptography`` extra is installed, the honest-fix
verdict is additionally sealed into an Evidence Bundle and verified against
an external context, end to end.  Exits non-zero on any deviation.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _ROOT)

from evoom_guard.cli import main as cli_main  # noqa: E402
from evoom_guard.record_verifier import verify_record  # noqa: E402

SDIST_NAME = "charset-normalizer-3.3.2.tar.gz"
SDIST_SHA256 = "f30c3cb33b24454a82faecaf01b19c18562b1e89558fb6c56de4d9118a032fd5"
TEST_COMMAND = "python -m pytest tests -q -o addopts= -p no:cacheprovider"

# candidate file -> (expected verdict, expected reason_code)
EXPECTED = {
    "1-honest-fix.txt": ("PASS", "tests_passed"),
    "2-test-tamper.txt": ("REJECTED", "protected_harness_edit"),
    "3-fake-fix.txt": ("FAIL", "tests_failed"),
}


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download_sdist(sdists: str) -> str:
    archive = os.path.join(sdists, SDIST_NAME)
    if not os.path.isfile(archive):
        subprocess.run(
            [
                sys.executable, "-m", "pip", "download",
                "--no-binary", ":all:", "--no-deps",
                "charset-normalizer==3.3.2", "-d", sdists,
            ],
            check=True,
        )
    actual = _sha256(archive)
    if actual != SDIST_SHA256:
        raise SystemExit(
            f"sdist digest mismatch (fail-closed): expected {SDIST_SHA256}, got {actual}"
        )
    return archive


def _safe_extract(archive: str, destination: str) -> None:
    # Refuse member paths that escape the destination — the sdist is digest
    # pinned, but extraction stays fail-closed anyway.
    with tarfile.open(archive) as tar:
        base = os.path.realpath(destination)
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(destination, member.name))
            if not target.startswith(base + os.sep) and target != base:
                raise SystemExit(f"unsafe tar member (fail-closed): {member.name}")
            if member.islnk() or member.issym():
                raise SystemExit(f"linked tar member (fail-closed): {member.name}")
        tar.extractall(destination)  # noqa: S202 - members vetted above


def _guard_artifact_sha256() -> str:
    # The digest of the package tree that judged this run. A release pipeline
    # would pin the evo-guard.pyz digest instead; the binding idea is the same.
    digest = hashlib.sha256()
    package = os.path.join(_ROOT, "evoom_guard")
    for directory, dirnames, filenames in sorted(os.walk(package)):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        for name in sorted(filenames):
            if name.endswith(".py") or name.endswith(".json"):
                rel = os.path.relpath(os.path.join(directory, name), package)
                digest.update(rel.replace(os.sep, "/").encode("utf-8"))
                with open(os.path.join(directory, name), "rb") as f:
                    digest.update(f.read())
    return digest.hexdigest()


def _bundle_honest_verdict(work: str, verdict_path: str) -> bool:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        print("evidence bundle: skipped (install the 'sign' extra to enable)")
        return True

    record = json.loads(open(verdict_path, encoding="utf-8").read())
    attestation = record["attestation"]
    context = {
        "repository": "local/case-study-charset-normalizer",
        "repository_id": "local",
        "run_id": "case-study",
        "run_attempt": 1,
        "base_sha": None,
        "head_sha": None,
        "base_tree_sha": None,
        "head_tree_sha": None,
        "candidate_sha256": attestation["candidate_sha256"],
        "policy_sha256": attestation["policy_sha256"],
        "verifier_pack_sha256": None,
        "guard_artifact_sha256": _guard_artifact_sha256(),
    }
    context_path = os.path.join(work, "context.json")
    with open(context_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(context, f, indent=2, sort_keys=True)

    key = os.path.join(work, "signing.pem")
    pub = os.path.join(work, "signing.pub")
    bundle = os.path.join(work, "honest-fix.evb")
    steps: tuple[tuple[list[str], str], ...] = ()
    if not (os.path.isfile(key) and os.path.isfile(pub)):
        steps += ((["keygen", "--key", key, "--pub", pub], "keygen"),)
    steps += (
        (
            [
                "bundle-evidence", verdict_path, "--out", bundle,
                "--context", context_path, "--sign-key", key, "--force",
            ],
            "bundle-evidence",
        ),
        (
            [
                "verify-bundle", bundle, "--trusted-pub", pub,
                "--expect-context", context_path, "--require-pass",
            ],
            "verify-bundle --require-pass",
        ),
    )
    for argv, label in steps:
        code = cli_main(list(argv))
        if code != 0:
            print(f"evidence bundle: {label} exited {code}")
            return False
    print(f"evidence bundle: sealed and verified -> {bundle}")
    return True


def main() -> int:
    work = os.path.join(_HERE, "work")
    verdicts_dir = os.path.join(work, "verdicts")
    os.makedirs(verdicts_dir, exist_ok=True)

    archive = _download_sdist(os.path.join(work, "sdists"))

    base_repo = os.path.join(work, "base-repo")
    if os.path.isdir(base_repo):
        shutil.rmtree(base_repo)
    extract_root = os.path.join(work, "extract")
    if os.path.isdir(extract_root):
        shutil.rmtree(extract_root)
    _safe_extract(archive, extract_root)
    shutil.move(os.path.join(extract_root, "charset-normalizer-3.3.2"), base_repo)

    # The maintainer's move: the bug reproduction joins the suite BEFORE any
    # candidate is judged, so the base is red for exactly one reason.
    shutil.copyfile(
        os.path.join(_HERE, "fixtures", "test_eq_regression.py"),
        os.path.join(base_repo, "tests", "test_eq_regression.py"),
    )

    failures: list[str] = []
    fingerprints: set[str] = set()
    honest_verdict_path = ""
    for candidate, (want_verdict, want_reason) in EXPECTED.items():
        out_path = os.path.join(verdicts_dir, candidate.replace(".txt", ".json"))
        cli_main(
            [
                "guard", base_repo,
                "--patch", os.path.join(_HERE, "candidates", candidate),
                "--test-command", TEST_COMMAND,
                "--baseline-evidence", "--require-demonstrated-fix",
                "--timeout", "600", "--json", out_path,
            ]
        )
        record = json.loads(open(out_path, encoding="utf-8").read())
        got = (record["verdict"], record["reason_code"])
        baseline = record.get("baseline") or {}
        print(
            f"{candidate:22s} -> {record['verdict']:8s} {record['reason_code']:24s} "
            f"suite {record['tests_passed']}/{record['tests_total']} "
            f"repair_effect={baseline.get('repair_effect')}"
        )
        if got != (want_verdict, want_reason):
            failures.append(f"{candidate}: expected {want_verdict}/{want_reason}, got {got}")
        report = verify_record(record)
        if report["ok"] is not True:
            bad = [c["id"] for c in report["checks"] if c["status"] == "fail"]
            failures.append(f"{candidate}: verify_record rejected the record: {bad}")
        attestation = record.get("attestation") or {}
        if attestation.get("policy_sha256"):
            fingerprints.add(attestation["policy_sha256"])
        if candidate == "1-honest-fix.txt":
            honest_verdict_path = out_path

    if len(fingerprints) != 1:
        failures.append(f"policy fingerprints diverged: {sorted(fingerprints)}")
    else:
        print(f"shared policy_sha256: {next(iter(fingerprints))}")

    if honest_verdict_path and not _bundle_honest_verdict(work, honest_verdict_path):
        failures.append("evidence bundle flow failed")

    for failure in failures:
        print(f"MISMATCH: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
