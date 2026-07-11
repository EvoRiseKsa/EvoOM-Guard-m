# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""EvoOM Guard — an AI patch verification gate.

Guard answers one question objectively, for a code change produced by anyone (a
human or — the motivating case — an AI agent):

    *Does this patch fix the code, **without gaming the tests**?*

It is a thin, model-free composition of assets that already exist in EvoOM:

  * the **reward-hack-resistant repo judge** (:class:`evoom_guard.verifiers.repo_verifier.RepoVerifier`)
    — applies the patch to a throwaway copy and reads the verdict from a
    *judge-owned* JUnit report + the process exit code, so the patch cannot fake a
    pass by writing to stdout, and is **rejected** outright if it edits the tests or
    their configuration; and
  * the **blast-radius risk score** (:func:`evoom_guard.patchmin.risk_score`).

The result is a single verdict — ``PASS`` / ``REJECTED`` / ``FAIL`` / ``ERROR`` — a
process exit code suitable for CI, and a Markdown report suitable for a PR comment.

Two input shapes:
  * a candidate in EvoOM's edit-block format (``<<<FILE>>>`` / ``<<<PATCH>>>``), the
    same format agents already emit; or
  * a **base** and **head** checkout (the natural shape in a GitHub Action), which
    :func:`candidate_from_dirs` diffs into the block format.

Trust boundary (honest): the judge runs the repo's own test suite in a subprocess
with rlimits and a timeout. That is fine for **trusted** repositories (your own
code, gating a patch). For **untrusted** code, run it inside a network-less
container with CPU/memory limits — see the trust boundary in ``docs/GUARD.md``.
Guard never claims the subprocess is a security sandbox.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any

from evoom_guard import __version__
from evoom_guard.patchmin import risk_score
from evoom_guard.verifiers.repo_verifier import (
    COPY_IGNORE,
    RepoVerifier,
    _matches_globs,
    copy_repo_tree,
    is_addable_new_test,
    is_judge_autoexec,
    is_protected,
    is_protected_ci,
    is_protected_config,
    is_safe_relpath,
    parse_file_blocks,
    parse_patch_blocks,
)

# Globs the risk scorer treats as "protected" so a protected hit is visible in the
# blast radius too (mirrors the judge's protected-path convention).
_PROTECTED_GLOBS = (
    "*tests/*", "*test/*", "test_*.py", "*_test.py", "conftest.py",
    "pyproject.toml", "*pytest.ini", "tox.ini", "setup.cfg",
    "*.pth", "sitecustomize.py", "usercustomize.py", "Makefile", "GNUmakefile", "noxfile.py",
    # EvoGuard's own config + the CI that runs the gate (see is_protected_ci).
    ".evoguard.json", "*.github/workflows/*", "*.github/actions/*",
)

# The machine-readable JSON contract version. Bump on any breaking change to the
# JSON shape, verdict names, or reason codes (adapters pin on this — see
# docs/JSON_SCHEMA.md).
#   1.1 — deletions are now gated: a head that deletes a protected harness file is
#         REJECTED, and a deleted *source* file is applied to the verified tree (so
#         the verdict matches the merge). The optional ``deleted_not_gated`` array
#         was renamed to ``deleted`` to reflect that deletions are no longer ungated.
#   1.2 — additive evidence fields: ``diff_coverage`` (changed-line coverage, opt-in)
#         and ``attestation`` (context binding for the signed verdict); one new
#         reason code, ``diff_coverage_below_threshold``.
#   1.3 — additive ``assurance`` object stating how much the verdict can be trusted
#         (harness_integrity / report_integrity / candidate_isolation). Honesty:
#         report_integrity is same_process_candidate_writable — see _assurance_profile.
#   1.4 — attestation gains ``mode`` (repo|blackbox); a new reason code
#         ``assurance_requirement_not_met`` (the enforceable --require-* policy,
#         fail-closed); black-box verdicts now carry attestation too.
#   1.5 — black-box candidate_isolation is now the *delivered* boundary (a real
#         CandidateRunner; fail-closed when a container cannot be delivered), the
#         verdict is composite (repo suite AND pack) unless --blackbox-only, and
#         the attestation gains isolation_evidence / deleted_paths_applied /
#         repo_suite_* / base_sha / head_sha / junit_sha256.
#   1.6 — additive: ``baseline`` (opt-in before/after differential evidence with
#         ``repair_effect``), one new reason code ``fix_not_demonstrated`` (the
#         opt-in --require-demonstrated-fix gate), attestation gains
#         base_tree_sha / head_tree_sha / policy_id / policy_version, and
#         base_sha / head_sha are now bound in EVERY mode (repo-native too,
#         not only black-box).
SCHEMA_VERSION = "1.6"

# Verdicts.
PASS = "PASS"          # tests pass and the harness was untouched
REJECTED = "REJECTED"  # the patch edits the tests / their config (reward-hack)
FAIL = "FAIL"          # the patch applied and ran, but the tests fail
ERROR = "ERROR"        # the patch did not apply / produced no parseable edits
TAMPERED = "TAMPERED"  # the exit code and the judge-owned JUnit report disagree

# Stable machine codes for the verdict's cause (never reword without a SCHEMA_VERSION
# bump). The human ``reason`` may change freely; adapters key off ``reason_code``.
REASON_TESTS_PASSED = "tests_passed"
REASON_PROTECTED_HARNESS_EDIT = "protected_harness_edit"
REASON_TESTS_FAILED = "tests_failed"
REASON_NO_PARSEABLE_EDITS = "no_parseable_edits"
REASON_UNSAFE_PATH = "unsafe_path"
REASON_PATCH_APPLY_FAILED = "patch_apply_failed"
REASON_NO_TEST_VERDICT = "no_test_verdict"
REASON_JUNIT_EXIT_MISMATCH = "junit_exit_mismatch"
REASON_EMPTY_DIFF = "empty_diff"
REASON_BINARY_PATCH = "binary_patch"
REASON_REVERSE_APPLY_FAILED = "reverse_apply_failed"
REASON_NO_VERIFIABLE_CHANGES = "no_verifiable_changes"
REASON_DIFF_COVERAGE_BELOW_THRESHOLD = "diff_coverage_below_threshold"
REASON_TEST_TIMEOUT = "test_timeout"
REASON_SETUP_TIMEOUT = "setup_timeout"
REASON_SETUP_FAILED = "setup_failed"
REASON_ASSURANCE_REQUIREMENT_NOT_MET = "assurance_requirement_not_met"
REASON_FIX_NOT_DEMONSTRATED = "fix_not_demonstrated"

# Ordering of report-integrity levels, weakest → strongest. A caller can demand a
# floor with require_report_integrity; if the run's actual level is below it, the
# verdict is refused (fail-closed) rather than shipping a weaker guarantee than
# was asked for. Enforced against what actually ran, never against a CLI wish.
_REPORT_INTEGRITY_RANK = {
    "same_process_candidate_writable": 0,
    "external_process_isolated": 1,
}
_ISOLATION_RANK = {"subprocess": 0, "docker": 1, "gvisor": 2}

# Verifier ``outcome`` marker → (verdict, reason_code). The patch applied and the
# session started, but did not produce a clean pass/fail — a timeout or a failed
# setup step must NOT be mislabelled as "the patch did not apply".
_OUTCOME_REASON = {
    "test_timeout": (FAIL, REASON_TEST_TIMEOUT),
    "setup_timeout": (ERROR, REASON_SETUP_TIMEOUT),
    "setup_failed": (ERROR, REASON_SETUP_FAILED),
}

# The judge-owned directory an Independent Verifier Pack is mounted at inside
# the throwaway copy. It arrives at judgment time (the candidate never saw it),
# and a candidate that tries to pre-plant or edit it is rejected outright.
VERIFIER_PACK_DIR = "evoguard_verifier_pack"


@dataclass
class GuardResult:
    """The outcome of a Guard run."""

    verdict: str
    passed: bool
    reason: str
    files_changed: list[str]
    protected_violations: list[str]
    risk_level: str
    risk_score: float
    tests_passed: int | None = None
    tests_total: int | None = None
    verdict_source: str | None = None
    diagnostics: str = ""
    source: str | None = None              # how the candidate was supplied (e.g. "diff")
    base_reconstruction: str | None = None  # "ok" | "failed" (only for --diff)
    reason_code: str = ""                  # stable machine code for the cause (see REASON_*)
    isolation: str = "subprocess"          # how the suite ran: subprocess / docker / gvisor
    diff_coverage: dict[str, Any] | None = None   # changed-line coverage evidence (opt-in)
    baseline: dict[str, Any] | None = None        # before/after differential evidence (opt-in)
    attestation: dict[str, Any] | None = None     # context binding for the signed verdict
    assurance: dict[str, Any] | None = None       # how much the verdict can be trusted

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": "evoguard",
            "tool_version": __version__,
            "verdict": self.verdict,
            "passed": self.passed,
            "exit_code": self.exit_code,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "files_changed": self.files_changed,
            "protected_violations": self.protected_violations,
            "risk_level": self.risk_level,
            "risk_score": round(self.risk_score, 3),
            "tests_passed": self.tests_passed,
            "tests_total": self.tests_total,
            "test_command_ran": self.verdict_source is not None,
            "verdict_source": self.verdict_source,
            "source": self.source,
            "base_reconstruction": self.base_reconstruction,
            "assurance": self.assurance,
            "diff_coverage": self.diff_coverage,
            "baseline": self.baseline,
            "attestation": self.attestation,
            "diagnostics": self.diagnostics[:2000],
        }

    @property
    def exit_code(self) -> int:
        """0 only on a clean PASS; non-zero otherwise (CI-gate friendly).

        Every non-PASS verdict (REJECTED / FAIL / ERROR / TAMPERED) exits ``1``;
        invalid CLI usage exits ``2`` (handled in the CLI, not here).
        """
        return 0 if self.verdict == PASS else 1


def _read_repo_file(repo_path: str, rel: str) -> str:
    try:
        with open(os.path.join(repo_path, *rel.split("/")), encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def _diff_counts(old: str, new: str) -> tuple[int, int]:
    """(added, removed) line counts between two file contents."""
    added = removed = 0
    for line in difflib.unified_diff(old.splitlines(), new.splitlines(), n=0):
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return added, removed


def _risk_map(
    repo_path: str, candidate: str, file_blocks: dict[str, str] | None = None
) -> dict[str, tuple[int, int]]:
    """Build a ``{path: (added, removed)}`` map for the risk scorer.

    For whole-file blocks the count is the real diff against the base file; for
    surgical PATCH blocks it is approximated by the search/replace line counts
    (we do not re-apply to count exactly — risk is a coarse, bounded signal).
    With a structured ``file_blocks`` mapping (the dirs/diff path), the marker
    parse is skipped entirely.
    """
    out: dict[str, tuple[int, int]] = {}
    blocks = file_blocks if file_blocks else parse_file_blocks(candidate)
    for path, new in blocks.items():
        out[path] = _diff_counts(_read_repo_file(repo_path, path), new)
    for pb in ([] if file_blocks else parse_patch_blocks(candidate)):
        a, r = len(pb.replace.splitlines()), len(pb.search.splitlines())
        prev_a, prev_r = out.get(pb.path, (0, 0))
        out[pb.path] = (prev_a + a, prev_r + r)
    return out


def changed_paths(candidate: str, file_blocks: dict[str, str] | None = None) -> list[str]:
    """All repo-relative paths a candidate would create or modify."""
    if file_blocks:
        return sorted(file_blocks)
    blocks = parse_file_blocks(candidate)
    patches = parse_patch_blocks(candidate)
    return sorted(set(blocks) | {pb.path for pb in patches})


def guard(
    repo_path: str,
    candidate: str,
    *,
    deleted: tuple[str, ...] = (),
    test_command: list[str] | None = None,
    setup_command: list[str] | None = None,
    protected: tuple[str, ...] = (),
    allow: tuple[str, ...] = (),
    allow_new_tests: bool = False,
    timeout: int = 120,
    mem_limit_mb: int = 1024,
    isolation: str = "subprocess",
    docker_image: str | None = None,
    docker_network: str = "none",
    verifier_pack: str | None = None,
    diff_coverage: bool = False,
    min_diff_coverage: float | None = None,
    blackbox: bool = False,
    blackbox_only: bool = False,
    require_report_integrity: str | None = None,
    require_candidate_isolation: str | None = None,
    base_sha: str | None = None,
    head_sha: str | None = None,
    base_tree_sha: str | None = None,
    head_tree_sha: str | None = None,
    policy_id: str | None = None,
    policy_version: str | None = None,
    baseline_evidence: bool = False,
    require_demonstrated_fix: bool = False,
    file_blocks: dict[str, str] | None = None,
) -> GuardResult:
    """Verify ``candidate`` against ``repo_path`` and return a :class:`GuardResult`.

    ``file_blocks`` is the STRUCTURED candidate the dirs/diff path supplies
    (``{relpath: new_content}``): when given, the ``candidate`` text is kept only
    for hashing/diagnostics and is never re-parsed for ``<<<FILE>>>`` markers —
    so a target file whose content legitimately contains a literal
    ``<<<END FILE>>>`` line cannot terminate its own block and be silently
    truncated (a defect found by running Guard on its own repository).

    The repo at ``repo_path`` is never modified — the judge works on a throwaway
    copy. ``deleted`` lists repo-relative paths the change removes (from a base→head
    diff): a deleted *source* file is applied to the verified copy so the verdict
    matches the real merge, while deleting a protected harness file (a test, its
    config, the gate's CI, or an auto-exec file) is a reward-hack and yields
    ``REJECTED`` — removing a check is as much a hack as editing one.
    ``protected`` adds extra globs the patch may not touch (on top of the
    built-in tests/config/auto-exec set). ``mem_limit_mb`` is the address-space cap
    for the test subprocess; pass ``0`` to disable it (required for Node/V8 suites,
    which reserve far more virtual memory than any sane ``RLIMIT_AS``).
    ``setup_command`` runs inside the repo copy before the test suite (e.g.
    ``["pnpm", "install", "--frozen-lockfile"]``) — useful when dependency
    installation is needed but should stay separate from the token-list
    ``test_command``.

    ``allow_new_tests`` (opt-in "feature mode", default off) lets a change add
    **brand-new** test files while still rejecting any edit to an *existing* test or
    to the harness/config/auto-exec/CI — so a feature PR can ship its own tests. New
    test code still runs in the judge process; this is for trusted authors (see
    ``docs/FEATURE_MODE.md``).

    ``allow`` is an adopter-curated allowlist of globs (a *baseline*): a matching
    path is exempt from the test/config/CI rejection — for a built-in pattern's false
    positive or a known pre-existing hit. It never exempts auto-exec or unsafe paths.

    ``isolation="docker"`` runs the suite inside a short-lived, network-less,
    read-only container (``docker_image`` required; defence in depth for semi-trusted
    code — not a complete boundary for hostile code). Default ``"subprocess"`` is
    unchanged.

    ``verifier_pack`` mounts an **Independent Verifier Pack** — a directory of
    judge-owned tests/invariants the **patch cannot modify** (org-owned checks
    injected at judgment time) — into the copy at ``evoguard_verifier_pack/``. The
    suite then also collects the pack's tests, so a candidate overfitted to the
    visible tests fails the pack's checks. A candidate that writes anywhere under
    that directory is ``REJECTED``. **Not secret:** the running test code *can*
    read the pack files off disk; the guarantee is tamper-resistance (the patch
    cannot change the checks), not secrecy. See ``docs/VERIFIER_PACKS.md``.

    ``diff_coverage=True`` adds **changed-line coverage evidence** (one extra
    suite run under ``coverage``): which changed lines the suite actually
    executed. Evidence only, unless ``min_diff_coverage`` sets a gate: a ``PASS``
    whose measured changed-line coverage is below the threshold becomes ``FAIL``
    (``diff_coverage_below_threshold``). Executed is not asserted — see
    :mod:`evoom_guard.evidence`.
    """
    changed = changed_paths(candidate, file_blocks)
    # Deletions are gated too: deleting a protected harness file is as much a
    # reward-hack as editing it (removing a failing test/check), and a deleted
    # *source* file must be applied to the verified tree so the verdict matches the
    # real merge. Both the safety and protected-path checks therefore span the
    # added/modified *and* deleted paths.
    deleted_touched = [d for d in deleted if d not in changed]
    all_touched = changed + deleted_touched
    unsafe = sorted(p for p in all_touched if not is_safe_relpath(p))
    new_paths = frozenset(
        p for p in changed
        if is_safe_relpath(p) and not os.path.exists(os.path.join(repo_path, p))
    )

    def _is_violation(p: str) -> bool:
        if p == VERIFIER_PACK_DIR or p.startswith(VERIFIER_PACK_DIR + "/"):
            return True  # the judge-owned pack mount point — never writable
        if is_judge_autoexec(p):
            return True  # auto-exec runs in the judge process — never exempt
        if not (is_protected(p, protected) or is_protected_config(p) or is_protected_ci(p)):
            return False
        if _matches_globs(p, allow):
            return False  # adopter-allowlisted (baseline)
        return not (allow_new_tests and is_addable_new_test(p, protected, is_new=p in new_paths))

    # A deleted path is never "new", so a protected deletion is always a violation
    # (feature mode lets you *add* a new test, never *remove* an existing check).
    violations = sorted(p for p in all_touched if _is_violation(p))
    # Safe, non-protected deletions are applied to the verified copy.
    safe_deleted = sorted(
        d for d in deleted if is_safe_relpath(d) and not _is_violation(d)
    )

    problem: dict[str, Any] = {"name": "guard", "repo_path": repo_path}
    if test_command:
        problem["test_command"] = test_command
    if setup_command:
        problem["setup_command"] = setup_command
    if protected:
        problem["protected"] = list(protected)
    if allow:
        problem["allow"] = list(allow)
    if allow_new_tests:
        problem["allow_new_tests"] = True
    if safe_deleted:
        problem["deleted"] = safe_deleted
    if verifier_pack:
        problem["verifier_pack"] = os.path.abspath(verifier_pack)
    if file_blocks:
        problem["file_blocks"] = dict(file_blocks)

    # Black-box mode: the verdict is produced by the judge's OWN pytest over the
    # judge-owned pack, which never imports the candidate — closing same-process
    # report forgery. Requires a pack (there is nothing to assert otherwise); the
    # harness-integrity checks above still apply.
    if blackbox and not (unsafe or violations or not all_touched):
        from evoom_guard.blackbox import run_blackbox

        if not verifier_pack:
            return GuardResult(
                verdict=ERROR, passed=False,
                reason="--blackbox requires --verifier-pack (the judge-owned protocol tests)",
                files_changed=changed, protected_violations=[],
                risk_level=risk_score(_risk_map(repo_path, candidate, file_blocks)).level,
                risk_score=risk_score(_risk_map(repo_path, candidate, file_blocks)).score,
                reason_code=REASON_NO_VERIFIABLE_CHANGES, isolation=isolation,
                assurance=_assurance_profile(isolation, verifier_pack, blackbox=True),
            )
        bx = run_blackbox(
            repo_path, candidate, os.path.abspath(verifier_pack), timeout=timeout,
            isolation=isolation, docker_image=docker_image, docker_network=docker_network,
            mem_limit_mb=mem_limit_mb, deleted_paths=tuple(safe_deleted),
            file_blocks=file_blocks,
        )
        # candidate_isolation comes from what the runner DELIVERED, never the flag.
        delivered_iso = (bx.isolation or {}).get("delivered", "subprocess")
        rmap_bx = _risk_map(repo_path, candidate, file_blocks)
        for d in all_touched:
            if d in deleted and d not in rmap_bx:
                rmap_bx[d] = (0, len(_read_repo_file(repo_path, d).splitlines()))
        risk_bx = risk_score(rmap_bx, protected=_PROTECTED_GLOBS + tuple(protected))

        # Composite verdict: the external pack ADDS a dimension, it must never
        # REPLACE the repo's own suite. Unless --blackbox-only, run the repo-native
        # suite too and require BOTH to pass (a green pack must not mask an internal
        # regression). A pure-CLI target with no repo suite uses --blackbox-only.
        repo_verdict = None
        if not blackbox_only:
            repo_problem = {k: v for k, v in problem.items() if k != "verifier_pack"}
            repo_verdict = RepoVerifier(
                timeout=timeout, mem_limit_mb=mem_limit_mb,
                isolation=isolation, docker_image=docker_image, docker_network=docker_network,
            ).verify(candidate, repo_problem)

        if not bx.ran:
            v_bx, code_bx = ERROR, (REASON_TEST_TIMEOUT if bx.error == "timeout" else REASON_NO_TEST_VERDICT)
            reason_bx = bx.error or "the black-box pack produced no verdict"
        elif not bx.passed:
            v_bx, code_bx, reason_bx = FAIL, REASON_TESTS_FAILED, (
                f"the black-box pack failed ({bx.tests_passed}/{bx.tests_total})"
            )
        elif repo_verdict is not None and not repo_verdict.passed:
            # Pack passed, but the repo's own suite did not — block the merge.
            v_bx, code_bx, reason_bx = FAIL, REASON_TESTS_FAILED, (
                "the black-box pack passed but the repo's own test suite failed "
                f"({repo_verdict.diagnostics[:200]}) — a green pack must not mask an "
                "internal regression; fix the repo suite or use --blackbox-only"
            )
        else:
            extra = "" if repo_verdict is None else " and the repo's own suite passed"
            v_bx, code_bx, reason_bx = PASS, REASON_TESTS_PASSED, (
                f"the black-box pack passed ({bx.tests_passed}/{bx.tests_total}){extra} — "
                "the candidate satisfied the judge-owned protocol tests, judged from "
                "outside its own process"
            )
        assurance_bx = _assurance_profile(
            delivered_iso, verifier_pack, blackbox=True,
            composed_repo_suite=(repo_verdict is not None),
        )
        # Enforceable assurance policy (fail-closed): refuse to ship a verdict whose
        # ACTUAL (delivered) assurance is below what the caller required.
        shortfall_bx = _assurance_shortfall(
            assurance_bx,
            require_report_integrity=require_report_integrity,
            require_candidate_isolation=require_candidate_isolation,
        )
        if shortfall_bx is not None:
            v_bx, code_bx, reason_bx = ERROR, REASON_ASSURANCE_REQUIREMENT_NOT_MET, shortfall_bx
        repo_art = repo_verdict.artifact if repo_verdict is not None else {}
        return GuardResult(
            verdict=v_bx, passed=(v_bx == PASS), reason=reason_bx,
            files_changed=changed, protected_violations=[],
            risk_level=risk_bx.level, risk_score=risk_bx.score,
            tests_passed=bx.tests_passed if bx.ran else None,
            tests_total=bx.tests_total if bx.ran else None,
            verdict_source="blackbox" if bx.ran else None,
            diagnostics=bx.diagnostics, reason_code=code_bx, isolation=delivered_iso,
            assurance=assurance_bx,
            attestation=_build_attestation(
                candidate, safe_deleted=safe_deleted, test_command=test_command,
                protected=protected, allow=allow, allow_new_tests=allow_new_tests,
                isolation=delivered_iso,
                art={
                    "verifier_pack_sha256": bx.pack_sha256,
                    "verifier_pack_manifest": bx.pack_manifest,
                    "junit_sha256": bx.junit_sha256,
                    "isolation_evidence": bx.isolation,
                    "deleted_paths_applied": bx.deleted_applied,
                    "repo_suite_junit_sha256": repo_art.get("junit_sha256") if repo_art else None,
                    "repo_suite_passed": repo_verdict.passed if repo_verdict is not None else None,
                    "base_sha": base_sha,
                    "head_sha": head_sha,
                    "base_tree_sha": base_tree_sha,
                    "head_tree_sha": head_tree_sha,
                    "policy_id": policy_id,
                    "policy_version": policy_version,
                },
                mode="blackbox",
            ),
        )

    # The pre-gate is decided BEFORE the suite runs — for every rejection shape.
    # A candidate whose only violation is a protected *deletion* used to slip past
    # this (its added/modified paths are clean, so the verifier ran the suite once
    # before the mapping below flipped the verdict to REJECTED) — leaving
    # ``test_command_ran: true`` on a verdict documented as pre-execution. Skip
    # the run entirely whenever the outcome is already decided by the diff alone.
    run_suite = bool(all_touched) and not unsafe and not violations
    if run_suite:
        verdict = RepoVerifier(
            timeout=timeout, mem_limit_mb=mem_limit_mb,
            isolation=isolation, docker_image=docker_image, docker_network=docker_network,
        ).verify(candidate, problem)
        art = verdict.artifact or {}
        diagnostics = verdict.diagnostics or ""
    else:
        verdict = None
        art = {}
        diagnostics = ""
    # Deletions count toward the blast radius too: a change that removes source
    # files should not read as *lower* risk than one that edits them. Each deleted
    # path contributes its base-file line count as removed lines (0 added).
    rmap = _risk_map(repo_path, candidate, file_blocks)
    for d in all_touched:
        if d in deleted and d not in rmap:
            base = _read_repo_file(repo_path, d)
            rmap[d] = (0, len(base.splitlines()))
    risk = risk_score(rmap, protected=_PROTECTED_GLOBS + tuple(protected))

    if not all_touched:
        v, reason, code = ERROR, (
            "no parseable edit blocks — the patch produced no <<<FILE>>> or "
            "<<<PATCH>>> edits (and no deletions) to verify"
        ), REASON_NO_PARSEABLE_EDITS
    elif unsafe:
        # An absolute path, a ``..`` escape, or anything leaving the repo root. The
        # verifier already refused to apply it; name the real cause here rather than
        # mislabel it as a failed patch anchor.
        v, reason, code = ERROR, (
            "the patch references an unsafe path (absolute, '..', or escaping the "
            f"repo root) — refusing to apply: {', '.join(unsafe)}"
        ), REASON_UNSAFE_PATH
    elif violations:
        v, reason, code = REJECTED, (
            "reward-hack guard: the patch edits or deletes the judging tests, their "
            "configuration, the gate's CI/config, or an auto-executed file — fix the "
            f"source under test, not the harness ({', '.join(violations)})"
        ), REASON_PROTECTED_HARNESS_EDIT
    elif art.get("tamper"):
        # The two trustworthy signals (process exit code and the judge-owned JUnit
        # report) disagree — a forced exit / rewritten ``$?``. Never read as a pass.
        v, reason, code = TAMPERED, (
            "tamper signature: the suite's exit code and its judge-owned JUnit report "
            f"disagree ({art.get('tests_passed', 0)}/{art.get('tests_total', 0)} in the "
            "report) — refusing to read this as a pass"
        ), REASON_JUNIT_EXIT_MISMATCH
    elif verdict is not None and verdict.passed:
        v, reason, code = PASS, (
            "all repo tests pass and the patch leaves the test harness untouched"
        ), REASON_TESTS_PASSED
    elif art.get("tests_total"):
        v, reason, code = FAIL, (
            f"the repo's tests fail on this patch "
            f"({art.get('tests_passed', 0)}/{art.get('tests_total')} passed)"
        ), REASON_TESTS_FAILED
    elif art.get("outcome") in _OUTCOME_REASON:
        # The patch applied and the session started, but timed out or its setup
        # step failed — never mislabel these as "the patch did not apply".
        v, code = _OUTCOME_REASON[art["outcome"]]
        reason = diagnostics or f"run ended: {art['outcome']}"
    elif verdict is not None and verdict.score <= 0.08:
        v, reason, code = ERROR, (
            "the patch did not apply cleanly (a PATCH anchor did not match)"
        ), REASON_PATCH_APPLY_FAILED
    else:
        v, reason, code = FAIL, (
            "the test session produced no clean verdict (collection/usage error)"
        ), REASON_NO_TEST_VERDICT

    # Changed-line coverage evidence (opt-in; one extra suite run). Only when the
    # suite actually ran — a REJECTED/ERROR verdict has nothing to measure.
    coverage_evidence: dict[str, Any] | None = None
    if diff_coverage and v in (PASS, FAIL) and isolation == "subprocess":
        from evoom_guard.evidence import collect_diff_coverage

        coverage_evidence = collect_diff_coverage(
            repo_path, candidate,
            deleted=tuple(safe_deleted), test_command=test_command, timeout=timeout,
            file_blocks=file_blocks,
        )
        if (
            v == PASS
            and min_diff_coverage is not None
            and coverage_evidence.get("measured")
            and float(coverage_evidence.get("percent", 100.0)) < min_diff_coverage
        ):
            v, code = FAIL, REASON_DIFF_COVERAGE_BELOW_THRESHOLD
            reason = (
                "the suite passes but executed only "
                f"{coverage_evidence['executed']}/{coverage_evidence['total']} of the "
                f"changed lines ({coverage_evidence['percent']}% < the required "
                f"{min_diff_coverage:g}%) — the change is largely unexercised by the "
                "tests that judged it"
            )

    # Baseline differential evidence (opt-in; one extra suite run on the
    # PRISTINE base — no candidate applied). "all tests pass on head" does not
    # by itself show the change FIXED anything: the base may already have been
    # green. The baseline run makes the counterfactual measurable:
    #   baseline FAIL → candidate PASS, same tests/policy/env  ⇒ repair_effect
    #   "demonstrated". Anything else ⇒ "not_demonstrated" (or "unmeasured"
    # when the baseline produced no clean verdict). Evidence only, unless
    # require_demonstrated_fix demotes an undemonstrated PASS to FAIL.
    baseline_info: dict[str, Any] | None = None
    if (
        (baseline_evidence or require_demonstrated_fix)
        and v in (PASS, FAIL)
        and isolation == "subprocess"
    ):
        baseline_info = _run_baseline_suite(
            repo_path, test_command=test_command, setup_command=setup_command,
            timeout=timeout, mem_limit_mb=mem_limit_mb,
        )
        if baseline_info.get("verdict") == "NO_CLEAN_VERDICT":
            baseline_info["repair_effect"] = "unmeasured"
        elif baseline_info.get("verdict") == "FAIL" and v == PASS:
            baseline_info["repair_effect"] = "demonstrated"
        else:
            baseline_info["repair_effect"] = "not_demonstrated"
        baseline_info["note"] = (
            "counterfactual test evidence, not a causal proof: the same judge, "
            "policy and environment ran the suite on the pristine base and on "
            "the candidate; 'demonstrated' means the base failed and the "
            "candidate passed"
        )
        if (
            require_demonstrated_fix
            and v == PASS
            and baseline_info["repair_effect"] != "demonstrated"
        ):
            v, code = FAIL, REASON_FIX_NOT_DEMONSTRATED
            reason = (
                "the suite passes on the candidate, but the fix is not "
                "demonstrated: the pristine base "
                + ("already passes the same suite"
                   if baseline_info.get("verdict") == "PASS"
                   else "produced no clean baseline verdict")
                + " — --require-demonstrated-fix demands baseline FAIL → "
                "candidate PASS under an unchanged harness"
            )

    attestation = _build_attestation(
        candidate, safe_deleted=safe_deleted, test_command=test_command,
        protected=protected, allow=allow, allow_new_tests=allow_new_tests,
        isolation=isolation, art={
            **art,
            # Repo-native verdicts are revision-bound too (1.6): black-box was
            # the only mode carrying base/head before, which left the common
            # Action path's signed verdicts unbound from the commit they judged.
            "base_sha": base_sha, "head_sha": head_sha,
            "base_tree_sha": base_tree_sha, "head_tree_sha": head_tree_sha,
            "policy_id": policy_id, "policy_version": policy_version,
        }, mode="repo",
    )

    assurance = _assurance_profile(isolation, verifier_pack)
    # Enforceable assurance policy (fail-closed): the default judge is
    # same_process_candidate_writable, so a --require-report-integrity of
    # external_process_isolated here correctly refuses rather than overclaims.
    shortfall = _assurance_shortfall(
        assurance,
        require_report_integrity=require_report_integrity,
        require_candidate_isolation=require_candidate_isolation,
    )
    if shortfall is not None:
        v, code, reason = ERROR, REASON_ASSURANCE_REQUIREMENT_NOT_MET, shortfall

    return GuardResult(
        verdict=v,
        passed=(v == PASS),
        reason=reason,
        files_changed=changed,
        protected_violations=violations,
        risk_level=risk.level,
        risk_score=risk.score,
        tests_passed=art.get("tests_passed"),
        tests_total=art.get("tests_total"),
        verdict_source=art.get("verdict_source"),
        diagnostics=diagnostics,
        reason_code=code,
        isolation=isolation,
        diff_coverage=coverage_evidence,
        baseline=baseline_info,
        attestation=attestation,
        assurance=assurance,
    )


def _run_baseline_suite(
    repo_path: str,
    *,
    test_command: list[str] | None,
    setup_command: list[str] | None,
    timeout: int,
    mem_limit_mb: int,
) -> dict[str, Any]:
    """Run the repo's suite on a PRISTINE copy (no candidate) — the baseline.

    Subprocess judge only (mirrors diff-coverage's scope). The verdict here is
    graded from the same judge-owned JUnit + exit-code channel as the main run,
    so baseline evidence carries the same anti-forgery properties. Returns a
    small dict: verdict (PASS | FAIL | NO_CLEAN_VERDICT), tests_passed,
    tests_total.
    """
    import tempfile as _tempfile

    from evoom_guard.adapters import instrument_command
    from evoom_guard.verifiers.repo_verifier import (
        RepoVerifier,
        detect_tamper,
        grade_repo_run,
        parse_junit_dir,
        parse_junit_xml,
    )

    rv = RepoVerifier(timeout=timeout, mem_limit_mb=mem_limit_mb)
    workdir = _tempfile.mkdtemp(prefix="evo_baseline_")
    copy = os.path.join(workdir, "repo")
    try:
        copy_repo_tree(repo_path, copy)
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin"),
            "HOME": workdir,
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }
        if setup_command:
            setup_env = dict(env)
            setup_env["HOME"] = os.environ.get("HOME", workdir)
            for _k, _v in os.environ.items():
                if _k.startswith(("PNPM_", "NPM_", "YARN_", "NODE_", "npm_", "BUN_")):
                    setup_env[_k] = _v
            try:
                r_setup = subprocess.run(
                    list(setup_command), cwd=copy, capture_output=True,
                    text=True, timeout=timeout, env=setup_env,
                )
            except (OSError, subprocess.TimeoutExpired):
                return {"verdict": "NO_CLEAN_VERDICT", "tests_passed": None,
                        "tests_total": None}
            if r_setup.returncode != 0:
                return {"verdict": "NO_CLEAN_VERDICT", "tests_passed": None,
                        "tests_total": None}
        base_cmd = rv._command({"repo_path": repo_path})
        if test_command:
            base_cmd = list(test_command)
        host_xml = os.path.join(workdir, "judge-result.xml")
        cmd, report_expected, report_env = instrument_command(base_cmd, host_xml)
        try:
            r = subprocess.run(
                cmd, cwd=copy, capture_output=True, text=True, timeout=timeout,
                env={**env, **report_env},
                preexec_fn=rv._limits() if os.name == "posix" else None,
            )
        except (OSError, subprocess.TimeoutExpired):
            return {"verdict": "NO_CLEAN_VERDICT", "tests_passed": None,
                    "tests_total": None}
        xml_text = ""
        try:
            with open(host_xml, encoding="utf-8") as f:
                xml_text = f.read()
        except OSError:
            pass
        junit = parse_junit_xml(xml_text)
        if junit is None:
            junit = parse_junit_dir(host_xml + ".d")
        passed, _score, tp, tt = grade_repo_run(
            r.returncode, junit, report_expected=report_expected
        )
        tampered = detect_tamper(r.returncode, junit, report_expected=report_expected)
        if tampered or (junit is None and report_expected):
            return {"verdict": "NO_CLEAN_VERDICT", "tests_passed": tp, "tests_total": tt}
        return {
            "verdict": "PASS" if passed else "FAIL",
            "tests_passed": tp,
            "tests_total": tt,
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Assurance levels — see docs/ASSURANCE.md. The honest, load-bearing distinction
# is between TWO integrity properties that people conflate:
#
#   * harness_integrity — can the patch change the CHECKS (tests/config/CI)?
#     "pre_gate_enforced": no. This is a STATIC analysis of the diff done before
#     anything runs, so runtime code cannot undo it. This guarantee is robust.
#
#   * report_integrity — can the code under test forge the RESULT (the JUnit
#     report + exit code) from inside the run? For every runner today the answer
#     is yes: the candidate's source runs in the same process as pytest and the
#     report writer, so an ``atexit`` hook can overwrite the judge's report and
#     ``os._exit(0)`` can force a zero exit. "same_process_candidate_writable"
#     names this plainly. It is NOT closed by the container isolation modes
#     (they isolate the host, not the report from the code). The real fix is an
#     external black-box judge — see ROADMAP.md. There is an adversarial test
#     that proves this so the claim can never silently drift to "unforgeable".
#
# So Guard reliably blocks the reward-hacks agents do in practice (editing or
# deleting tests, deselecting in config, forging stdout — all caught) but does
# NOT stop a patch that writes deliberate process-level forgery code into
# source. Read report_integrity before trusting a PASS on untrusted authors.
def _build_attestation(
    candidate: str, *, safe_deleted: list[str], test_command: list[str] | None,
    protected: tuple[str, ...], allow: tuple[str, ...], allow_new_tests: bool,
    isolation: str, art: dict[str, Any], mode: str,
) -> dict[str, Any]:
    """Context binding for the (optionally signed) verdict. Shared by the default
    and black-box paths so a black-box verdict is bound to what was judged too."""
    return {
        "created_utc": _utc_now(),
        "guard_version": __version__,
        "mode": mode,  # "repo" | "blackbox"
        "candidate_sha256": hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        "deleted_paths": list(safe_deleted),
        "test_command": list(test_command) if test_command else "default:python -m pytest",
        "policy_sha256": hashlib.sha256(json.dumps({
            "protected": sorted(protected), "allow": sorted(allow),
            "allow_new_tests": allow_new_tests, "isolation": isolation, "mode": mode,
        }, sort_keys=True).encode("utf-8")).hexdigest(),
        "junit_sha256": art.get("junit_sha256"),
        "verifier_pack_sha256": art.get("verifier_pack_sha256"),
        "verifier_pack_manifest": art.get("verifier_pack_manifest"),
        # Black-box binding: the delivered isolation, the applied deletions, the
        # composed repo-native suite result, and the base→head commits — so a
        # signed black-box verdict is bound to the tree and boundary it judged,
        # not just the candidate text.
        "isolation_evidence": art.get("isolation_evidence"),
        "deleted_paths_applied": art.get("deleted_paths_applied"),
        "repo_suite_junit_sha256": art.get("repo_suite_junit_sha256"),
        "repo_suite_passed": art.get("repo_suite_passed"),
        "base_sha": art.get("base_sha"),
        "head_sha": art.get("head_sha"),
        # Exact-revision binding (1.6): tree hashes pin the CONTENT judged even
        # when a commit SHA is unavailable (a plain `git diff` carries neither).
        "base_tree_sha": art.get("base_tree_sha"),
        "head_tree_sha": art.get("head_tree_sha"),
        # Which repo policy produced this verdict (from .evoguard.json).
        "policy_id": art.get("policy_id"),
        "policy_version": art.get("policy_version"),
    }


def _assurance_shortfall(
    assurance: dict[str, Any],
    *,
    require_report_integrity: str | None,
    require_candidate_isolation: str | None,
) -> str | None:
    """Return a human reason if the ACTUAL assurance is below what was required.

    Fail-closed: the check is against what the run really delivered
    (`assurance`), never against the requested CLI value — so Guard can never
    claim an assurance level it did not enforce.
    """
    if require_report_integrity:
        want = _REPORT_INTEGRITY_RANK.get(require_report_integrity)
        got = _REPORT_INTEGRITY_RANK.get(assurance.get("report_integrity", ""), -1)
        if want is None:
            return f"unknown --require-report-integrity value: {require_report_integrity!r}"
        if got < want:
            return (
                f"required report_integrity ≥ '{require_report_integrity}' but the run "
                f"delivered '{assurance.get('report_integrity')}' "
                "(use --blackbox for external_process_isolated)"
            )
    if require_candidate_isolation:
        want_i = _ISOLATION_RANK.get(require_candidate_isolation)
        got_i = _ISOLATION_RANK.get(assurance.get("candidate_isolation", ""), -1)
        if want_i is None:
            return f"unknown --require-candidate-isolation value: {require_candidate_isolation!r}"
        if got_i < want_i:
            return (
                f"required candidate_isolation ≥ '{require_candidate_isolation}' but the "
                f"run used '{assurance.get('candidate_isolation')}'"
            )
    return None


def _assurance_profile(
    isolation: str, verifier_pack: str | None, *, blackbox: bool = False,
    composed_repo_suite: bool = False,
) -> dict[str, Any]:
    pack = None
    if verifier_pack:
        pack = {
            "present": True,
            "integrity": "diff_excluded",       # the patch cannot modify the pack
            # In a container boundary the pack is not mounted into the candidate at
            # all, so candidate code cannot reach it; in a subprocess boundary it
            # shares the host and a determined candidate could locate and rewrite it.
            "secrecy": "unmounted_from_candidate" if isolation in ("docker", "gvisor")
                       else "reachable_same_host",
        }
    if blackbox:
        # ``isolation`` here is the DELIVERED boundary (from the runner), not the
        # requested flag — so candidate_isolation can never claim more than ran.
        return {
            "harness_integrity": "pre_gate_enforced",
            "report_integrity": "external_process_isolated",
            "candidate_isolation": isolation,
            "verifier_pack": pack,
            "repo_native_suite": (
                "composed_required" if composed_repo_suite else "not_run (--blackbox-only)"
            ),
            "overall_profile": "black_box_external_judge",
            "note": (
                "report_integrity is external_process_isolated: the verdict comes "
                "from the judge's own pytest over judge-owned protocol tests, which "
                "never import the candidate — so in-process report/exit forgery "
                "cannot reach it. candidate_isolation is what was DELIVERED "
                f"('{isolation}'); a container boundary also removes the pack from "
                "the candidate's reach. Unless --blackbox-only, the repo's own suite "
                "was ALSO required to pass. See docs/BLACKBOX.md."
            ),
        }
    overall = "isolated_repo_native" if isolation in ("docker", "gvisor") else "repo_native_same_process"
    return {
        "harness_integrity": "pre_gate_enforced",
        "report_integrity": "same_process_candidate_writable",
        "candidate_isolation": isolation,
        "verifier_pack": pack,
        "overall_profile": overall,
        "note": (
            "report_integrity is same_process_candidate_writable: a determined "
            "in-process patch can forge the JUnit report and exit code together. "
            "Guard blocks the harness edits/deletions and stdout forgery agents do "
            "in practice; it does not stop deliberate process-level forgery in "
            "source. The container modes isolate the host, not the report. Use "
            "--blackbox for external_process_isolated. See docs/ASSURANCE.md."
        ),
    }


def blocks_from_dirs(
    base_dir: str, head_dir: str, *, max_bytes: int = 1_000_000
) -> tuple[dict[str, str], list[str]]:
    """Diff a base and head checkout into a STRUCTURED candidate.

    Returns ``({relpath: new_content}, deleted)`` for every file added or
    modified in ``head`` relative to ``base`` (skipping ``.git`` and the standard
    ignored dirs); ``deleted`` lists files present in base but absent in head.
    Binary/oversized files are skipped. This mapping is the authoritative
    candidate for the dirs/diff path — it never round-trips through the
    ``<<<FILE>>>`` text format, so content containing literal block markers
    survives intact.
    """
    base_files = _walk_text_files(base_dir, max_bytes)
    head_files = _walk_text_files(head_dir, max_bytes)
    blocks: dict[str, str] = {}
    for rel in sorted(head_files):
        new = head_files[rel]
        if base_files.get(rel) != new:  # added or modified
            blocks[rel] = new
    deleted = sorted(set(base_files) - set(head_files))
    return blocks, deleted


def candidate_from_dirs(base_dir: str, head_dir: str, *, max_bytes: int = 1_000_000) -> tuple[str, list[str]]:
    """Diff a base and head checkout into an EvoOM ``<<<FILE>>>`` candidate.

    Returns ``(candidate, deleted)`` — the text serialization of
    :func:`blocks_from_dirs` (kept for hashing, display and API compatibility).
    NOTE: callers that verify the result should pass the structured mapping from
    :func:`blocks_from_dirs` to :func:`guard` via ``file_blocks`` rather than
    re-parsing this text — content containing a literal ``<<<END FILE>>>`` line
    would terminate its own block in the parse.
    """
    blocks, deleted = blocks_from_dirs(base_dir, head_dir, max_bytes=max_bytes)
    text = "\n".join(
        f"<<<FILE: {rel}>>>\n{new}\n<<<END FILE>>>" for rel, new in blocks.items()
    )
    return text, deleted


def _walk_text_files(root: str, max_bytes: int) -> dict[str, str]:
    out: dict[str, str] = {}
    ignore = set(COPY_IGNORE) | {".git"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ignore]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            try:
                if os.path.getsize(full) > max_bytes:
                    continue
                with open(full, encoding="utf-8") as f:
                    out[rel] = f.read()
            except (OSError, UnicodeDecodeError):
                continue  # binary or unreadable — not a text patch target
    return out


def _reverse_apply(work_dir: str, diff_file: str) -> bool:
    """Reverse-apply a unified diff in ``work_dir`` (undo it). True on success.

    Tries ``git apply -R`` first (works on a plain directory, no repo needed), then
    falls back to ``patch -R -p1``. Used to reconstruct the BASE tree from the HEAD
    working tree given a base→head diff.
    """
    for cmd in (
        ["git", "apply", "-R", "--whitespace=nowarn", diff_file],
        ["patch", "-R", "-p1", "--no-backup-if-mismatch", "-i", diff_file],
    ):
        if shutil.which(cmd[0]) is None:
            continue
        try:
            r = subprocess.run(cmd, cwd=work_dir, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if r.returncode == 0:
            return True
    return False


def _diff_error(
    reason: str, *, reason_code: str, base_reconstruction: str = "failed"
) -> GuardResult:
    return GuardResult(
        verdict=ERROR, passed=False, reason=reason,
        files_changed=[], protected_violations=[],
        risk_level="low", risk_score=0.0, diagnostics="",
        source="diff", base_reconstruction=base_reconstruction,
        reason_code=reason_code,
    )


def _is_binary_diff(diff_text: str) -> bool:
    """Git marks binary changes with a ``GIT binary patch`` block or a one-line
    ``Binary files a/x and b/x differ`` — Guard cannot verify those."""
    return ("GIT binary patch" in diff_text) or ("\nBinary files " in ("\n" + diff_text))


def _diff_target_paths(diff_text: str) -> list[str]:
    """Every file path a diff targets (both ``---``/``+++`` sides), prefix-stripped.

    ``/dev/null`` (the add/delete marker) is excluded. Used to refuse a diff that
    points outside the repo *before* anything is applied — defence in depth on top
    of ``git apply``'s own unsafe-path guard and the verifier's relpath gate.
    """
    paths: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith(("--- ", "+++ ")):
            tok = line[4:].strip().split("\t", 1)[0]
            if tok in ("/dev/null", ""):
                continue
            if tok.startswith(("a/", "b/")):
                tok = tok[2:]
            paths.append(tok)
    return paths


def _diff_head_sha(diff_text: str) -> str | None:
    """Extract the head commit SHA if the diff carries one (git format-patch),
    else ``None``. A plain ``git diff`` does not embed a commit SHA, so we never
    invent one — the attestation records exactly what the diff proves."""
    for line in (diff_text or "").splitlines():
        if line.startswith("From ") and len(line) > 45:
            tok = line[5:45]
            if len(tok) == 40 and all(c in "0123456789abcdef" for c in tok):
                return tok
        if line.startswith(("--- ", "+++ ", "diff ")):
            break
    return None


def _diff_base_sha(diff_text: str) -> str | None:
    """Base commit SHA if present. A unified ``git diff`` only carries per-file
    blob hashes (``index <base>..<head>``), which are NOT commit SHAs, so this
    returns ``None`` rather than misrepresent a blob hash as a commit."""
    return None


def guard_from_diff(
    head_dir: str,
    diff_text: str,
    *,
    test_command: list[str] | None = None,
    setup_command: list[str] | None = None,
    protected: tuple[str, ...] = (),
    allow: tuple[str, ...] = (),
    allow_new_tests: bool = False,
    timeout: int = 120,
    mem_limit_mb: int = 1024,
    isolation: str = "subprocess",
    docker_image: str | None = None,
    docker_network: str = "none",
    verifier_pack: str | None = None,
    diff_coverage: bool = False,
    min_diff_coverage: float | None = None,
    blackbox: bool = False,
    blackbox_only: bool = False,
    require_report_integrity: str | None = None,
    require_candidate_isolation: str | None = None,
    base_sha: str | None = None,
    head_sha: str | None = None,
    base_tree_sha: str | None = None,
    head_tree_sha: str | None = None,
    policy_id: str | None = None,
    policy_version: str | None = None,
    baseline_evidence: bool = False,
    require_demonstrated_fix: bool = False,
) -> tuple[GuardResult, list[str]]:
    """Verify a unified diff against the working tree it was produced from.

    ``head_dir`` is the **current** checkout (e.g. the PR head you are standing in);
    ``diff_text`` is a base→head unified diff (e.g. ``git diff main...HEAD``). Guard
    reconstructs the base by **reverse-applying** the diff to a throwaway copy of
    ``head_dir`` — ``head_dir`` itself is **never modified** — then verifies the
    head's changes against that base with the repo's own tests. So
    ``git diff … | evo guard --diff -`` works straight from your tree.

    Returns ``(GuardResult, deleted)``. The verdict is a clear ``ERROR`` (never an
    apply against the real tree) when the diff is empty, binary, references an
    unsafe path (absolute / ``..`` / repo escape), or does not reverse-apply.
    """
    if not (diff_text or "").strip():
        return _diff_error("empty diff — nothing to verify", reason_code=REASON_EMPTY_DIFF), []
    if _is_binary_diff(diff_text):
        return _diff_error(
            "binary patches are not supported — Guard verifies text source changes; "
            "the diff contains a binary file change",
            reason_code=REASON_BINARY_PATCH,
        ), []
    unsafe = sorted({p for p in _diff_target_paths(diff_text) if not is_safe_relpath(p)})
    if unsafe:
        return _diff_error(
            "the diff references unsafe path(s) outside the repo (absolute, '..', or "
            f"escaping the root) — refusing to apply: {', '.join(unsafe)}",
            reason_code=REASON_UNSAFE_PATH,
        ), []

    workdir = tempfile.mkdtemp(prefix="evo_guard_diff_")
    base = os.path.join(workdir, "base")
    try:
        # base is a copy of head; head_dir is only ever read, never written.
        # (copy_repo_tree keeps symlinks as symlinks — a dangling link, e.g. into
        # an ignored .venv/, must not crash the judge; COPY_IGNORE covers .git.)
        copy_repo_tree(head_dir, base)
        diff_file = os.path.join(workdir, "patch.diff")
        with open(diff_file, "w", encoding="utf-8") as f:
            f.write(diff_text if diff_text.endswith("\n") else diff_text + "\n")
        if not _reverse_apply(base, diff_file):
            return _diff_error(
                "the diff did not reverse-apply to the working tree — make sure you "
                "are in the head checkout and the diff is 'base...HEAD' (git/patch needed)",
                reason_code=REASON_REVERSE_APPLY_FAILED,
            ), []
        file_blocks, deleted = blocks_from_dirs(base, head_dir)
        candidate = "\n".join(
            f"<<<FILE: {rel}>>>\n{new}\n<<<END FILE>>>"
            for rel, new in file_blocks.items()
        )
        if not file_blocks and not deleted:
            return _diff_error(
                "the diff changed no verifiable source files",
                reason_code=REASON_NO_VERIFIABLE_CHANGES, base_reconstruction="ok",
            ), deleted
        result = guard(
            base, candidate,
            deleted=tuple(deleted),
            test_command=test_command, setup_command=setup_command,
            protected=protected, allow=allow, allow_new_tests=allow_new_tests, timeout=timeout,
            mem_limit_mb=mem_limit_mb,
            isolation=isolation, docker_image=docker_image, docker_network=docker_network,
            verifier_pack=verifier_pack,
            diff_coverage=diff_coverage, min_diff_coverage=min_diff_coverage,
            blackbox=blackbox, blackbox_only=blackbox_only,
            require_report_integrity=require_report_integrity,
            require_candidate_isolation=require_candidate_isolation,
            # Explicit CI-provided revision identity wins over what the diff
            # text happens to carry (a plain `git diff` embeds neither SHA).
            base_sha=base_sha or _diff_base_sha(diff_text),
            head_sha=head_sha or _diff_head_sha(diff_text),
            base_tree_sha=base_tree_sha, head_tree_sha=head_tree_sha,
            policy_id=policy_id, policy_version=policy_version,
            baseline_evidence=baseline_evidence,
            require_demonstrated_fix=require_demonstrated_fix,
            file_blocks=file_blocks,
        )
        result.source = "diff"
        result.base_reconstruction = "ok"
        return result, deleted
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


_BADGE = {
    PASS: "✅ PASS", REJECTED: "⛔ REJECTED", FAIL: "❌ FAIL",
    ERROR: "⚠️ ERROR", TAMPERED: "🚨 TAMPERED",
}


def render_report(result: GuardResult, *, deleted: list[str] | None = None, title: str = "EvoGuard") -> str:
    """Render a :class:`GuardResult` as a Markdown report (PR-comment ready)."""
    r = result
    tests = (
        f"{r.tests_passed}/{r.tests_total}"
        if r.tests_total is not None else "—"
    )
    lines = [
        f"## {title} — {_BADGE.get(r.verdict, r.verdict)}",
        "",
        f"**{r.reason}**",
        "",
        "| | |",
        "|---|---|",
        f"| Verdict | **{r.verdict}** |",
        f"| Tests passed | {tests} |",
        f"| Files changed | {len(r.files_changed)} |",
        f"| Blast radius | **{r.risk_level}** ({r.risk_score:.2f}) |",
        f"| Verdict source | {r.verdict_source or '—'} |",
    ]
    if r.source:
        lines.append(f"| Input | {r.source} |")
    if r.base_reconstruction:
        lines.append(f"| Base reconstruction | {r.base_reconstruction} |")
    if r.diff_coverage is not None:
        dc = r.diff_coverage
        if dc.get("measured"):
            lines.append(
                f"| Changed lines executed | {dc['executed']}/{dc['total']} "
                f"({dc['percent']}%) |"
            )
        else:
            lines.append(f"| Changed lines executed | not measured — {dc.get('note', '')} |")
    if r.baseline is not None:
        b = r.baseline
        btests = (
            f" ({b['tests_passed']}/{b['tests_total']})"
            if b.get("tests_total") is not None else ""
        )
        lines.append(f"| Baseline (pristine base) | {b.get('verdict')}{btests} |")
        lines.append(f"| Repair effect | **{b.get('repair_effect')}** |")
    if r.attestation and r.attestation.get("policy_id"):
        pv = r.attestation.get("policy_version")
        lines.append(
            f"| Policy | `{r.attestation['policy_id']}`"
            + (f" v{pv}" if pv else "") + " |"
        )
    if r.attestation and r.attestation.get("verifier_pack_sha256"):
        lines.append(
            f"| Verifier pack | `{str(r.attestation['verifier_pack_sha256'])[:12]}…` |"
        )
    if r.assurance:
        a = r.assurance
        lines.append(
            f"| Assurance | harness `{a['harness_integrity']}` · "
            f"report `{a['report_integrity']}` · isolation `{a['candidate_isolation']}` |"
        )
    # On a PASS, spell out the report-integrity caveat so a green verdict is never
    # read as a stronger guarantee than it is.
    if r.verdict == PASS and r.assurance and r.assurance.get("report_integrity") == "same_process_candidate_writable":
        lines += [
            "",
            "> <sub>**Assurance note:** this PASS means the repo's suite passed and the "
            "test harness was left untouched. The result is read from a judge-owned "
            "report, which resists stdout forgery — but the code under test runs in the "
            "same process as the reporter, so a *deliberate* in-process forgery is not "
            "caught here (see [`docs/ASSURANCE.md`](docs/ASSURANCE.md)). For untrusted "
            "authors, gate on this in review.</sub>",
        ]
    if r.protected_violations:
        lines += [
            "",
            "### ⛔ Reward-hack: the patch tried to edit the judging harness",
            "",
            *[f"- `{p}`" for p in r.protected_violations],
            "",
            "A patch must fix the **source under test**, never the tests or their "
            "configuration. This is rejected before the suite runs.",
        ]
    if r.diff_coverage is not None and r.diff_coverage.get("measured"):
        missed = {
            p: d["missed"] for p, d in r.diff_coverage.get("files", {}).items() if d.get("missed")
        }
        if missed:
            lines += [
                "",
                "<details><summary>Changed lines the suite never executed</summary>",
                "",
                *[f"- `{p}`: lines {', '.join(map(str, ln))}" for p, ln in sorted(missed.items())],
                "",
                f"<sub>{r.diff_coverage.get('caveat', '')}</sub>",
                "</details>",
            ]
    if deleted:
        lines += [
            "",
            "> Note: these files were **deleted** in head and applied to the verified "
            "tree (a deletion of a test/config/CI/auto-exec file is instead "
            "**REJECTED**): " + ", ".join(f"`{p}`" for p in deleted),
        ]
    if r.files_changed and not r.protected_violations:
        shown = ", ".join(f"`{p}`" for p in r.files_changed[:15])
        more = "" if len(r.files_changed) <= 15 else f" (+{len(r.files_changed) - 15} more)"
        lines += ["", f"<details><summary>Files changed</summary>\n\n{shown}{more}\n</details>"]
    if r.verdict == TAMPERED:
        lines += [
            "",
            "### 🚨 Tamper signature: exit code ⟷ JUnit report disagree",
            "",
            "The process exit code and the judge-owned JUnit report — the two signals "
            "the candidate cannot forge via stdout — **disagree**. This is treated as "
            "tampering and is never read as a pass.",
        ]
    if r.diagnostics and r.verdict in (FAIL, ERROR, TAMPERED):
        diag = r.diagnostics.strip()[:1200]
        lines += ["", "<details><summary>Diagnostics</summary>\n", "```", diag, "```", "</details>"]
    _judge = {
        "docker": "in a network-less, read-only container (defence in depth — but a "
                  "container shares the host kernel, so not a complete boundary)",
        "gvisor": "in a network-less container under the gVisor (runsc) runtime — a "
                  "separate user-space guest kernel (for untrusted code)",
    }.get(
        r.isolation,
        "in a subprocess with rlimits + a timeout — fine for trusted repos, not a "
        "sandbox for untrusted code; isolate it further (--isolation docker|gvisor) for that",
    )
    lines += [
        "",
        "<sub>EvoGuard reads the verdict from a judge-owned JUnit report + the "
        "process exit code (not stdout), and rejects any edit to the tests or their "
        f"config. The judge runs the suite {_judge}. See docs/GUARD.md.</sub>",
    ]
    return "\n".join(lines)


def write_json(result: GuardResult, path: str, *, deleted: list[str] | None = None) -> None:
    payload = result.to_dict()
    if deleted:
        # Files deleted in head. Non-protected (source) deletions are applied to the
        # verified tree; a protected-harness deletion instead drives REJECTED. (Was
        # ``deleted_not_gated`` before schema 1.1, when deletions were ungated.)
        payload["deleted"] = deleted
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def to_sarif(result: GuardResult) -> dict[str, Any]:
    """Render the verdict as a minimal **SARIF 2.1.0** document for GitHub
    code-scanning (the *Security* tab).

    A clean ``PASS`` yields **no results** (no alert). Any non-``PASS`` verdict
    yields one ``error``-level result whose ``ruleId`` is the stable ``reason_code``
    and whose locations point at the protected-violation files (for ``REJECTED``) or
    the changed files. SARIF is only a *view*; the decision stays the verdict + exit
    code.
    """
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    if result.verdict != PASS:
        rule_id = result.reason_code or result.verdict.lower()
        located = result.protected_violations or result.files_changed
        locations = [
            {"physicalLocation": {"artifactLocation": {"uri": p}}} for p in located if p
        ]
        entry: dict[str, Any] = {
            "ruleId": rule_id,
            "level": "error",
            "message": {"text": f"EvoGuard {result.verdict}: {result.reason}"},
            "properties": {
                "verdict": result.verdict,
                "risk_level": result.risk_level,
                "verdict_source": result.verdict_source,
                "isolation": result.isolation,
            },
        }
        if locations:
            entry["locations"] = locations
        results.append(entry)
        rules.append({"id": rule_id, "name": result.verdict})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "EvoGuard",
                        "version": __version__,
                        "informationUri": "https://github.com/EvoRiseKsa/EvoOM-Guard-m",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(result: GuardResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(to_sarif(result), f, indent=2)
