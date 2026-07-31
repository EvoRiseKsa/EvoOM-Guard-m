# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""EvoOM Guard — evidence-bound verification for untrusted code changes.

Guard evaluates one explicit policy question, for a code change produced by anyone (a
human or — the motivating case — an AI agent):

    *Does this change satisfy the selected judge, **without gaming its evidence**?*

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
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, TypedDict, cast

import evoom_guard.workspace.candidate_tree as _candidate_tree
import evoom_guard.workspace.repository as _repository_workspace
from evoom_guard import __version__
from evoom_guard.application.assurance import (
    ISOLATION_RANK_POLICY,
    REPORT_INTEGRITY_RANK_POLICY,
    pack_assurance,
)
from evoom_guard.application.assurance import (
    assurance_profile as _assurance_profile,
)
from evoom_guard.application.assurance import (
    assurance_shortfall as _assurance_shortfall,
)
from evoom_guard.application.assurance import (
    preflight_assurance_profile as _preflight_assurance_profile,
)
from evoom_guard.application.assurance import (
    static_assurance_profile as _static_assurance_profile,
)
from evoom_guard.application.attestation import (
    build_attestation as _build_attestation_payload,
)
from evoom_guard.application.blackbox_finalization import (
    BlackboxFinalizationInput,
    BlackboxFinalizationServices,
    finalize_blackbox_verification,
)
from evoom_guard.application.diff_verification import (
    DiffVerificationOptions,
    DiffVerificationRequest,
    DiffVerificationServices,
    verify_diff,
)
from evoom_guard.application.pipeline import VerificationPipeline
from evoom_guard.application.repo_decision import (
    OUTCOME_REASON_POLICY,
    TAMPER_OUTCOME_REASON_POLICY,
)
from evoom_guard.application.repo_finalization import (
    RepoCoverageCollector,
    RepoFinalizationInput,
    RepoFinalizationServices,
    finalize_repo_verification,
)
from evoom_guard.application.repo_judgment import (
    RepoJudgmentInput,
    RepoJudgmentOutcome,
    RepoJudgmentServices,
    build_repo_judgment,
)
from evoom_guard.application.request_preparation import (
    GuardRequestPreparationInput,
    GuardRequestPreparationServices,
    prepare_guard_request,
)
from evoom_guard.candidate import parse_file_blocks, parse_patch_blocks
from evoom_guard.contracts import VerdictResult
from evoom_guard.domain import (
    CandidateInput,
    GuardRequest,
    RepositoryInput,
    SourceIdentity,
)
from evoom_guard.domain.decision import GuardDecision
from evoom_guard.domain.evidence import VerificationEvidence
from evoom_guard.domain.verdict import (
    ERROR,
    EXECUTION_COMPLETED,
    EXECUTION_NOT_STARTED,
    EXECUTION_STARTED_INCOMPLETE,
    EXECUTION_STATIC_GATE,
    FAIL,
    PASS,
    REASON_BINARY_PATCH,
    REASON_EMPTY_DIFF,
    REASON_NO_VERIFIABLE_CHANGES,
    REASON_POLICY_REQUIREMENT_UNSUPPORTED,
    REASON_REVERSE_APPLY_FAILED,
    REASON_UNSAFE_PATH,
    REASON_VERIFIER_PACK_INVALID,
    REASON_VERIFIER_PACK_REQUIRED,
    REJECTED,
    TAMPERED,
)
from evoom_guard.domain.verdict import (
    REASON_ASSURANCE_REQUIREMENT_NOT_MET as REASON_ASSURANCE_REQUIREMENT_NOT_MET,
)
from evoom_guard.domain.verdict import (
    REASON_CANDIDATE_NOT_EXERCISED as REASON_CANDIDATE_NOT_EXERCISED,
)
from evoom_guard.domain.verdict import (
    REASON_CANDIDATE_TREE_CHANGED as REASON_CANDIDATE_TREE_CHANGED,
)
from evoom_guard.domain.verdict import (
    REASON_DIFF_COVERAGE_BELOW_THRESHOLD as REASON_DIFF_COVERAGE_BELOW_THRESHOLD,
)
from evoom_guard.domain.verdict import (
    REASON_FIX_NOT_DEMONSTRATED as REASON_FIX_NOT_DEMONSTRATED,
)
from evoom_guard.domain.verdict import (
    REASON_JUNIT_EXIT_MISMATCH as REASON_JUNIT_EXIT_MISMATCH,
)
from evoom_guard.domain.verdict import (
    REASON_NO_PARSEABLE_EDITS as REASON_NO_PARSEABLE_EDITS,
)
from evoom_guard.domain.verdict import (
    REASON_NO_TEST_VERDICT as REASON_NO_TEST_VERDICT,
)
from evoom_guard.domain.verdict import (
    REASON_PATCH_APPLY_FAILED as REASON_PATCH_APPLY_FAILED,
)
from evoom_guard.domain.verdict import (
    REASON_PROTECTED_HARNESS_EDIT as REASON_PROTECTED_HARNESS_EDIT,
)
from evoom_guard.domain.verdict import (
    REASON_RUNTIME_CLEANUP_FAILED as REASON_RUNTIME_CLEANUP_FAILED,
)
from evoom_guard.domain.verdict import (
    REASON_SETUP_FAILED as REASON_SETUP_FAILED,
)
from evoom_guard.domain.verdict import (
    REASON_SETUP_TIMEOUT as REASON_SETUP_TIMEOUT,
)
from evoom_guard.domain.verdict import (
    REASON_TEST_COMMAND_UNAVAILABLE as REASON_TEST_COMMAND_UNAVAILABLE,
)
from evoom_guard.domain.verdict import (
    REASON_TEST_TIMEOUT as REASON_TEST_TIMEOUT,
)
from evoom_guard.domain.verdict import (
    REASON_TESTS_FAILED as REASON_TESTS_FAILED,
)
from evoom_guard.domain.verdict import (
    REASON_TESTS_PASSED as REASON_TESTS_PASSED,
)
from evoom_guard.domain.verdict import (
    REASON_VERIFIER_PACK_IDENTITY_MISMATCH as REASON_VERIFIER_PACK_IDENTITY_MISMATCH,
)
from evoom_guard.domain.verdict import (
    REASON_VERIFIER_PACK_NOT_FOUND as REASON_VERIFIER_PACK_NOT_FOUND,
)
from evoom_guard.domain.verdict import (
    REASON_VERIFIER_PACK_SNAPSHOT_CHANGED as REASON_VERIFIER_PACK_SNAPSHOT_CHANGED,
)
from evoom_guard.execution import (
    ProcessContainmentError as _SubprocessContainmentError,
)
from evoom_guard.execution import (
    ProcessOutputLimitExceeded as _SubprocessOutputLimitExceeded,
)
from evoom_guard.execution import (
    resolve_host_command as _resolve_host_command,
)
from evoom_guard.execution import (
    run_bounded_subprocess as _run_bounded_subprocess,
)
from evoom_guard.integrations import guard_output as _guard_output
from evoom_guard.pack_manifest import PACK_DIGEST_FORMAT
from evoom_guard.patchmin import RiskScore, risk_score
from evoom_guard.policy import HarnessInputPolicyError
from evoom_guard.policy import (
    build_effective_policy as _build_effective_policy_contract,
)
from evoom_guard.policy import (
    effective_policy_payload as _effective_policy_payload,
)
from evoom_guard.policy import (
    effective_policy_sha256 as _effective_policy_digest,
)
from evoom_guard.verdict_contract_v1_11 import SCHEMA_VERSION
from evoom_guard.verdict_contract_v1_12 import (
    SCHEMA_VERSION as OPERATING_PROFILE_SCHEMA_VERSION,
)
from evoom_guard.verifiers.candidate_preflight import (
    VERIFIER_PACK_DIR as VERIFIER_PACK_DIR,
)
from evoom_guard.verifiers.candidate_preflight import (
    CandidatePreflightRequest,
    CandidatePreflightServices,
    evaluate_candidate_preflight,
)
from evoom_guard.verifiers.harness_policy import (
    discover_local_action_dirs as discover_local_action_dirs,
)
from evoom_guard.verifiers.harness_policy import (
    is_allowlist_exemptible as is_allowlist_exemptible,
)
from evoom_guard.verifiers.harness_policy import (
    matches_globs as _matches_globs,
)
from evoom_guard.verifiers.harness_policy import (
    validate_harness_input_files,
)
from evoom_guard.verifiers.repo_baseline import (
    RepoBaselineRequest,
    RepoBaselineServices,
    run_repo_baseline,
)
from evoom_guard.verifiers.repo_evidence import (
    repo_attestation_evidence_payload,
    repo_verification_evidence_from_artifact,
)
from evoom_guard.verifiers.repo_verifier import (
    COPY_IGNORE,
    RepoVerifier,
    copy_repo_tree,
    is_addable_new_test,
    is_judge_autoexec,
    is_protected,
    is_protected_ci,
    is_protected_config,
    is_safe_relpath,
    judge_subprocess_env,
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
#   1.7 — policy consistency (fail-closed): one new reason code
#         ``policy_requirement_unsupported`` — a requested gate the selected
#         judge cannot enforce (require_demonstrated_fix / min_diff_coverage
#         outside the subprocess judge) is an ERROR, never silently dropped.
#         The attestation gains ``effective_policy`` (the COMPLETE canonical
#         policy that shaped the judgment) and ``policy_sha256`` is now
#         computed over it (previously only 5 fields — two materially
#         different policies could hash identically). ``baseline`` gains
#         ``scope: repo_suite_only`` (the baseline never collects a verifier
#         pack); evidence-only requests in unsupported modes attach an
#         explicit unmeasured/note record instead of silently vanishing.
#   1.8 — canonical verifier-pack identity and execution fidelity: V2 pack
#         digests, expected digest pins, mandatory separate pack execution,
#         setup/suite isolation evidence, candidate/pack drift reason codes,
#         and explicit JUnit digest formats for composite reports.
#   1.9 — adversarial boundary hardening: descriptor-bound POSIX workspace
#         operations, all-or-nothing JUnit directory parsing, and a canonical
#         full post-setup runtime-tree identity across repo-suite/pack phases.
#   1.10 — pre-execution assurance honesty: static refusals report every
#          runtime-dependent assurance axis as not run/not applicable, preserve
#          the requested repo/black-box policy in the attestation, and do not
#          let runtime assurance floors overwrite an already-final static gate.
#   1.11 — explicit execution/phase state; observed black-box launcher/CID
#          evidence; phase-specific Docker start/isolation evidence; honest
#          composite source/count/report-integrity semantics; additive
#          candidate_not_exercised reason; top-level JSON isolation.
# The frozen schema-1.11 vocabulary is imported above and deliberately
# re-exported from this established module. Producer behavior remains local:
# outcome selection, policy construction, assurance, and attestation are not
# shared with the independent record verifier.

# Ordering of report-integrity levels, weakest → strongest. A caller can demand a
# floor with require_report_integrity; if the run's actual level is below it, the
# verdict is refused (fail-closed) rather than shipping a weaker guarantee than
# was asked for. Enforced against what actually ran, never against a CLI wish.
_OUTCOME_REASON = OUTCOME_REASON_POLICY
_TAMPER_OUTCOME_REASON = TAMPER_OUTCOME_REASON_POLICY
_REPORT_INTEGRITY_RANK = REPORT_INTEGRITY_RANK_POLICY
_ISOLATION_RANK = ISOLATION_RANK_POLICY
_pack_assurance = pack_assurance


def _blackbox_decision_symbol_providers() -> dict[str, Callable[[], str]]:
    """Expose Guard's established verdict vocabulary through live lookups."""

    # Deliberately do not bind these names as lambda defaults.  Historical
    # Guard loaded them only after the risk and optional repo effects returned.
    return {
        "PASS": lambda: PASS,
        "FAIL": lambda: FAIL,
        "ERROR": lambda: ERROR,
        "TAMPERED": lambda: TAMPERED,
        "EXECUTION_COMPLETED": lambda: EXECUTION_COMPLETED,
        "EXECUTION_NOT_STARTED": lambda: EXECUTION_NOT_STARTED,
        "EXECUTION_STARTED_INCOMPLETE": (
            lambda: EXECUTION_STARTED_INCOMPLETE
        ),
        "REASON_ASSURANCE_REQUIREMENT_NOT_MET": (
            lambda: REASON_ASSURANCE_REQUIREMENT_NOT_MET
        ),
        "REASON_CANDIDATE_NOT_EXERCISED": (
            lambda: REASON_CANDIDATE_NOT_EXERCISED
        ),
        "REASON_CANDIDATE_TREE_CHANGED": (
            lambda: REASON_CANDIDATE_TREE_CHANGED
        ),
        "REASON_JUNIT_EXIT_MISMATCH": (
            lambda: REASON_JUNIT_EXIT_MISMATCH
        ),
        "REASON_NO_TEST_VERDICT": lambda: REASON_NO_TEST_VERDICT,
        "REASON_PATCH_APPLY_FAILED": lambda: REASON_PATCH_APPLY_FAILED,
        "REASON_RUNTIME_CLEANUP_FAILED": (
            lambda: REASON_RUNTIME_CLEANUP_FAILED
        ),
        "REASON_TEST_TIMEOUT": lambda: REASON_TEST_TIMEOUT,
        "REASON_TESTS_FAILED": lambda: REASON_TESTS_FAILED,
        "REASON_TESTS_PASSED": lambda: REASON_TESTS_PASSED,
        "REASON_UNSAFE_PATH": lambda: REASON_UNSAFE_PATH,
        "REASON_VERIFIER_PACK_IDENTITY_MISMATCH": (
            lambda: REASON_VERIFIER_PACK_IDENTITY_MISMATCH
        ),
        "REASON_VERIFIER_PACK_INVALID": (
            lambda: REASON_VERIFIER_PACK_INVALID
        ),
        "REASON_VERIFIER_PACK_NOT_FOUND": (
            lambda: REASON_VERIFIER_PACK_NOT_FOUND
        ),
        "REASON_VERIFIER_PACK_SNAPSHOT_CHANGED": (
            lambda: REASON_VERIFIER_PACK_SNAPSHOT_CHANGED
        ),
    }


class _BlackboxHarnessOptions(TypedDict, total=False):
    """Additive schema-1.12 keyword passed only when explicitly configured."""

    harness_inputs: tuple[str, ...]


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
    isolation: str = "subprocess"          # suite boundary label; "not_run" when no suite starts
    diff_coverage: dict[str, Any] | None = None   # changed-line coverage evidence (opt-in)
    baseline: dict[str, Any] | None = None        # before/after differential evidence (opt-in)
    attestation: dict[str, Any] | None = None     # context binding for the signed verdict
    assurance: dict[str, Any] | None = None       # how much the verdict can be trusted
    # Additive 1.11 fields stay at the end to preserve GuardResult's positional
    # constructor order for integrations that predate the state-machine contract.
    test_command_ran: bool | None = None
    execution_state: str = ""
    execution_phase: str = ""

    def __post_init__(self) -> None:
        """Fill additive 1.11 fields for legacy manual constructors only.

        Production Guard paths pass explicit runner evidence.  The fallback
        preserves the pre-1.11 ``GuardResult(...)`` API used by report adapters;
        it must never replace explicit timeout/preflight facts.
        """
        if self.test_command_ran is None:
            self.test_command_ran = bool(
                self.verdict_source is not None
                or self.verdict in (PASS, FAIL, TAMPERED)
            )
        if not self.execution_state:
            self.execution_state = (
                EXECUTION_COMPLETED
                if self.test_command_ran
                else EXECUTION_STATIC_GATE
                if self.verdict == REJECTED
                else EXECUTION_NOT_STARTED
            )
        if not self.execution_phase:
            self.execution_phase = (
                "complete"
                if self.execution_state == EXECUTION_COMPLETED
                else "pre_gate"
                if self.execution_state == EXECUTION_STATIC_GATE
                else "preflight"
            )

    @property
    def blast_radius_level(self) -> str:
        """Coarse change-size level; the frozen wire name is ``risk_level``."""

        return self.risk_level

    @property
    def blast_radius_score(self) -> float:
        """Change-size score; not a semantic, security, or maliciousness risk."""

        return self.risk_score

    def to_dict(self) -> dict[str, Any]:
        schema_version = SCHEMA_VERSION
        if isinstance(self.attestation, Mapping):
            effective_policy = self.attestation.get("effective_policy")
            if (
                isinstance(effective_policy, Mapping)
                and (
                    "operating_profile" in effective_policy
                    or "harness_inputs" in effective_policy
                )
            ):
                schema_version = OPERATING_PROFILE_SCHEMA_VERSION
        return {
            "schema_version": schema_version,
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
            "test_command_ran": bool(self.test_command_ran),
            "execution_state": self.execution_state,
            "execution_phase": self.execution_phase,
            "verdict_source": self.verdict_source,
            "isolation": self.isolation,
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


def _repo_coverage_collector() -> RepoCoverageCollector:
    """Resolve the historical local-import coverage seam only when reached."""

    from evoom_guard.evidence import collect_diff_coverage

    return collect_diff_coverage


def guard(
    repo_path: str,
    candidate: str,
    *,
    deleted: tuple[str, ...] = (),
    test_command: list[str] | None = None,
    setup_command: list[str] | None = None,
    trust_setup_on_host: bool = False,
    setup_output_globs: tuple[str, ...] = (),
    protected: tuple[str, ...] = (),
    allow: tuple[str, ...] = (),
    allow_new_tests: bool = False,
    timeout: int = 120,
    mem_limit_mb: int = 1024,
    isolation: str = "subprocess",
    docker_image: str | None = None,
    docker_network: str = "none",
    verifier_pack: str | None = None,
    expect_verifier_pack_sha256: str | None = None,
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
    strict_harness: bool = False,
    file_blocks: dict[str, str] | None = None,
    operating_profile: str | None = None,
    harness_inputs: tuple[str, ...] = (),
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
    built-in tests/config/auto-exec set). A trusted policy must list custom
    repository-local command wrappers and helper files in ``harness_inputs``;
    those exact paths become non-exemptible judge inputs. ``mem_limit_mb`` is
    the address-space cap
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

    ``allow`` is an adopter-curated allowlist of *extra* ``protected`` globs. It
    cannot exempt built-in tests, test/build configuration, CI, auto-executed files,
    or unsafe paths: those are judge-owned evidence rather than candidate policy.

    ``isolation="docker"`` runs the suite inside a short-lived, network-less,
    read-only container (``docker_image`` required; defence in depth for semi-trusted
    code — not a complete boundary for hostile code). Default ``"subprocess"`` is
    unchanged.

    ``verifier_pack`` supplies an **Independent Verifier Pack** of judge-owned
    pytest invariants. Guard accepts a verified snapshot outside the candidate
    tree. Repo-native mode runs it as a separate mandatory phase after the repo
    suite; black-box mode runs the external phase first and may short-circuit
    before the repo phase. Every policy-required phase must pass.
    ``expect_verifier_pack_sha256`` can pin its V2 portable
    content/tree identity before candidate code runs. Repo-native tests share the
    judge process with candidate imports, so this provides integrity, not secrecy;
    use black-box plus container isolation for runtime separation.

    ``diff_coverage=True`` adds **changed-line coverage evidence** (one extra
    suite run under ``coverage``): which changed lines the suite actually
    executed. Evidence only, unless ``min_diff_coverage`` sets a gate (and
    implies measurement): a ``PASS`` whose measured changed-line coverage is
    below the threshold becomes ``FAIL`` (``diff_coverage_below_threshold``),
    while unavailable measurement becomes ``ERROR``. This is a quality gate
    for non-hostile candidate code, not an adversarial integrity control:
    candidate imports share the collector process and can mutate its live
    coverage state. Executed is also not asserted — see
    :mod:`evoom_guard.evidence`.
    """
    prepared_request = prepare_guard_request(
        GuardRequestPreparationInput(
            repository_path=repo_path,
            candidate_text=candidate,
            deleted_paths=deleted,
            test_command=test_command,
            setup_command=setup_command,
            trust_setup_on_host=trust_setup_on_host,
            setup_output_globs=setup_output_globs,
            protected=protected,
            allow=allow,
            allow_new_tests=allow_new_tests,
            timeout=timeout,
            mem_limit_mb=mem_limit_mb,
            isolation=isolation,
            docker_image=docker_image,
            docker_network=docker_network,
            verifier_pack_path=verifier_pack,
            expect_verifier_pack_sha256=expect_verifier_pack_sha256,
            collect_diff_coverage=diff_coverage,
            min_diff_coverage=min_diff_coverage,
            blackbox=blackbox,
            blackbox_only=blackbox_only,
            require_report_integrity=require_report_integrity,
            require_candidate_isolation=require_candidate_isolation,
            base_sha=base_sha,
            head_sha=head_sha,
            base_tree_sha=base_tree_sha,
            head_tree_sha=head_tree_sha,
            policy_id=policy_id,
            policy_version=policy_version,
            baseline_evidence=baseline_evidence,
            require_demonstrated_fix=require_demonstrated_fix,
            strict_harness=strict_harness,
            file_blocks=file_blocks,
            operating_profile=operating_profile,
            harness_inputs=harness_inputs,
        ),
        services=GuardRequestPreparationServices(
            repository_input_provider=lambda: RepositoryInput,
            candidate_input_provider=lambda: CandidateInput,
            source_identity_provider=lambda: SourceIdentity,
            effective_policy_provider=lambda: _build_effective_policy_contract,
            guard_request_provider=lambda: GuardRequest,
            effective_policy_payload_provider=lambda: _effective_policy_payload,
        ),
    )
    effective_policy = prepared_request.effective_policy
    compatibility = prepared_request.compatibility
    repo_path = compatibility.repository_path
    candidate = compatibility.candidate_text
    deleted = compatibility.deleted_paths
    file_blocks = compatibility.file_blocks
    base_sha = compatibility.base_sha
    head_sha = compatibility.head_sha
    base_tree_sha = compatibility.base_tree_sha
    head_tree_sha = compatibility.head_tree_sha
    test_command = compatibility.test_command
    setup_command = compatibility.setup_command
    trust_setup_on_host = compatibility.trust_setup_on_host
    setup_output_globs = compatibility.setup_output_globs
    protected = compatibility.protected
    allow = compatibility.allow
    allow_new_tests = compatibility.allow_new_tests
    timeout = compatibility.timeout
    mem_limit_mb = compatibility.mem_limit_mb
    isolation = compatibility.isolation
    docker_image = compatibility.docker_image
    docker_network = compatibility.docker_network
    verifier_pack = compatibility.verifier_pack_path
    expect_verifier_pack_sha256 = compatibility.expect_verifier_pack_sha256
    diff_coverage = compatibility.collect_diff_coverage
    min_diff_coverage = compatibility.min_diff_coverage
    blackbox = compatibility.blackbox
    blackbox_only = compatibility.blackbox_only
    require_report_integrity = compatibility.require_report_integrity
    require_candidate_isolation = compatibility.require_candidate_isolation
    policy_id = compatibility.policy_id
    policy_version = compatibility.policy_version
    baseline_evidence = compatibility.baseline_evidence
    require_demonstrated_fix = compatibility.require_demonstrated_fix
    strict_harness = compatibility.strict_harness
    # Compatibility projections created before schema 1.12 may omit this
    # optional field. Absence is the canonical 1.11/default policy.
    harness_inputs = getattr(compatibility, "harness_inputs", ())
    harness_input_problems = validate_harness_input_files(
        repo_path,
        harness_inputs,
    )
    if harness_input_problems:
        raise HarnessInputPolicyError(
            "invalid harness_inputs in trusted base: "
            + "; ".join(harness_input_problems)
        )

    # Fail-closed policy consistency (1.7): a GATE the selected judge cannot
    # enforce must stop the run — "require X" answered with a PASS that never
    # checked X is exactly the silent-degradation failure the policy contract
    # exists to prevent. (Evidence-only requests degrade EXPLICITLY instead:
    # see the unmeasured/note records attached further down.)
    _unsupported: list[str] = []
    if require_demonstrated_fix and (blackbox or isolation != "subprocess"):
        _unsupported.append("require_demonstrated_fix")
    if min_diff_coverage is not None and (blackbox or isolation != "subprocess"):
        _unsupported.append("min_diff_coverage")
    if blackbox and setup_command:
        _unsupported.append("setup_command")
    if _unsupported:
        _mode_desc = "the black-box judge" if blackbox else f"isolation {isolation!r}"
        return GuardResult(
            verdict=ERROR, passed=False,
            reason=(
                f"policy requirement(s) {', '.join(_unsupported)} cannot be "
                f"enforced under {_mode_desc}. Refusing to return a verdict that "
                "silently drops or ignores a requested option; select a compatible "
                "mode/policy or remove the requirement."
            ),
            files_changed=changed_paths(candidate, file_blocks),
            protected_violations=[], risk_level="low", risk_score=0.0,
            reason_code=REASON_POLICY_REQUIREMENT_UNSUPPORTED,
            isolation="not_run",
            execution_state=EXECUTION_NOT_STARTED,
            execution_phase="preflight",
            assurance=_preflight_assurance_profile(verifier_pack),
            attestation=_build_attestation(
                candidate, safe_deleted=[], test_command=test_command,
                effective_policy=effective_policy, art={
                    "base_sha": base_sha, "head_sha": head_sha,
                    "base_tree_sha": base_tree_sha, "head_tree_sha": head_tree_sha,
                    "policy_id": policy_id, "policy_version": policy_version,
                    "execution_state": EXECUTION_NOT_STARTED,
                    "execution_phase": "preflight",
                    "test_command_started": False,
                    "delivered_isolation": "not_run",
                }, mode="blackbox" if blackbox else "repo",
            ),
        )

    # This is the historical pre-execution seam: parsing has completed, while
    # no candidate file has been materialized and no candidate command started.
    preflight = evaluate_candidate_preflight(
        CandidatePreflightRequest(
            repo_path=repo_path,
            changed_paths=tuple(changed_paths(candidate, file_blocks)),
            deleted_paths=tuple(deleted),
            protected=tuple(protected),
            allow=tuple(allow),
            allow_new_tests=allow_new_tests,
            strict_harness=strict_harness,
            harness_inputs=harness_inputs,
        ),
        services=CandidatePreflightServices(
            path_exists=lambda path: os.path.exists(path),
            discover_local_action_dirs=lambda repo: discover_local_action_dirs(repo),
            is_safe_relpath=lambda path: is_safe_relpath(path),
            is_judge_autoexec=lambda path: is_judge_autoexec(path),
            is_protected_config=lambda path, *, strict_harness: (
                is_protected_config(path, strict_harness=strict_harness)
            ),
            is_protected_ci=lambda path, *, local_action_dirs: is_protected_ci(
                path, local_action_dirs=local_action_dirs
            ),
            is_protected=lambda path, protected: is_protected(path, protected),
            is_addable_new_test=lambda path, extra, **kwargs: is_addable_new_test(
                path, extra, **kwargs
            ),
            is_allowlist_exemptible=(
                lambda path, **kwargs: is_allowlist_exemptible(path, **kwargs)
            ),
            matches_globs=lambda path, globs: _matches_globs(path, globs),
            verifier_pack_dir=lambda: VERIFIER_PACK_DIR,
        ),
    )
    # Preserve the established mutable-list API at Guard's compatibility edge.
    changed = list(preflight.changed_paths)
    all_touched = list(preflight.all_touched_paths)
    unsafe = list(preflight.unsafe_paths)
    violations = list(preflight.protected_violations)
    safe_deleted = list(preflight.safe_deleted_paths)

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
    if strict_harness:
        problem["strict_harness"] = True
    if harness_inputs:
        problem["harness_inputs"] = list(harness_inputs)
    if safe_deleted:
        problem["deleted"] = safe_deleted
    if verifier_pack:
        problem["verifier_pack"] = os.path.abspath(verifier_pack)
    if expect_verifier_pack_sha256:
        problem["expect_verifier_pack_sha256"] = expect_verifier_pack_sha256.lower()
    if file_blocks:
        problem["file_blocks"] = dict(file_blocks)

    # Black-box mode: the verdict is produced by the judge's OWN pytest over the
    # judge-owned pack, which never imports the candidate — closing same-process
    # report forgery. Requires a pack (there is nothing to assert otherwise); the
    # harness-integrity checks above still apply.
    if blackbox and preflight.may_execute:
        from evoom_guard.blackbox import run_blackbox

        if not verifier_pack:
            return GuardResult(
                verdict=ERROR, passed=False,
                reason="--blackbox requires --verifier-pack (the judge-owned protocol tests)",
                files_changed=changed, protected_violations=[],
                risk_level=risk_score(_risk_map(repo_path, candidate, file_blocks)).level,
                risk_score=risk_score(_risk_map(repo_path, candidate, file_blocks)).score,
                reason_code=REASON_VERIFIER_PACK_REQUIRED,
                isolation="not_run",
                execution_state=EXECUTION_NOT_STARTED,
                execution_phase="preflight",
                assurance=_preflight_assurance_profile(None),
                attestation=_build_attestation(
                    candidate,
                    safe_deleted=safe_deleted,
                    test_command=test_command,
                    effective_policy=effective_policy,
                    art={
                        "base_sha": base_sha,
                        "head_sha": head_sha,
                        "base_tree_sha": base_tree_sha,
                        "head_tree_sha": head_tree_sha,
                        "policy_id": policy_id,
                        "policy_version": policy_version,
                        "execution_state": EXECUTION_NOT_STARTED,
                        "execution_phase": "preflight",
                        "test_command_started": False,
                        "delivered_isolation": "not_run",
                    },
                    mode="blackbox",
                ),
            )
        blackbox_harness_options: _BlackboxHarnessOptions = (
            {"harness_inputs": harness_inputs}
            if harness_inputs
            else {}
        )
        bx = run_blackbox(
            repo_path, candidate, os.path.abspath(verifier_pack), timeout=timeout,
            isolation=isolation, docker_image=docker_image, docker_network=docker_network,
            mem_limit_mb=mem_limit_mb, deleted_paths=tuple(safe_deleted),
            file_blocks=file_blocks,
            expect_verifier_pack_sha256=expect_verifier_pack_sha256,
            **blackbox_harness_options,
        )

        def assess_blackbox_risk() -> RiskScore:
            risk_map = _risk_map(repo_path, candidate, file_blocks)
            for touched_path in all_touched:
                if touched_path in deleted and touched_path not in risk_map:
                    risk_map[touched_path] = (
                        0,
                        len(
                            _read_repo_file(
                                repo_path, touched_path
                            ).splitlines()
                        ),
                    )
            return risk_score(
                risk_map,
                protected=_PROTECTED_GLOBS + tuple(protected),
            )

        def verify_composed_repo() -> VerdictResult:
            repo_problem = {
                key: value
                for key, value in problem.items()
                if key
                not in ("verifier_pack", "expect_verifier_pack_sha256")
            }
            repo_docker_image = (
                (bx.isolation or {}).get("image_digest")
                if isolation in ("docker", "gvisor")
                else docker_image
            )
            return RepoVerifier(
                timeout=timeout,
                mem_limit_mb=mem_limit_mb,
                isolation=isolation,
                docker_image=repo_docker_image,
                docker_network=docker_network,
                trust_setup_on_host=trust_setup_on_host,
                setup_output_globs=setup_output_globs,
                strict_harness=strict_harness,
            ).verify(candidate, repo_problem)

        finalization_bx = finalize_blackbox_verification(
            BlackboxFinalizationInput(
                runtime_result=bx,
                blackbox_only=blackbox_only,
                verifier_pack_path=verifier_pack,
                candidate_text=candidate,
                safe_deleted_paths=safe_deleted,
                test_command=test_command,
                effective_policy=effective_policy,
                collect_baseline_evidence=baseline_evidence,
                collect_diff_coverage=diff_coverage,
                require_report_integrity=require_report_integrity,
                require_candidate_isolation=require_candidate_isolation,
                base_sha=base_sha,
                head_sha=head_sha,
                base_tree_sha=base_tree_sha,
                head_tree_sha=head_tree_sha,
                policy_id=policy_id,
                policy_version=policy_version,
            ),
            services=BlackboxFinalizationServices(
                risk_assessor_provider=lambda: assess_blackbox_risk,
                composed_repo_verifier_provider=(
                    lambda: verify_composed_repo
                ),
                assurance_builder_provider=lambda: _assurance_profile,
                assurance_shortfall_provider=(
                    lambda: _assurance_shortfall
                ),
                attestation_builder_provider=(
                    lambda: _build_attestation
                ),
                verification_pipeline_provider=(
                    lambda: VerificationPipeline
                ),
                guard_decision_provider=lambda: GuardDecision,
                guard_result_factory_provider=lambda: GuardResult,
                decision_symbol_providers=(
                    _blackbox_decision_symbol_providers()
                ),
                outcome_reason_policy_provider=lambda: _OUTCOME_REASON,
                tamper_outcome_reason_policy_provider=(
                    lambda: _TAMPER_OUTCOME_REASON
                ),
            ),
        )
        return cast(
            "GuardResult",
            finalization_bx.guard_result_factory(
                verdict=finalization_bx.verdict,
                passed=finalization_bx.passed,
                reason=finalization_bx.reason,
                files_changed=changed,
                protected_violations=[],
                risk_level=finalization_bx.risk_level,
                risk_score=finalization_bx.risk_score,
                tests_passed=finalization_bx.tests_passed,
                tests_total=finalization_bx.tests_total,
                test_command_ran=finalization_bx.test_command_started,
                execution_state=finalization_bx.execution_state,
                execution_phase=finalization_bx.execution_phase,
                verdict_source=finalization_bx.verdict_source,
                diagnostics=finalization_bx.diagnostics,
                reason_code=finalization_bx.reason_code,
                isolation=finalization_bx.effective_candidate_isolation,
                assurance=cast(dict[str, Any], finalization_bx.assurance),
                baseline=cast(
                    dict[str, Any] | None,
                    finalization_bx.baseline,
                ),
                diff_coverage=cast(
                    dict[str, Any] | None,
                    finalization_bx.diff_coverage,
                ),
                attestation=cast(
                    dict[str, Any],
                    finalization_bx.attestation,
                ),
            ),
        )

    # The pre-gate is decided BEFORE the suite runs — for every rejection shape.
    # A candidate whose only violation is a protected *deletion* used to slip past
    # this (its added/modified paths are clean, so the verifier ran the suite once
    # before the mapping below flipped the verdict to REJECTED) — leaving
    # ``test_command_ran: true`` on a verdict documented as pre-execution. Skip
    # the run entirely whenever the outcome is already decided by the diff alone.
    judgment_services: RepoJudgmentServices[
        VerificationEvidence,
        RiskScore,
        VerificationPipeline,
    ] = RepoJudgmentServices(
        repo_verifier_provider=lambda: RepoVerifier,
        evidence_projector_provider=(
            lambda: repo_verification_evidence_from_artifact
        ),
        risk_map_provider=lambda: _risk_map,
        repo_file_reader_provider=lambda: _read_repo_file,
        risk_scorer_provider=lambda: risk_score,
        protected_globs_provider=lambda: _PROTECTED_GLOBS,
        verification_pipeline_provider=lambda: VerificationPipeline,
    )
    judgment: RepoJudgmentOutcome[
        VerificationEvidence,
        RiskScore,
        VerificationPipeline,
    ] = build_repo_judgment(
        RepoJudgmentInput(
            run_suite=preflight.may_execute,
            repository_path=repo_path,
            candidate_text=candidate,
            problem=problem,
            all_touched_paths=all_touched,
            unsafe_paths=unsafe,
            protected_violations=violations,
            deleted_paths=deleted,
            protected_patterns=protected,
            file_blocks=file_blocks,
            timeout=timeout,
            mem_limit_mb=mem_limit_mb,
            isolation=isolation,
            docker_image=docker_image,
            docker_network=docker_network,
            trust_setup_on_host=trust_setup_on_host,
            setup_output_globs=setup_output_globs,
            strict_harness=strict_harness,
        ),
        services=judgment_services,
    )
    run_suite = judgment.run_suite
    art = cast(dict[str, Any], judgment.raw_artifact)
    verification_evidence = judgment.verification_evidence
    diagnostics = judgment.diagnostics
    risk = judgment.risk
    decision_pipeline = judgment.pipeline
    finalization = finalize_repo_verification(
        RepoFinalizationInput(
            pipeline=decision_pipeline,
            verification_evidence=verification_evidence,
            raw_artifact=art,
            run_suite=run_suite,
            repository_path=repo_path,
            candidate_text=candidate,
            safe_deleted_paths=safe_deleted,
            test_command=test_command,
            setup_command=setup_command,
            setup_output_globs=setup_output_globs,
            file_blocks=file_blocks,
            timeout=timeout,
            mem_limit_mb=mem_limit_mb,
            strict_harness=strict_harness,
            isolation=isolation,
            judgment_mode="blackbox" if blackbox else "repo",
            verifier_pack_path=verifier_pack,
            collect_diff_coverage=diff_coverage,
            min_diff_coverage=min_diff_coverage,
            collect_baseline_evidence=baseline_evidence,
            require_demonstrated_fix=require_demonstrated_fix,
            require_report_integrity=require_report_integrity,
            require_candidate_isolation=require_candidate_isolation,
            effective_policy=effective_policy,
            base_sha=base_sha,
            head_sha=head_sha,
            base_tree_sha=base_tree_sha,
            head_tree_sha=head_tree_sha,
            policy_id=policy_id,
            policy_version=policy_version,
            harness_inputs=harness_inputs,
        ),
        services=RepoFinalizationServices(
            coverage_collector_provider=lambda: _repo_coverage_collector(),
            baseline_runner_provider=lambda: _run_baseline_suite,
            attestation_builder_provider=lambda: _build_attestation,
            runtime_assurance_builder_provider=lambda: _assurance_profile,
            static_assurance_builder_provider=lambda: _static_assurance_profile,
            assurance_shortfall_provider=lambda: _assurance_shortfall,
            attestation_evidence_projector_provider=(
                lambda: repo_attestation_evidence_payload
            ),
            pack_directory_predicate=lambda path: os.path.isdir(path),
        ),
    )
    current_decision = finalization.decision
    v = current_decision.verdict
    code = current_decision.reason_code
    reason = current_decision.reason
    execution_state = finalization.execution_state
    execution_phase = finalization.execution_phase
    test_command_started = finalization.test_command_started
    effective_candidate_isolation = finalization.effective_candidate_isolation
    coverage_evidence = cast(dict[str, Any] | None, finalization.diff_coverage)
    baseline_info = cast(dict[str, Any] | None, finalization.baseline)
    attestation = cast(dict[str, Any], finalization.attestation)
    assurance = cast(dict[str, Any], finalization.assurance)

    return GuardResult(
        verdict=v,
        passed=(v == PASS),
        reason=reason,
        files_changed=changed,
        protected_violations=violations,
        risk_level=risk.level,
        risk_score=risk.score,
        tests_passed=(
            verification_evidence.tests_passed
            if verification_evidence is not None
            else None
        ),
        tests_total=(
            verification_evidence.tests_total
            if verification_evidence is not None
            else None
        ),
        test_command_ran=test_command_started,
        execution_state=execution_state,
        execution_phase=execution_phase,
        verdict_source=(
            verification_evidence.verdict_source
            if verification_evidence is not None
            else None
        ),
        diagnostics=diagnostics,
        reason_code=code,
        isolation=effective_candidate_isolation,
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
    setup_output_globs: tuple[str, ...],
    timeout: int,
    mem_limit_mb: int,
    strict_harness: bool,
    harness_inputs: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Compatibility facade for the pristine repository baseline owner."""
    import tempfile as _tempfile

    from evoom_guard.adapters import instrument_command
    from evoom_guard.verifiers.fidelity import (
        setup_fidelity_changes as _setup_fidelity_changes,
    )
    from evoom_guard.verifiers.fidelity import (
        setup_fidelity_snapshot as _setup_fidelity_snapshot,
    )
    from evoom_guard.verifiers.repo_verifier import (
        RepoVerifier,
        SetupFidelityError,
        detect_tamper,
        grade_repo_run,
        parse_junit_dir,
        parse_junit_xml,
        read_junit_xml,
    )

    return run_repo_baseline(
        RepoBaselineRequest(
            repository_path=repo_path,
            test_command=test_command,
            setup_command=setup_command,
            setup_output_globs=setup_output_globs,
            timeout=timeout,
            mem_limit_mb=mem_limit_mb,
            strict_harness=strict_harness,
            harness_inputs=harness_inputs,
        ),
        services=RepoBaselineServices(
            verifier_factory=RepoVerifier,
            workspace_factory_provider=lambda: _tempfile.mkdtemp,
            path_join_provider=lambda: cast(Any, os.path.join),
            platform_name_provider=lambda: os.name,
            os_error_provider=lambda: OSError,
            setup_fidelity_error_provider=lambda: SetupFidelityError,
            containment_error_provider=(
                lambda: _SubprocessContainmentError
            ),
            output_limit_error_provider=(
                lambda: _SubprocessOutputLimitExceeded
            ),
            timeout_error_provider=lambda: subprocess.TimeoutExpired,
            copy_repository_provider=lambda: cast(Any, copy_repo_tree),
            judge_environment_provider=lambda: judge_subprocess_env,
            setup_fidelity_snapshot=cast(
                Any,
                _setup_fidelity_snapshot,
            ),
            setup_fidelity_changes=_setup_fidelity_changes,
            instrument_command=cast(Any, instrument_command),
            resolve_host_command_provider=lambda: cast(
                Any,
                _resolve_host_command,
            ),
            run_bounded_subprocess_provider=lambda: _run_bounded_subprocess,
            read_junit_xml=read_junit_xml,
            parse_junit_xml=cast(Any, parse_junit_xml),
            parse_junit_dir=cast(Any, parse_junit_dir),
            grade_repo_run=grade_repo_run,
            detect_tamper=detect_tamper,
            cleanup_workspace_provider=lambda: shutil.rmtree,
        ),
    )


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Assurance levels — see docs/ASSURANCE.md. The honest, load-bearing distinction
# is between TWO integrity properties that people conflate:
#
#   * harness_integrity — was candidate protected-path admission enforced?
#     "pre_gate_enforced": yes. This is a STATIC classification of the candidate
#     paths before execution. Runtime code cannot retroactively change that fact,
#     but the field alone does not claim complete dependency discovery or
#     continuous runtime byte immutability. Explicit ``harness_inputs`` are also
#     compared with their accepted identities at documented checkpoints.
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
# Guard blocks edits/deletions to the modelled protected path set and stdout-only
# forgery, but does NOT infer every transitive judge dependency or stop a patch
# that writes deliberate process-level forgery code into source. Read the
# effective policy and report_integrity before trusting a PASS.
def build_effective_policy_payload(
    *, mode: str, isolation: str, docker_image: str | None, docker_network: str,
    test_command: list[str] | None, setup_command: list[str] | None,
    trust_setup_on_host: bool,
    setup_output_globs: tuple[str, ...],
    protected: tuple[str, ...], allow: tuple[str, ...], allow_new_tests: bool,
    timeout: int, mem_limit_mb: int, verifier_pack: str | None,
    expect_verifier_pack_sha256: str | None,
    blackbox: bool, blackbox_only: bool,
    require_report_integrity: str | None, require_candidate_isolation: str | None,
    min_diff_coverage: float | None, baseline_evidence: bool,
    require_demonstrated_fix: bool, strict_harness: bool,
    policy_id: str | None, policy_version: str | None,
    operating_profile: str | None = None,
    harness_inputs: tuple[str, ...] = (),
) -> dict[str, Any]:
    """The COMPLETE canonical policy that shaped this judgment (1.7).

    ``policy_sha256`` is computed over this object. Before 1.7 the hash covered
    only five fields (protected/allow/allow_new_tests/isolation/mode), so two
    materially different policies — e.g. one demanding
    ``external_process_isolated`` + 90% diff coverage and one demanding
    neither — could produce the SAME fingerprint, and
    ``verify-verdict --expect-policy-sha`` proved less than it appeared to.
    Every knob that changes what a verdict means belongs here.
    """
    policy = _build_effective_policy_contract(
        mode=mode,
        isolation=isolation,
        docker_image=docker_image,
        docker_network=docker_network,
        test_command=test_command,
        setup_command=setup_command,
        trust_setup_on_host=trust_setup_on_host,
        setup_output_globs=setup_output_globs,
        protected=protected,
        allow=allow,
        allow_new_tests=allow_new_tests,
        timeout=timeout,
        mem_limit_mb=mem_limit_mb,
        verifier_pack=verifier_pack,
        expect_verifier_pack_sha256=expect_verifier_pack_sha256,
        blackbox=blackbox,
        blackbox_only=blackbox_only,
        require_report_integrity=require_report_integrity,
        require_candidate_isolation=require_candidate_isolation,
        min_diff_coverage=min_diff_coverage,
        baseline_evidence=baseline_evidence,
        require_demonstrated_fix=require_demonstrated_fix,
        strict_harness=strict_harness,
        policy_id=policy_id,
        policy_version=policy_version,
        operating_profile=operating_profile,
        harness_inputs=harness_inputs,
    )
    return _effective_policy_payload(policy)


# Historical compatibility seam.  New cross-package callers must use the
# public name above; keeping the alias avoids breaking integrations that
# imported or monkeypatched the pre-extraction helper.
_effective_policy = build_effective_policy_payload


def effective_policy_sha256(policy: Mapping[str, Any]) -> str:
    """Return the frozen JSON fingerprint used by Guard attestations."""

    return _effective_policy_digest(policy)


def _build_attestation(
    candidate: str, *, safe_deleted: list[str], test_command: list[str] | None,
    effective_policy: dict[str, Any], art: dict[str, Any], mode: str,
) -> dict[str, Any]:
    """Context binding for the (optionally signed) verdict. Shared by the default
    and black-box paths so a black-box verdict is bound to what was judged too.
    ``policy_sha256`` covers the COMPLETE effective policy (see
    :func:`build_effective_policy_payload`), and the policy itself ships in the
    so a consumer can audit exactly what the fingerprint commits to."""
    return _build_attestation_payload(
        candidate,
        safe_deleted=safe_deleted,
        test_command=test_command,
        effective_policy=effective_policy,
        artifacts=art,
        mode=mode,
        now=lambda: _utc_now(),
        guard_version=lambda: __version__,
        candidate_digest=lambda value: hashlib.sha256(
            value.encode("utf-8")
        ).hexdigest(),
        policy_digest=lambda policy: effective_policy_sha256(policy),
        pack_digest_format=lambda: PACK_DIGEST_FORMAT,
    )


@dataclass(frozen=True)
class _TreeEntry:
    """A non-ignored filesystem entry used by ``blocks_from_dirs``.

    Metadata is retained even for entries that cannot become text edit blocks.
    Otherwise a changed oversized or binary harness file could disappear before
    the static gate saw it.
    """

    full_path: str
    kind: str
    mode: int | None
    size: int | None
    link_target: str | None = None
    problem: str | None = None
    identity: tuple[int, ...] | None = None
    path_times: tuple[int, int] | None = None


class _UnverifiableChangedPathsError(ValueError):
    """A base/head change cannot be represented safely as Guard file blocks."""

    def __init__(self, problems: list[tuple[str, str]]) -> None:
        self.problems = tuple(problems)
        listed = "; ".join(f"{path}: {reason}" for path, reason in problems)
        super().__init__(
            "changed path(s) cannot be safely represented for verification "
            f"({listed})"
        )


def blocks_from_dirs(
    base_dir: str, head_dir: str, *, max_bytes: int = 1_000_000
) -> tuple[dict[str, str], list[str]]:
    """Diff a base and head checkout into a STRUCTURED candidate.

    Returns ``({relpath: new_content}, deleted)`` for every changed regular text
    file (skipping ``.git`` and the standard ignored dirs); ``deleted`` lists all
    paths present in base but absent in head, including directories and
    large/binary deletions. A changed path that cannot be represented faithfully
    (oversized, binary, unreadable, symlink/special, mode-only, or a new empty
    directory) raises fail-closed instead of disappearing from the candidate.
    This mapping is the authoritative
    candidate for the dirs/diff path — it never round-trips through the
    ``<<<FILE>>>`` text format, so content containing literal block markers
    survives intact.
    """
    return _candidate_tree.blocks_from_dirs(
        base_dir,
        head_dir,
        max_bytes=max_bytes,
        tree_entry_lookup=lambda path: _tree_entry(path),
        walk_tree_entries=lambda root: _walk_tree_entries(root),
        directory_has_regular_descendant=(
            lambda entries, directory: _directory_has_regular_descendant(
                cast(dict[str, _TreeEntry], entries), directory
            )
        ),
        entries_changed=lambda base, head: _entries_changed(
            cast(_TreeEntry | None, base), cast(_TreeEntry, head)
        ),
        entry_problem=lambda entry: _entry_problem(cast(_TreeEntry, entry)),
        read_changed_text=lambda entry, limit: _read_changed_text(
            cast(_TreeEntry, entry), limit
        ),
        unverifiable_error=lambda problems: _UnverifiableChangedPathsError(
            problems
        ),
    )


def serialize_candidate_blocks(blocks: Mapping[str, str]) -> str:
    """Return the canonical textual identity for structured candidate blocks.

    The engine uses ``blocks`` directly when it applies a base/head candidate;
    this serialization exists only for the stable candidate digest and human
    display.  Sorting here, rather than relying on a caller's insertion order,
    keeps that identity stable for filesystem and raw-Git derivations alike.
    Deletions are deliberately not serialized: the immutable base/head tree
    bindings carry their identity separately.
    """

    return _candidate_tree.serialize_candidate_blocks(blocks)


def candidate_from_dirs(base_dir: str, head_dir: str, *, max_bytes: int = 1_000_000) -> tuple[str, list[str]]:
    """Diff a base and head checkout into an EvoOM ``<<<FILE>>>`` candidate.

    Returns ``(candidate, deleted)`` — the text serialization of
    :func:`blocks_from_dirs` (kept for hashing, display and API compatibility).
    NOTE: callers that verify the result should pass the structured mapping from
    :func:`blocks_from_dirs` to :func:`guard` via ``file_blocks`` rather than
    re-parsing this text — content containing a literal ``<<<END FILE>>>`` line
    would terminate its own block in the parse.
    """
    def derive_blocks(
        base_dir: str,
        head_dir: str,
        *,
        max_bytes: int = 1_000_000,
    ) -> tuple[dict[str, str], list[str]]:
        return blocks_from_dirs(base_dir, head_dir, max_bytes=max_bytes)

    return _candidate_tree.candidate_from_dirs(
        base_dir,
        head_dir,
        max_bytes=max_bytes,
        derive_blocks=derive_blocks,
        serialize_blocks=lambda blocks: serialize_candidate_blocks(blocks),
    )


def _walk_tree_entries(root: str) -> dict[str, _TreeEntry]:
    """Return every non-ignored path without dropping non-text entries."""
    return cast(
        dict[str, _TreeEntry],
        _candidate_tree.walk_tree_entries(
            root,
            copy_ignore=COPY_IGNORE,
            tree_entry_lookup=lambda path: _tree_entry(path),
            entry_factory=lambda *args, **kwargs: cast(
                Any,
                _TreeEntry(*args, **kwargs),
            ),
        ),
    )


def _tree_entry(full_path: str) -> _TreeEntry:
    """Describe a path without following a symlink or reading its payload."""
    return cast(
        _TreeEntry,
        _candidate_tree.tree_entry(
            full_path,
            entry_factory=lambda *args, **kwargs: cast(
                Any,
                _TreeEntry(*args, **kwargs),
            ),
            is_windows_reparse=lambda path, info: _is_windows_reparse(path, info),
            stat_identity=lambda info: _stat_identity(info),
            stat_path_times=lambda info: _stat_path_times(info),
        ),
    )


def _is_windows_reparse(
    full_path: str,
    info: os.stat_result,
    *,
    platform_name: str | None = None,
    junction_probe: Callable[[str], bool] | None = None,
) -> bool:
    """Whether ``info`` names a Windows reparse object.

    ``st_file_attributes`` exposes the reparse flag throughout Python
    3.10-3.12. ``os.path.isjunction`` is supplemental when available.
    """
    return _candidate_tree.is_windows_reparse(
        full_path,
        info,
        platform_name=platform_name,
        junction_probe=junction_probe,
    )


def _stat_identity(info: os.stat_result) -> tuple[int, ...]:
    """Return object/type/mode/size identity stable across path/handle APIs."""
    return _candidate_tree.stat_identity(info)


def _stat_path_times(info: os.stat_result) -> tuple[int, int]:
    """Return mutation-sensitive times compared only across path observations.

    Windows can expose different timestamp precision through ``lstat`` and
    ``fstat``. Keeping times out of descriptor identity prevents false drift
    while path-before/path-after checks still detect same-object writes.
    """
    return _candidate_tree.stat_path_times(info)


def _verify_regular_snapshot(
    entry: _TreeEntry,
    observed: os.stat_result,
    *,
    problem: str,
    path_observation: bool,
) -> None:
    """Reject a path/descriptor that no longer matches its captured ``lstat``."""
    _candidate_tree.verify_regular_snapshot(
        entry,
        observed,
        problem=problem,
        path_observation=path_observation,
        stat_identity_provider=lambda info: _stat_identity(info),
        stat_path_times_provider=lambda info: _stat_path_times(info),
    )


def _open_regular_snapshot(entry: _TreeEntry) -> int:
    """Open one classified regular file without accepting a name swap."""
    return _candidate_tree.open_regular_snapshot(
        entry,
        is_windows_reparse=lambda path, info: _is_windows_reparse(path, info),
        verify_regular_snapshot_provider=(
            lambda candidate, observed, problem, path_observation:
            _verify_regular_snapshot(
                cast(_TreeEntry, candidate),
                observed,
                problem=problem,
                path_observation=path_observation,
            )
        ),
        open_flags=lambda: _regular_snapshot_open_flags(),
    )


def _regular_snapshot_open_flags(
    *,
    platform_name: str | None = None,
    flag_provider: Callable[[str], int | None] | None = None,
) -> int:
    """Build a non-following, non-blocking POSIX open contract.

    ``O_NONBLOCK`` prevents a regular-to-FIFO swap from hanging between the
    path observation and descriptor verification. Missing POSIX primitives are
    an unverifiable runtime, never a silent downgrade.
    """
    return _candidate_tree.regular_snapshot_open_flags(
        platform_name=platform_name,
        flag_provider=flag_provider,
    )


def _verify_open_regular_snapshot(
    entry: _TreeEntry,
    descriptor: int,
    *,
    operation: str,
) -> None:
    """Bind a completed read/compare to both its descriptor and path name."""
    _candidate_tree.verify_open_regular_snapshot(
        entry,
        descriptor,
        operation=operation,
        is_windows_reparse=lambda path, info: _is_windows_reparse(path, info),
        verify_regular_snapshot_provider=(
            lambda candidate, observed, problem, path_observation:
            _verify_regular_snapshot(
                cast(_TreeEntry, candidate),
                observed,
                problem=problem,
                path_observation=path_observation,
            )
        ),
    )


def _entries_changed(
    base: _TreeEntry | None, head: _TreeEntry
) -> tuple[bool, str | None]:
    """Return whether a path changed and whether that fact is unverifiable."""
    return _candidate_tree.entries_changed(
        base,
        head,
        regular_files_equal=(
            lambda base_path, head_path, base_snapshot, head_snapshot:
            _regular_files_equal(
                base_path,
                head_path,
                base_snapshot=cast(_TreeEntry | None, base_snapshot),
                head_snapshot=cast(_TreeEntry | None, head_snapshot),
            )
        ),
        entry_problem=lambda entry: _entry_problem(cast(_TreeEntry, entry)),
    )


def _regular_files_equal(
    base_path: str,
    head_path: str,
    *,
    base_snapshot: _TreeEntry | None = None,
    head_snapshot: _TreeEntry | None = None,
) -> bool:
    """Compare two stable regular-file snapshots with bounded memory."""
    return _candidate_tree.regular_files_equal(
        base_path,
        head_path,
        base_snapshot=base_snapshot,
        head_snapshot=head_snapshot,
        tree_entry_lookup=lambda path: _tree_entry(path),
        open_regular_snapshot_provider=(
            lambda candidate: _open_regular_snapshot(
                cast(_TreeEntry, candidate)
            )
        ),
        verify_open_regular_snapshot_provider=(
            lambda candidate, descriptor, operation:
            _verify_open_regular_snapshot(
                cast(_TreeEntry, candidate),
                descriptor,
                operation=operation,
            )
        ),
    )


def _entry_problem(entry: _TreeEntry) -> str:
    return _candidate_tree.entry_problem(entry)


def _directory_has_regular_descendant(
    entries: dict[str, _TreeEntry], directory: str
) -> bool:
    """Whether FILE blocks implicitly recreate a newly added directory."""
    return _candidate_tree.directory_has_regular_descendant(
        cast(dict[str, _candidate_tree.TreeEntry], entries),
        directory,
    )


def _read_changed_text(entry: _TreeEntry, max_bytes: int) -> str:
    """Read one changed regular text file, failing before it can be dropped."""
    return _candidate_tree.read_changed_text(
        entry,
        max_bytes,
        open_regular_snapshot_provider=(
            lambda candidate: _open_regular_snapshot(
                cast(_TreeEntry, candidate)
            )
        ),
        read_fd_bounded_provider=(
            lambda descriptor, maximum: _read_fd_bounded(descriptor, maximum)
        ),
        verify_open_regular_snapshot_provider=(
            lambda candidate, descriptor, operation:
            _verify_open_regular_snapshot(
                cast(_TreeEntry, candidate),
                descriptor,
                operation=operation,
            )
        ),
    )


def _read_fd_bounded(descriptor: int, maximum: int) -> bytes:
    """Read at most ``maximum`` bytes from a regular-file descriptor."""
    return _candidate_tree.read_fd_bounded(descriptor, maximum)


def _reverse_apply(work_dir: str, diff_file: str) -> bool:
    """Reverse-apply a unified diff in ``work_dir`` (undo it). True on success.

    Tries ``git apply -R`` first (works on a plain directory, no repo needed), then
    falls back to ``patch -R -p1``. Used to reconstruct the BASE tree from the HEAD
    working tree given a base→head diff.
    """
    # ``work_dir`` can itself live below another Git worktree (for example when
    # TMPDIR points into a CI checkout).  Without a ceiling, ``git apply`` walks
    # upward, discovers that unrelated repository, and may return success while
    # silently ignoring paths outside its current subdirectory.  Stop discovery
    # at the throwaway directory's parent so apply always treats ``work_dir`` as
    # the standalone tree it is meant to reconstruct.
    git_env = os.environ.copy()
    git_env["GIT_CEILING_DIRECTORIES"] = os.path.dirname(
        os.path.abspath(work_dir)
    )
    for cmd in (
        ["git", "apply", "-R", "--whitespace=nowarn", diff_file],
        ["patch", "-R", "-p1", "--no-backup-if-mismatch", "-i", diff_file],
    ):
        if shutil.which(cmd[0]) is None:
            continue
        try:
            # A malformed diff can make ``git apply``/``patch`` print an
            # arbitrarily large diagnostic. This is still untrusted input, so
            # use the same bounded capture and process-tree cleanup primitive
            # as the actual judge rather than ``capture_output=True``.
            r = _run_bounded_subprocess(
                cmd,
                cwd=work_dir,
                timeout=60,
                env=git_env if cmd[0] == "git" else None,
            )
        except (
            OSError,
            subprocess.TimeoutExpired,
            _SubprocessOutputLimitExceeded,
            _SubprocessContainmentError,
        ):
            continue
        if r.returncode == 0:
            return True
    return False


def input_error_result(
    reason: str,
    *,
    reason_code: str,
    source: str,
    base_reconstruction: str | None = None,
    verifier_pack: str | None = None,
    effective_policy: dict[str, Any] | None = None,
    test_command: list[str] | None = None,
    base_sha: str | None = None,
    head_sha: str | None = None,
    base_tree_sha: str | None = None,
    head_tree_sha: str | None = None,
    policy_id: str | None = None,
    policy_version: str | None = None,
) -> GuardResult:
    """Create a fail-closed result before a candidate tree is assembled."""
    result = GuardResult(
        verdict=ERROR, passed=False, reason=reason,
        files_changed=[], protected_violations=[],
        risk_level="low", risk_score=0.0, diagnostics="",
        source=source, base_reconstruction=base_reconstruction,
        reason_code=reason_code, isolation="not_run",
        execution_state=EXECUTION_NOT_STARTED,
        execution_phase="preflight",
        assurance=_preflight_assurance_profile(verifier_pack),
    )
    if effective_policy is not None:
        _bind_unmaterialized_input_policy(
            result,
            effective_policy=effective_policy,
            test_command=test_command,
            verifier_pack=verifier_pack,
            base_sha=base_sha,
            head_sha=head_sha,
            base_tree_sha=base_tree_sha,
            head_tree_sha=head_tree_sha,
            policy_id=policy_id,
            policy_version=policy_version,
        )
    return result


def _bind_unmaterialized_input_policy(
    result: GuardResult,
    *,
    effective_policy: dict[str, Any],
    test_command: list[str] | None,
    verifier_pack: str | None,
    base_sha: str | None,
    head_sha: str | None,
    base_tree_sha: str | None,
    head_tree_sha: str | None,
    policy_id: str | None,
    policy_version: str | None,
) -> None:
    """Bind a complete policy to an error raised before candidate assembly.

    ``candidate_sha256`` intentionally commits to the canonical empty candidate:
    these input paths never produced edit blocks or a candidate tree.  In
    particular, a raw unified diff is not mislabeled as the materialized
    candidate.  Source commit/tree identities remain available in their
    dedicated attestation fields when the caller supplied them.
    """
    result.assurance = _preflight_assurance_profile(verifier_pack)
    result.attestation = _build_attestation(
        "",
        safe_deleted=[],
        test_command=test_command,
        effective_policy=effective_policy,
        art={
            "base_sha": base_sha,
            "head_sha": head_sha,
            "base_tree_sha": base_tree_sha,
            "head_tree_sha": head_tree_sha,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "execution_state": EXECUTION_NOT_STARTED,
            "execution_phase": "preflight",
            "test_command_started": False,
            "delivered_isolation": "not_run",
            "effective_candidate_isolation": None,
        },
        mode=cast(str, effective_policy["mode"]),
    )


def _diff_error(
    reason: str, *, reason_code: str, base_reconstruction: str = "failed"
) -> GuardResult:
    return input_error_result(
        reason,
        reason_code=reason_code,
        source="diff",
        base_reconstruction=base_reconstruction,
    )


def verifier_pack_trust_error(
    candidate_dir: str,
    verifier_pack: str | None,
    expect_verifier_pack_sha256: str | None,
) -> str | None:
    """Return a fail-closed reason when a pack is candidate-controlled.

    ``--diff`` and ``--base/--head`` receive an on-disk candidate checkout. A
    pack below that checkout can be edited by the same change under judgment,
    so snapshotting it would only preserve attacker-selected bytes. Require an
    identity pin and an external (or base-materialized) path before the runner
    ever touches candidate code.  ``realpath`` also closes an external-looking
    symlink that resolves back into the candidate tree.
    """
    if not verifier_pack:
        return None
    if not expect_verifier_pack_sha256:
        return (
            "an untrusted-change diff requires an EVOGUARD_PACK_V2 SHA-256 pin "
            "for --verifier-pack; materialize the pack from a trusted base or "
            "immutable artifact outside the candidate checkout"
        )
    try:
        candidate_real = os.path.normcase(os.path.realpath(candidate_dir))
        pack_real = os.path.normcase(os.path.realpath(verifier_pack))
        inside_candidate = os.path.commonpath((candidate_real, pack_real)) == candidate_real
    except ValueError:
        # Different Windows volumes cannot have a containment relationship.
        inside_candidate = False
    if inside_candidate:
        return (
            "verifier-pack resolves inside the candidate checkout; use a pack "
            "materialized from the trusted base or an immutable external artifact"
        )
    return None


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


def _write_diff_file(diff_file: str, diff_text: str) -> None:
    """Write the normalized unified diff through Guard's effectful facade."""
    # Unified diffs are protocol text. Force LF even on Windows: the default
    # text-mode CRLF translation leaves ``\r`` on context lines and can make
    # ``git apply -R`` reject an otherwise valid base...HEAD diff.
    with open(diff_file, "w", encoding="utf-8", newline="\n") as f:
        f.write(diff_text if diff_text.endswith("\n") else diff_text + "\n")


def _allocate_diff_workspace(*, prefix: str) -> str:
    """Allocate one identity-bound workspace for base reconstruction."""

    return _repository_workspace.allocate_owned_workspace(
        prefix=prefix,
        create_workspace=tempfile.mkdtemp,
    )


def _cleanup_diff_workspace(
    path: str,
    *,
    primary: BaseException | None,
) -> None:
    """Remove the owned reconstruction root without masking ``primary``."""

    _repository_workspace.cleanup_repo_workspaces(
        (("reconstruction workspace", path),),
        primary=primary,
        # Keep lookup within the cleanup owner so it is secondary to an
        # exception already unwinding from diff reconstruction.
        remove_tree=lambda target: shutil.rmtree(target),
        owner_name="DiffVerification",
    )


def guard_from_diff(
    head_dir: str,
    diff_text: str,
    *,
    test_command: list[str] | None = None,
    setup_command: list[str] | None = None,
    trust_setup_on_host: bool = False,
    setup_output_globs: tuple[str, ...] = (),
    protected: tuple[str, ...] = (),
    allow: tuple[str, ...] = (),
    allow_new_tests: bool = False,
    timeout: int = 120,
    mem_limit_mb: int = 1024,
    isolation: str = "subprocess",
    docker_image: str | None = None,
    docker_network: str = "none",
    verifier_pack: str | None = None,
    expect_verifier_pack_sha256: str | None = None,
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
    strict_harness: bool = False,
    operating_profile: str | None = None,
    harness_inputs: tuple[str, ...] = (),
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
    profiled_effective_policy: dict[str, Any] | None = None
    if operating_profile is not None or harness_inputs:
        # A profiled early result is a schema-1.12 artifact, so it must pass the
        # same scalar validation and canonical policy construction as guard().
        # Keep the historical no-profile early-return order untouched.
        prepared_profile = prepare_guard_request(
            GuardRequestPreparationInput(
                repository_path=head_dir,
                candidate_text="",
                deleted_paths=(),
                test_command=test_command,
                setup_command=setup_command,
                trust_setup_on_host=trust_setup_on_host,
                setup_output_globs=setup_output_globs,
                protected=protected,
                allow=allow,
                allow_new_tests=allow_new_tests,
                timeout=timeout,
                mem_limit_mb=mem_limit_mb,
                isolation=isolation,
                docker_image=docker_image,
                docker_network=docker_network,
                verifier_pack_path=verifier_pack,
                expect_verifier_pack_sha256=expect_verifier_pack_sha256,
                collect_diff_coverage=diff_coverage,
                min_diff_coverage=min_diff_coverage,
                blackbox=blackbox,
                blackbox_only=blackbox_only,
                require_report_integrity=require_report_integrity,
                require_candidate_isolation=require_candidate_isolation,
                base_sha=base_sha,
                head_sha=head_sha,
                base_tree_sha=base_tree_sha,
                head_tree_sha=head_tree_sha,
                policy_id=policy_id,
                policy_version=policy_version,
                baseline_evidence=baseline_evidence,
                require_demonstrated_fix=require_demonstrated_fix,
                strict_harness=strict_harness,
                file_blocks=None,
                operating_profile=operating_profile,
                harness_inputs=harness_inputs,
            ),
            services=GuardRequestPreparationServices(
                repository_input_provider=lambda: RepositoryInput,
                candidate_input_provider=lambda: CandidateInput,
                source_identity_provider=lambda: SourceIdentity,
                effective_policy_provider=lambda: _build_effective_policy_contract,
                guard_request_provider=lambda: GuardRequest,
                effective_policy_payload_provider=lambda: _effective_policy_payload,
            ),
        )
        profiled_effective_policy = cast(
            dict[str, Any],
            prepared_profile.effective_policy,
        )
        compatibility = prepared_profile.compatibility
        test_command = compatibility.test_command
        setup_command = compatibility.setup_command
        trust_setup_on_host = compatibility.trust_setup_on_host
        setup_output_globs = compatibility.setup_output_globs
        protected = compatibility.protected
        allow = compatibility.allow
        allow_new_tests = compatibility.allow_new_tests
        timeout = compatibility.timeout
        mem_limit_mb = compatibility.mem_limit_mb
        isolation = compatibility.isolation
        docker_image = compatibility.docker_image
        docker_network = compatibility.docker_network
        verifier_pack = compatibility.verifier_pack_path
        expect_verifier_pack_sha256 = (
            compatibility.expect_verifier_pack_sha256
        )
        diff_coverage = compatibility.collect_diff_coverage
        min_diff_coverage = compatibility.min_diff_coverage
        blackbox = compatibility.blackbox
        blackbox_only = compatibility.blackbox_only
        require_report_integrity = compatibility.require_report_integrity
        require_candidate_isolation = compatibility.require_candidate_isolation
        base_sha = compatibility.base_sha
        head_sha = compatibility.head_sha
        base_tree_sha = compatibility.base_tree_sha
        head_tree_sha = compatibility.head_tree_sha
        policy_id = compatibility.policy_id
        policy_version = compatibility.policy_version
        baseline_evidence = compatibility.baseline_evidence
        require_demonstrated_fix = compatibility.require_demonstrated_fix
        strict_harness = compatibility.strict_harness
        operating_profile = compatibility.operating_profile
        harness_inputs = getattr(compatibility, "harness_inputs", ())

    outcome = verify_diff(
        DiffVerificationRequest(
            head_dir=head_dir,
            diff_text=diff_text,
            options=DiffVerificationOptions(
                test_command=test_command,
                setup_command=setup_command,
                trust_setup_on_host=trust_setup_on_host,
                setup_output_globs=setup_output_globs,
                protected=protected,
                allow=allow,
                allow_new_tests=allow_new_tests,
                timeout=timeout,
                mem_limit_mb=mem_limit_mb,
                isolation=isolation,
                docker_image=docker_image,
                docker_network=docker_network,
                verifier_pack=verifier_pack,
                expect_verifier_pack_sha256=expect_verifier_pack_sha256,
                diff_coverage=diff_coverage,
                min_diff_coverage=min_diff_coverage,
                blackbox=blackbox,
                blackbox_only=blackbox_only,
                require_report_integrity=require_report_integrity,
                require_candidate_isolation=require_candidate_isolation,
                base_sha=base_sha,
                head_sha=head_sha,
                base_tree_sha=base_tree_sha,
                head_tree_sha=head_tree_sha,
                policy_id=policy_id,
                policy_version=policy_version,
                baseline_evidence=baseline_evidence,
                require_demonstrated_fix=require_demonstrated_fix,
                strict_harness=strict_harness,
                operating_profile=operating_profile,
                harness_inputs=harness_inputs,
            ),
        ),
        DiffVerificationServices(
            diff_error_provider=lambda: _diff_error,
            input_error_provider=lambda: input_error_result,
            empty_diff_reason_code_provider=lambda: REASON_EMPTY_DIFF,
            binary_patch_reason_code_provider=lambda: REASON_BINARY_PATCH,
            unsafe_path_reason_code_provider=lambda: REASON_UNSAFE_PATH,
            verifier_pack_invalid_reason_code_provider=(
                lambda: REASON_VERIFIER_PACK_INVALID
            ),
            reverse_apply_failed_reason_code_provider=(
                lambda: REASON_REVERSE_APPLY_FAILED
            ),
            no_verifiable_changes_reason_code_provider=(
                lambda: REASON_NO_VERIFIABLE_CHANGES
            ),
            binary_diff_provider=lambda: _is_binary_diff,
            diff_target_paths_provider=lambda: _diff_target_paths,
            safe_relpath_provider=lambda: is_safe_relpath,
            verifier_pack_trust_check_provider=(
                lambda: verifier_pack_trust_error
            ),
            workspace_factory_provider=lambda: _allocate_diff_workspace,
            path_join_provider=lambda: os.path.join,
            copy_repo_tree_provider=lambda: copy_repo_tree,
            diff_writer_provider=lambda: _write_diff_file,
            reverse_apply_provider=lambda: _reverse_apply,
            blocks_from_dirs_provider=lambda: blocks_from_dirs,
            unverifiable_errors_provider=(
                lambda: (_UnverifiableChangedPathsError,)
            ),
            guard_provider=lambda: guard,
            diff_base_sha_provider=lambda: _diff_base_sha,
            diff_head_sha_provider=lambda: _diff_head_sha,
            cleanup_workspace_provider=lambda: _cleanup_diff_workspace,
        ),
    )
    if (
        profiled_effective_policy is not None
        and outcome.result.attestation is None
    ):
        _bind_unmaterialized_input_policy(
            outcome.result,
            effective_policy=profiled_effective_policy,
            test_command=test_command,
            verifier_pack=verifier_pack,
            base_sha=base_sha,
            head_sha=head_sha,
            base_tree_sha=base_tree_sha,
            head_tree_sha=head_tree_sha,
            policy_id=policy_id,
            policy_version=policy_version,
        )
    return outcome.result, outcome.deleted


_BADGE = _guard_output.DEFAULT_BADGES


def render_report(
    result: GuardResult,
    *,
    deleted: list[str] | None = None,
    title: str = "EvoGuard",
) -> str:
    """Render a :class:`GuardResult` as a Markdown report (PR-comment ready)."""

    return _guard_output.render_report(
        result,
        deleted=deleted,
        title=title,
        badge_provider=lambda: _BADGE,
        pass_verdict_provider=lambda: PASS,
        fail_verdict_provider=lambda: FAIL,
        error_verdict_provider=lambda: ERROR,
        tampered_verdict_provider=lambda: TAMPERED,
        static_gate_provider=lambda: EXECUTION_STATIC_GATE,
        not_started_provider=lambda: EXECUTION_NOT_STARTED,
        started_incomplete_provider=lambda: EXECUTION_STARTED_INCOMPLETE,
    )


def write_json(
    result: GuardResult,
    path: str,
    *,
    deleted: list[str] | None = None,
) -> None:
    _guard_output.write_json(
        result,
        path,
        deleted=deleted,
        json_dump=json.dump,
    )


def to_sarif(result: GuardResult) -> dict[str, Any]:
    """Render the verdict as a minimal **SARIF 2.1.0** document for GitHub
    code-scanning (the *Security* tab).

    A clean ``PASS`` yields **no results** (no alert). Any non-``PASS`` verdict
    yields one ``error``-level result whose ``ruleId`` is the stable ``reason_code``
    and whose locations point at the protected-violation files (for ``REJECTED``) or
    the changed files. SARIF is only a *view*; the decision stays the verdict + exit
    code.
    """

    return _guard_output.to_sarif(
        result,
        pass_verdict_provider=lambda: PASS,
        version_provider=lambda: __version__,
    )


def write_sarif(result: GuardResult, path: str) -> None:
    _guard_output.write_sarif(
        result,
        path,
        converter=lambda current: to_sarif(current),  # type: ignore[arg-type]
        json_dump=json.dump,
    )
