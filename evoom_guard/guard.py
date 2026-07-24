# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
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
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

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
from evoom_guard.application.pipeline import VerificationPipeline
from evoom_guard.application.repo_decision import (
    OUTCOME_REASON_POLICY,
    TAMPER_OUTCOME_REASON_POLICY,
)
from evoom_guard.application.request_preparation import (
    GuardRequestPreparationInput,
    GuardRequestPreparationServices,
    prepare_guard_request,
)
from evoom_guard.candidate import parse_file_blocks, parse_patch_blocks
from evoom_guard.domain import (
    CandidateInput,
    GuardRequest,
    RepositoryInput,
    SourceIdentity,
)
from evoom_guard.domain.decision import GuardDecision
from evoom_guard.domain.verdict import (
    ERROR,
    EXECUTION_COMPLETED,
    EXECUTION_NOT_STARTED,
    EXECUTION_STARTED_INCOMPLETE,
    EXECUTION_STATIC_GATE,
    FAIL,
    PASS,
    REASON_ASSURANCE_REQUIREMENT_NOT_MET,
    REASON_BINARY_PATCH,
    REASON_CANDIDATE_NOT_EXERCISED,
    REASON_EMPTY_DIFF,
    REASON_JUNIT_EXIT_MISMATCH,
    REASON_NO_TEST_VERDICT,
    REASON_NO_VERIFIABLE_CHANGES,
    REASON_PATCH_APPLY_FAILED,
    REASON_POLICY_REQUIREMENT_UNSUPPORTED,
    REASON_REVERSE_APPLY_FAILED,
    REASON_RUNTIME_CLEANUP_FAILED,
    REASON_TEST_TIMEOUT,
    REASON_TESTS_FAILED,
    REASON_TESTS_PASSED,
    REASON_UNSAFE_PATH,
    REASON_VERIFIER_PACK_IDENTITY_MISMATCH,
    REASON_VERIFIER_PACK_INVALID,
    REASON_VERIFIER_PACK_NOT_FOUND,
    REASON_VERIFIER_PACK_REQUIRED,
    REASON_VERIFIER_PACK_SNAPSHOT_CHANGED,
    REJECTED,
    TAMPERED,
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
    REASON_NO_PARSEABLE_EDITS as REASON_NO_PARSEABLE_EDITS,
)
from evoom_guard.domain.verdict import (
    REASON_PROTECTED_HARNESS_EDIT as REASON_PROTECTED_HARNESS_EDIT,
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
from evoom_guard.pack_manifest import PACK_DIGEST_FORMAT
from evoom_guard.patchmin import risk_score
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
        bx = run_blackbox(
            repo_path, candidate, os.path.abspath(verifier_pack), timeout=timeout,
            isolation=isolation, docker_image=docker_image, docker_network=docker_network,
            mem_limit_mb=mem_limit_mb, deleted_paths=tuple(safe_deleted),
            file_blocks=file_blocks,
            expect_verifier_pack_sha256=expect_verifier_pack_sha256,
        )
        # ``ran`` means a gradeable verdict; it is deliberately not used as a
        # proxy for process start (timeouts and contradictory reports did run).
        bx_started = bool(getattr(bx, "started", bx.ran))
        bx_completed = bool(getattr(bx, "completed", bx.ran))
        bx_state = str(
            getattr(
                bx,
                "execution_state",
                EXECUTION_COMPLETED if bx.ran else EXECUTION_NOT_STARTED,
            )
        )
        bx_phase = str(getattr(bx, "execution_phase", "blackbox_pack"))
        # Preparing a launcher proves only availability. Candidate isolation is
        # claimed only after the black-box judge observes a launcher receipt
        # (and, for container modes, a runtime-written CID).
        delivered_iso = (
            (bx.isolation or {}).get("delivered", "subprocess")
            if bx_started
            else "not_run"
        )
        candidate_launcher_invocation_observed = bool(
            getattr(bx, "candidate_launcher_invocation_observed", False)
        )
        candidate_invocations = int(getattr(bx, "candidate_invocations", 0))
        candidate_iso_bx = (
            str(delivered_iso)
            if candidate_launcher_invocation_observed
            else "not_run"
        )
        bx_gradeable = bool(bx.ran and candidate_launcher_invocation_observed)
        isolation_evidence_bx = bx.isolation
        if (
            not bx_started
            and isolation_evidence_bx
            and isolation_evidence_bx.get("delivered") != "unavailable"
        ):
            prepared = isolation_evidence_bx.get(
                "prepared", isolation_evidence_bx.get("delivered")
            )
            isolation_evidence_bx = {
                **isolation_evidence_bx,
                "delivered": "not_run",
                "prepared": prepared,
                "note": (
                    "the launcher/boundary was prepared but the black-box judge "
                    "did not start, so candidate isolation was not exercised"
                ),
            }
        elif (
            bx_started
            and not candidate_launcher_invocation_observed
            and isolation_evidence_bx
            and isolation_evidence_bx.get("delivered") != "unavailable"
        ):
            prepared = isolation_evidence_bx.get(
                "prepared", isolation_evidence_bx.get("delivered")
            )
            isolation_evidence_bx = {
                **isolation_evidence_bx,
                "delivered": "not_run",
                "prepared": prepared,
                "note": (
                    "the judge ran, but no candidate launcher invocation was "
                    "observed; the prepared boundary is not delivery evidence"
                ),
            }
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
        if not blackbox_only and bx_gradeable and bx.passed:
            repo_problem = {
                k: v
                for k, v in problem.items()
                if k not in ("verifier_pack", "expect_verifier_pack_sha256")
            }
            repo_docker_image = (
                (bx.isolation or {}).get("image_digest")
                if isolation in ("docker", "gvisor")
                else docker_image
            )
            repo_verdict = RepoVerifier(
                timeout=timeout, mem_limit_mb=mem_limit_mb,
                isolation=isolation, docker_image=repo_docker_image,
                docker_network=docker_network,
                trust_setup_on_host=trust_setup_on_host,
                setup_output_globs=setup_output_globs,
                strict_harness=strict_harness,
            ).verify(candidate, repo_problem)

        repo_art = repo_verdict.artifact if repo_verdict is not None else {}
        repo_started = bool(repo_art.get("test_command_started"))
        repo_completed = bool(
            repo_started
            and repo_art.get("execution_state") == EXECUTION_COMPLETED
        )
        repo_clean_source = bool(repo_art.get("verdict_source"))
        repo_suite_state = (
            "not_required_blackbox_only"
            if blackbox_only
            else "required_not_run_short_circuit"
            if repo_verdict is None
            else "required_not_started"
            if not repo_started
            else "required_started_incomplete"
            if not repo_completed
            else "composed_completed"
        )
        if bx.ran and not candidate_launcher_invocation_observed:
            v_bx, code_bx = ERROR, REASON_CANDIDATE_NOT_EXERCISED
            reason_bx = (
                "the black-box pack completed without an observed "
                "$EVOGUARD_EXEC invocation, so it did not prove that it exercised "
                "the candidate; direct EVOGUARD_TARGET access and constant tests "
                "cannot produce a gradeable black-box verdict"
            )
        elif not bx.ran:
            if bx.error == "timeout":
                v_bx, code_bx = ERROR, REASON_TEST_TIMEOUT
            elif bx.error == "verifier pack identity mismatch":
                v_bx, code_bx = ERROR, REASON_VERIFIER_PACK_IDENTITY_MISMATCH
            elif bx.error == "verifier pack invalid":
                v_bx, code_bx = ERROR, REASON_VERIFIER_PACK_INVALID
            elif (bx.error or "").startswith("verifier pack not found:"):
                v_bx, code_bx = ERROR, REASON_VERIFIER_PACK_NOT_FOUND
            elif bx.error == "patch did not apply":
                v_bx, code_bx = ERROR, REASON_PATCH_APPLY_FAILED
            elif bx.error == "unsafe deletion path":
                v_bx, code_bx = ERROR, REASON_UNSAFE_PATH
            elif bx.error == "isolation unavailable":
                v_bx, code_bx = ERROR, REASON_ASSURANCE_REQUIREMENT_NOT_MET
            elif bx.error in (
                "verifier pack snapshot changed",
                "verifier pack changed while executing",
            ):
                v_bx, code_bx = TAMPERED, REASON_VERIFIER_PACK_SNAPSHOT_CHANGED
            elif bx.error == "black-box JUnit/exit mismatch":
                v_bx, code_bx = TAMPERED, REASON_JUNIT_EXIT_MISMATCH
            elif bx.error in (
                "candidate container cleanup failed",
                "judge process cleanup failed",
            ):
                v_bx, code_bx = ERROR, REASON_RUNTIME_CLEANUP_FAILED
            else:
                v_bx, code_bx = ERROR, REASON_NO_TEST_VERDICT
            reason_bx = bx.diagnostics or bx.error or "the black-box pack produced no verdict"
        elif not bx.passed:
            v_bx, code_bx, reason_bx = FAIL, REASON_TESTS_FAILED, (
                f"the black-box pack failed ({bx.tests_passed}/{bx.tests_total})"
            )
        elif repo_verdict is not None and not repo_verdict.passed:
            # Preserve the repo phase's actual failure class. A timeout,
            # unavailable boundary, or tamper signature is not a test failure
            # merely because the black-box pack completed first.
            repo_outcome = repo_art.get("outcome")
            if repo_outcome in _TAMPER_OUTCOME_REASON:
                code_bx, summary = _TAMPER_OUTCOME_REASON[
                    cast(str, repo_outcome)
                ]
                v_bx, repo_cause = TAMPERED, summary
            elif repo_art.get("tamper"):
                v_bx, code_bx = TAMPERED, REASON_JUNIT_EXIT_MISMATCH
                repo_cause = "the repo suite's exit code and JUnit report disagree"
            elif repo_outcome in _OUTCOME_REASON:
                v_bx, code_bx = _OUTCOME_REASON[cast(str, repo_outcome)]
                repo_cause = repo_verdict.diagnostics or str(repo_outcome)
            elif repo_art.get("tests_total") is not None:
                v_bx, code_bx = FAIL, REASON_TESTS_FAILED
                repo_cause = (
                    "the repo suite failed "
                    f"({repo_art.get('tests_passed', 0)}/"
                    f"{repo_art.get('tests_total')} passed)"
                )
            elif repo_verdict.score <= 0.08:
                v_bx, code_bx = ERROR, REASON_PATCH_APPLY_FAILED
                repo_cause = repo_verdict.diagnostics or "the patch did not apply"
            else:
                v_bx, code_bx = FAIL, REASON_NO_TEST_VERDICT
                repo_cause = repo_verdict.diagnostics or "no clean repo-suite verdict"
            reason_bx = (
                "the black-box pack passed, but the repo's own test suite "
                "(the required repo-native phase) "
                f"did not: {repo_cause} — a green pack must not mask a repo failure"
            )
        else:
            extra = "" if repo_verdict is None else " and the repo's own suite passed"
            v_bx, code_bx, reason_bx = PASS, REASON_TESTS_PASSED, (
                f"the black-box pack passed ({bx.tests_passed}/{bx.tests_total}){extra} — "
                "the candidate satisfied the judge-owned protocol tests, judged from "
                "outside its own process"
            )
        repo_state = repo_art.get("execution_state") if repo_art else None
        execution_state_bx = (
            EXECUTION_COMPLETED
            if repo_verdict is not None
            and repo_state == EXECUTION_COMPLETED
            and bx_state == EXECUTION_COMPLETED
            else EXECUTION_STARTED_INCOMPLETE
            if repo_verdict is not None
            else bx_state
        )
        execution_phase_bx = (
            str(repo_art.get("execution_phase", "repo_suite"))
            if repo_verdict is not None
            else bx_phase
        )
        test_started_bx = bx_started or bool(repo_art.get("test_command_started"))
        verdict_source_bx = (
            "composite:blackbox+repo"
            if repo_verdict is not None and repo_art.get("verdict_source") and bx_gradeable
            else None
            if repo_verdict is not None
            else "blackbox"
            if bx_gradeable
            else None
        )
        tests_passed_bx: int | None
        tests_total_bx: int | None
        if repo_verdict is not None:
            if execution_state_bx == EXECUTION_COMPLETED:
                repo_passed_count = repo_art.get("tests_passed")
                repo_total_count = repo_art.get("tests_total")
                if repo_passed_count is not None and repo_total_count is not None:
                    tests_passed_bx = bx.tests_passed + int(repo_passed_count)
                    tests_total_bx = bx.tests_total + int(repo_total_count)
                else:
                    tests_passed_bx = tests_total_bx = None
            else:
                # A required composite is one evidence unit. Never expose only
                # the already-finished black-box counts as if they described the
                # incomplete whole; phase-level counts remain in attestation.
                tests_passed_bx = tests_total_bx = None
        else:
            tests_passed_bx = bx.tests_passed if bx_completed else None
            tests_total_bx = bx.tests_total if bx_completed else None
        pack_outcome_bx = None
        if bx.error == "verifier pack invalid":
            pack_outcome_bx = "pack_invalid"
        elif bx.error == "verifier pack identity mismatch":
            pack_outcome_bx = "pack_identity_mismatch"
        elif bx.error in (
            "verifier pack snapshot changed",
            "verifier pack changed while executing",
        ):
            pack_outcome_bx = "pack_snapshot_changed"
        pack_evidence_bx = {
            "present": getattr(
                bx,
                "pack_present",
                True if bx.pack_sha256 else False if "not found" in (bx.error or "") else None,
            ),
            "snapshot_sha256": bx.pack_sha256,
            "started": bx_started,
            "completed": bx_completed,
            "outcome": pack_outcome_bx,
            "candidate_launcher_invocation_observed": (
                candidate_launcher_invocation_observed
            ),
        }
        assurance_bx = _assurance_profile(
            candidate_iso_bx, verifier_pack, blackbox=True,
            composed_repo_suite=repo_started,
            repo_suite_required=not blackbox_only,
            repo_suite_state=repo_suite_state,
            candidate_isolation=candidate_iso_bx,
            setup_isolation=repo_art.get("setup_isolation") if repo_art else None,
            runtime_continuity=repo_art.get("runtime_continuity") if repo_art else None,
            execution_state=execution_state_bx,
            execution_phase=execution_phase_bx,
            test_command_started=test_started_bx,
            pack_evidence=pack_evidence_bx,
        )
        decision_pipeline_bx = VerificationPipeline.from_decision(
            GuardDecision(
                verdict=v_bx,
                reason_code=code_bx,
                reason=reason_bx,
            )
        ).apply_assurance(
            assurance=assurance_bx,
            execution_state=execution_state_bx,
            execution_requested=True,
            require_report_integrity=require_report_integrity,
            require_candidate_isolation=require_candidate_isolation,
            shortfall_evaluator=_assurance_shortfall,
            eager_shortfall=True,
        )
        current_decision_bx = decision_pipeline_bx.decision
        v_bx = current_decision_bx.verdict
        code_bx = current_decision_bx.reason_code
        reason_bx = current_decision_bx.reason
        # Evidence-only requests the black-box judge cannot fulfil degrade
        # EXPLICITLY (an unmeasured record with a note), never silently (1.7).
        baseline_bx = None
        if baseline_evidence:
            baseline_bx = {
                "verdict": None, "tests_passed": None, "tests_total": None,
                "repair_effect": "unmeasured", "scope": "unsupported_mode",
                "note": "baseline differential evidence runs under the "
                        "subprocess repo judge only; the black-box judge did "
                        "not measure it",
            }
        coverage_bx = None
        if diff_coverage:
            coverage_bx = {
                "measured": False,
                "note": "changed-line coverage runs under the subprocess repo "
                        "judge only; the black-box judge did not measure it",
            }
        return GuardResult(
            verdict=v_bx, passed=(v_bx == PASS), reason=reason_bx,
            files_changed=changed, protected_violations=[],
            risk_level=risk_bx.level, risk_score=risk_bx.score,
            tests_passed=tests_passed_bx,
            tests_total=tests_total_bx,
            test_command_ran=test_started_bx,
            execution_state=execution_state_bx,
            execution_phase=execution_phase_bx,
            verdict_source=verdict_source_bx,
            diagnostics=bx.diagnostics, reason_code=code_bx,
            isolation=candidate_iso_bx,
            assurance=assurance_bx,
            baseline=baseline_bx,
            diff_coverage=coverage_bx,
            attestation=_build_attestation(
                candidate, safe_deleted=safe_deleted, test_command=test_command,
                effective_policy=effective_policy,
                art={
                    "verifier_pack_sha256": bx.pack_sha256,
                    "verifier_pack_manifest": bx.pack_manifest,
                    "verifier_pack_present": pack_evidence_bx["present"],
                    "verifier_pack_started": bx_started,
                    "verifier_pack_completed": bx_completed,
                    "verifier_pack_tests_passed": bx.tests_passed if bx_completed else None,
                    "verifier_pack_tests_total": bx.tests_total if bx_completed else None,
                    "verifier_pack_junit_sha256": bx.junit_sha256,
                    "verifier_pack_junit_digest_format": (
                        "JUNIT_XML_SHA256" if bx.junit_sha256 else None
                    ),
                    "junit_sha256": bx.junit_sha256,
                    "junit_digest_format": (
                        "JUNIT_XML_SHA256" if bx.junit_sha256 else None
                    ),
                    "isolation_evidence": isolation_evidence_bx,
                    "blackbox_pack_isolation_evidence": isolation_evidence_bx,
                    "setup_isolation_evidence": repo_art.get(
                        "setup_isolation_evidence"
                    ),
                    "repo_suite_isolation_evidence": repo_art.get(
                        "repo_suite_isolation_evidence"
                    ),
                    "verifier_pack_isolation_evidence": repo_art.get(
                        "verifier_pack_isolation_evidence"
                    ),
                    "deleted_paths_applied": bx.deleted_applied,
                    "repo_suite_junit_sha256": repo_art.get("junit_sha256") if repo_art else None,
                    "repo_suite_junit_digest_format": (
                        repo_art.get("junit_digest_format") if repo_art else None
                    ),
                    "repo_suite_passed": (
                        repo_verdict.passed
                        if repo_verdict is not None and repo_clean_source
                        else None
                    ),
                    "repo_suite_started": repo_started,
                    "repo_suite_completed": repo_completed,
                    "repo_suite_state": repo_suite_state,
                    "repo_suite_image_digest": (
                        repo_art.get("image_digest") if repo_art else None
                    ),
                    "base_sha": base_sha,
                    "head_sha": head_sha,
                    "base_tree_sha": base_tree_sha,
                    "head_tree_sha": head_tree_sha,
                    "policy_id": policy_id,
                    "policy_version": policy_version,
                    "setup_isolation": repo_art.get("setup_isolation"),
                    "execution_state": execution_state_bx,
                    "execution_phase": execution_phase_bx,
                    "test_command_started": test_started_bx,
                    "candidate_invocations": candidate_invocations,
                    "candidate_launcher_invocation_observed": (
                        candidate_launcher_invocation_observed
                    ),
                    "delivered_isolation": candidate_iso_bx,
                    "effective_candidate_isolation": candidate_iso_bx,
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
    run_suite = preflight.may_execute
    if run_suite:
        verdict = RepoVerifier(
            timeout=timeout, mem_limit_mb=mem_limit_mb,
            isolation=isolation, docker_image=docker_image, docker_network=docker_network,
            trust_setup_on_host=trust_setup_on_host,
            setup_output_globs=setup_output_globs,
            strict_harness=strict_harness,
        ).verify(candidate, problem)
        art = verdict.artifact or {}
        verification_evidence = repo_verification_evidence_from_artifact(
            art,
            default_isolation=isolation,
        )
        diagnostics = verdict.diagnostics or ""
    else:
        verdict = None
        art = {}
        verification_evidence = None
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

    decision_pipeline = VerificationPipeline.from_repo_facts(
        has_changes=bool(all_touched),
        unsafe_paths=unsafe,
        protected_violations=violations,
        verifier_present=verdict is not None,
        verifier_passed=verdict.passed if verdict is not None else None,
        verifier_score=verdict.score if verdict is not None else None,
        diagnostics=diagnostics,
        evidence=verification_evidence,
    )
    initial_decision = decision_pipeline.decision
    current_decision = initial_decision
    v = current_decision.verdict
    code = current_decision.reason_code
    reason = current_decision.reason

    # Preserve both layers before later evidence gates can demote the top-level
    # verdict. Coverage gates the full core verdict. Baseline is narrower:
    # ``scope=repo_suite_only`` compares the pristine suite with the candidate's
    # repo phase, even when a separately composed verifier pack later fails.
    core_verdict_completed = v in (PASS, FAIL)
    core_verdict_passed = v == PASS
    repo_suite_pass_value = (
        verification_evidence.repo_suite.passed
        if verification_evidence is not None
        else None
    )
    repo_suite_completed = (
        verification_evidence is not None
        and verification_evidence.repo_suite.started is True
        and verification_evidence.repo_suite.completed is True
        and isinstance(repo_suite_pass_value, bool)
    )
    candidate_suite_completed = repo_suite_completed or core_verdict_completed
    candidate_suite_passed = (
        repo_suite_pass_value is True if repo_suite_completed else core_verdict_passed
    )

    # Changed-line coverage evidence (opt-in; one extra suite run). Only when the
    # suite actually ran — a REJECTED/ERROR verdict has nothing to measure. A
    # request the container judges cannot fulfil degrades EXPLICITLY (1.7).
    coverage_evidence: dict[str, Any] | None = None
    if diff_coverage and isolation != "subprocess":
        coverage_evidence = {
            "measured": False,
            "note": f"changed-line coverage runs under the subprocess judge "
                    f"only; isolation {isolation!r} did not measure it",
        }
    if diff_coverage and core_verdict_completed and isolation == "subprocess":
        from evoom_guard.evidence import collect_diff_coverage

        coverage_evidence = collect_diff_coverage(
            repo_path, candidate,
            deleted=tuple(safe_deleted), test_command=test_command,
            setup_command=setup_command, setup_output_globs=setup_output_globs,
            timeout=timeout, mem_limit_mb=mem_limit_mb,
            file_blocks=file_blocks,
            require_passing_suite=(
                core_verdict_passed and min_diff_coverage is not None
            ),
        )
        decision_pipeline = decision_pipeline.apply_diff_coverage(
            coverage_evidence=coverage_evidence,
            min_diff_coverage=min_diff_coverage,
        )
        current_decision = decision_pipeline.decision
        v = current_decision.verdict
        code = current_decision.reason_code
        reason = current_decision.reason

    # Baseline differential evidence (opt-in; one extra suite run on the
    # PRISTINE base — no candidate applied). "all tests pass on head" does not
    # by itself show the change FIXED anything: the base may already have been
    # green. The baseline run makes the counterfactual measurable:
    #   baseline FAIL → candidate PASS, same tests/policy/env  ⇒ repair_effect
    #   "demonstrated". Anything else ⇒ "not_demonstrated" (or "unmeasured"
    # when the baseline produced no clean verdict). Evidence only, unless
    # require_demonstrated_fix demotes an undemonstrated PASS to FAIL.
    baseline_info: dict[str, Any] | None = None
    if baseline_evidence and isolation != "subprocess":
        baseline_info = {
            "verdict": None, "tests_passed": None, "tests_total": None,
            "repair_effect": "unmeasured", "scope": "unsupported_mode",
            "note": f"baseline differential evidence runs under the subprocess "
                    f"judge only; isolation {isolation!r} did not measure it",
        }
    if (
        (baseline_evidence or require_demonstrated_fix)
        and candidate_suite_completed
        and isolation == "subprocess"
    ):
        baseline_info = _run_baseline_suite(
            repo_path, test_command=test_command, setup_command=setup_command,
            setup_output_globs=setup_output_globs,
            timeout=timeout, mem_limit_mb=mem_limit_mb,
            strict_harness=strict_harness,
        )
        if baseline_info.get("verdict") == "NO_CLEAN_VERDICT":
            baseline_info["repair_effect"] = "unmeasured"
        elif baseline_info.get("verdict") == "FAIL" and candidate_suite_passed:
            baseline_info["repair_effect"] = "demonstrated"
        else:
            baseline_info["repair_effect"] = "not_demonstrated"
        # Honest scope: the baseline runs the repo's own suite ONLY —
        # the candidate-only verifier-pack phase is NOT run here,
        # so with a pack the two runs are not judged by identical check sets.
        baseline_info["scope"] = "repo_suite_only"
        baseline_info["note"] = (
            "counterfactual suite-transition evidence, not a causal proof: the "
            "same judge and environment ran the REPO suite on the pristine base "
            "and on the candidate; 'demonstrated' means the base failed and the "
            "candidate passed. A verifier pack (if any) is exercised only on "
            "the candidate run — see scope."
        )
        decision_pipeline = decision_pipeline.apply_demonstrated_fix(
            baseline_evidence=baseline_info,
            require_demonstrated_fix=require_demonstrated_fix,
        )
        current_decision = decision_pipeline.decision
        v = current_decision.verdict
        code = current_decision.reason_code
        reason = current_decision.reason

    if run_suite:
        assert verification_evidence is not None
        execution_state = verification_evidence.execution.execution_state
        execution_phase = verification_evidence.execution.execution_phase
        test_command_started = (
            verification_evidence.execution.test_command_started
        )
        delivered_isolation = (
            verification_evidence.execution.delivered_isolation
        )
    else:
        execution_state = EXECUTION_STATIC_GATE
        execution_phase = "pre_gate"
        test_command_started = False
        delivered_isolation = "not_run"

    effective_candidate_isolation = (
        "subprocess"
        if (
            verification_evidence is not None
            and verification_evidence.setup_isolation == "subprocess_host_opt_in"
        )
        else delivered_isolation
    )

    pack_evidence: dict[str, Any] | None = None
    if verifier_pack:
        if verification_evidence is None:
            pack_evidence = {
                "present": None,
                "snapshot_sha256": None,
                "started": False,
                "completed": False,
                "outcome": None,
            }
        else:
            present = verification_evidence.verifier_pack.present
            if present is None and verification_evidence.verifier_pack.sha256:
                present = True
            if present is None and verification_evidence.outcome == "pack_invalid":
                present = os.path.isdir(verifier_pack)
            pack_evidence = {
                "present": present,
                "snapshot_sha256": verification_evidence.verifier_pack.sha256,
                "started": verification_evidence.execution.verifier_pack_started,
                "completed": verification_evidence.execution.verifier_pack_completed,
                "outcome": verification_evidence.outcome,
            }

    judgment_mode = "blackbox" if blackbox else "repo"
    attestation_art = dict(art)
    if verification_evidence is not None:
        attestation_art.update(
            repo_attestation_evidence_payload(verification_evidence)
        )
    attestation_art.update(
        {
            "execution_state": execution_state,
            "execution_phase": execution_phase,
            "test_command_started": test_command_started,
            "delivered_isolation": delivered_isolation,
            "effective_candidate_isolation": effective_candidate_isolation,
            # Repo-native verdicts are revision-bound too (1.6): black-box was
            # the only mode carrying base/head before, which left the common
            # Action path's signed verdicts unbound from the commit they judged.
            "base_sha": base_sha,
            "head_sha": head_sha,
            "base_tree_sha": base_tree_sha,
            "head_tree_sha": head_tree_sha,
            "policy_id": policy_id,
            "policy_version": policy_version,
        }
    )
    attestation = _build_attestation(
        candidate, safe_deleted=safe_deleted, test_command=test_command,
        effective_policy=effective_policy, art=attestation_art,
        mode=judgment_mode,
    )

    assurance = (
        _assurance_profile(
            delivered_isolation,
            verifier_pack,
            setup_isolation=(
                verification_evidence.setup_isolation
                if verification_evidence is not None
                else None
            ),
            runtime_continuity=(
                verification_evidence.runtime.continuity
                if verification_evidence is not None
                else None
            ),
            execution_state=execution_state,
            execution_phase=execution_phase,
            test_command_started=test_command_started,
            pack_evidence=pack_evidence,
        )
        if run_suite
        else _static_assurance_profile(verifier_pack)
    )
    decision_pipeline = decision_pipeline.apply_assurance(
        assurance=assurance,
        execution_state=execution_state,
        execution_requested=run_suite,
        require_report_integrity=require_report_integrity,
        require_candidate_isolation=require_candidate_isolation,
        shortfall_evaluator=_assurance_shortfall,
        eager_shortfall=False,
    )
    current_decision = decision_pipeline.decision
    v = current_decision.verdict
    code = current_decision.reason_code
    reason = current_decision.reason

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

    rv = RepoVerifier(
        timeout=timeout,
        mem_limit_mb=mem_limit_mb,
        strict_harness=strict_harness,
    )
    workdir = _tempfile.mkdtemp(prefix="evo_baseline_")
    copy = os.path.join(workdir, "repo")
    try:
        copy_repo_tree(repo_path, copy)
        env = judge_subprocess_env(workdir)
        if setup_command:
            try:
                setup_before = _setup_fidelity_snapshot(copy, setup_output_globs)
                setup_env = dict(env)
                setup_cmd = _resolve_host_command(
                    list(setup_command), cwd=copy, env=setup_env
                )
                # Baseline evidence is still candidate-adjacent execution: its
                # setup command and suite must not regain an unbounded stdout /
                # stderr channel merely because they run on the pristine tree.
                r_setup = _run_bounded_subprocess(
                    setup_cmd,
                    cwd=copy,
                    env=setup_env,
                    timeout=timeout,
                    preexec_fn=rv._limits() if os.name == "posix" else None,
                    require_process_group_cleanup_proof=strict_harness,
                )
                setup_after = _setup_fidelity_snapshot(
                    copy, setup_output_globs, baseline=setup_before
                )
            except (
                OSError,
                SetupFidelityError,
                _SubprocessContainmentError,
                _SubprocessOutputLimitExceeded,
                subprocess.TimeoutExpired,
            ):
                return {"verdict": "NO_CLEAN_VERDICT", "tests_passed": None,
                        "tests_total": None, "setup_fidelity": "unverified"}
            if r_setup.returncode != 0:
                return {"verdict": "NO_CLEAN_VERDICT", "tests_passed": None,
                        "tests_total": None, "setup_fidelity": "setup_failed"}
            setup_changes = _setup_fidelity_changes(setup_before, setup_after)
            if setup_changes:
                return {
                    "verdict": "NO_CLEAN_VERDICT",
                    "tests_passed": None,
                    "tests_total": None,
                    "setup_fidelity": "changed_judged_tree",
                    "setup_fidelity_changes": setup_changes,
                }
        base_cmd = rv._command({"repo_path": repo_path})
        if test_command:
            base_cmd = list(test_command)
        host_xml = os.path.join(workdir, "judge-result.xml")
        cmd, report_expected, report_env = instrument_command(base_cmd, host_xml)
        run_env = {**env, **report_env}
        cmd = _resolve_host_command(cmd, cwd=copy, env=run_env)
        try:
            r = _run_bounded_subprocess(
                cmd,
                cwd=copy,
                env=run_env,
                preexec_fn=rv._limits() if os.name == "posix" else None,
                timeout=timeout,
                require_process_group_cleanup_proof=strict_harness,
            )
        except (
            OSError,
            _SubprocessContainmentError,
            _SubprocessOutputLimitExceeded,
            subprocess.TimeoutExpired,
        ):
            return {"verdict": "NO_CLEAN_VERDICT", "tests_passed": None,
                    "tests_total": None}
        # The report path is judge-owned, but its contents are produced by the
        # command being judged.  Read it through the same byte-bounded helper as
        # the main RepoVerifier path; a missing, oversized, or racing report is
        # no clean baseline evidence.
        xml_text = read_junit_xml(host_xml) or ""
        junit = parse_junit_xml(xml_text)
        if junit is None:
            junit = parse_junit_dir(host_xml + ".d")
        passed, _score, tp, tt = grade_repo_run(
            r.returncode, junit, report_expected=report_expected
        )
        tampered = detect_tamper(r.returncode, junit, report_expected=report_expected)
        if tampered or (junit is None and report_expected) or (
            strict_harness
            and (not report_expected or junit is None or junit.total <= 0)
        ):
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
def _effective_policy(
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
    )
    return _effective_policy_payload(policy)


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
    :func:`_effective_policy`), and the policy itself ships in the attestation
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
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")

    base_entries = _walk_tree_entries(base_dir)
    head_entries = _walk_tree_entries(head_dir)
    blocks: dict[str, str] = {}
    deleted = sorted(set(base_entries) - set(head_entries))
    problems: list[tuple[str, str]] = []

    for rel in sorted(head_entries):
        head = head_entries[rel]
        base = base_entries.get(rel)
        # Writing a file creates its parent directories, so a new directory
        # with a regular-file descendant is faithfully implied by ``blocks``.
        # Git cannot serialize an empty directory through the FILE-block
        # format, however; accepting it would recreate the old silent-drop
        # class of bypass for filesystem-sensitive projects.
        if head.kind == "directory" and base is None:
            if not _directory_has_regular_descendant(head_entries, rel):
                problems.append((rel, "new empty directory cannot be represented"))
            continue
        changed, comparison_problem = _entries_changed(base, head)
        if comparison_problem:
            problems.append((rel, comparison_problem))
            continue
        if not changed:
            continue
        if head.kind != "regular":
            problems.append((rel, _entry_problem(head)))
            continue
        try:
            blocks[rel] = _read_changed_text(head, max_bytes)
        except OSError as exc:
            problems.append((rel, f"cannot read changed file ({exc.strerror or exc})"))
        except UnicodeDecodeError:
            problems.append((rel, "changed file is not valid UTF-8 text"))
        except ValueError as exc:
            problems.append((rel, str(exc)))

    if problems:
        raise _UnverifiableChangedPathsError(problems)
    return blocks, deleted


def serialize_candidate_blocks(blocks: Mapping[str, str]) -> str:
    """Return the canonical textual identity for structured candidate blocks.

    The engine uses ``blocks`` directly when it applies a base/head candidate;
    this serialization exists only for the stable candidate digest and human
    display.  Sorting here, rather than relying on a caller's insertion order,
    keeps that identity stable for filesystem and raw-Git derivations alike.
    Deletions are deliberately not serialized: the immutable base/head tree
    bindings carry their identity separately.
    """

    return "\n".join(
        f"<<<FILE: {rel}>>>\n{blocks[rel]}\n<<<END FILE>>>"
        for rel in sorted(blocks)
    )


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
    text = serialize_candidate_blocks(blocks)
    return text, deleted


def _walk_tree_entries(root: str) -> dict[str, _TreeEntry]:
    """Return every non-ignored path without dropping non-text entries."""
    out: dict[str, _TreeEntry] = {}
    ignore = set(COPY_IGNORE) | {".git"}
    def walk_error(exc: OSError) -> None:
        # ``os.walk`` otherwise silently skips an unreadable directory. Keep a
        # sentinel so a change cannot vanish merely because it became
        # inaccessible between the base/head walks.
        if not exc.filename:
            return
        try:
            rel = os.path.relpath(exc.filename, root).replace(os.sep, "/")
        except ValueError:
            return
        if rel in (".", "") or rel.startswith("../"):
            return
        out[rel] = _TreeEntry(
            exc.filename, "unreadable", None, None,
            problem=f"cannot walk directory ({exc.strerror or exc})",
        )

    for dirpath, dirnames, filenames in os.walk(root, onerror=walk_error):
        dirnames[:] = [d for d in dirnames if d not in ignore]
        traversable_dirs: list[str] = []
        for dirname in dirnames:
            full = os.path.join(dirpath, dirname)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            entry = _tree_entry(full)
            out[rel] = entry
            # ``os.walk`` normally avoids symlink recursion, but explicitly
            # removing every non-directory protects against platform-specific
            # reparse/special behaviour and prevents an escape on followlinks.
            if entry.kind == "directory":
                traversable_dirs.append(dirname)
        dirnames[:] = traversable_dirs
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            out[rel] = _tree_entry(full)
    return out


def _tree_entry(full_path: str) -> _TreeEntry:
    """Describe a path without following a symlink or reading its payload."""
    try:
        info = os.lstat(full_path)
    except OSError as exc:
        return _TreeEntry(
            full_path, "unreadable", None, None,
            problem=f"cannot stat path ({exc.strerror or exc})",
        )

    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISREG(info.st_mode):
        return _TreeEntry(full_path, "regular", mode, int(info.st_size))
    if stat.S_ISDIR(info.st_mode):
        return _TreeEntry(full_path, "directory", mode, None)
    if stat.S_ISLNK(info.st_mode):
        try:
            return _TreeEntry(
                full_path, "symlink", mode, None, os.readlink(full_path)
            )
        except OSError as exc:
            return _TreeEntry(
                full_path, "unreadable", mode, None,
                problem=f"cannot read symlink ({exc.strerror or exc})",
            )
    return _TreeEntry(
        full_path, "special", mode, None,
        problem="path is not a regular file or symlink",
    )


def _entries_changed(
    base: _TreeEntry | None, head: _TreeEntry
) -> tuple[bool, str | None]:
    """Return whether a path changed and whether that fact is unverifiable."""
    if base is None:
        return True, None
    if base.kind == "unreadable":
        return True, _entry_problem(base)
    if head.kind == "unreadable":
        return True, _entry_problem(head)
    if base.kind != head.kind:
        return True, f"path type changed from {base.kind} to {head.kind}"
    if base.mode != head.mode:
        return True, "path mode changed; Guard file blocks cannot preserve modes"
    if head.kind == "regular":
        if base.size != head.size:
            return True, None
        try:
            return (not _regular_files_equal(base.full_path, head.full_path)), None
        except OSError as exc:
            return True, f"cannot compare file content ({exc.strerror or exc})"
    if head.kind == "symlink":
        return base.link_target != head.link_target, None
    if head.kind == "directory":
        # Existing directories carry no independent payload. Their descendant
        # file blocks (or explicit deletion paths) reconstruct membership; the
        # only unrepresentable directory state is a mode change above.
        return False, None
    # A special path is never a safe candidate representation, even if two
    # filesystem objects superficially look alike.
    return True, _entry_problem(head)


def _regular_files_equal(base_path: str, head_path: str) -> bool:
    """Compare two regular files exactly while keeping memory bounded."""
    with open(base_path, "rb") as base_file, open(head_path, "rb") as head_file:
        while True:
            left = base_file.read(1024 * 1024)
            right = head_file.read(1024 * 1024)
            if left != right:
                return False
            if not left:
                return True


def _entry_problem(entry: _TreeEntry) -> str:
    if entry.problem:
        return entry.problem
    if entry.kind == "symlink":
        return "path is a symlink, which Guard file blocks cannot represent"
    if entry.kind == "special":
        return "path is not a regular file"
    return "path cannot be represented safely"


def _directory_has_regular_descendant(
    entries: dict[str, _TreeEntry], directory: str
) -> bool:
    """Whether FILE blocks implicitly recreate a newly added directory."""
    prefix = directory.rstrip("/") + "/"
    return any(
        path.startswith(prefix) and entry.kind == "regular"
        for path, entry in entries.items()
    )


def _read_changed_text(entry: _TreeEntry, max_bytes: int) -> str:
    """Read one changed regular text file, failing before it can be dropped."""
    if entry.size is None:
        raise ValueError("changed file has no stable size")
    if entry.size > max_bytes:
        raise ValueError(
            f"changed file is {entry.size} bytes, above the {max_bytes}-byte limit"
        )
    # Read one extra byte so a concurrent enlargement cannot turn into a silent
    # truncation after the lstat above. Candidate memory is still bounded.
    with open(entry.full_path, "rb") as f:
        data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(
            f"changed file grew above the {max_bytes}-byte limit while being read"
        )
    return data.decode("utf-8")


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
) -> GuardResult:
    """Create a fail-closed result before a candidate tree is assembled."""
    return GuardResult(
        verdict=ERROR, passed=False, reason=reason,
        files_changed=[], protected_violations=[],
        risk_level="low", risk_score=0.0, diagnostics="",
        source=source, base_reconstruction=base_reconstruction,
        reason_code=reason_code, isolation="not_run",
        execution_state=EXECUTION_NOT_STARTED,
        execution_phase="preflight",
        assurance=_preflight_assurance_profile(verifier_pack),
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
    pack_trust_problem = verifier_pack_trust_error(
        head_dir, verifier_pack, expect_verifier_pack_sha256
    )
    if pack_trust_problem:
        return input_error_result(
            pack_trust_problem,
            reason_code=REASON_VERIFIER_PACK_INVALID,
            source="diff",
            base_reconstruction="failed",
            verifier_pack=verifier_pack,
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
        try:
            file_blocks, deleted = blocks_from_dirs(base, head_dir)
        except _UnverifiableChangedPathsError as exc:
            return _diff_error(
                "the diff includes changed path(s) Guard cannot safely verify: "
                f"{exc}",
                reason_code=REASON_NO_VERIFIABLE_CHANGES,
                base_reconstruction="ok",
            ), []
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
            trust_setup_on_host=trust_setup_on_host,
            setup_output_globs=setup_output_globs,
            protected=protected, allow=allow, allow_new_tests=allow_new_tests, timeout=timeout,
            mem_limit_mb=mem_limit_mb,
            isolation=isolation, docker_image=docker_image, docker_network=docker_network,
            verifier_pack=verifier_pack,
            expect_verifier_pack_sha256=expect_verifier_pack_sha256,
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
            strict_harness=strict_harness,
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
        f"| Execution | `{r.execution_state}` · phase `{r.execution_phase}` |",
        f"| Test command started | {'yes' if r.test_command_ran else 'no'} |",
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
        bverdict = b.get("verdict") or "not measured"
        lines.append(f"| Baseline (pristine base) | {bverdict}{btests} |")
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
    if r.execution_state == EXECUTION_STATIC_GATE:
        _execution_note = (
            "EvoGuard decided this result from the pre-execution diff gate; the "
            "suite was not started, so no test command, JUnit report, or runtime "
            "isolation was delivered."
        )
    elif r.execution_state == EXECUTION_NOT_STARTED:
        _execution_note = (
            "Runtime verification stopped before any test command started "
            f"(furthest phase: {r.execution_phase}); no suite/report isolation "
            "is claimed."
        )
    elif r.execution_state == EXECUTION_STARTED_INCOMPLETE:
        _execution_note = (
            "A verification command started but the required execution sequence "
            f"did not complete (furthest phase: {r.execution_phase}); therefore "
            "there is no clean verdict source."
        )
    else:
        _execution_note = (
            "EvoGuard reads the verdict from a judge-owned JUnit report + the "
            "process exit code (not stdout), and rejects any edit to the tests or "
            f"their config. The judge runs the suite {_judge}."
        )
    lines += [
        "",
        f"<sub>{_execution_note} See docs/GUARD.md.</sub>",
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
                "test_command_ran": result.test_command_ran,
                "execution_state": result.execution_state,
                "execution_phase": result.execution_phase,
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
