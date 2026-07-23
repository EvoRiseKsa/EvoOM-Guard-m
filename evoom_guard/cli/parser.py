"""Declarative construction of the public ``evo-guard`` argument parser.

This module owns parser shape only.  Command handlers and compatibility seams
remain in :mod:`evoom_guard.cli`; the facade injects its live helper functions
on every build so adopter monkeypatches retain their historical behavior.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable

ParserArgumentAdder = Callable[[argparse.ArgumentParser], None]
ImmutableReleaseRef = Callable[[object], str]


def build_parser(
    *,
    immutable_release_ref: ImmutableReleaseRef,
    add_github_attestation_policy_arguments: ParserArgumentAdder,
    add_github_attestation_verifier_arguments: ParserArgumentAdder,
    add_release_artifact_key_registry_arguments: ParserArgumentAdder,
    add_nested_release_source_expectation_arguments: ParserArgumentAdder,
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evo-guard",
        description="EvoGuard — evidence-bound verification for untrusted software changes.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ----- guard (untrusted-change verification gate) ------------------- #
    g_p = sub.add_parser(
        "guard",
        help="verify a change against repo tests while rejecting test/config edits",
    )
    g_p.add_argument(
        "repo", nargs="?", default=None,
        help="the repository to verify against (the base); omit when using --base/--head",
    )
    g_p.add_argument(
        "--patch", default=None,
        help="candidate patch in <<<FILE>>>/<<<PATCH>>> block format ('-' for stdin)",
    )
    g_p.add_argument("--base", default=None, help="base checkout dir (diff mode, e.g. a PR's target)")
    g_p.add_argument("--head", default=None, help="head checkout dir (diff mode, e.g. a PR's source)")
    g_p.add_argument(
        "--diff", default=None,
        help="a base...HEAD unified diff ('-' for stdin), verified against the current "
        "checkout (the repo arg or cwd) by reverse-applying it",
    )
    g_p.add_argument(
        "--test-command", default=None,
        help="test command run inside the repo copy (default: pytest -q)",
    )
    g_p.add_argument(
        "--protected", nargs="*", default=None,
        help="extra globs the patch may not modify (default: none; or .evoguard.json)",
    )
    g_p.add_argument(
        "--allow", nargs="*", default=None,
        help="baseline allowlist for extra --protected globs only. It never exempts "
        "built-in tests, test/build config, CI, or auto-executed judge files. "
        "Default: none; or .evoguard.json",
    )
    g_p.add_argument(
        "--allow-new-tests", dest="allow_new_tests", action="store_const",
        const=True, default=None,
        help="opt-in 'feature mode': allow brand-new test files (edits to existing "
        "tests/config/auto-exec stay rejected). Default: off; or .evoguard.json.",
    )
    g_p.add_argument(
        "--verifier-pack", dest="verifier_pack", default=None,
        help="directory of judge-owned tests/invariants the PATCH CANNOT include "
        "or modify. Repo-native mode runs the verified snapshot after the repo "
        "suite; black-box mode runs it first and may short-circuit before the repo "
        "phase. A narrowed repo command cannot skip it. Repo-native candidate imports "
        "share the judge process — the pack is not secret (use "
        "--blackbox with --isolation docker for that). In --diff and --base/--head "
        "modes it must be outside the candidate checkout (or materialized from the "
        "trusted base) and have --expect-verifier-pack-sha256. "
        "See docs/VERIFIER_PACKS.md.",
    )
    blackbox_group = g_p.add_mutually_exclusive_group()
    blackbox_group.add_argument(
        "--blackbox", dest="blackbox", action="store_const", const=True, default=None,
        help="external black-box judge (needs --verifier-pack): the verdict comes "
        "from the JUDGE's own pytest over the pack, which never imports the "
        "candidate — closing same-process report forgery for that phase. The "
        "pack must invoke the candidate via $EVOGUARD_EXEC; isolation is proven "
        "only by an observed launcher invocation (plus a CID for containers). "
        "By default the repo's own suite is ALSO required, so the completed "
        "composite has the weaker repo-native report-integrity level. "
        "See docs/BLACKBOX.md.",
    )
    blackbox_group.add_argument(
        "--no-blackbox", dest="blackbox", action="store_const", const=False,
        help="explicitly override blackbox: true from a trusted policy",
    )
    blackbox_only_group = g_p.add_mutually_exclusive_group()
    blackbox_only_group.add_argument(
        "--blackbox-only", dest="blackbox_only", action="store_const", const=True,
        default=None,
        help="with --blackbox, judge ONLY the external pack and skip the repo's own "
        "suite (for pure-CLI/service targets that have no in-repo tests). Without "
        "this, a failing repo suite blocks the merge even if the pack passes.",
    )
    blackbox_only_group.add_argument(
        "--no-blackbox-only", dest="blackbox_only", action="store_const", const=False,
        help="explicitly override blackbox_only: true from a trusted policy",
    )
    g_p.add_argument(
        "--require-report-integrity", dest="require_report_integrity", default=None,
        choices=("same_process_candidate_writable", "external_process_isolated"),
        help="for a completed PASS, fail closed unless this end-to-end "
        "report_integrity level is delivered. Static/preflight/incomplete causes "
        "remain unchanged. 'external_process_isolated' needs --blackbox-only; "
        "default --blackbox is composite with the weaker repo-native channel.",
    )
    g_p.add_argument(
        "--require-candidate-isolation", dest="require_candidate_isolation", default=None,
        choices=("subprocess", "docker", "gvisor"),
        help="for a completed PASS, fail closed unless this candidate isolation "
        "was observed. In black-box mode preparation is insufficient: a launcher "
        "receipt (and container CID for docker/gvisor) is required. "
        "Static/preflight/incomplete causes remain unchanged.",
    )
    g_p.add_argument(
        "--expect-verifier-pack-sha256",
        dest="expect_verifier_pack_sha256",
        default=None,
        help="fail-closed identity pin for --verifier-pack (64 hex characters, "
        "EVOGUARD_PACK_V2 digest from pack-doctor). The accepted snapshot must "
        "match before any candidate code runs.",
    )
    g_p.add_argument(
        "--trust-setup-on-host", dest="trust_setup_on_host", action="store_const",
        const=True, default=None,
        help="explicit compatibility opt-in: with docker/gvisor, run setup_command "
        "on the host. This weakens the delivered candidate isolation to subprocess "
        "and is recorded in the assurance/attestation.",
    )
    g_p.add_argument(
        "--no-trust-setup-on-host", dest="trust_setup_on_host", action="store_const",
        const=False, default=None,
        help="explicitly override trust_setup_on_host=true from .evoguard.json and "
        "keep docker/gvisor setup inside the requested container boundary.",
    )
    baseline_group = g_p.add_mutually_exclusive_group()
    baseline_group.add_argument(
        "--baseline-evidence", dest="baseline_evidence", action="store_const",
        const=True, default=None,
        help="differential evidence (opt-in): also run the suite on the PRISTINE "
        "base (no candidate) and report repair_effect — 'demonstrated' only when "
        "the base fails and the candidate passes under the same judge/policy/env. "
        "Evidence only; the verdict is unchanged. Subprocess judge only.",
    )
    baseline_group.add_argument(
        "--no-baseline-evidence", dest="baseline_evidence", action="store_const",
        const=False,
        help="explicitly override baseline_evidence: true from a trusted policy",
    )
    demonstrated_fix_group = g_p.add_mutually_exclusive_group()
    demonstrated_fix_group.add_argument(
        "--require-demonstrated-fix", dest="require_demonstrated_fix", action="store_const",
        const=True, default=None,
        help="gate (opt-in, implies --baseline-evidence): a PASS whose repair "
        "effect is not demonstrated (the base already passed, or no clean "
        "baseline verdict) becomes FAIL (fix_not_demonstrated). For agent 'fix' "
        "PRs; do NOT use on ordinary feature PRs, which start from a green base.",
    )
    demonstrated_fix_group.add_argument(
        "--no-require-demonstrated-fix", dest="require_demonstrated_fix",
        action="store_const", const=False,
        help="explicitly override require_demonstrated_fix: true from a trusted policy",
    )
    g_p.add_argument(
        "--base-sha", dest="base_sha", default=None,
        help="base commit SHA to bind into the attestation (a plain git diff "
        "carries no commit identity; CI should pass `git rev-parse <base>`)",
    )
    g_p.add_argument(
        "--head-sha", dest="head_sha", default=None,
        help="head commit SHA to bind into the attestation (CI: git rev-parse HEAD)",
    )
    g_p.add_argument(
        "--base-tree-sha", dest="base_tree_sha", default=None,
        help="base TREE SHA (git rev-parse <base>^{tree}) — pins the exact "
        "content judged even where a commit SHA is unavailable",
    )
    g_p.add_argument(
        "--head-tree-sha", dest="head_tree_sha", default=None,
        help="head TREE SHA (git rev-parse HEAD^{tree})",
    )
    coverage_group = g_p.add_mutually_exclusive_group()
    coverage_group.add_argument(
        "--diff-coverage", dest="diff_coverage", action="store_const", const=True,
        default=None,
        help="measure which changed lines the suite actually executed (one extra "
        "suite run under coverage; needs the 'cov' extra). Evidence only unless "
        "--min-diff-coverage is set. Executed is not asserted; same-process "
        "candidate code can mutate coverage state.",
    )
    coverage_group.add_argument(
        "--no-diff-coverage", dest="diff_coverage", action="store_const", const=False,
        help="explicitly override diff_coverage: true from a trusted policy",
    )
    g_p.add_argument(
        "--min-diff-coverage", dest="min_diff_coverage", type=float, default=None,
        help="quality gate for non-hostile code: a PASS whose measured "
        "changed-line coverage is below this "
        "percentage becomes FAIL (diff_coverage_below_threshold); unavailable "
        "measurement becomes ERROR (assurance_requirement_not_met); implies "
        "--diff-coverage and ignores repository coverage config, but candidate "
        "code still shares and can mutate the collector process",
    )
    g_p.add_argument(
        "--timeout", type=int, default=None,
        help="per-run suite timeout in seconds (default: 120; or .evoguard.json)",
    )
    g_p.add_argument(
        "--mem-limit", dest="mem_limit", type=int, default=None,
        help="address-space cap (MB) for the test subprocess; 0 disables it "
        "(required for Node/V8 suites, which reserve far more virtual memory than "
        "any sane RLIMIT_AS). Default: 1024; or .evoguard.json.",
    )
    config_group = g_p.add_mutually_exclusive_group()
    config_group.add_argument(
        "--config", default=None,
        help="trusted repo policy (JSON). With --base/--head or <repo> --patch, "
        "an omitted value reads .evoguard.json from the baseline. With --diff, "
        "pass an absolute config path outside the candidate checkout. CLI flags "
        "override it.",
    )
    config_group.add_argument(
        "--no-config", action="store_true",
        help="run without a repository policy. Required explicitly with --diff "
        "when no trusted base policy is materialized.",
    )
    g_p.add_argument(
        "--isolation", choices=("subprocess", "docker", "gvisor"), default=None,
        help="how to run the suite: 'subprocess' (default; rlimits+timeout, not a "
        "sandbox), 'docker' (network-less, read-only container — defence in depth for "
        "semi-trusted code), or 'gvisor' (same, via the runsc OCI runtime — a "
        "user-space guest kernel, no /dev/kvm; for untrusted code). The container "
        "modes need --docker-image and a docker daemon",
    )
    g_p.add_argument(
        "--docker-image", dest="docker_image", default=None,
        help="container image for --isolation docker/gvisor (must contain the repo's "
        "test runner, e.g. node:22-slim for `node --test`)",
    )
    g_p.add_argument(
        "--docker-network", dest="docker_network", default=None,
        help="container network for --isolation docker/gvisor (default: 'none' — no "
        "network, the safe choice; pass a docker network name only if the suite "
        "genuinely needs it)",
    )
    strict_harness_group = g_p.add_mutually_exclusive_group()
    strict_harness_group.add_argument(
        "--strict-harness", dest="strict_harness", action="store_const",
        const=True, default=None,
        help="opt-in strict profile: make dependency/compiler/project manifests "
        "immutable and require a non-empty structured JUnit test verdict",
    )
    strict_harness_group.add_argument(
        "--no-strict-harness", dest="strict_harness", action="store_const",
        const=False,
        help="explicitly override strict_harness: true from a trusted policy",
    )
    g_p.add_argument("--json", dest="json_out", default=None, help="write the JSON verdict to this path")
    g_p.add_argument(
        "--sarif", default=None,
        help="write a SARIF 2.1.0 report here (for GitHub code-scanning / the Security tab)",
    )
    g_p.add_argument("--report", default=None, help="write the Markdown report here (else stdout)")
    g_p.add_argument(
        "--sign-key", dest="sign_key", default=None,
        help="Ed25519 private key (PEM) to sign the --json verdict with; writes a "
        "detached base64 signature to <json>.sig (needs the 'sign' extra)",
    )

    # ----- keygen ---------------------------------------------------------- #
    k_p = sub.add_parser(
        "keygen",
        help="generate an Ed25519 keypair for verdict signing (needs the 'sign' extra)",
    )
    k_p.add_argument(
        "--key", default="evoguard-signing.pem",
        help="private key output path (default: evoguard-signing.pem; keep it a CI secret)",
    )
    k_p.add_argument(
        "--pub", default="evoguard-signing.pub",
        help="public key output path (default: evoguard-signing.pub; distribute freely)",
    )

    # ----- verify-verdict --------------------------------------------------- #
    v_p = sub.add_parser(
        "verify-verdict",
        help="verify a signed verdict file offline (exit 0 valid / 1 invalid)",
    )
    v_p.add_argument("verdict", help="the JSON verdict file whose bytes were signed")
    v_p.add_argument(
        "--sig", default=None,
        help="the detached signature (default: <verdict>.sig)",
    )
    v_p.add_argument("--pub", required=True, help="the judge's Ed25519 public key (PEM)")
    v_p.add_argument(
        "--expect-head-sha", dest="expect_head_sha", default=None,
        help="context check: the verdict's attestation.head_sha must equal this "
        "(e.g. $GITHUB_SHA) — a valid signature over the WRONG commit fails",
    )
    v_p.add_argument(
        "--expect-base-sha", dest="expect_base_sha", default=None,
        help="context check: attestation.base_sha must equal this",
    )
    v_p.add_argument(
        "--expect-policy-sha", dest="expect_policy_sha", default=None,
        help="context check: attestation.policy_sha256 must equal this",
    )
    v_p.add_argument(
        "--expect-policy-id", dest="expect_policy_id", default=None,
        help="context check: attestation.policy_id must equal this",
    )

    # ----- verify-record ---------------------------------------------------- #
    vr_p = sub.add_parser(
        "verify-record",
        help="validate a verdict record's schema and cross-field semantics offline",
    )
    vr_p.add_argument(
        "verdict",
        help="the JSON verdict file to validate, or '-' to read JSON from stdin",
    )

    # ----- bundle-evidence -------------------------------------------------- #
    be_p = sub.add_parser(
        "bundle-evidence",
        help="sign a verdict and its declared materials into a canonical evidence envelope",
    )
    be_p.add_argument("verdict", help="the schema-1.11 verdict JSON to bundle")
    be_p.add_argument("--out", required=True, help="output .evb path")
    be_p.add_argument(
        "--context",
        required=True,
        help="trusted finalizer context JSON (repository/run/revision/digest bindings)",
    )
    be_p.add_argument(
        "--sign-key",
        required=True,
        help="trusted finalizer Ed25519 private key (PEM; never expose it to the candidate job)",
    )
    be_p.add_argument(
        "--material",
        action="append",
        default=[],
        metavar="ROLE=PATH",
        help="supporting regular file to bind; repeat for multiple materials",
    )
    be_p.add_argument(
        "--force",
        action="store_true",
        help="replace an existing output (default is atomic no-clobber)",
    )

    # ----- finalize-record -------------------------------------------------- #
    fr_p = sub.add_parser(
        "finalize-record",
        help="seal a semantic record against externally derived finalizer context",
    )
    fr_p.add_argument(
        "verdict",
        help="regular JSON verdict file from the trusted re-verification job",
    )
    fr_p.add_argument("--out", required=True, help="output .evb path")
    fr_p.add_argument(
        "--expected-context",
        required=True,
        help="context derived outside the candidate/artifact (exactly bound before signing)",
    )
    fr_p.add_argument(
        "--sign-key",
        required=True,
        help="finalizer Ed25519 private key (PEM; never expose it to candidate execution)",
    )
    fr_p.add_argument(
        "--material",
        action="append",
        default=[],
        metavar="ROLE=PATH",
        help="supporting regular file to bind; repeat for multiple materials",
    )
    fr_p.add_argument(
        "--force",
        action="store_true",
        help="replace an existing output (default is atomic no-clobber)",
    )
    fr_p.add_argument(
        "--require-pass",
        action="store_true",
        help="return exit 1 for a sealed semantic denial while preserving its evidence bundle",
    )

    # ----- finalizer-handoff ----------------------------------------------- #
    fh_p = sub.add_parser(
        "finalizer-handoff",
        help="write a canonical re-verification handoff without signing it",
    )
    fh_p.add_argument("verdict", help="regular semantic verdict JSON from the re-verification job")
    fh_p.add_argument("--out", required=True, help="output canonical handoff JSON")
    fh_p.add_argument(
        "--source",
        required=True,
        help="trusted pull-request/reverify-run metadata JSON, not a candidate artifact",
    )
    fh_p.add_argument(
        "--context",
        required=True,
        help="trusted finalizer evidence-context JSON bound to the verdict",
    )
    fh_p.add_argument(
        "--force",
        action="store_true",
        help="replace an existing output (default is atomic no-clobber)",
    )

    # ----- seal-finalizer -------------------------------------------------- #
    sf_p = sub.add_parser(
        "seal-finalizer",
        help="validate a finalizer handoff against external inputs, then sign its evidence",
    )
    sf_p.add_argument("handoff", help="canonical handoff JSON from the unprivileged reverify job")
    sf_p.add_argument("verdict", help="regular semantic verdict JSON referenced by the handoff")
    sf_p.add_argument("--out", required=True, help="output signed .evb path")
    sf_p.add_argument(
        "--expected-source",
        required=True,
        help="source JSON re-derived by the sealing job from trusted control-plane metadata",
    )
    sf_p.add_argument(
        "--expected-context",
        required=True,
        help="context JSON re-derived by the sealing job; exact match is required",
    )
    sf_p.add_argument(
        "--expected-derivation",
        default=None,
        help="optional canonical raw-Git binding record; rechecked before the signing key is read",
    )
    sf_p.add_argument(
        "--sign-key",
        required=True,
        help="sealing Ed25519 private key; use only in a job that never executes candidate code",
    )
    sf_p.add_argument(
        "--material",
        action="append",
        default=[],
        metavar="ROLE=PATH",
        help="supporting regular file to bind; repeat for multiple materials",
    )
    sf_p.add_argument(
        "--force",
        action="store_true",
        help="replace an existing output (default is atomic no-clobber)",
    )
    sf_p.add_argument(
        "--require-pass",
        action="store_true",
        help="return exit 1 for a sealed denial while preserving its signed evidence bundle",
    )

    # ----- derive-finalizer-bindings --------------------------------------- #
    df_p = sub.add_parser(
        "derive-finalizer-bindings",
        help="derive finalizer bindings from raw immutable Git objects without a checkout",
    )
    df_p.add_argument("--base-repo", required=True, help="base Git worktree or object store")
    df_p.add_argument("--head-repo", required=True, help="head Git worktree or object store")
    df_p.add_argument("--base-bare", action="store_true", help="base-repo is a bare Git dir")
    df_p.add_argument("--head-bare", action="store_true", help="head-repo is a bare Git dir")
    df_p.add_argument("--base-sha", required=True, help="immutable base commit SHA")
    df_p.add_argument("--head-sha", required=True, help="immutable head commit SHA")
    df_p.add_argument("--base-tree-sha", required=True, help="expected base tree SHA")
    df_p.add_argument("--head-tree-sha", required=True, help="expected head tree SHA")
    df_p.add_argument("--repository", required=True, help="GitHub owner/repository identity")
    df_p.add_argument("--repository-id", required=True, help="immutable GitHub repository ID")
    df_p.add_argument("--pr-number", required=True, type=int, help="pull-request number")
    df_p.add_argument("--run-id", required=True, help="reverification workflow run ID")
    df_p.add_argument("--run-attempt", required=True, type=int, help="reverification run attempt")
    df_p.add_argument(
        "--guard-artifact-sha",
        required=True,
        help="protected SHA-256 of the reviewed Guard runtime",
    )
    df_p.add_argument("--out", required=True, help="canonical raw-Git binding JSON output")
    df_p.add_argument(
        "--force",
        action="store_true",
        help="replace an existing output (default is atomic no-clobber)",
    )

    # ----- verify-finalizer-bindings --------------------------------------- #
    vfdb_p = sub.add_parser(
        "verify-finalizer-bindings",
        help="compare a verdict to raw-Git bindings and write safe finalizer metadata",
    )
    vfdb_p.add_argument("verdict", help="regular semantic verdict JSON")
    vfdb_p.add_argument("--bindings", required=True, help="canonical raw-Git binding JSON")
    vfdb_p.add_argument("--source-out", required=True, help="verified source JSON output")
    vfdb_p.add_argument("--context-out", required=True, help="verified context JSON output")
    vfdb_p.add_argument(
        "--force",
        action="store_true",
        help="replace existing source/context outputs (default is no-clobber)",
    )

    # ----- verify-finalized ------------------------------------------------ #
    vf_p = sub.add_parser(
        "verify-finalized",
        help="verify a signed finalizer bundle, its exact handoff, and external bindings",
    )
    vf_p.add_argument("bundle", help="the signed finalizer .evb evidence bundle")
    vf_p.add_argument(
        "--trusted-pub",
        required=True,
        help="externally trusted Ed25519 public key for the sealing job",
    )
    vf_p.add_argument(
        "--expected-source",
        required=True,
        help="external source JSON; exact match is required to prevent replays",
    )
    vf_p.add_argument(
        "--expected-context",
        required=True,
        help="external context JSON; exact match is required to prevent replays",
    )
    vf_p.add_argument(
        "--require-pass",
        action="store_true",
        help="also act as a gate: exit 0 only for a verified semantic PASS",
    )

    # ----- Agent Change admission profile ---------------------------------- #
    acp_p = sub.add_parser(
        "validate-agent-change-proposal",
        help="validate one canonical untrusted Agent Change proposal",
    )
    acp_p.add_argument("proposal", help="canonical proposal JSON")

    dacb_p = sub.add_parser(
        "derive-agent-change-bindings",
        help="derive changed paths and identities from immutable raw Git",
    )
    dacb_p.add_argument("--base-repo", required=True, help="trusted base Git worktree/object store")
    dacb_p.add_argument("--head-repo", required=True, help="trusted head Git worktree/object store")
    dacb_p.add_argument("--git-executable", required=True, help="trusted absolute POSIX Git executable")
    dacb_p.add_argument("--git-executable-sha256", required=True, help="external SHA-256 pin for Git")
    dacb_p.add_argument("--base-bare", action="store_true", help="base-repo is a bare Git dir")
    dacb_p.add_argument("--head-bare", action="store_true", help="head-repo is a bare Git dir")
    dacb_p.add_argument("--base-sha", required=True, help="immutable base commit SHA")
    dacb_p.add_argument("--head-sha", required=True, help="immutable head commit SHA")
    dacb_p.add_argument("--base-tree-sha", required=True, help="expected base tree SHA")
    dacb_p.add_argument("--head-tree-sha", required=True, help="expected head tree SHA")
    dacb_p.add_argument("--out", required=True, help="canonical Agent Change binding JSON")
    dacb_p.add_argument("--force", action="store_true", help="replace an existing output")

    saca_p = sub.add_parser(
        "seal-agent-change-authorization",
        help="sign a trusted control-plane scope for one exact agent change",
    )
    saca_p.add_argument("--source", required=True, help="trusted authorization source JSON")
    saca_p.add_argument("--scope", required=True, help="trusted authorization scope JSON")
    saca_p.add_argument("--required", required=True, help="trusted policy/pack requirements JSON")
    saca_p.add_argument("--sign-key", required=True, help="authorization-domain Ed25519 private key")
    saca_p.add_argument("--out", required=True, help="signed canonical .aca authorization")
    saca_p.add_argument("--force", action="store_true", help="replace an existing output")

    sacf_p = sub.add_parser(
        "seal-agent-change-finalized",
        help="seal Trusted Finalizer ALLOW with proposal, authorization, and raw-Git bindings",
    )
    sacf_p.add_argument("proposal", help="canonical untrusted proposal JSON")
    sacf_p.add_argument("authorization", help="signed .aca authorization archive")
    sacf_p.add_argument("handoff", help="canonical Trusted Finalizer handoff")
    sacf_p.add_argument("verdict", help="semantic Guard verdict referenced by the handoff")
    sacf_p.add_argument("--base-repo", required=True, help="trusted base Git worktree/object store")
    sacf_p.add_argument("--head-repo", required=True, help="trusted head Git worktree/object store")
    sacf_p.add_argument("--git-executable", required=True, help="trusted absolute POSIX Git executable")
    sacf_p.add_argument("--git-executable-sha256", required=True, help="external SHA-256 pin for Git")
    sacf_p.add_argument("--base-bare", action="store_true", help="base-repo is a bare Git dir")
    sacf_p.add_argument("--head-bare", action="store_true", help="head-repo is a bare Git dir")
    sacf_p.add_argument("--finalizer-bindings", required=True, help="canonical Trusted Finalizer raw-Git bindings")
    sacf_p.add_argument("--authorization-source", required=True, help="external authorization source JSON")
    sacf_p.add_argument("--authorization-pub", required=True, help="trusted authorization public key")
    sacf_p.add_argument("--expected-source", required=True, help="external finalizer source JSON")
    sacf_p.add_argument("--expected-context", required=True, help="external finalizer context JSON")
    sacf_p.add_argument("--sign-key", required=True, help="Trusted Finalizer private key")
    sacf_p.add_argument("--trusted-pub", required=True, help="matching Trusted Finalizer public key")
    sacf_p.add_argument("--out", required=True, help="signed Agent Change finalizer .evb")
    sacf_p.add_argument("--force", action="store_true", help="replace an existing output")

    vacf_p = sub.add_parser(
        "verify-agent-change-finalized",
        help="offline-verify the complete Agent Change finalizer profile",
    )
    vacf_p.add_argument("bundle", help="signed Agent Change finalizer .evb")
    vacf_p.add_argument("--agent-bindings", required=True, help="external raw-Git Agent Change bindings")
    vacf_p.add_argument("--authorization-source", required=True, help="external authorization source JSON")
    vacf_p.add_argument("--authorization-pub", required=True, help="trusted authorization public key")
    vacf_p.add_argument("--expected-source", required=True, help="external finalizer source JSON")
    vacf_p.add_argument("--expected-context", required=True, help="external finalizer context JSON")
    vacf_p.add_argument("--trusted-pub", required=True, help="trusted finalizer public key")

    # ----- release-source finalizer V1 ----------------------------------- #
    rsfh_p = sub.add_parser(
        "release-source-handoff",
        help="write an unsigned canonical handoff for one exact protected-main source",
    )
    rsfh_p.add_argument("verdict", help="regular semantic verdict JSON from re-verification")
    rsfh_p.add_argument("--out", required=True, help="output canonical handoff JSON")
    rsfh_p.add_argument(
        "--source",
        required=True,
        help="trusted protected-main source metadata JSON, never a PR artifact",
    )
    rsfh_p.add_argument(
        "--context",
        required=True,
        help="trusted release-source context JSON bound to the verdict",
    )
    rsfh_p.add_argument(
        "--force",
        action="store_true",
        help="replace an existing output (default is atomic no-clobber)",
    )

    srsf_p = sub.add_parser(
        "seal-release-source-finalizer",
        help="sign a release-source handoff only after exact external control-plane matching",
    )
    srsf_p.add_argument("handoff", help="canonical release-source handoff JSON")
    srsf_p.add_argument("verdict", help="regular semantic verdict JSON referenced by handoff")
    srsf_p.add_argument("--out", required=True, help="output signed .rse evidence bundle")
    srsf_p.add_argument(
        "--expected-source",
        required=True,
        help="source JSON independently derived by the protected sealing job",
    )
    srsf_p.add_argument(
        "--expected-context",
        required=True,
        help="context JSON expected from raw-Git derivation by the protected sealing job",
    )
    srsf_p.add_argument(
        "--git-repository",
        required=True,
        help="trusted raw-Git worktree/object store used to re-derive refs/heads/main",
    )
    srsf_p.add_argument(
        "--git-repository-bare",
        action="store_true",
        help="treat --git-repository as a bare Git directory",
    )
    srsf_p.add_argument(
        "--sign-key",
        required=True,
        help="distinct release-source Ed25519 private key; never expose it to source execution",
    )
    srsf_p.add_argument(
        "--must-differ-from-key-id",
        action="append",
        required=True,
        metavar="KEY_ID",
        help="required: reject this signing key identity (repeat for PR/admission key identities)",
    )
    srsf_p.add_argument(
        "--force",
        action="store_true",
        help="replace an existing output (default is atomic no-clobber)",
    )
    srsf_p.add_argument(
        "--allow-deny-evidence",
        action="store_true",
        help="explicitly return zero after recording DENY evidence; never use in a release gate",
    )

    vrsf_p = sub.add_parser(
        "verify-release-source-finalized",
        help="verify signed protected-main release-source evidence and exact external bindings",
    )
    vrsf_p.add_argument("bundle", help="signed .rse release-source evidence bundle")
    vrsf_p.add_argument(
        "--trusted-pub",
        required=True,
        help="externally trusted release-source Ed25519 public key",
    )
    vrsf_p.add_argument(
        "--expected-source",
        required=True,
        help="external protected-main source JSON; exact match is required",
    )
    vrsf_p.add_argument(
        "--expected-context",
        required=True,
        help="external release-source context JSON; exact match is required",
    )
    vrsf_p.add_argument(
        "--must-differ-from-key-id",
        action="append",
        required=True,
        metavar="KEY_ID",
        help="required: reject this trusted key identity (repeat for PR/admission key identities)",
    )
    vrsf_p.add_argument(
        "--allow-deny-evidence",
        action="store_true",
        help="explicitly return zero after verifying DENY evidence; never use in a release gate",
    )

    # ----- authenticated producer receipt (non-admitting) ---------------- #
    drsc_p = sub.add_parser(
        "derive-release-source-controls",
        help="derive protected-main source/context from raw Git without a checkout",
    )
    drsc_p.add_argument("verdict", help="regular semantic verdict JSON")
    drsc_p.add_argument(
        "--source",
        required=True,
        help="untrusted-to-verify protected-main source metadata JSON",
    )
    drsc_p.add_argument("--git-repository", required=True, help="raw Git worktree or object store")
    drsc_p.add_argument(
        "--git-repository-bare",
        action="store_true",
        help="treat --git-repository as a bare Git directory",
    )
    drsc_p.add_argument("--source-out", required=True, help="verified source JSON output")
    drsc_p.add_argument("--context-out", required=True, help="verified context JSON output")
    drsc_p.add_argument(
        "--force",
        action="store_true",
        help="replace existing output files (default is atomic no-clobber)",
    )

    crspr_p = sub.add_parser(
        "create-release-source-producer-receipt",
        help="create a canonical non-admitting producer claim after raw-Git rederivation",
    )
    crspr_p.add_argument("verdict", help="regular semantic verdict JSON")
    crspr_p.add_argument("handoff", help="canonical release-source handoff JSON")
    crspr_p.add_argument("--out", required=True, help="canonical producer-receipt JSON output")
    crspr_p.add_argument("--source", required=True, help="verified release-source JSON")
    crspr_p.add_argument("--context", required=True, help="verified release-source context JSON")
    crspr_p.add_argument("--producer", required=True, help="trusted receipt-producer identity JSON")
    crspr_p.add_argument(
        "--bootstrap-guard-sha",
        required=True,
        help="protected SHA-256 of the immutable prior Guard runtime",
    )
    crspr_p.add_argument("--git-repository", required=True, help="raw Git worktree or object store")
    crspr_p.add_argument(
        "--git-repository-bare",
        action="store_true",
        help="treat --git-repository as a bare Git directory",
    )
    crspr_p.add_argument(
        "--force",
        action="store_true",
        help="replace an existing output (default is atomic no-clobber)",
    )

    vrspr_p = sub.add_parser(
        "verify-release-source-producer-receipt",
        help="verify an unsigned producer claim against exact external and raw-Git inputs",
    )
    vrspr_p.add_argument("receipt", help="canonical producer-receipt JSON")
    vrspr_p.add_argument("handoff", help="canonical release-source handoff JSON")
    vrspr_p.add_argument("verdict", help="regular semantic verdict JSON")
    vrspr_p.add_argument("--source", required=True, help="externally expected release-source JSON")
    vrspr_p.add_argument("--context", required=True, help="externally expected release-source context JSON")
    vrspr_p.add_argument("--producer", required=True, help="externally expected producer identity JSON")
    vrspr_p.add_argument(
        "--bootstrap-guard-sha",
        required=True,
        help="protected SHA-256 of the immutable prior Guard runtime",
    )
    vrspr_p.add_argument("--git-repository", required=True, help="raw Git worktree or object store")
    vrspr_p.add_argument(
        "--git-repository-bare",
        action="store_true",
        help="treat --git-repository as a bare Git directory",
    )
    vrspr_p.add_argument(
        "--allow-nonadmitting-evidence",
        action="store_true",
        help="explicitly return zero after non-admitting verification; never use in a release, deployment, or merge gate",
    )

    arspr_p = sub.add_parser(
        "reverify-attested-release-source-producer-receipt",
        help="verify a producer claim then make one fresh constrained GitHub attestation check",
    )
    arspr_p.add_argument("receipt", help="canonical producer-receipt JSON")
    arspr_p.add_argument("handoff", help="canonical release-source handoff JSON")
    arspr_p.add_argument("verdict", help="regular semantic verdict JSON")
    arspr_p.add_argument("--source", required=True, help="externally expected release-source JSON")
    arspr_p.add_argument("--context", required=True, help="externally expected release-source context JSON")
    arspr_p.add_argument("--producer", required=True, help="externally expected producer identity JSON")
    arspr_p.add_argument(
        "--bootstrap-guard-sha",
        required=True,
        help="protected SHA-256 of the immutable prior Guard runtime",
    )
    arspr_p.add_argument(
        "--github-policy",
        required=True,
        help="exact GitHub provider-policy JSON for the producer receipt",
    )
    arspr_p.add_argument("--git-repository", required=True, help="raw Git worktree or object store")
    arspr_p.add_argument(
        "--git-repository-bare",
        action="store_true",
        help="treat --git-repository as a bare Git directory",
    )
    arspr_p.add_argument("--github-receipt-out", required=True, help="provider receipt output")
    arspr_p.add_argument("--github-raw-output-out", required=True, help="provider raw-output file")
    arspr_p.add_argument("--gh-executable", default="gh", help="trusted absolute gh executable")
    arspr_p.add_argument(
        "--timeout-seconds",
        type=int,
        default=120,
        help="bounded GitHub attestation verification timeout",
    )
    arspr_p.add_argument(
        "--allow-nonadmitting-evidence",
        action="store_true",
        help="explicitly return zero after non-admitting verification; never use in a release, deployment, or merge gate",
    )

    srsa_p = sub.add_parser(
        "seal-release-source-admission",
        help="freshly verify a producer receipt, then seal a distinct V2 release-source ALLOW",
    )
    srsa_p.add_argument("receipt", help="canonical producer-receipt JSON")
    srsa_p.add_argument("handoff", help="canonical release-source handoff JSON")
    srsa_p.add_argument("verdict", help="regular semantic verdict JSON")
    srsa_p.add_argument("--out", required=True, help="output signed .rsae release-source admission")
    srsa_p.add_argument("--source", required=True, help="externally expected release-source JSON")
    srsa_p.add_argument("--context", required=True, help="externally expected release-source context JSON")
    srsa_p.add_argument("--producer", required=True, help="externally expected producer identity JSON")
    srsa_p.add_argument("--admitter", required=True, help="externally expected protected C workflow identity JSON")
    srsa_p.add_argument(
        "--bootstrap-guard-sha",
        required=True,
        help="protected SHA-256 of the immutable prior Guard runtime",
    )
    srsa_p.add_argument(
        "--github-policy",
        required=True,
        help="exact GitHub provider-policy JSON for the producer receipt",
    )
    srsa_p.add_argument("--git-repository", required=True, help="raw Git worktree or object store")
    srsa_p.add_argument(
        "--git-repository-bare",
        action="store_true",
        help="treat --git-repository as a bare Git directory",
    )
    srsa_p.add_argument(
        "--git-executable",
        required=True,
        help="trusted absolute POSIX Git executable",
    )
    srsa_p.add_argument(
        "--git-executable-sha256",
        required=True,
        help="external SHA-256 pin for the trusted Git executable",
    )
    srsa_p.add_argument("--github-receipt-out", required=True, help="fresh provider receipt output")
    srsa_p.add_argument("--github-raw-output-out", required=True, help="fresh provider raw-output file")
    srsa_p.add_argument("--gh-executable", required=True, help="trusted absolute gh executable")
    srsa_p.add_argument(
        "--gh-executable-sha256",
        required=True,
        help="external SHA-256 pin for the trusted gh executable",
    )
    srsa_p.add_argument(
        "--provider-isolation-uid",
        required=True,
        type=int,
        help="dedicated non-root POSIX UID used only for the GitHub provider process",
    )
    srsa_p.add_argument(
        "--provider-isolation-gid",
        required=True,
        type=int,
        help="dedicated non-root POSIX GID used only for the GitHub provider process",
    )
    srsa_p.add_argument(
        "--timeout-seconds",
        type=int,
        default=120,
        help="bounded GitHub attestation verification timeout",
    )
    srsa_p.add_argument(
        "--sign-key",
        required=True,
        help="distinct release-source-admission Ed25519 private key",
    )
    srsa_p.add_argument(
        "--sign-pub",
        required=True,
        help="external public key corresponding to --sign-key",
    )
    srsa_p.add_argument(
        "--trusted-finalizer-pub",
        required=True,
        help="public key for the Trusted Finalizer domain",
    )
    srsa_p.add_argument(
        "--artifact-admission-v1-pub",
        required=True,
        help="public key for Artifact Admission V1",
    )
    srsa_p.add_argument(
        "--artifact-digest-admission-v2-pub",
        required=True,
        help="public key for Artifact Digest Admission V2 / GitHub bridge",
    )
    srsa_p.add_argument(
        "--release-source-finalizer-v1-pub",
        required=True,
        help="public key for the DENY-only Release Source Finalizer V1",
    )
    srsa_p.add_argument(
        "--force",
        action="store_true",
        help="replace only the final .rsae output; provider evidence remains no-clobber",
    )

    vrsa_p = sub.add_parser(
        "verify-release-source-admission",
        help="verify a V2 release-source ALLOW against external trust inputs",
    )
    vrsa_p.add_argument("bundle", help="signed .rsae release-source admission")
    vrsa_p.add_argument("--trusted-pub", required=True, help="externally trusted V2 public key")
    vrsa_p.add_argument("--expected-source", required=True, help="external release-source JSON")
    vrsa_p.add_argument("--expected-context", required=True, help="external release-source context JSON")
    vrsa_p.add_argument("--expected-producer", required=True, help="external producer identity JSON")
    vrsa_p.add_argument("--expected-admitter", required=True, help="external protected C workflow identity JSON")
    vrsa_p.add_argument(
        "--expected-bootstrap-guard-sha",
        required=True,
        help="external SHA-256 of the immutable prior Guard runtime",
    )
    vrsa_p.add_argument(
        "--expected-github-policy",
        required=True,
        help="external GitHub producer-attestation policy JSON",
    )
    vrsa_p.add_argument(
        "--expected-git-executable-sha256",
        required=True,
        help="external SHA-256 pin for the Git executable used by the admitting run",
    )
    vrsa_p.add_argument(
        "--expected-gh-executable-sha256",
        required=True,
        help="external SHA-256 pin for the GitHub CLI used by the admitting run",
    )
    vrsa_p.add_argument(
        "--expected-provider-isolation-uid",
        required=True,
        type=int,
        help="external expected non-root POSIX UID for provider verification",
    )
    vrsa_p.add_argument(
        "--expected-provider-isolation-gid",
        required=True,
        type=int,
        help="external expected non-root POSIX GID for provider verification",
    )
    vrsa_p.add_argument(
        "--trusted-finalizer-pub",
        required=True,
        help="public key for the Trusted Finalizer domain",
    )
    vrsa_p.add_argument(
        "--artifact-admission-v1-pub",
        required=True,
        help="public key for Artifact Admission V1",
    )
    vrsa_p.add_argument(
        "--artifact-digest-admission-v2-pub",
        required=True,
        help="public key for Artifact Digest Admission V2 / GitHub bridge",
    )
    vrsa_p.add_argument(
        "--release-source-finalizer-v1-pub",
        required=True,
        help="public key for the DENY-only Release Source Finalizer V1",
    )

    # ----- protected-main release-artifact admission V1 ----------------- #
    sgraa_p = sub.add_parser(
        "seal-github-release-artifact-admission",
        help=(
            "freshly verify one protected-main GitHub artifact attestation and "
            "seal a distinct release-artifact ALLOW"
        ),
    )
    sgraa_p.add_argument(
        "release_source_admission",
        help="signed V2 .rsae release-source admission prerequisite",
    )
    sgraa_p.add_argument(
        "artifact",
        help="external regular release artifact to attest and bind",
    )
    sgraa_p.add_argument(
        "--out",
        required=True,
        help="new signed .raae output; an existing file is never overwritten",
    )
    sgraa_p.add_argument(
        "--builder",
        required=True,
        help="exact protected E workflow builder identity JSON",
    )
    sgraa_p.add_argument(
        "--admitter",
        required=True,
        help="exact key-bearing F workflow admitter identity JSON",
    )
    add_nested_release_source_expectation_arguments(sgraa_p)
    sgraa_p.add_argument(
        "--git-repository",
        required=True,
        help="raw Git worktree or object store used to verify E/F workflow blobs",
    )
    sgraa_p.add_argument(
        "--git-repository-bare",
        action="store_true",
        help="treat --git-repository as a bare Git directory",
    )
    sgraa_p.add_argument(
        "--git-executable",
        required=True,
        help="trusted absolute POSIX Git executable for outer RAAE verification",
    )
    sgraa_p.add_argument(
        "--git-executable-sha256",
        required=True,
        help="external SHA-256 pin for the outer RAAE Git executable",
    )
    sgraa_p.add_argument(
        "--gh-executable",
        required=True,
        help="trusted absolute GitHub CLI executable used for fresh verification",
    )
    sgraa_p.add_argument(
        "--gh-executable-sha256",
        required=True,
        help="external SHA-256 pin for the outer RAAE GitHub CLI executable",
    )
    sgraa_p.add_argument(
        "--provider-isolation-uid",
        required=True,
        type=int,
        help="dedicated non-root POSIX UID for the outer provider process",
    )
    sgraa_p.add_argument(
        "--provider-isolation-gid",
        required=True,
        type=int,
        help="dedicated non-root POSIX GID for the outer provider process",
    )
    sgraa_p.add_argument(
        "--timeout-seconds",
        type=int,
        default=120,
        help="bounded fresh GitHub attestation verification timeout (default: 120)",
    )
    sgraa_p.add_argument(
        "--sign-key",
        required=True,
        help="distinct release-artifact-admission Ed25519 private key",
    )
    sgraa_p.add_argument(
        "--sign-pub",
        required=True,
        help="external public key corresponding to --sign-key",
    )
    add_release_artifact_key_registry_arguments(sgraa_p)

    vgraa_p = sub.add_parser(
        "verify-github-release-artifact-admission",
        help="verify one .raae and its detached artifact entirely offline",
    )
    vgraa_p.add_argument("bundle", help="signed .raae release-artifact admission")
    vgraa_p.add_argument("artifact", help="external regular artifact bound by the .raae")
    vgraa_p.add_argument(
        "--trusted-pub",
        required=True,
        help="externally trusted release-artifact-admission public key",
    )
    vgraa_p.add_argument(
        "--expected-builder",
        required=True,
        help="external protected E workflow builder identity JSON",
    )
    vgraa_p.add_argument(
        "--expected-admitter",
        required=True,
        help="external key-bearing F workflow admitter identity JSON",
    )
    add_nested_release_source_expectation_arguments(vgraa_p)
    vgraa_p.add_argument(
        "--expected-git-executable-sha256",
        required=True,
        help="external SHA-256 pin for the outer RAAE Git executable",
    )
    vgraa_p.add_argument(
        "--expected-gh-executable-sha256",
        required=True,
        help="external SHA-256 pin for the outer RAAE GitHub CLI executable",
    )
    vgraa_p.add_argument(
        "--expected-provider-isolation-uid",
        required=True,
        type=int,
        help="external expected non-root POSIX UID for the outer provider process",
    )
    vgraa_p.add_argument(
        "--expected-provider-isolation-gid",
        required=True,
        type=int,
        help="external expected non-root POSIX GID for the outer provider process",
    )
    add_release_artifact_key_registry_arguments(vgraa_p)

    # ----- artifact admission --------------------------------------------- #
    saa_p = sub.add_parser(
        "seal-artifact-admission",
        help="bind one regular file to an externally verified finalizer ALLOW",
    )
    saa_p.add_argument(
        "artifact",
        help="regular file to bind; this command does not establish build provenance",
    )
    saa_p.add_argument("finalizer_bundle", help="signed .evb from the Trusted Finalizer")
    saa_p.add_argument("--out", required=True, help="output signed .eab artifact binding")
    saa_p.add_argument(
        "--finalizer-pub",
        required=True,
        help="externally trusted Ed25519 public key for the finalizer",
    )
    saa_p.add_argument(
        "--expected-source",
        required=True,
        help="external finalizer source JSON; exact match is required",
    )
    saa_p.add_argument(
        "--expected-context",
        required=True,
        help="external finalizer context JSON; exact match is required",
    )
    saa_p.add_argument(
        "--sign-key",
        required=True,
        help="artifact-admission Ed25519 private key in a post-build protected job",
    )
    saa_p.add_argument(
        "--force",
        action="store_true",
        help="replace an existing output (default is atomic no-clobber)",
    )

    vaa_p = sub.add_parser(
        "verify-artifact-admission",
        help="verify a file artifact binding and its external finalizer prerequisite",
    )
    vaa_p.add_argument("binding", help="signed .eab artifact binding")
    vaa_p.add_argument("artifact", help="regular file artifact to hash independently")
    vaa_p.add_argument("finalizer_bundle", help="signed .evb from the Trusted Finalizer")
    vaa_p.add_argument(
        "--trusted-pub",
        required=True,
        help="externally trusted Ed25519 public key for the artifact-admission signer",
    )
    vaa_p.add_argument(
        "--finalizer-pub",
        required=True,
        help="externally trusted Ed25519 public key for the finalizer",
    )
    vaa_p.add_argument(
        "--expected-source",
        required=True,
        help="external finalizer source JSON; exact match is required",
    )
    vaa_p.add_argument(
        "--expected-context",
        required=True,
        help="external finalizer context JSON; exact match is required",
    )

    # ----- artifact digest admission V2 ---------------------------------- #
    sada_p = sub.add_parser(
        "seal-artifact-digest-admission",
        help="bind one exact artifact or OCI digest to a verified finalizer ALLOW",
    )
    sada_p.add_argument("finalizer_bundle", help="signed .evb from the Trusted Finalizer")
    sada_p.add_argument(
        "--subject-kind",
        required=True,
        choices=("artifact-sha256", "oci-manifest-or-index"),
        help="immutable subject type; this command never accepts a tag, URL, or registry name",
    )
    sada_p.add_argument(
        "--subject-digest",
        required=True,
        help="exact lowercase sha256:<64-hex> digest from a protected external boundary",
    )
    sada_p.add_argument(
        "--provenance",
        required=True,
        help="regular opaque provenance file to bind by exact SHA-256 bytes",
    )
    sada_p.add_argument(
        "--provenance-identity",
        required=True,
        help="external provenance identity label; it is bound, not independently verified",
    )
    sada_p.add_argument("--out", required=True, help="output signed V2 artifact binding")
    sada_p.add_argument(
        "--finalizer-pub",
        required=True,
        help="externally trusted Ed25519 public key for the finalizer",
    )
    sada_p.add_argument(
        "--expected-source",
        required=True,
        help="external finalizer source JSON; exact match is required",
    )
    sada_p.add_argument(
        "--expected-context",
        required=True,
        help="external finalizer context JSON; exact match is required",
    )
    sada_p.add_argument(
        "--sign-key",
        required=True,
        help="separate V2 artifact-admission Ed25519 private key in a protected job",
    )
    sada_p.add_argument(
        "--force",
        action="store_true",
        help="replace an existing output (default is atomic no-clobber)",
    )

    vada_p = sub.add_parser(
        "verify-artifact-digest-admission",
        help="verify a V2 immutable digest binding with external finalizer and provenance inputs",
    )
    vada_p.add_argument("binding", help="signed V2 artifact binding")
    vada_p.add_argument("finalizer_bundle", help="signed .evb from the Trusted Finalizer")
    vada_p.add_argument(
        "--subject-kind",
        required=True,
        choices=("artifact-sha256", "oci-manifest-or-index"),
        help="expected immutable subject type",
    )
    vada_p.add_argument(
        "--subject-digest",
        required=True,
        help="expected exact lowercase sha256:<64-hex> digest",
    )
    vada_p.add_argument(
        "--provenance",
        required=True,
        help="expected regular opaque provenance file",
    )
    vada_p.add_argument(
        "--provenance-identity",
        required=True,
        help="expected external provenance identity label",
    )
    vada_p.add_argument(
        "--trusted-pub",
        required=True,
        help="externally trusted Ed25519 public key for the V2 artifact-admission signer",
    )
    vada_p.add_argument(
        "--finalizer-pub",
        required=True,
        help="externally trusted Ed25519 public key for the finalizer",
    )
    vada_p.add_argument(
        "--expected-source",
        required=True,
        help="external finalizer source JSON; exact match is required",
    )
    vada_p.add_argument(
        "--expected-context",
        required=True,
        help="external finalizer context JSON; exact match is required",
    )

    # ----- GitHub Artifact Attestation protected-boundary adapter --------- #
    gar_p = sub.add_parser(
        "github-attestation-receipt",
        help="run one fixed-policy GitHub artifact attestation verification and retain its receipt",
    )
    gar_p.add_argument("artifact", help="regular immutable artifact file to verify")
    gar_p.add_argument(
        "--receipt-out",
        required=True,
        help="new canonical receipt output; never overwrites an existing file",
    )
    gar_p.add_argument(
        "--raw-output-out",
        required=True,
        help="new exact GitHub CLI JSON output; never overwrites an existing file",
    )
    add_github_attestation_policy_arguments(gar_p)
    add_github_attestation_verifier_arguments(gar_p)

    vgar_p = sub.add_parser(
        "verify-github-attestation-receipt",
        help="check retained GitHub attestation receipt/output bytes against exact external policy",
    )
    vgar_p.add_argument("receipt", help="canonical retained GitHub attestation receipt")
    vgar_p.add_argument("artifact", help="regular artifact expected by the receipt")
    vgar_p.add_argument("raw_output", help="retained exact GitHub CLI JSON output")
    add_github_attestation_policy_arguments(vgar_p)

    rgar_p = sub.add_parser(
        "reverify-github-attestation-receipt",
        help="perform a fresh fixed-policy GitHub artifact attestation verification",
    )
    rgar_p.add_argument("receipt", help="canonical retained GitHub attestation receipt")
    rgar_p.add_argument("artifact", help="regular artifact expected by the receipt")
    add_github_attestation_policy_arguments(rgar_p)
    add_github_attestation_verifier_arguments(rgar_p)

    sgaa_p = sub.add_parser(
        "seal-github-attestation-admission",
        help=(
            "freshly verify one GitHub artifact attestation, then bind it to a "
            "Trusted Finalizer ALLOW through the separate V2 admission key"
        ),
    )
    sgaa_p.add_argument(
        "artifact",
        help="regular immutable artifact file; this command does not prove publication or deployment",
    )
    sgaa_p.add_argument(
        "finalizer_bundle",
        help="signed Trusted Finalizer .evb that must independently verify as ALLOW",
    )
    sgaa_p.add_argument(
        "--receipt-out",
        required=True,
        help="new canonical GitHub verification receipt; never overwrites an existing file",
    )
    sgaa_p.add_argument(
        "--raw-output-out",
        required=True,
        help="new exact GitHub CLI JSON output; never overwrites an existing file",
    )
    sgaa_p.add_argument(
        "--out",
        required=True,
        help="new signed V2 admission binding; never overwrites an existing file",
    )
    sgaa_p.add_argument(
        "--finalizer-pub",
        required=True,
        help="externally trusted Ed25519 public key for the finalizer",
    )
    sgaa_p.add_argument(
        "--expected-source",
        required=True,
        help="external finalizer source JSON; exact match is required",
    )
    sgaa_p.add_argument(
        "--expected-context",
        required=True,
        help=(
            "external finalizer context JSON; exact match is required and its head_sha "
            "must equal --source-digest"
        ),
    )
    sgaa_p.add_argument(
        "--sign-key",
        required=True,
        help="separate V2 artifact-admission Ed25519 private key in a protected job",
    )
    add_github_attestation_policy_arguments(sgaa_p)
    add_github_attestation_verifier_arguments(sgaa_p)

    vgaa_p = sub.add_parser(
        "verify-github-attestation-admission",
        help=(
            "verify a retained GitHub attestation receipt and its V2 admission "
            "binding against exact external finalizer and provider-policy inputs"
        ),
    )
    vgaa_p.add_argument("binding", help="signed V2 GitHub attestation admission binding")
    vgaa_p.add_argument("artifact", help="regular artifact expected by the receipt and binding")
    vgaa_p.add_argument("receipt", help="canonical retained GitHub attestation receipt")
    vgaa_p.add_argument("raw_output", help="retained exact GitHub CLI JSON output")
    vgaa_p.add_argument("finalizer_bundle", help="signed Trusted Finalizer .evb")
    vgaa_p.add_argument(
        "--trusted-pub",
        required=True,
        help="externally trusted Ed25519 public key for the V2 admission signer",
    )
    vgaa_p.add_argument(
        "--finalizer-pub",
        required=True,
        help="externally trusted Ed25519 public key for the finalizer",
    )
    vgaa_p.add_argument(
        "--expected-source",
        required=True,
        help="external finalizer source JSON; exact match is required",
    )
    vgaa_p.add_argument(
        "--expected-context",
        required=True,
        help=(
            "external finalizer context JSON; exact match is required and its head_sha "
            "must equal --source-digest"
        ),
    )
    add_github_attestation_policy_arguments(vgaa_p)

    # ----- verify-bundle ---------------------------------------------------- #
    vb_p = sub.add_parser(
        "verify-bundle",
        help="authenticate an evidence envelope against an external key and exact context",
    )
    vb_p.add_argument("bundle", help="the .evb evidence envelope")
    vb_p.add_argument(
        "--trusted-pub",
        required=True,
        help="externally trusted Ed25519 public key; a bundled key is never a trust root",
    )
    vb_p.add_argument(
        "--expect-context",
        required=True,
        help="external expected-context JSON; exact match is required to prevent replay",
    )
    vb_p.add_argument(
        "--require-pass",
        action="store_true",
        help="also act as a gate: exit 0 only for an authenticated semantic PASS",
    )

    # ----- doctor -------------------------------------------------------- #
    d_p = sub.add_parser(
        "doctor",
        help="report the environment EvoGuard needs (version, platform, git/patch)",
    )
    d_p.add_argument(
        "--json", dest="doctor_json", action="store_true",
        help="emit the environment report as JSON instead of human text",
    )

    # ----- pack-doctor ---------------------------------------------------- #
    pd_p = sub.add_parser(
        "pack-doctor",
        help="validate a verifier pack directory (manifest schema, tests, digest)",
    )
    pd_p.add_argument("pack", help="the pack directory to validate")
    pd_p.add_argument(
        "--json", dest="pack_json", action="store_true",
        help="emit the validation report as JSON",
    )

    # ----- init ---------------------------------------------------------- #
    i_p = sub.add_parser(
        "init",
        help="scaffold a ready-to-use EvoGuard GitHub Actions workflow",
    )
    i_p.add_argument(
        "--path", default=".github/workflows/evoguard.yml",
        help="where to write the workflow (default: .github/workflows/evoguard.yml)",
    )
    i_p.add_argument(
        "--test-command", dest="test_command", default="python -m pytest -q",
        help="test command to write into the trusted .evoguard.json policy "
        "(default: python -m pytest -q; the -m form puts the repo root on sys.path)",
    )
    i_p.add_argument(
        "--policy-path", default=None,
        help="where to write the trusted policy (default: .evoguard.json at the "
        "repository root inferred from --path)",
    )
    i_p.add_argument(
        "--ref",
        required=True,
        type=immutable_release_ref,
        help="exact EvoGuard SemVer tag (vX.Y.Z) or full 40-hex commit SHA; branches are refused",
    )
    i_p.add_argument("--force", action="store_true", help="overwrite an existing workflow file")
    i_p.add_argument(
        "--stdout", action="store_true",
        help="print the workflow to stdout instead of writing a file",
    )
    i_p.add_argument(
        "--private-evoguard", dest="private_evoguard", action="store_true",
        help="generate a pip-install workflow for a private EvoGuard repo — uses a "
        "PAT stored in an Actions secret instead of the default cross-repo action "
        "(required when the EvoGuard repo is not accessible with the default GITHUB_TOKEN)",
    )
    i_p.add_argument(
        "--evoguard-token-secret", dest="github_actions_credential_key",
        default="EVOGUARD_TOKEN",
        help="name of the Actions secret that holds the PAT for the private EvoGuard "
        "repo (default: EVOGUARD_TOKEN; only used with --private-evoguard)",
    )

    # ----- version ------------------------------------------------------- #
    sub.add_parser("version", help="print the EvoGuard version")

    return parser
