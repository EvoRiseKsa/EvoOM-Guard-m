# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""The ``evo-guard`` command line for evidence-bound change verification.

Subcommands:

  * ``evo-guard guard`` — verify a candidate change against a repo's tests, rejecting
    any edit to the tests or their configuration.
  * ``evo-guard verify-record`` — verify a verdict's structural/semantic contract.
  * ``evo-guard verify-bundle`` — authenticate a portable verdict envelope.
  * ``evo-guard finalize-record`` — seal a semantic record against trusted context.
  * ``evo-guard finalizer-handoff`` — bind a re-verification record to source metadata.
  * ``evo-guard seal-finalizer`` — sign only a handoff matched to external metadata.
  * ``evo-guard release-source-handoff`` — bind a protected-main re-verification
    record to a distinct release-source contract.
  * ``evo-guard seal-release-source-finalizer`` — sign that release-source handoff
    only after an external control plane exactly matches it.
  * ``evo-guard verify-release-source-finalized`` — verify the separate release
    source envelope and its exact control-plane bindings.
  * ``evo-guard derive-release-source-controls`` — derive protected-main source/context
    from raw Git without a checkout.
  * ``evo-guard create-release-source-producer-receipt`` — create a canonical
    non-admitting producer claim for later provider authentication.
  * ``evo-guard verify-release-source-producer-receipt`` — recheck that claim,
    raw-Git bindings, and its exact execution record without contacting a provider.
  * ``evo-guard reverify-attested-release-source-producer-receipt`` — perform
    those checks, then make one fresh constrained GitHub verification.
  * ``evo-guard seal-release-source-admission`` — issue a separately keyed V2
    source ``ALLOW`` only after that fresh provider verification succeeds.
  * ``evo-guard verify-release-source-admission`` — verify the V2 source
    authorization against external source, producer, runtime, policy, and key roots.
  * ``evo-guard seal-github-release-artifact-admission`` — freshly verify and
    seal one protected-main release artifact rooted in a V2 source admission.
  * ``evo-guard verify-github-release-artifact-admission`` — verify that release
    artifact admission and its detached artifact entirely offline.
  * ``evo-guard seal-artifact-admission`` — bind one file to a verified finalizer ALLOW.
  * ``evo-guard verify-artifact-admission`` — verify that file/finalizer binding.
  * ``evo-guard seal-artifact-digest-admission`` — bind one immutable digest to a finalizer.
  * ``evo-guard verify-artifact-digest-admission`` — verify that V2 digest relation.
  * ``evo-guard github-attestation-receipt`` — record one constrained GitHub verification.
  * ``evo-guard verify-github-attestation-receipt`` — check retained attestation bytes.
  * ``evo-guard reverify-github-attestation-receipt`` — make a fresh constrained GitHub check.
  * ``evo-guard seal-github-attestation-admission`` — bind one freshly verified
    GitHub attestation to a Trusted Finalizer ALLOW through the separate V2 key.
  * ``evo-guard verify-github-attestation-admission`` — check that retained V2 relation.
  * ``evo-guard version`` — print the EvoGuard version.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
import platform
import re
import shutil
import sys
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TypedDict

from evoom_guard import __version__
from evoom_guard.pack_manifest import (
    PACK_DIGEST_FORMAT,
    PackManifestError,
    load_pack_manifest,
    pack_digest,
    pack_test_files,
)
from evoom_guard.policy.config import ConfigError
from evoom_guard.policy.config import load_config as _load_config

if TYPE_CHECKING:
    from evoom_guard.evidence_bundle import EvidenceMaterial
    from evoom_guard.github_attestation import GitHubAttestationProviderIsolation

MAX_OFFLINE_RECORD_BYTES = 8 * 1024 * 1024
MAX_CONTEXT_INPUT_BYTES = 1 * 1024 * 1024
MAX_SIGNATURE_FILE_BYTES = 4096


class _GitHubAttestationPolicyKwargs(TypedDict):
    """Exact provider-policy keyword arguments shared by CLI adapters.

    A plain ``dict[str, str]`` loses the names of these keys to static type
    checkers.  Keeping the contract explicit prevents a policy string from
    ever being confused with unrelated keyword-only controls such as
    ``force``.
    """

    repository: str
    signer_workflow: str
    signer_digest: str
    source_ref: str
    source_digest: str
    cert_oidc_issuer: str


def _configure_stdio() -> None:
    """Make Unicode verdicts reliable on legacy Windows console code pages."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def _read_text(path: str) -> str:
    """Read a file, or stdin when *path* is ``-``."""
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as f:
        return f.read()


def _read_bounded_bytes(path: str, *, limit: int, label: str) -> bytes:
    if path == "-":
        binary = getattr(sys.stdin, "buffer", None)
        data = (
            binary.read(limit + 1)
            if binary is not None
            else sys.stdin.read(limit + 1).encode("utf-8")
        )
    else:
        with open(path, "rb") as handle:
            data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{label} exceeds the {limit}-byte input limit")
    return data


_GITHUB_ACTIONS_CREDENTIAL_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_IMMUTABLE_RELEASE_REF_RE = re.compile(r"(?:v\d+\.\d+\.\d+|[0-9a-f]{40})\Z")


def _github_actions_credential_key(value: object) -> str:
    """Validate the *name* of a GitHub Actions credential reference.

    ``evo-guard init --private-evoguard`` never receives a PAT value. It writes
    a literal ``${{ secrets.NAME }}`` expression into a workflow for GitHub to
    resolve later. Restricting ``NAME`` prevents a caller from injecting YAML,
    shell syntax, or a second expression into that generated template.
    """
    if not isinstance(value, str) or _GITHUB_ACTIONS_CREDENTIAL_KEY_RE.fullmatch(value) is None:
        raise ValueError(
            "--evoguard-token-secret must be a GitHub Actions credential name "
            "containing only letters, digits, and underscores"
        )
    if value.upper().startswith("GITHUB_"):
        raise ValueError("--evoguard-token-secret must not begin with GITHUB_")
    return value


def _immutable_release_ref(value: object) -> str:
    """Accept only an exact release tag or full commit SHA for ``init``.

    Workflow scaffolding is a security-sensitive operation: silently choosing a
    branch, an unverified tag, or a stale "latest" value makes the generated
    gate less reproducible than the user believes. This local parser cannot
    establish remote tag availability; it enforces the immutable-reference
    shape and refuses moving branch names. The caller chooses a published tag
    or full commit SHA explicitly.
    """
    if not isinstance(value, str) or _IMMUTABLE_RELEASE_REF_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "--ref must be an exact release tag (vX.Y.Z) or a full 40-hex commit SHA"
        )
    return value


def _path_is_within(path: str, root: str) -> bool:
    """Return whether ``path`` resolves inside ``root``.

    Real paths matter here: a candidate checkout must not be able to smuggle its
    policy in through a symlink when a caller supplied an apparently external
    ``--config`` file.
    """
    try:
        return (
            os.path.commonpath((os.path.realpath(path), os.path.realpath(root)))
            == os.path.realpath(root)
        )
    except ValueError:
        # Different Windows drives, for example, cannot be nested.
        return False


def _config_path_for_guard(args: argparse.Namespace) -> str | None:
    """Resolve the policy file from a trusted side of a change comparison.

    Repository policy can shape the command, protected paths, and assurance
    floor. It must therefore never be read from the candidate checkout. The
    edit-block and ``--base/--head`` forms have an explicit baseline directory,
    so an omitted config resolves there. A unified diff has only a candidate
    checkout; it deliberately gets *no* implicit config. Automation must
    materialize a base-owned policy outside that checkout and pass its absolute
    path explicitly.
    """
    if args.no_config:
        return None

    if args.diff is not None:
        if args.config is None:
            raise ConfigError(
                "--diff requires an explicit trusted --config outside the candidate "
                "checkout, or --no-config"
            )
        if not os.path.isabs(args.config):
            raise ConfigError(
                "--diff requires --config to be an absolute path outside the "
                "candidate checkout (or use --no-config)"
            )
        head = args.repo or os.getcwd()
        if _path_is_within(args.config, head):
            raise ConfigError(
                "--diff refuses a config from the candidate checkout; materialize "
                "the policy from the trusted base outside that checkout"
            )
        return os.path.abspath(args.config)

    if args.base and args.head:
        baseline = args.base
        candidate = args.head
    elif args.repo and args.patch:
        # The patch is text, not a checked-out candidate tree: ``repo`` is the
        # trusted baseline for this input form.
        baseline = args.repo
        candidate = None
    else:
        return None

    if args.config is None:
        config_path = os.path.abspath(os.path.join(baseline, ".evoguard.json"))
        if not _path_is_within(config_path, baseline):
            raise ConfigError(
                "baseline .evoguard.json must resolve inside the trusted baseline "
                "directory"
            )
        return config_path
    if os.path.isabs(args.config):
        if candidate and _path_is_within(args.config, candidate):
            raise ConfigError(
                "--base/--head refuses a config from the candidate checkout; "
                "use the base policy or an external trusted policy file"
            )
        return os.path.abspath(args.config)

    candidate_path = os.path.abspath(os.path.join(baseline, args.config))
    if not _path_is_within(candidate_path, baseline):
        raise ConfigError("--config must stay inside the trusted baseline directory")
    return candidate_path


def _add_github_attestation_policy_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the fixed provider policy inputs; no caller can omit a trust pin."""

    parser.add_argument(
        "--repo",
        required=True,
        help="exact GitHub owner/repository whose artifact attestation is verified",
    )
    parser.add_argument(
        "--signer-workflow",
        required=True,
        help="same-repository workflow path; GitHub URL aliases are normalized before gh",
    )
    parser.add_argument(
        "--signer-digest",
        required=True,
        help="exact lowercase 40- or 64-hex Git object ID for the signer workflow",
    )
    parser.add_argument(
        "--source-ref",
        required=True,
        help="exact canonical refs/heads/... or refs/tags/... source reference",
    )
    parser.add_argument(
        "--source-digest",
        required=True,
        help="exact lowercase 40- or 64-hex Git object ID for the source",
    )
    parser.add_argument(
        "--cert-oidc-issuer",
        required=True,
        help="must be exactly https://token.actions.githubusercontent.com",
    )


def _add_github_attestation_verifier_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--gh-executable",
        default="gh",
        help=(
            "protected GitHub CLI executable (default: gh); local gh config is ignored, "
            "so a protected GH_TOKEN or GITHUB_TOKEN is required"
        ),
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=120,
        help="bounded GitHub CLI verification timeout in seconds (default: 120)",
    )
    parser.add_argument(
        "--gh-executable-sha256",
        default=None,
        help=(
            "opt-in POSIX isolation: exact lowercase SHA-256 of the absolute "
            "--gh-executable"
        ),
    )
    parser.add_argument(
        "--provider-isolation-uid",
        type=int,
        default=None,
        help="opt-in POSIX isolation: distinct non-root UID for the provider process",
    )
    parser.add_argument(
        "--provider-isolation-gid",
        type=int,
        default=None,
        help="opt-in POSIX isolation: distinct non-root GID for the provider process",
    )


def _add_release_artifact_key_registry_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    """Add the five earlier public roots required by the RAAE key registry."""

    parser.add_argument(
        "--trusted-finalizer-pub",
        required=True,
        help="public key for the Trusted Finalizer domain",
    )
    parser.add_argument(
        "--artifact-admission-v1-pub",
        required=True,
        help="public key for Artifact Admission V1",
    )
    parser.add_argument(
        "--artifact-digest-admission-v2-pub",
        required=True,
        help="public key for Artifact Digest Admission V2 / GitHub bridge",
    )
    parser.add_argument(
        "--release-source-finalizer-v1-pub",
        required=True,
        help="public key for the DENY-only Release Source Finalizer V1",
    )
    parser.add_argument(
        "--release-source-admission-v2-pub",
        required=True,
        help=(
            "trusted V2 release-source admission public key and fifth earlier "
            "RAAE trust root"
        ),
    )


def _add_nested_release_source_expectation_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    """Add exact external RSAE expectations without conflating outer RAAE pins."""

    parser.add_argument(
        "--expected-release-source",
        required=True,
        help="external protected-main release-source JSON",
    )
    parser.add_argument(
        "--expected-release-source-context",
        required=True,
        help="external release-source context JSON",
    )
    parser.add_argument(
        "--expected-release-source-producer",
        required=True,
        help="external release-source producer identity JSON",
    )
    parser.add_argument(
        "--expected-release-source-admitter",
        required=True,
        help="external protected C workflow identity JSON",
    )
    parser.add_argument(
        "--expected-release-source-bootstrap-guard-sha",
        required=True,
        help="external SHA-256 of the immutable Guard runtime embedded by the RSAE",
    )
    parser.add_argument(
        "--expected-release-source-github-policy",
        required=True,
        help="external GitHub policy JSON for the embedded release-source admission",
    )
    parser.add_argument(
        "--expected-release-source-git-executable-sha256",
        required=True,
        help="external RSAE Git executable SHA-256 pin",
    )
    parser.add_argument(
        "--expected-release-source-gh-executable-sha256",
        required=True,
        help="external RSAE GitHub CLI executable SHA-256 pin",
    )
    parser.add_argument(
        "--expected-release-source-provider-isolation-uid",
        required=True,
        type=int,
        help="external RSAE provider-isolation POSIX UID",
    )
    parser.add_argument(
        "--expected-release-source-provider-isolation-gid",
        required=True,
        type=int,
        help="external RSAE provider-isolation POSIX GID",
    )


def build_parser() -> argparse.ArgumentParser:
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
    _add_nested_release_source_expectation_arguments(sgraa_p)
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
    _add_release_artifact_key_registry_arguments(sgraa_p)

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
    _add_nested_release_source_expectation_arguments(vgraa_p)
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
    _add_release_artifact_key_registry_arguments(vgraa_p)

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
    _add_github_attestation_policy_arguments(gar_p)
    _add_github_attestation_verifier_arguments(gar_p)

    vgar_p = sub.add_parser(
        "verify-github-attestation-receipt",
        help="check retained GitHub attestation receipt/output bytes against exact external policy",
    )
    vgar_p.add_argument("receipt", help="canonical retained GitHub attestation receipt")
    vgar_p.add_argument("artifact", help="regular artifact expected by the receipt")
    vgar_p.add_argument("raw_output", help="retained exact GitHub CLI JSON output")
    _add_github_attestation_policy_arguments(vgar_p)

    rgar_p = sub.add_parser(
        "reverify-github-attestation-receipt",
        help="perform a fresh fixed-policy GitHub artifact attestation verification",
    )
    rgar_p.add_argument("receipt", help="canonical retained GitHub attestation receipt")
    rgar_p.add_argument("artifact", help="regular artifact expected by the receipt")
    _add_github_attestation_policy_arguments(rgar_p)
    _add_github_attestation_verifier_arguments(rgar_p)

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
    _add_github_attestation_policy_arguments(sgaa_p)
    _add_github_attestation_verifier_arguments(sgaa_p)

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
    _add_github_attestation_policy_arguments(vgaa_p)

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
        type=_immutable_release_ref,
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


def cmd_guard(args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    """Execute ``evo-guard guard`` — the untrusted-change verification gate."""
    from evoom_guard.guard import (
        REASON_NO_VERIFIABLE_CHANGES,
        REASON_VERIFIER_PACK_INVALID,
        _UnverifiableChangedPathsError,
        blocks_from_dirs,
        guard,
        guard_from_diff,
        input_error_result,
        render_report,
        serialize_candidate_blocks,
        verifier_pack_trust_error,
        write_json,
        write_sarif,
    )

    # Effective settings: an explicit CLI flag wins; else a policy loaded from the
    # trusted baseline; else the built-in default. In --diff mode a trusted policy
    # or an explicit --no-config choice is required. A present but broken trusted
    # policy is fail-closed: exit 2, never weaker defaults.
    try:
        config_path = _config_path_for_guard(args)
        cfg = (
            _load_config(
                config_path,
                required=args.config is not None,
                out=out,
            )
            if config_path
            else {}
        )
    except ConfigError as exc:
        out(f"config error (fail-closed): {exc}")
        return 2

    def _policy_bool(key: str, cli_value: bool | None) -> bool:
        """Resolve a tri-state CLI flag against the already trusted policy."""
        if cli_value is not None:
            return cli_value
        value = cfg.get(key)
        return value if isinstance(value, bool) else False

    # These must be resolved *before* validation.  In pull_request mode the
    # Action deliberately supplies no candidate workflow flags, so the verified
    # base policy is the only source for these judge-shaping settings.
    blackbox = _policy_bool("blackbox", args.blackbox)
    blackbox_only = _policy_bool("blackbox_only", args.blackbox_only)
    diff_coverage_requested = _policy_bool("diff_coverage", args.diff_coverage)
    baseline_evidence = _policy_bool("baseline_evidence", args.baseline_evidence)
    require_demonstrated_fix = _policy_bool(
        "require_demonstrated_fix", args.require_demonstrated_fix
    )
    strict_harness = _policy_bool("strict_harness", args.strict_harness)

    if blackbox_only and not blackbox:
        out("usage: --blackbox-only requires --blackbox")
        return 2

    cfg_tc = args.test_command if args.test_command is not None else cfg.get("test_command")
    if isinstance(cfg_tc, str):
        # A string test_command containing shell operators must be wrapped in sh -c
        # rather than naively split — naive splitting would produce wrong tokens and
        # lose the operator semantics (e.g. "pnpm install && vitest run").split()
        # gives ["pnpm", "install", "&&", "vitest", "run"] which subprocess treats as
        # five literal arguments, not a shell pipeline.
        _SHELL_OPS = ("&&", "||", ";", "|", ">", "<", "$(", "`")
        if any(op in cfg_tc for op in _SHELL_OPS):
            test_command: list[str] | None = ["sh", "-c", cfg_tc]
        else:
            test_command = cfg_tc.split()
    elif isinstance(cfg_tc, list):
        test_command = [str(t) for t in cfg_tc]
    else:
        test_command = None

    cfg_sc = cfg.get("setup_command")
    setup_command: list[str] | None = [str(t) for t in cfg_sc] if isinstance(cfg_sc, list) else None
    cfg_tsoh = cfg.get("trust_setup_on_host")
    trust_setup_on_host = (
        args.trust_setup_on_host
        if args.trust_setup_on_host is not None
        else (cfg_tsoh if isinstance(cfg_tsoh, bool) else False)
    )
    cfg_sog = cfg.get("setup_output_globs")
    setup_output_globs = (
        tuple(str(glob) for glob in cfg_sog) if isinstance(cfg_sog, list) else ()
    )
    # A policy-owned pack makes the Action's PR mode usable without taking its
    # location from a candidate-controlled workflow.  Relative config values
    # are relative to the trusted policy file, never the candidate cwd.
    cfg_pack = cfg.get("verifier_pack")
    verifier_pack = args.verifier_pack
    if verifier_pack is None and isinstance(cfg_pack, str):
        # A value in cfg proves a config file was loaded; keep the invariant
        # explicit so relative paths cannot accidentally fall back to cwd.
        if config_path is None:
            raise AssertionError("configured verifier pack without a policy path")
        verifier_pack = (
            cfg_pack
            if os.path.isabs(cfg_pack)
            else os.path.abspath(
                os.path.join(os.path.dirname(os.path.abspath(config_path)), cfg_pack)
            )
        )
    cfg_pack_sha = cfg.get("expect_verifier_pack_sha256")
    expect_verifier_pack_sha256 = (
        args.expect_verifier_pack_sha256
        if args.expect_verifier_pack_sha256 is not None
        else (cfg_pack_sha if isinstance(cfg_pack_sha, str) else None)
    )
    if expect_verifier_pack_sha256 is not None:
        if re.fullmatch(r"[0-9a-fA-F]{64}", expect_verifier_pack_sha256) is None:
            out("usage: --expect-verifier-pack-sha256 must be exactly 64 hex characters")
            return 2
        if not verifier_pack:
            out("usage: --expect-verifier-pack-sha256 requires --verifier-pack")
            return 2
        expect_verifier_pack_sha256 = expect_verifier_pack_sha256.lower()

    if args.protected is not None:
        protected: tuple[str, ...] = tuple(args.protected)
    else:
        cfg_prot = cfg.get("protected")
        protected = tuple(str(g) for g in cfg_prot) if isinstance(cfg_prot, list) else ()

    if args.allow is not None:
        allow: tuple[str, ...] = tuple(args.allow)
    else:
        cfg_allow = cfg.get("allow")
        allow = tuple(str(g) for g in cfg_allow) if isinstance(cfg_allow, list) else ()

    cfg_to = cfg.get("timeout")
    timeout = args.timeout if args.timeout is not None else (cfg_to if isinstance(cfg_to, int) else 120)
    cfg_ml = cfg.get("mem_limit")
    mem_limit = args.mem_limit if args.mem_limit is not None else (cfg_ml if isinstance(cfg_ml, int) else 1024)
    if timeout < 1:
        out("usage: --timeout must be a positive integer")
        return 2
    if mem_limit < 0:
        out("usage: --mem-limit must be a non-negative integer")
        return 2

    cfg_ant = cfg.get("allow_new_tests")
    allow_new_tests = (
        args.allow_new_tests if args.allow_new_tests is not None
        else (cfg_ant if isinstance(cfg_ant, bool) else False)
    )

    # Protected policy contract: assurance floors + coverage gate + identity may
    # live in the (candidate-untouchable) .evoguard.json; a CLI flag still wins.
    # (_load_config already validated types fail-closed; the isinstance checks
    # here only narrow for the type checker.)
    _cfg_rri = cfg.get("require_report_integrity")
    require_report_integrity: str | None = (
        args.require_report_integrity
        if args.require_report_integrity is not None
        else (_cfg_rri if isinstance(_cfg_rri, str) else None)
    )
    _cfg_rci = cfg.get("require_candidate_isolation")
    require_candidate_isolation: str | None = (
        args.require_candidate_isolation
        if args.require_candidate_isolation is not None
        else (_cfg_rci if isinstance(_cfg_rci, str) else None)
    )
    _cfg_mdc = cfg.get("min_diff_coverage")
    min_diff_coverage: float | None = (
        args.min_diff_coverage
        if args.min_diff_coverage is not None
        else (_cfg_mdc if isinstance(_cfg_mdc, float) else None)
    )
    if min_diff_coverage is not None and (
        not math.isfinite(min_diff_coverage)
        or not 0 <= min_diff_coverage <= 100
    ):
        out("usage: --min-diff-coverage must be a finite number between 0 and 100")
        return 2
    _cfg_pid = cfg.get("policy_id")
    policy_id: str | None = _cfg_pid if isinstance(_cfg_pid, str) else None
    _cfg_pv = cfg.get("policy_version")
    policy_version: str | None = _cfg_pv if isinstance(_cfg_pv, str) else None
    # A coverage floor is itself a gate, so an explicit ``--no-diff-coverage``
    # must never weaken it.  The floor implies measurement in every policy
    # source; an unsupported execution mode still fails closed in ``guard``.
    diff_coverage = diff_coverage_requested or min_diff_coverage is not None

    # Auto-detect a Node.js project: V8 reserves huge virtual address space, which
    # makes RLIMIT_AS kill the test subprocess at startup. If package.json exists
    # and the user hasn't explicitly configured mem_limit (still at default 1024),
    # disable the address-space cap automatically.
    if mem_limit == 1024:
        _node_root = args.repo or args.head or args.base or os.getcwd()
        if os.path.isfile(os.path.join(_node_root, "package.json")):
            mem_limit = 0

    _cfg_isolation = cfg.get("isolation")
    isolation = (
        args.isolation
        if args.isolation is not None
        else (_cfg_isolation if isinstance(_cfg_isolation, str) else "subprocess")
    )
    _cfg_docker_image = cfg.get("docker_image")
    docker_image = (
        args.docker_image
        if args.docker_image is not None
        else (_cfg_docker_image if isinstance(_cfg_docker_image, str) else None)
    )
    _cfg_docker_network = cfg.get("docker_network")
    docker_network = (
        args.docker_network
        if args.docker_network is not None
        else (_cfg_docker_network if isinstance(_cfg_docker_network, str) else "none")
    )
    if isolation in ("docker", "gvisor") and not docker_image:
        out(f"usage: --isolation {isolation} requires --docker-image <image> "
            "(an image carrying the repo's test runner, e.g. node:22-slim)")
        return 2

    deleted: list[str] = []

    if args.diff is not None:
        # A base...HEAD diff verified against the current checkout (repo arg or cwd)
        # by reverse-applying it — so `git diff … | evo-guard guard --diff -` just works.
        head = args.repo or os.getcwd()
        result, deleted = guard_from_diff(
            head, _read_text(args.diff),
            test_command=test_command, setup_command=setup_command,
            trust_setup_on_host=trust_setup_on_host,
            setup_output_globs=setup_output_globs,
            protected=protected, allow=allow, allow_new_tests=allow_new_tests, timeout=timeout,
            mem_limit_mb=mem_limit, isolation=isolation, docker_image=docker_image,
            docker_network=docker_network,
            verifier_pack=verifier_pack,
            expect_verifier_pack_sha256=expect_verifier_pack_sha256,
            diff_coverage=diff_coverage,
            min_diff_coverage=min_diff_coverage,
            blackbox=blackbox, blackbox_only=blackbox_only,
            require_report_integrity=require_report_integrity,
            require_candidate_isolation=require_candidate_isolation,
            base_sha=args.base_sha, head_sha=args.head_sha,
            base_tree_sha=args.base_tree_sha, head_tree_sha=args.head_tree_sha,
            policy_id=policy_id, policy_version=policy_version,
            baseline_evidence=baseline_evidence,
            require_demonstrated_fix=require_demonstrated_fix,
            strict_harness=strict_harness,
        )
    elif args.base and args.head:
        # Structured candidate: never round-trip file content through the
        # <<<FILE>>> text format (content containing a literal marker line
        # must survive intact — see guard.blocks_from_dirs).
        # ``head`` is untrusted in this mode.  A pack nested beneath it would
        # let the candidate rewrite its own verifier before the snapshot is
        # taken, even if its eventual digest matched the rewritten content.
        # Require a pinned pack which is external or materialized from ``base``.
        pack_trust_problem = verifier_pack_trust_error(
            args.head, verifier_pack, expect_verifier_pack_sha256
        )
        if pack_trust_problem:
            result = input_error_result(
                pack_trust_problem,
                reason_code=REASON_VERIFIER_PACK_INVALID,
                source="base/head",
                verifier_pack=verifier_pack,
            )
        else:
            try:
                file_blocks, deleted = blocks_from_dirs(args.base, args.head)
            except _UnverifiableChangedPathsError as exc:
                result = input_error_result(
                    "the base/head input includes changed path(s) Guard cannot safely "
                    f"verify: {exc}",
                    reason_code=REASON_NO_VERIFIABLE_CHANGES,
                    source="base/head",
                    verifier_pack=verifier_pack,
                )
            else:
                candidate = serialize_candidate_blocks(file_blocks)
                result = guard(
                    args.base, candidate,
                    deleted=tuple(deleted),
                    file_blocks=file_blocks,
                    test_command=test_command, setup_command=setup_command,
                    trust_setup_on_host=trust_setup_on_host,
                    setup_output_globs=setup_output_globs,
                    protected=protected, allow=allow, allow_new_tests=allow_new_tests, timeout=timeout,
                    mem_limit_mb=mem_limit, isolation=isolation, docker_image=docker_image,
                    docker_network=docker_network,
                    verifier_pack=verifier_pack,
                    expect_verifier_pack_sha256=expect_verifier_pack_sha256,
                    diff_coverage=diff_coverage,
                    min_diff_coverage=min_diff_coverage,
                    blackbox=blackbox, blackbox_only=blackbox_only,
                    require_report_integrity=require_report_integrity,
                    require_candidate_isolation=require_candidate_isolation,
                    base_sha=args.base_sha, head_sha=args.head_sha,
                    base_tree_sha=args.base_tree_sha, head_tree_sha=args.head_tree_sha,
                    policy_id=policy_id, policy_version=policy_version,
                    baseline_evidence=baseline_evidence,
                    require_demonstrated_fix=require_demonstrated_fix,
                    strict_harness=strict_harness,
                )
                result.source = "base/head"
    elif args.repo and args.patch:
        result = guard(
            args.repo, _read_text(args.patch),
            test_command=test_command, setup_command=setup_command,
            trust_setup_on_host=trust_setup_on_host,
            setup_output_globs=setup_output_globs,
            protected=protected, allow=allow, allow_new_tests=allow_new_tests, timeout=timeout,
            mem_limit_mb=mem_limit, isolation=isolation, docker_image=docker_image,
            docker_network=docker_network,
            verifier_pack=verifier_pack,
            expect_verifier_pack_sha256=expect_verifier_pack_sha256,
            diff_coverage=diff_coverage,
            min_diff_coverage=min_diff_coverage,
            blackbox=blackbox, blackbox_only=blackbox_only,
            require_report_integrity=require_report_integrity,
            require_candidate_isolation=require_candidate_isolation,
            base_sha=args.base_sha, head_sha=args.head_sha,
            base_tree_sha=args.base_tree_sha, head_tree_sha=args.head_tree_sha,
            policy_id=policy_id, policy_version=policy_version,
            baseline_evidence=baseline_evidence,
            require_demonstrated_fix=require_demonstrated_fix,
            strict_harness=strict_harness,
        )
        result.source = "edit blocks"
    else:
        out(
            "usage: evo-guard guard <repo> --patch <file|->   |   "
            "evo-guard guard --base <dir> --head <dir>   |   "
            "evo-guard guard [<repo>] --diff <file|->"
        )
        return 2

    report = render_report(result, deleted=deleted)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(report + "\n")
        out(f"wrote {args.report}")
    else:
        out(report)
    if args.json_out:
        write_json(result, args.json_out, deleted=deleted)
    if getattr(args, "sign_key", None):
        if not args.json_out:
            out("--sign-key needs --json: the signature covers the JSON verdict file")
            return 2
        from evoom_guard.signing import sign_file

        sig = sign_file(args.json_out, args.sign_key)
        out(f"signed {args.json_out} -> {sig}")
    if args.sarif:
        write_sarif(result, args.sarif)
    return result.exit_code


def doctor_report() -> dict[str, object]:
    """The environment EvoGuard depends on, as a stable dict (see ``evo-guard doctor``).

    ``git``/``patch`` are the only host tools the gate shells out to (for
    ``--diff`` reverse-apply); ``supported`` is true when at least one is present.
    """
    has_git = shutil.which("git") is not None
    has_patch = shutil.which("patch") is not None
    return {
        "tool": "evoguard",
        "version": __version__,
        "platform": f"{sys.platform}-{platform.machine()}",
        "python": platform.python_version(),
        "git": has_git,
        "patch": has_patch,
        "supported": has_git or has_patch,
    }


def cmd_doctor(args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    """Execute ``evo-guard doctor`` — report the environment; exit 0 only if supported."""
    info = doctor_report()
    if getattr(args, "doctor_json", False):
        out(json.dumps(info, indent=2))
    else:
        out(f"evoguard {info['version']}  ({info['platform']}, python {info['python']})")
        out(f"  git:   {'found' if info['git'] else 'MISSING'}")
        out(f"  patch: {'found' if info['patch'] else 'MISSING'}")
        out(f"  supported: {'yes' if info['supported'] else 'no — need git or patch'}")
    return 0 if info["supported"] else 1


def _workflow_yaml(ref: str) -> str:
    """The EvoGuard GitHub Actions workflow that ``evo-guard init`` scaffolds.

    Pins the action to ``ref`` (the matching release tag by default). The judge
    command belongs in the base-owned ``.evoguard.json`` policy rather than the
    candidate-controlled pull-request workflow.
    """
    return f"""\
# EvoGuard — generated by `evo-guard init`.
# Verifies each PR's source changes against the repo's own tests and REJECTS any
# edit to the tests or their configuration (an AI-patch reward-hack gate).
# Judge settings are read from the target branch's .evoguard.json policy.
name: EvoGuard

on:
  pull_request:

permissions:
  contents: read
  pull-requests: write   # required to post the verdict as a PR comment

jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
        with:
          fetch-depth: 0            # Guard needs the base commit to diff against

      - uses: EvoRiseKsa/EvoOM-Guard-m@{ref}
        with:
          comment: "true"           # same-repo PR comment; forks keep the job summary
          fail-on: "any-non-pass"   # or "rejected-only" to gate only reward-hacks
"""


def _workflow_yaml_private(ref: str, credential_key: str = "EVOGUARD_TOKEN") -> str:
    """EvoGuard workflow for private EvoGuard repos — installs via pip + a PAT secret.

    Use when the EvoGuard repo is private and cannot be accessed by the default
    GITHUB_TOKEN (cross-repo private action access is not supported). The PAT must
    have at least read access to the EvoGuard repo and be stored as an Actions secret
    (Settings → Secrets and variables → Actions).
    """
    return f"""\
# EvoGuard — generated by `evo-guard init --private-evoguard`.
# EvoGuard is installed from a private GitHub repo via pip.
# Judge settings are read from the target branch's .evoguard.json policy.
# Add a PAT with read access to the EvoGuard repo as the {credential_key} secret:
#   Settings -> Secrets and variables -> Actions -> New repository secret
name: EvoGuard

on:
  pull_request:

permissions:
  contents: read
  pull-requests: write   # required to post the verdict as a PR comment

jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
        with:
          fetch-depth: 0            # Guard needs the base commit to diff against

      - name: Install EvoGuard
        env:
          {credential_key}: ${{{{ secrets.{credential_key} }}}}
        run: pip install "git+https://x-access-token:${{{credential_key}}}@github.com/EvoRiseKsa/EvoOM-Guard-m.git@{ref}"

      - name: Run EvoGuard
        run: |
          # Materialize policy from the event's base commit, never from the PR head.
          BASE="${{{{ github.event.pull_request.base.sha }}}}"
          git rev-parse --verify --quiet "$BASE^{{commit}}" >/dev/null
          BASE_POLICY_CONFIG="$RUNNER_TEMP/evoguard-base-policy.json"
          if git cat-file -e "$BASE:.evoguard.json" 2>/dev/null; then
            git show "$BASE:.evoguard.json" > "$BASE_POLICY_CONFIG"
          else
            printf '{{}}\\n' > "$BASE_POLICY_CONFIG"
          fi
          git diff "$BASE...HEAD" | \\
            evo-guard guard . --diff - --config "$BASE_POLICY_CONFIG" \\
            --report evoguard.md --json evoguard.json
          cat evoguard.md >> "$GITHUB_STEP_SUMMARY"

      - name: Post verdict as PR comment
        if: ${{{{ always() && github.event.pull_request.head.repo.full_name == github.repository && github.event.pull_request.user.login != 'dependabot[bot]' }}}}
        continue-on-error: true
        uses: actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9.0.0
        with:
          script: |
            const fs = require('fs');
            const report = fs.existsSync('evoguard.md')
              ? fs.readFileSync('evoguard.md', 'utf8')
              : '_EvoGuard did not produce a report._';
            await github.rest.issues.createComment({{
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: report,
            }});
"""


def _default_policy_path(workflow_path: str) -> str:
    """Infer a repository-root policy path from the conventional workflow path."""
    absolute = os.path.abspath(workflow_path)
    workflow_dir = os.path.dirname(absolute)
    github_dir = os.path.dirname(workflow_dir)
    if (
        os.path.basename(workflow_dir) == "workflows"
        and os.path.basename(github_dir) == ".github"
    ):
        return os.path.join(os.path.dirname(github_dir), ".evoguard.json")
    return os.path.join(workflow_dir or os.getcwd(), ".evoguard.json")


def cmd_init(args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    """Execute ``evo-guard init`` — scaffold a ready-to-use GitHub Actions workflow.

    Writes the workflow and, when absent, a trusted ``.evoguard.json`` policy.
    The workflow is refused when it exists unless ``--force`` is given; an
    existing policy is deliberately preserved so initialization cannot erase an
    adopter's judge contract. ``--stdout`` prints only the workflow. Pass
    ``--private-evoguard`` to generate a pip-install workflow for repos where the
    EvoGuard action is not accessible via the default GITHUB_TOKEN.
    """
    if getattr(args, "private_evoguard", False):
        try:
            credential_key = _github_actions_credential_key(
                getattr(args, "github_actions_credential_key", "EVOGUARD_TOKEN")
            )
        except ValueError as exc:
            out(f"usage: {exc}")
            return 2
        content = _workflow_yaml_private(args.ref, credential_key)
    else:
        content = _workflow_yaml(args.ref)
    if args.stdout:
        out(content)
        return 0
    path = args.path
    if os.path.exists(path) and not args.force:
        out(f"refusing to overwrite existing {path} — pass --force to replace it")
        return 1
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    policy_path = args.policy_path or _default_policy_path(path)
    if os.path.exists(policy_path):
        out(f"kept existing trusted policy {policy_path}")
    else:
        policy_parent = os.path.dirname(policy_path)
        if policy_parent:
            os.makedirs(policy_parent, exist_ok=True)
        with open(policy_path, "w", encoding="utf-8") as f:
            json.dump({"test_command": args.test_command}, f, indent=2)
            f.write("\n")
        out(f"wrote {policy_path}")
    out(f"wrote {path}")
    out(
        "next: commit it and open a PR — EvoGuard posts a verdict and fails the "
        "check on anything but PASS. Edit .evoguard.json to change the trusted judge policy."
    )
    return 0


def cmd_keygen(args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    """Execute ``evo-guard keygen`` — generate an Ed25519 signing keypair."""
    from evoom_guard.signing import generate_keypair

    try:
        generate_keypair(args.key, args.pub)
    except FileExistsError as exc:
        out(str(exc))
        return 2
    out(f"wrote {args.key} (private — keep it a CI secret) and {args.pub} (public)")
    return 0


def cmd_verify_verdict(args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    """Execute ``evo-guard verify-verdict`` — signature + CONTEXT check (exit 0/1).

    A valid signature only proves the verdict bytes did not change after
    signing. The optional ``--expect-*`` flags make the check *contextual*:
    a perfectly signed verdict for the WRONG commit / policy fails — which is
    what a merge or deploy gate actually needs (chain of custody, not just
    file integrity).
    """
    from evoom_guard.signing import SigningUnavailableError, verify_bytes

    sig = args.sig or (args.verdict + ".sig")
    try:
        payload_bytes = _read_bounded_bytes(
            args.verdict,
            limit=MAX_OFFLINE_RECORD_BYTES,
            label="verdict",
        )
        encoded_signature = _read_bounded_bytes(
            sig,
            limit=MAX_SIGNATURE_FILE_BYTES,
            label="signature",
        ).strip()
        signature = base64.b64decode(encoded_signature, validate=True)
        ok = verify_bytes(payload_bytes, signature, args.pub)
    except (OSError, ValueError, binascii.Error, SigningUnavailableError) as exc:
        out(f"unusable input: {exc}")
        return 2
    out(f"input sha256: {hashlib.sha256(payload_bytes).hexdigest()}")
    if not ok:
        out("signature: INVALID — the verdict bytes changed after signing")
        return 1
    out("signature: VALID")

    expectations = (
        ("head_sha", getattr(args, "expect_head_sha", None)),
        ("base_sha", getattr(args, "expect_base_sha", None)),
        ("policy_sha256", getattr(args, "expect_policy_sha", None)),
        ("policy_id", getattr(args, "expect_policy_id", None)),
    )
    if not any(want for _f, want in expectations):
        return 0
    try:
        from evoom_guard.record_verifier import strict_json_loads

        payload = strict_json_loads(payload_bytes.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        out(f"context: UNCHECKABLE — the verdict is not readable JSON ({exc})")
        return 1
    if not isinstance(payload, dict):
        out("context: UNCHECKABLE - the verdict JSON root is not an object")
        return 1
    raw_attestation = payload.get("attestation")
    att = raw_attestation if isinstance(raw_attestation, dict) else {}
    failed = False
    for field, want in expectations:
        if not want:
            continue
        got = att.get(field)
        if got == want:
            out(f"context: {field} matches ({want})")
        else:
            out(f"context: MISMATCH — {field} is {got!r}, expected {want!r}")
            failed = True
    if failed:
        out("context: FAILED — the signature is valid but this verdict was not "
            "produced for the expected revision/policy")
        return 1
    return 0


def cmd_verify_record(args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    """Validate record semantics and emit one machine-readable JSON report.

    This command intentionally leaves signature verification to
    :func:`cmd_verify_verdict`.  Exit 0 means no semantic contradiction was
    found, exit 1 means a well-formed JSON value failed validation, and exit 2
    means the input could not be read as JSON.
    """
    from evoom_guard.record_verifier import (
        invalid_json_report,
        strict_json_loads,
        verify_record,
    )

    try:
        payload_bytes = _read_bounded_bytes(
            args.verdict,
            limit=MAX_OFFLINE_RECORD_BYTES,
            label="verdict",
        )
    except (OSError, ValueError) as exc:
        report = invalid_json_report(f"unusable JSON input: {exc}")
        out(json.dumps(report, indent=2, sort_keys=True))
        return 2
    input_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    try:
        payload = strict_json_loads(payload_bytes.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        report = invalid_json_report(f"unusable JSON input: {exc}")
        report["input_sha256"] = input_sha256
        report["input_size"] = len(payload_bytes)
        out(json.dumps(report, indent=2, sort_keys=True))
        return 2
    report = verify_record(payload)
    report["input_sha256"] = input_sha256
    report["input_size"] = len(payload_bytes)
    out(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


def _machine_report(out: Callable[[str], None], value: dict[str, object]) -> None:
    out(json.dumps(value, indent=2, sort_keys=True))


def cmd_bundle_evidence(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Create a signed envelope only after semantic record validation succeeds."""

    from evoom_guard.evidence_bundle import (
        EvidenceBundleError,
        EvidenceMaterial,
        create_evidence_bundle,
    )
    from evoom_guard.record_verifier import strict_json_loads, verify_record
    from evoom_guard.signing import SigningUnavailableError

    try:
        verdict_bytes = _read_bounded_bytes(
            args.verdict,
            limit=MAX_OFFLINE_RECORD_BYTES,
            label="verdict",
        )
        context_bytes = _read_bounded_bytes(
            args.context,
            limit=MAX_CONTEXT_INPUT_BYTES,
            label="context",
        )
        verdict = strict_json_loads(verdict_bytes.decode("utf-8"))
        context = strict_json_loads(context_bytes.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_EVIDENCE_CREATION_V1",
                "ok": False,
                "status": "ERROR",
                "error": f"unusable JSON input: {exc}",
            },
        )
        return 2
    record_report = verify_record(verdict)
    if not record_report["ok"]:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_EVIDENCE_CREATION_V1",
                "ok": False,
                "status": "INVALID_RECORD",
                "record": record_report,
            },
        )
        return 1
    if not isinstance(context, dict):
        _machine_report(
            out,
            {
                "format": "EVOGUARD_EVIDENCE_CREATION_V1",
                "ok": False,
                "status": "ERROR",
                "error": "context JSON must be an object",
            },
        )
        return 2

    materials: list[EvidenceMaterial] = []
    for specification in args.material:
        role, separator, path = specification.partition("=")
        if not separator or not role or not path:
            _machine_report(
                out,
                {
                    "format": "EVOGUARD_EVIDENCE_CREATION_V1",
                    "ok": False,
                    "status": "ERROR",
                    "error": f"invalid --material {specification!r}; expected ROLE=PATH",
                },
            )
            return 2
        materials.append(EvidenceMaterial(role=role, source_path=path))

    try:
        manifest = create_evidence_bundle(
            args.verdict,
            args.out,
            context=context,
            private_key_path=args.sign_key,
            materials=materials,
            force=args.force,
            require_valid_record=True,
        )
    except EvidenceBundleError as exc:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_EVIDENCE_CREATION_V1",
                "ok": False,
                "status": "INVALID_INPUT",
                "error": str(exc),
            },
        )
        return 1
    except (OSError, ValueError, SigningUnavailableError) as exc:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_EVIDENCE_CREATION_V1",
                "ok": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2

    canonical_manifest = (
        json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")
    _machine_report(
        out,
        {
            "format": "EVOGUARD_EVIDENCE_CREATION_V1",
            "ok": True,
            "status": "CREATED",
            "bundle": os.path.abspath(args.out),
            "manifest_sha256": hashlib.sha256(canonical_manifest).hexdigest(),
            "record_sha256": manifest["record"]["sha256"],
            "key_id": manifest["authentication"]["key_id"],
        },
    )
    return 0


def cmd_finalize_record(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Seal a semantic record against trusted context and expose ALLOW/DENY.

    The command is deliberately not an execution verifier: its context must be
    derived by a trusted finalizer from the control plane, after an isolated
    re-verification.  It never upgrades a PR artifact into a trusted runtime
    observation by itself.
    """

    from evoom_guard.evidence_bundle import (
        EvidenceBundleError,
        EvidenceMaterial,
        finalize_evidence_bundle,
    )
    from evoom_guard.record_verifier import strict_json_loads, verify_record
    from evoom_guard.signing import SigningUnavailableError

    if args.verdict == "-":
        _machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
                "ok": False,
                "finalized": False,
                "status": "ERROR",
                "error": "finalize-record verdict must be a regular file, not standard input",
            },
        )
        return 2
    try:
        verdict_bytes = _read_bounded_bytes(
            args.verdict,
            limit=MAX_OFFLINE_RECORD_BYTES,
            label="verdict",
        )
        context_bytes = _read_bounded_bytes(
            args.expected_context,
            limit=MAX_CONTEXT_INPUT_BYTES,
            label="expected context",
        )
        verdict = strict_json_loads(verdict_bytes.decode("utf-8"))
        expected_context = strict_json_loads(context_bytes.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
                "ok": False,
                "finalized": False,
                "status": "ERROR",
                "error": f"unusable JSON input: {exc}",
            },
        )
        return 2
    if not isinstance(verdict, dict):
        _machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
                "ok": False,
                "finalized": False,
                "status": "INVALID_RECORD",
                "error": "verdict JSON must be an object",
            },
        )
        return 1
    record_report = verify_record(verdict)
    if not record_report["ok"]:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
                "ok": False,
                "finalized": False,
                "status": "INVALID_RECORD",
                "record": record_report,
            },
        )
        return 1
    if not isinstance(expected_context, dict):
        _machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
                "ok": False,
                "finalized": False,
                "status": "ERROR",
                "error": "expected context JSON must be an object",
            },
        )
        return 2

    materials: list[EvidenceMaterial] = []
    for specification in args.material:
        role, separator, path = specification.partition("=")
        if not separator or not role or not path:
            _machine_report(
                out,
                {
                    "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
                    "ok": False,
                    "finalized": False,
                    "status": "ERROR",
                    "error": f"invalid --material {specification!r}; expected ROLE=PATH",
                },
            )
            return 2
        materials.append(EvidenceMaterial(role=role, source_path=path))

    try:
        finalized = finalize_evidence_bundle(
            args.verdict,
            args.out,
            expected_context=expected_context,
            private_key_path=args.sign_key,
            materials=materials,
            force=args.force,
        )
    except EvidenceBundleError as exc:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
                "ok": False,
                "finalized": False,
                "status": "INVALID_INPUT",
                "error": str(exc),
            },
        )
        return 1
    except (OSError, ValueError, SigningUnavailableError) as exc:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
                "ok": False,
                "finalized": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2

    canonical_manifest = (
        json.dumps(
            finalized.manifest,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")
    allowed = finalized.decision == "ALLOW"
    _machine_report(
        out,
        {
            "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
            "ok": allowed,
            "finalized": True,
            "status": "FINALIZED" if allowed else "DENIED",
            "decision": finalized.decision,
            "bundle": finalized.bundle_path,
            "manifest_sha256": hashlib.sha256(canonical_manifest).hexdigest(),
            "record_sha256": finalized.manifest["record"]["sha256"],
            "key_id": finalized.manifest["authentication"]["key_id"],
            "record": finalized.record_report,
        },
    )
    return 0 if allowed or not args.require_pass else 1


def _read_external_finalizer_object(path: str, *, label: str) -> dict[str, object]:
    """Read a bounded JSON object supplied outside candidate-controlled artifacts."""

    from evoom_guard.evidence_bundle import EvidenceBundleError, _read_regular_file
    from evoom_guard.record_verifier import strict_json_loads

    if path == "-":
        raise ValueError(f"{label} must be a regular JSON file, not standard input")
    try:
        data = _read_regular_file(path, limit=MAX_CONTEXT_INPUT_BYTES, label=label)
    except EvidenceBundleError as exc:
        raise ValueError(str(exc)) from exc
    value = strict_json_loads(data.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} JSON must be an object")
    return value


def _parse_finalizer_materials(specifications: list[str]) -> list[EvidenceMaterial]:
    """Parse bounded material declarations shared by the finalizer commands."""

    from evoom_guard.evidence_bundle import EvidenceMaterial

    materials: list[EvidenceMaterial] = []
    for specification in specifications:
        role, separator, path = specification.partition("=")
        if not separator or not role or not path:
            raise ValueError(
                f"invalid --material {specification!r}; expected ROLE=PATH"
            )
        materials.append(EvidenceMaterial(role=role, source_path=path))
    return materials


def cmd_derive_finalizer_bindings(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Derive trusted-finalizer values from raw Git objects without a checkout."""

    from evoom_guard.finalizer_derivation import (
        FINALIZER_DERIVATION_FORMAT,
        FinalizerDerivationError,
        derive_finalizer_bindings,
        write_finalizer_bindings,
    )

    source = {
        "pull_request_number": args.pr_number,
        "workflow_run_id": args.run_id,
        "workflow_run_attempt": args.run_attempt,
        "base_sha": args.base_sha,
        "head_sha": args.head_sha,
    }
    try:
        bindings = derive_finalizer_bindings(
            base_repo=args.base_repo,
            head_repo=args.head_repo,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            base_tree_sha=args.base_tree_sha,
            head_tree_sha=args.head_tree_sha,
            source=source,
            repository=args.repository,
            repository_id=args.repository_id,
            guard_artifact_sha256=args.guard_artifact_sha,
            base_is_bare=args.base_bare,
            head_is_bare=args.head_bare,
        )
        output = write_finalizer_bindings(bindings, bindings_path=args.out, force=args.force)
    except (FinalizerDerivationError, OSError, UnicodeError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": FINALIZER_DERIVATION_FORMAT,
                "ok": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    _machine_report(
        out,
        {
            "format": FINALIZER_DERIVATION_FORMAT,
            "ok": True,
            "status": "DERIVED",
            "bindings": output,
            "candidate_sha256": bindings.candidate_sha256,
            "policy_sha256": bindings.policy_sha256,
            "verifier_pack_sha256": bindings.verifier_pack_sha256,
        },
    )
    return 0


def _read_semantic_finalizer_record(path: str) -> dict[str, Any]:
    """Read and validate one untrusted verdict before using its digest fields."""

    from evoom_guard.evidence_bundle import MAX_VERDICT_BYTES, _load_json_object, _read_regular_file
    from evoom_guard.record_verifier import verify_record

    if path == "-":
        raise ValueError("verdict must be a regular JSON file, not standard input")
    data = _read_regular_file(path, limit=MAX_VERDICT_BYTES, label="verdict")
    record = _load_json_object(data, "verdict")
    report = verify_record(record)
    if not report["ok"]:
        failed = ", ".join(
            item["id"] for item in report["checks"] if item.get("status") == "fail"
        )
        raise ValueError("verdict record is semantically invalid: " + failed)
    return record


def cmd_verify_finalizer_bindings(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Compare a semantic record to independently derived raw-Git bindings."""

    from evoom_guard.finalizer_derivation import (
        FINALIZER_DERIVATION_FORMAT,
        FinalizerDerivationError,
        context_from_verified_bindings,
        read_finalizer_bindings,
        write_verified_finalizer_context,
    )

    try:
        bindings = read_finalizer_bindings(args.bindings)
        record = _read_semantic_finalizer_record(args.verdict)
        source, context = context_from_verified_bindings(bindings, record)
        source_out, context_out = write_verified_finalizer_context(
            bindings,
            record,
            source_path=args.source_out,
            context_path=args.context_out,
            force=args.force,
        )
    except (FinalizerDerivationError, OSError, UnicodeError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": FINALIZER_DERIVATION_FORMAT,
                "ok": False,
                "status": "MISMATCH",
                "error": str(exc),
            },
        )
        return 1
    _machine_report(
        out,
        {
            "format": FINALIZER_DERIVATION_FORMAT,
            "ok": True,
            "status": "VERIFIED",
            "source": source,
            "context": context,
            "source_path": source_out,
            "context_path": context_out,
        },
    )
    return 0


def cmd_finalizer_handoff(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Bind a semantic re-verification record to explicit trusted metadata."""

    from evoom_guard.evidence_bundle import EvidenceBundleError
    from evoom_guard.trusted_finalizer import (
        FinalizerHandoffError,
        create_finalizer_handoff,
    )

    if args.verdict == "-":
        _machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZER_HANDOFF_V1",
                "ok": False,
                "status": "ERROR",
                "error": "finalizer-handoff verdict must be a regular file, not standard input",
            },
        )
        return 2
    try:
        source = _read_external_finalizer_object(args.source, label="source")
        context = _read_external_finalizer_object(args.context, label="context")
    except (OSError, UnicodeError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZER_HANDOFF_V1",
                "ok": False,
                "status": "ERROR",
                "error": f"unusable trusted metadata: {exc}",
            },
        )
        return 2
    try:
        handoff = create_finalizer_handoff(
            args.verdict,
            args.out,
            source=source,
            context=context,
            force=args.force,
        )
    except (EvidenceBundleError, FinalizerHandoffError) as exc:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZER_HANDOFF_V1",
                "ok": False,
                "status": "INVALID_INPUT",
                "error": str(exc),
            },
        )
        return 1
    except OSError as exc:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZER_HANDOFF_V1",
                "ok": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    _machine_report(
        out,
        {
            "format": "EVOGUARD_TRUSTED_FINALIZER_HANDOFF_V1",
            "ok": True,
            "status": "CREATED",
            "handoff": os.path.abspath(args.out),
            "record_sha256": handoff["record"]["sha256"],
            "source": handoff["source"],
            "context": handoff["context"],
        },
    )
    return 0


def cmd_seal_finalizer(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Seal only a handoff that matches externally re-derived metadata."""

    from evoom_guard.evidence_bundle import EvidenceBundleError
    from evoom_guard.finalizer_derivation import read_finalizer_bindings
    from evoom_guard.signing import SigningUnavailableError
    from evoom_guard.trusted_finalizer import FinalizerHandoffError, seal_finalizer_bundle

    if args.verdict == "-":
        _machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": "seal-finalizer verdict must be a regular file, not standard input",
            },
        )
        return 2
    try:
        expected_source = _read_external_finalizer_object(
            args.expected_source, label="expected source"
        )
        expected_context = _read_external_finalizer_object(
            args.expected_context, label="expected context"
        )
        expected_derivation = (
            read_finalizer_bindings(args.expected_derivation).payload
            if args.expected_derivation is not None
            else None
        )
        materials = _parse_finalizer_materials(args.material)
    except (OSError, UnicodeError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": f"unusable trusted input: {exc}",
            },
        )
        return 2
    try:
        sealed = seal_finalizer_bundle(
            args.handoff,
            args.verdict,
            args.out,
            expected_source=expected_source,
            expected_context=expected_context,
            private_key_path=args.sign_key,
            expected_derivation=expected_derivation,
            materials=materials,
            force=args.force,
        )
    except (EvidenceBundleError, FinalizerHandoffError) as exc:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
                "ok": False,
                "sealed": False,
                "status": "INVALID_INPUT",
                "error": str(exc),
            },
        )
        return 1
    except (OSError, ValueError, SigningUnavailableError) as exc:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    allowed = sealed.decision == "ALLOW"
    _machine_report(
        out,
        {
            "format": "EVOGUARD_TRUSTED_FINALIZATION_V1",
            "ok": allowed,
            "sealed": True,
            "status": "FINALIZED" if allowed else "DENIED",
            "decision": sealed.decision,
            "bundle": sealed.finalized.bundle_path,
            "record_sha256": sealed.finalized.manifest["record"]["sha256"],
            "key_id": sealed.finalized.manifest["authentication"]["key_id"],
        },
    )
    return 0 if allowed or not args.require_pass else 1


def cmd_verify_finalized(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Verify a signed finalizer bundle and all external anti-replay bindings."""

    from evoom_guard.signing import SigningUnavailableError
    from evoom_guard.trusted_finalizer import (
        FinalizerHandoffError,
        verify_finalized_bundle,
    )

    try:
        expected_source = _read_external_finalizer_object(
            args.expected_source, label="expected source"
        )
        expected_context = _read_external_finalizer_object(
            args.expected_context, label="expected context"
        )
    except (OSError, UnicodeError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZER_VERIFICATION_V1",
                "ok": False,
                "verified": False,
                "status": "INCOMPLETE",
                "error": f"unusable external trust input: {exc}",
            },
        )
        return 2
    try:
        verified = verify_finalized_bundle(
            args.bundle,
            trusted_public_key_path=args.trusted_pub,
            expected_source=expected_source,
            expected_context=expected_context,
        )
    except SigningUnavailableError as exc:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZER_VERIFICATION_V1",
                "ok": False,
                "verified": False,
                "status": "INCOMPLETE",
                "error": str(exc),
            },
        )
        return 2
    except (OSError, ValueError, FinalizerHandoffError) as exc:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_TRUSTED_FINALIZER_VERIFICATION_V1",
                "ok": False,
                "verified": False,
                "status": "INVALID",
                "error": str(exc),
            },
        )
        return 1
    allowed = verified.decision == "ALLOW"
    ok = allowed or not args.require_pass
    _machine_report(
        out,
        {
            "format": "EVOGUARD_TRUSTED_FINALIZER_VERIFICATION_V1",
            "ok": ok,
            "verified": True,
            "status": "VERIFIED" if ok else "DENIED",
            "decision": verified.decision,
            "key_id": verified.bundle.manifest["authentication"]["key_id"],
            "record": verified.bundle.record_report,
        },
    )
    return 0 if ok else 1


def cmd_release_source_handoff(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Write an unsigned handoff for the separate protected-main contract."""

    from evoom_guard.release_source_finalizer import (
        RELEASE_SOURCE_HANDOFF_FORMAT,
        ReleaseSourceFinalizerError,
        create_release_source_handoff,
    )

    if args.verdict == "-":
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_HANDOFF_FORMAT,
                "ok": False,
                "status": "ERROR",
                "error": "release-source-handoff verdict must be a regular file, not standard input",
            },
        )
        return 2
    try:
        source = _read_external_finalizer_object(args.source, label="release source")
        context = _read_external_finalizer_object(args.context, label="release-source context")
    except (OSError, UnicodeError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_HANDOFF_FORMAT,
                "ok": False,
                "status": "ERROR",
                "error": f"unusable trusted metadata: {exc}",
            },
        )
        return 2
    try:
        handoff = create_release_source_handoff(
            args.verdict,
            args.out,
            source=source,
            context=context,
            force=args.force,
        )
    except (OSError, ValueError, ReleaseSourceFinalizerError) as exc:
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_HANDOFF_FORMAT,
                "ok": False,
                "status": "INVALID_INPUT",
                "error": str(exc),
            },
        )
        return 1
    _machine_report(
        out,
        {
            "format": RELEASE_SOURCE_HANDOFF_FORMAT,
            "ok": True,
            "status": "CREATED",
            "handoff": os.path.abspath(args.out),
            "record_sha256": handoff["record"]["sha256"],
            "source": handoff["source"],
            "context": handoff["context"],
        },
    )
    return 0


def cmd_seal_release_source_finalizer(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Seal a protected-main handoff only after external source matching."""

    from evoom_guard.release_source_finalizer import (
        RELEASE_SOURCE_EVIDENCE_FORMAT,
        ReleaseSourceFinalizerError,
        seal_release_source_bundle,
    )
    from evoom_guard.signing import SigningUnavailableError

    if args.verdict == "-":
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_EVIDENCE_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": "seal-release-source-finalizer verdict must be a regular file, not standard input",
            },
        )
        return 2
    try:
        source = _read_external_finalizer_object(args.expected_source, label="expected release source")
        context = _read_external_finalizer_object(
            args.expected_context, label="expected release-source context"
        )
    except (OSError, UnicodeError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_EVIDENCE_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": f"unusable external trust input: {exc}",
            },
        )
        return 2
    try:
        sealed = seal_release_source_bundle(
            args.handoff,
            args.verdict,
            args.out,
            expected_source=source,
            expected_context=context,
            git_repository=args.git_repository,
            git_repository_is_bare=args.git_repository_bare,
            private_key_path=args.sign_key,
            prohibited_key_ids=args.must_differ_from_key_id,
            force=args.force,
        )
    except (OSError, ValueError, ReleaseSourceFinalizerError) as exc:
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_EVIDENCE_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "INVALID_INPUT",
                "error": str(exc),
            },
        )
        return 1
    except SigningUnavailableError as exc:
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_EVIDENCE_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "INCOMPLETE",
                "error": str(exc),
            },
        )
        return 2
    allowed = sealed.decision == "ALLOW"
    _machine_report(
        out,
        {
            "format": RELEASE_SOURCE_EVIDENCE_FORMAT,
            "ok": allowed,
            "sealed": True,
            "status": "FINALIZED" if allowed else "DENIED",
            "decision": sealed.decision,
            "bundle": sealed.bundle_path,
            "record_sha256": sealed.manifest["record"]["sha256"],
            "key_id": sealed.manifest["authentication"]["key_id"],
        },
    )
    return 0 if allowed or args.allow_deny_evidence else 1


def cmd_verify_release_source_finalized(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Verify a separate release-source envelope and external bindings."""

    from evoom_guard.release_source_finalizer import (
        RELEASE_SOURCE_EVIDENCE_FORMAT,
        ReleaseSourceFinalizerError,
        verify_release_source_bundle,
    )
    from evoom_guard.signing import SigningUnavailableError

    try:
        source = _read_external_finalizer_object(args.expected_source, label="expected release source")
        context = _read_external_finalizer_object(
            args.expected_context, label="expected release-source context"
        )
    except (OSError, UnicodeError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_EVIDENCE_FORMAT,
                "ok": False,
                "verified": False,
                "status": "INCOMPLETE",
                "error": f"unusable external trust input: {exc}",
            },
        )
        return 2
    try:
        verified = verify_release_source_bundle(
            args.bundle,
            trusted_public_key_path=args.trusted_pub,
            expected_source=source,
            expected_context=context,
            prohibited_key_ids=args.must_differ_from_key_id,
        )
    except SigningUnavailableError as exc:
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_EVIDENCE_FORMAT,
                "ok": False,
                "verified": False,
                "status": "INCOMPLETE",
                "error": str(exc),
            },
        )
        return 2
    except (OSError, ValueError, ReleaseSourceFinalizerError) as exc:
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_EVIDENCE_FORMAT,
                "ok": False,
                "verified": False,
                "status": "INVALID",
                "error": str(exc),
            },
        )
        return 1
    allowed = verified.decision == "ALLOW"
    _machine_report(
        out,
        {
            "format": RELEASE_SOURCE_EVIDENCE_FORMAT,
            "ok": allowed,
            "verified": True,
            "status": "VERIFIED" if allowed else "DENIED",
            "decision": verified.decision,
            "key_id": verified.bundle.manifest["authentication"]["key_id"],
            "record": verified.record_report,
        },
    )
    return 0 if allowed or args.allow_deny_evidence else 1


def cmd_derive_release_source_controls(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Re-derive source/context from raw Git without making an admission claim."""

    from evoom_guard.evidence_bundle import _canonical_json
    from evoom_guard.release_source_finalizer import (
        RELEASE_SOURCE_CONTEXT_FORMAT,
        ReleaseSourceFinalizerError,
        _publish_bytes,
        _record_snapshot,
        context_from_release_source_bindings,
        derive_release_source_bindings,
    )

    if args.verdict == "-":
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_CONTEXT_FORMAT,
                "ok": False,
                "status": "ERROR",
                "error": "derive-release-source-controls verdict must be a regular file, not standard input",
            },
        )
        return 2
    try:
        source = _read_external_finalizer_object(args.source, label="release source")
        _verdict_bytes, verdict, _record_report = _record_snapshot(args.verdict)
        bindings = derive_release_source_bindings(
            git_repository=args.git_repository,
            source=source,
            git_repository_is_bare=args.git_repository_bare,
        )
        context = context_from_release_source_bindings(bindings, verdict)
        _publish_bytes(
            args.source_out,
            _canonical_json(bindings.source),
            force=args.force,
            prefix=".evoguard-release-source-",
            label="verified release source",
        )
        _publish_bytes(
            args.context_out,
            _canonical_json(context),
            force=args.force,
            prefix=".evoguard-release-source-context-",
            label="verified release-source context",
        )
    except (OSError, UnicodeError, ValueError, ReleaseSourceFinalizerError) as exc:
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_CONTEXT_FORMAT,
                "ok": False,
                "status": "REJECTED",
                "error": str(exc),
            },
        )
        return 1
    _machine_report(
        out,
        {
            "format": RELEASE_SOURCE_CONTEXT_FORMAT,
            "ok": True,
            "status": "RAW_GIT_CONTROLS_DERIVED",
            "source": os.path.abspath(args.source_out),
            "context": os.path.abspath(args.context_out),
            "decision": "NONE",
            "admission": False,
        },
    )
    return 0


def cmd_create_release_source_producer_receipt(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Create an unsigned canonical claim; it is never an admission decision."""

    from evoom_guard.release_source_producer_receipt import (
        RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
        ReleaseSourceProducerReceiptError,
        create_release_source_producer_receipt,
    )

    if any(value == "-" for value in (args.verdict, args.handoff)):
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
                "ok": False,
                "status": "ERROR",
                "error": "producer receipt verdict and handoff must be regular files, not standard input",
            },
        )
        return 2
    try:
        source = _read_external_finalizer_object(args.source, label="release source")
        context = _read_external_finalizer_object(args.context, label="release-source context")
        producer = _read_external_finalizer_object(args.producer, label="producer identity")
        receipt = create_release_source_producer_receipt(
            args.verdict,
            args.handoff,
            args.out,
            source=source,
            context=context,
            bootstrap_guard_sha256=args.bootstrap_guard_sha,
            producer=producer,
            git_repository=args.git_repository,
            git_repository_is_bare=args.git_repository_bare,
            force=args.force,
        )
    except (OSError, UnicodeError, ValueError, ReleaseSourceProducerReceiptError) as exc:
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
                "ok": False,
                "status": "REJECTED",
                "error": str(exc),
            },
        )
        return 1
    _machine_report(
        out,
        {
            "format": RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
            "ok": True,
            "status": "CANONICAL_CLAIM_CREATED",
            "receipt": os.path.abspath(args.out),
            "record_sha256": receipt["record"]["sha256"],
            "decision": "NONE",
            "admission": False,
            "requires": "fresh-provider-gh-attestation-verify-before-any-future-admission",
        },
    )
    return 0


def _producer_receipt_external_inputs(args: argparse.Namespace) -> tuple[
    dict[str, object], dict[str, object], dict[str, object]
]:
    return (
        _read_external_finalizer_object(args.source, label="expected release source"),
        _read_external_finalizer_object(args.context, label="expected release-source context"),
        _read_external_finalizer_object(args.producer, label="expected producer identity"),
    )


def cmd_verify_release_source_producer_receipt(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Verify local/raw-Git producer binding without treating it as provider proof."""

    from evoom_guard.release_source_producer_receipt import (
        RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
        ReleaseSourceProducerReceiptError,
        verify_release_source_producer_receipt,
    )

    if any(value == "-" for value in (args.receipt, args.handoff, args.verdict)):
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
                "ok": False,
                "status": "ERROR",
                "error": "producer receipt, handoff, and verdict must be regular files, not standard input",
            },
        )
        return 2
    try:
        source, context, producer = _producer_receipt_external_inputs(args)
        verified = verify_release_source_producer_receipt(
            args.receipt,
            args.handoff,
            args.verdict,
            expected_source=source,
            expected_context=context,
            expected_producer=producer,
            expected_bootstrap_guard_sha256=args.bootstrap_guard_sha,
            git_repository=args.git_repository,
            git_repository_is_bare=args.git_repository_bare,
        )
    except (OSError, UnicodeError, ValueError, ReleaseSourceProducerReceiptError) as exc:
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
                "ok": False,
                "verified": False,
                "status": "REJECTED",
                "error": str(exc),
            },
        )
        return 1
    _machine_report(
        out,
        {
            "format": RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
            "ok": False,
            "verified": True,
            "status": "NONADMITTING_LOCAL_AND_RAW_GIT_VERIFIED",
            "record_sha256": verified.receipt.payload["record"]["sha256"],
            "decision": "NONE",
            "admission": False,
            "provider_verified": False,
            "requires": "explicit-allow-nonadmitting-evidence-for-archive-only-success",
        },
    )
    return 0 if args.allow_nonadmitting_evidence else 1


def cmd_reverify_attested_release_source_producer_receipt(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Make a fresh GitHub provider check after local/raw-Git verification."""

    from evoom_guard.release_source_producer_receipt import (
        RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
        ReleaseSourceProducerReceiptError,
        reverify_attested_release_source_producer_receipt,
    )

    if any(value == "-" for value in (args.receipt, args.handoff, args.verdict)):
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
                "ok": False,
                "status": "ERROR",
                "error": "producer receipt, handoff, and verdict must be regular files, not standard input",
            },
        )
        return 2
    try:
        source, context, producer = _producer_receipt_external_inputs(args)
        github_policy = _read_external_finalizer_object(
            args.github_policy, label="GitHub producer-attestation policy"
        )
        verified = reverify_attested_release_source_producer_receipt(
            args.receipt,
            args.handoff,
            args.verdict,
            expected_source=source,
            expected_context=context,
            expected_producer=producer,
            expected_bootstrap_guard_sha256=args.bootstrap_guard_sha,
            expected_github_policy=github_policy,
            git_repository=args.git_repository,
            git_repository_is_bare=args.git_repository_bare,
            github_receipt_path=args.github_receipt_out,
            github_raw_output_path=args.github_raw_output_out,
            gh_executable=args.gh_executable,
            timeout_seconds=args.timeout_seconds,
        )
    except (OSError, UnicodeError, ValueError, ReleaseSourceProducerReceiptError) as exc:
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
                "ok": False,
                "verified": False,
                "status": "REJECTED",
                "error": str(exc),
            },
        )
        return 1
    _machine_report(
        out,
        {
            "format": RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
            "ok": False,
            "verified": True,
            "status": "NONADMITTING_FRESH_PROVIDER_VERIFIED",
            "record_sha256": verified.verified.receipt.payload["record"]["sha256"],
            "github_receipt": verified.github_receipt.receipt_path,
            "github_raw_output": verified.github_receipt.raw_output_path,
            "decision": "NONE",
            "admission": False,
            "requires": "explicit-allow-nonadmitting-evidence-for-archive-only-success",
        },
    )
    return 0 if args.allow_nonadmitting_evidence else 1


def _release_source_key_separation(args: argparse.Namespace) -> dict[str, str]:
    """Derive the closed-world cross-domain key registry from public keys."""

    from evoom_guard.signing import public_key_id

    return {
        "trusted_finalizer": public_key_id(args.trusted_finalizer_pub),
        "artifact_admission_v1": public_key_id(args.artifact_admission_v1_pub),
        "artifact_digest_admission_v2": public_key_id(
            args.artifact_digest_admission_v2_pub
        ),
        "release_source_finalizer_v1": public_key_id(
            args.release_source_finalizer_v1_pub
        ),
    }


def _preflight_release_source_admission_paths(args: argparse.Namespace) -> None:
    """Reject destructive aliases and no-clobber failures before provider I/O."""

    def resolved(path: str) -> str:
        return os.path.normcase(os.path.realpath(os.path.abspath(path)))

    paths = {
        "output": args.out,
        "source": args.source,
        "context": args.context,
        "producer identity": args.producer,
        "admitter identity": args.admitter,
        "GitHub policy": args.github_policy,
        "producer receipt": args.receipt,
        "handoff": args.handoff,
        "verdict": args.verdict,
        "Git executable": args.git_executable,
        "GitHub CLI executable": args.gh_executable,
        "private key": args.sign_key,
        "public key": args.sign_pub,
        "Trusted Finalizer public key": args.trusted_finalizer_pub,
        "Artifact Admission V1 public key": args.artifact_admission_v1_pub,
        "Artifact Digest Admission V2 public key": (
            args.artifact_digest_admission_v2_pub
        ),
        "Release Source Finalizer V1 public key": (
            args.release_source_finalizer_v1_pub
        ),
        "provider receipt": args.github_receipt_out,
        "provider raw output": args.github_raw_output_out,
    }
    identities: dict[str, str] = {}
    for label, path in paths.items():
        identity = resolved(path)
        if identity in identities:
            raise ValueError(
                f"release-source admission {label} path aliases {identities[identity]}"
            )
        identities[identity] = label
    if os.path.lexists(args.out) and not args.force:
        raise ValueError("release-source admission output already exists and --force was not set")
    for label, path in (
        ("provider receipt", args.github_receipt_out),
        ("provider raw output", args.github_raw_output_out),
    ):
        if os.path.lexists(path):
            raise ValueError(f"{label} output already exists; provider evidence is no-clobber")


def cmd_seal_release_source_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Freshly verify the protected producer relation, then sign one V2 ALLOW."""

    from evoom_guard.admission.release_source import (
        RELEASE_SOURCE_ADMISSION_FORMAT,
        ReleaseSourceAdmissionError,
        seal_release_source_admission,
    )
    from evoom_guard.finalizer_derivation import (
        FinalizerDerivationError,
        git_executable_pin,
    )
    from evoom_guard.github_attestation import (
        GitHubAttestationError,
        github_attestation_provider_isolation,
    )
    from evoom_guard.release_source_producer_receipt import (
        ReleaseSourceProducerReceiptError,
        reverify_attested_release_source_producer_receipt,
        validate_release_source_admitter_runtime_environment,
        verify_release_source_admitter_workflow_blob,
    )
    from evoom_guard.signing import SigningUnavailableError, public_key_id

    if any(value == "-" for value in (args.receipt, args.handoff, args.verdict)):
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_ADMISSION_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": "producer receipt, handoff, and verdict must be regular files, not standard input",
            },
        )
        return 2
    try:
        source, context, producer = _producer_receipt_external_inputs(args)
        admitter = _read_external_finalizer_object(
            args.admitter,
            label="expected release-source admitter",
        )
        github_policy = _read_external_finalizer_object(
            args.github_policy, label="GitHub producer-attestation policy"
        )
        key_separation = _release_source_key_separation(args)
        expected_signing_key_id = public_key_id(args.sign_pub)
        if expected_signing_key_id in set(key_separation.values()):
            raise ValueError(
                "release-source admission public key belongs to another configured trust domain"
            )
        _preflight_release_source_admission_paths(args)
        git_executable = git_executable_pin(
            args.git_executable,
            args.git_executable_sha256,
        )
        provider_isolation = github_attestation_provider_isolation(
            args.gh_executable,
            args.gh_executable_sha256,
            uid=args.provider_isolation_uid,
            gid=args.provider_isolation_gid,
        )
        admitter = verify_release_source_admitter_workflow_blob(
            source=source,
            producer=producer,
            admitter=admitter,
            git_repository=args.git_repository,
            git_repository_is_bare=args.git_repository_bare,
            git_executable=git_executable,
        )
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        if not event_path:
            raise ValueError(
                "seal-release-source-admission requires GitHub Actions GITHUB_EVENT_PATH"
            )
        event_payload = _read_external_finalizer_object(
            event_path,
            label="GitHub Actions workflow_run event payload",
        )
        runtime_admitter = validate_release_source_admitter_runtime_environment(
            admitter,
            producer,
            environment=os.environ,
            event_payload=event_payload,
        )
        attested = reverify_attested_release_source_producer_receipt(
            args.receipt,
            args.handoff,
            args.verdict,
            expected_source=source,
            expected_context=context,
            expected_producer=producer,
            expected_bootstrap_guard_sha256=args.bootstrap_guard_sha,
            expected_github_policy=github_policy,
            git_repository=args.git_repository,
            git_repository_is_bare=args.git_repository_bare,
            github_receipt_path=args.github_receipt_out,
            github_raw_output_path=args.github_raw_output_out,
            gh_executable=args.gh_executable,
            timeout_seconds=args.timeout_seconds,
            provider_isolation=provider_isolation,
            protected_signing_key_path=args.sign_key,
            git_executable=git_executable,
        )
        sealed = seal_release_source_admission(
            attested,
            args.out,
            admitter=runtime_admitter,
            key_separation=key_separation,
            git_repository=args.git_repository,
            git_repository_is_bare=args.git_repository_bare,
            git_executable=git_executable,
            provider_isolation=provider_isolation,
            private_key_path=args.sign_key,
            signing_public_key_path=args.sign_pub,
            expected_signing_key_id=expected_signing_key_id,
            force=args.force,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        ReleaseSourceAdmissionError,
        ReleaseSourceProducerReceiptError,
        GitHubAttestationError,
        FinalizerDerivationError,
        SigningUnavailableError,
    ) as exc:
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_ADMISSION_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "REJECTED",
                "error": str(exc),
            },
        )
        return 1
    _machine_report(
        out,
        {
            "format": RELEASE_SOURCE_ADMISSION_FORMAT,
            "ok": True,
            "sealed": True,
            "verified": True,
            "status": "SEALED",
            "bundle": sealed.bundle_path,
            "key_id": sealed.manifest["authentication"]["key_id"],
            "record_sha256": sealed.manifest["record"]["sha256"],
            "producer_receipt_sha256": sealed.manifest["producer_receipt"]["sha256"],
            "decision": sealed.decision,
            "admission": True,
            "provider_verified": True,
        },
    )
    return 0


def cmd_verify_release_source_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Verify a V2 source authorization using only external trust roots."""

    from evoom_guard.admission.release_source import (
        RELEASE_SOURCE_ADMISSION_FORMAT,
        ReleaseSourceAdmissionError,
        verify_release_source_admission,
    )
    from evoom_guard.signing import SigningUnavailableError

    if args.bundle == "-":
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_ADMISSION_FORMAT,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": "release-source admission bundle must be a regular file, not standard input",
            },
        )
        return 2
    try:
        source = _read_external_finalizer_object(args.expected_source, label="expected release source")
        context = _read_external_finalizer_object(
            args.expected_context, label="expected release-source context"
        )
        producer = _read_external_finalizer_object(
            args.expected_producer, label="expected producer identity"
        )
        admitter = _read_external_finalizer_object(
            args.expected_admitter, label="expected protected C workflow identity"
        )
        github_policy = _read_external_finalizer_object(
            args.expected_github_policy, label="expected GitHub producer-attestation policy"
        )
        key_separation = _release_source_key_separation(args)
        verified = verify_release_source_admission(
            args.bundle,
            trusted_public_key_path=args.trusted_pub,
            expected_source=source,
            expected_context=context,
            expected_producer=producer,
            expected_admitter=admitter,
            expected_bootstrap_guard_sha256=args.expected_bootstrap_guard_sha,
            expected_github_policy=github_policy,
            expected_key_separation=key_separation,
            expected_git_executable_sha256=args.expected_git_executable_sha256,
            expected_github_cli_executable_sha256=args.expected_gh_executable_sha256,
            expected_provider_isolation_uid=args.expected_provider_isolation_uid,
            expected_provider_isolation_gid=args.expected_provider_isolation_gid,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        ReleaseSourceAdmissionError,
        SigningUnavailableError,
    ) as exc:
        _machine_report(
            out,
            {
                "format": RELEASE_SOURCE_ADMISSION_FORMAT,
                "ok": False,
                "verified": False,
                "status": "REJECTED",
                "error": str(exc),
            },
        )
        return 1
    _machine_report(
        out,
        {
            "format": RELEASE_SOURCE_ADMISSION_FORMAT,
            "ok": True,
            "verified": True,
            "status": "VERIFIED",
            "key_id": verified.bundle.manifest["authentication"]["key_id"],
            "record_sha256": verified.bundle.manifest["record"]["sha256"],
            "producer_receipt_sha256": verified.bundle.manifest["producer_receipt"]["sha256"],
            "decision": verified.decision,
            "admission": True,
        },
    )
    return 0


def _release_artifact_key_separation(args: argparse.Namespace) -> dict[str, str]:
    """Derive the exact five-root registry that precedes the RAAE signer."""

    from evoom_guard.signing import public_key_id

    return {
        "trusted_finalizer": public_key_id(args.trusted_finalizer_pub),
        "artifact_admission_v1": public_key_id(args.artifact_admission_v1_pub),
        "artifact_digest_admission_v2": public_key_id(
            args.artifact_digest_admission_v2_pub
        ),
        "release_source_finalizer_v1": public_key_id(
            args.release_source_finalizer_v1_pub
        ),
        "release_source_admission_v2": public_key_id(
            args.release_source_admission_v2_pub
        ),
    }


def _release_artifact_nested_expectations(
    args: argparse.Namespace,
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    """Read the externally controlled objects used to re-verify the nested RSAE."""

    source = _read_external_finalizer_object(
        args.expected_release_source,
        label="expected protected-main release source",
    )
    context = _read_external_finalizer_object(
        args.expected_release_source_context,
        label="expected release-source context",
    )
    producer = _read_external_finalizer_object(
        args.expected_release_source_producer,
        label="expected release-source producer",
    )
    admitter = _read_external_finalizer_object(
        args.expected_release_source_admitter,
        label="expected release-source admitter",
    )
    github_policy = _read_external_finalizer_object(
        args.expected_release_source_github_policy,
        label="expected release-source GitHub policy",
    )
    return source, context, producer, admitter, github_policy


def _preflight_release_artifact_admission_paths(
    args: argparse.Namespace,
    *,
    event_path: str,
) -> None:
    """Reject destructive aliases and an existing RAAE before provider access."""

    def resolved(path: str) -> str:
        return os.path.normcase(os.path.realpath(os.path.abspath(path)))

    paths = {
        "output": args.out,
        "release-source admission": args.release_source_admission,
        "artifact": args.artifact,
        "builder identity": args.builder,
        "admitter identity": args.admitter,
        "release source": args.expected_release_source,
        "release-source context": args.expected_release_source_context,
        "release-source producer": args.expected_release_source_producer,
        "release-source admitter": args.expected_release_source_admitter,
        "release-source GitHub policy": args.expected_release_source_github_policy,
        "GitHub event payload": event_path,
        "Git executable": args.git_executable,
        "GitHub CLI executable": args.gh_executable,
        "private key": args.sign_key,
        "public key": args.sign_pub,
        "Trusted Finalizer public key": args.trusted_finalizer_pub,
        "Artifact Admission V1 public key": args.artifact_admission_v1_pub,
        "Artifact Digest Admission V2 public key": (
            args.artifact_digest_admission_v2_pub
        ),
        "Release Source Finalizer V1 public key": (
            args.release_source_finalizer_v1_pub
        ),
        "Release Source Admission V2 public key": (
            args.release_source_admission_v2_pub
        ),
    }
    identities: dict[str, str] = {}
    for label, path in paths.items():
        if path == "-":
            raise ValueError(
                f"release-artifact admission {label} must be a regular path, "
                "not standard input/output"
            )
        identity = resolved(path)
        if identity in identities:
            raise ValueError(
                f"release-artifact admission {label} path aliases "
                f"{identities[identity]}"
            )
        identities[identity] = label
    if os.path.lexists(args.out):
        raise ValueError("release-artifact admission output already exists")


def cmd_seal_github_release_artifact_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Bind the live F job to E, freshly verify GitHub, then seal one RAAE."""

    from evoom_guard.admission.release_artifact import (
        RELEASE_ARTIFACT_ADMISSION_FORMAT,
        ReleaseArtifactAdmissionError,
        bind_release_artifact_admitter_runtime,
        seal_release_artifact_admission,
    )
    from evoom_guard.finalizer_derivation import (
        FinalizerDerivationError,
        git_executable_pin,
    )
    from evoom_guard.github_attestation import (
        GitHubAttestationError,
        github_attestation_provider_isolation,
    )
    from evoom_guard.signing import SigningUnavailableError, public_key_id

    try:
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        if not event_path:
            raise ValueError(
                "seal-github-release-artifact-admission requires GitHub Actions "
                "GITHUB_EVENT_PATH"
            )
        _preflight_release_artifact_admission_paths(args, event_path=event_path)
        source, context, producer, source_admitter, source_policy = (
            _release_artifact_nested_expectations(args)
        )
        builder = _read_external_finalizer_object(
            args.builder,
            label="protected release-artifact builder identity",
        )
        admitter = _read_external_finalizer_object(
            args.admitter,
            label="protected release-artifact admitter identity",
        )
        event_payload = _read_external_finalizer_object(
            event_path,
            label="GitHub Actions release-artifact workflow_run event payload",
        )
        runtime_admitter = bind_release_artifact_admitter_runtime(
            builder,
            admitter,
            source=source,
            environment=os.environ,
            event_payload=event_payload,
        )
        key_separation = _release_artifact_key_separation(args)
        expected_signing_key_id = public_key_id(args.sign_pub)
        if expected_signing_key_id in set(key_separation.values()):
            raise ValueError(
                "release-artifact admission public key belongs to an earlier "
                "configured trust domain"
            )
        git_executable = git_executable_pin(
            args.git_executable,
            args.git_executable_sha256,
        )
        provider_isolation = github_attestation_provider_isolation(
            args.gh_executable,
            args.gh_executable_sha256,
            uid=args.provider_isolation_uid,
            gid=args.provider_isolation_gid,
        )
        sealed = seal_release_artifact_admission(
            args.release_source_admission,
            args.artifact,
            args.out,
            admitter=runtime_admitter,
            trusted_release_source_public_key_path=(
                args.release_source_admission_v2_pub
            ),
            expected_release_source=source,
            expected_release_source_context=context,
            expected_release_source_producer=producer,
            expected_release_source_admitter=source_admitter,
            expected_release_source_bootstrap_guard_sha256=(
                args.expected_release_source_bootstrap_guard_sha
            ),
            expected_release_source_github_policy=source_policy,
            expected_release_source_git_executable_sha256=(
                args.expected_release_source_git_executable_sha256
            ),
            expected_release_source_github_cli_executable_sha256=(
                args.expected_release_source_gh_executable_sha256
            ),
            expected_release_source_provider_isolation_uid=(
                args.expected_release_source_provider_isolation_uid
            ),
            expected_release_source_provider_isolation_gid=(
                args.expected_release_source_provider_isolation_gid
            ),
            key_separation=key_separation,
            git_repository=args.git_repository,
            git_repository_is_bare=args.git_repository_bare,
            git_executable=git_executable,
            provider_isolation=provider_isolation,
            private_key_path=args.sign_key,
            signing_public_key_path=args.sign_pub,
            expected_signing_key_id=expected_signing_key_id,
            gh_executable=args.gh_executable,
            timeout_seconds=args.timeout_seconds,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        ReleaseArtifactAdmissionError,
        GitHubAttestationError,
        FinalizerDerivationError,
        SigningUnavailableError,
    ) as exc:
        _machine_report(
            out,
            {
                "format": RELEASE_ARTIFACT_ADMISSION_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "REJECTED",
                "error": str(exc),
            },
        )
        return 1
    _machine_report(
        out,
        {
            "format": RELEASE_ARTIFACT_ADMISSION_FORMAT,
            "ok": True,
            "sealed": True,
            "verified": True,
            "status": "SEALED",
            "bundle": sealed.bundle_path,
            "artifact": sealed.artifact.as_dict(),
            "release_source": sealed.manifest["release_source"],
            "builder": sealed.manifest["builder"],
            "admitter": sealed.manifest["admitter"],
            "key_id": sealed.manifest["authentication"]["key_id"],
            "decision": sealed.decision,
            "admission": True,
            "provider_verified": True,
            "live_provider_reverification": True,
        },
    )
    return 0


def cmd_verify_github_release_artifact_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Verify one RAAE, its artifact, nested RSAE, and all six roots offline."""

    from evoom_guard.admission.release_artifact import (
        RELEASE_ARTIFACT_ADMISSION_FORMAT,
        ReleaseArtifactAdmissionError,
        verify_release_artifact_admission,
    )
    from evoom_guard.signing import SigningUnavailableError

    try:
        if args.bundle == "-" or args.artifact == "-":
            raise ValueError(
                "release-artifact admission bundle and artifact must be regular "
                "files, not standard input"
            )
        source, context, producer, source_admitter, source_policy = (
            _release_artifact_nested_expectations(args)
        )
        builder = _read_external_finalizer_object(
            args.expected_builder,
            label="expected protected release-artifact builder identity",
        )
        admitter = _read_external_finalizer_object(
            args.expected_admitter,
            label="expected protected release-artifact admitter identity",
        )
        key_separation = _release_artifact_key_separation(args)
        verified = verify_release_artifact_admission(
            args.bundle,
            args.artifact,
            trusted_public_key_path=args.trusted_pub,
            trusted_release_source_public_key_path=(
                args.release_source_admission_v2_pub
            ),
            expected_release_source=source,
            expected_release_source_context=context,
            expected_release_source_producer=producer,
            expected_release_source_admitter=source_admitter,
            expected_release_source_bootstrap_guard_sha256=(
                args.expected_release_source_bootstrap_guard_sha
            ),
            expected_release_source_github_policy=source_policy,
            expected_release_source_git_executable_sha256=(
                args.expected_release_source_git_executable_sha256
            ),
            expected_release_source_github_cli_executable_sha256=(
                args.expected_release_source_gh_executable_sha256
            ),
            expected_release_source_provider_isolation_uid=(
                args.expected_release_source_provider_isolation_uid
            ),
            expected_release_source_provider_isolation_gid=(
                args.expected_release_source_provider_isolation_gid
            ),
            expected_builder=builder,
            expected_admitter=admitter,
            expected_key_separation=key_separation,
            expected_git_executable_sha256=args.expected_git_executable_sha256,
            expected_github_cli_executable_sha256=(
                args.expected_gh_executable_sha256
            ),
            expected_provider_isolation_uid=args.expected_provider_isolation_uid,
            expected_provider_isolation_gid=args.expected_provider_isolation_gid,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        ReleaseArtifactAdmissionError,
        SigningUnavailableError,
    ) as exc:
        _machine_report(
            out,
            {
                "format": RELEASE_ARTIFACT_ADMISSION_FORMAT,
                "ok": False,
                "verified": False,
                "status": "REJECTED",
                "error": str(exc),
            },
        )
        return 1
    manifest = verified.bundle.manifest
    _machine_report(
        out,
        {
            "format": RELEASE_ARTIFACT_ADMISSION_FORMAT,
            "ok": True,
            "verified": True,
            "status": "VERIFIED",
            "decision": verified.decision,
            "admission": True,
            "artifact": verified.artifact.as_dict(),
            "release_source": manifest["release_source"],
            "builder": manifest["builder"],
            "admitter": manifest["admitter"],
            "key_id": manifest["authentication"]["key_id"],
            "verification_scope": "detached-offline-retained-provider-evidence",
            "live_provider_reverification": False,
        },
    )
    return 0


def cmd_seal_artifact_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Seal one file only after an external Trusted Finalizer ALLOW."""

    from evoom_guard.artifact_admission import (
        ARTIFACT_BINDING_FORMAT,
        ArtifactAdmissionError,
        seal_artifact_admission,
    )
    from evoom_guard.signing import SigningUnavailableError

    if args.artifact == "-" or args.finalizer_bundle == "-":
        _machine_report(
            out,
            {
                "format": ARTIFACT_BINDING_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": "artifact and finalizer bundle must be regular files, not standard input",
            },
        )
        return 2
    try:
        expected_source = _read_external_finalizer_object(
            args.expected_source, label="expected source"
        )
        expected_context = _read_external_finalizer_object(
            args.expected_context, label="expected context"
        )
    except (OSError, UnicodeError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": ARTIFACT_BINDING_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": f"unusable external trust input: {exc}",
            },
        )
        return 2
    try:
        sealed = seal_artifact_admission(
            args.artifact,
            args.finalizer_bundle,
            args.out,
            trusted_finalizer_public_key_path=args.finalizer_pub,
            expected_finalizer_source=expected_source,
            expected_finalizer_context=expected_context,
            private_key_path=args.sign_key,
            force=args.force,
        )
    except ArtifactAdmissionError as exc:
        _machine_report(
            out,
            {
                "format": ARTIFACT_BINDING_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "INVALID_INPUT",
                "error": str(exc),
            },
        )
        return 1
    except (OSError, ValueError, SigningUnavailableError) as exc:
        _machine_report(
            out,
            {
                "format": ARTIFACT_BINDING_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    _machine_report(
        out,
        {
            "format": ARTIFACT_BINDING_FORMAT,
            "ok": True,
            "sealed": True,
            "status": "SEALED",
            "decision": "ALLOW",
            "binding": sealed.binding_path,
            "subject": sealed.subject.as_dict(),
            "finalizer": sealed.payload["finalizer"],
            "key_id": sealed.payload["authentication"]["key_id"],
        },
    )
    return 0


def cmd_verify_artifact_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Verify a file binding with external artifact/finalizer trust inputs."""

    from evoom_guard.artifact_admission import (
        ARTIFACT_BINDING_FORMAT,
        ArtifactAdmissionError,
        verify_artifact_admission,
    )
    from evoom_guard.signing import SigningUnavailableError

    if any(value == "-" for value in (args.binding, args.artifact, args.finalizer_bundle)):
        _machine_report(
            out,
            {
                "format": ARTIFACT_BINDING_FORMAT,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": "binding, artifact, and finalizer bundle must be regular files, not standard input",
            },
        )
        return 2
    try:
        expected_source = _read_external_finalizer_object(
            args.expected_source, label="expected source"
        )
        expected_context = _read_external_finalizer_object(
            args.expected_context, label="expected context"
        )
    except (OSError, UnicodeError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": ARTIFACT_BINDING_FORMAT,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": f"unusable external trust input: {exc}",
            },
        )
        return 2
    try:
        verified = verify_artifact_admission(
            args.binding,
            args.artifact,
            args.finalizer_bundle,
            trusted_public_key_path=args.trusted_pub,
            trusted_finalizer_public_key_path=args.finalizer_pub,
            expected_finalizer_source=expected_source,
            expected_finalizer_context=expected_context,
        )
    except ArtifactAdmissionError as exc:
        _machine_report(
            out,
            {
                "format": ARTIFACT_BINDING_FORMAT,
                "ok": False,
                "verified": False,
                "status": "INVALID",
                "error": str(exc),
            },
        )
        return 1
    except (OSError, ValueError, SigningUnavailableError) as exc:
        _machine_report(
            out,
            {
                "format": ARTIFACT_BINDING_FORMAT,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    _machine_report(
        out,
        {
            "format": ARTIFACT_BINDING_FORMAT,
            "ok": True,
            "verified": True,
            "status": "VERIFIED",
            "decision": "ALLOW",
            "subject": verified.subject.as_dict(),
            "finalizer": verified.inspection.finalizer,
            "key_id": verified.inspection.payload["authentication"]["key_id"],
        },
    )
    return 0


def cmd_seal_artifact_digest_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Seal one immutable digest after an external Trusted Finalizer ALLOW."""

    from evoom_guard.artifact_digest_admission import (
        ARTIFACT_DIGEST_BINDING_FORMAT,
        ArtifactDigestAdmissionError,
        seal_artifact_digest_admission,
    )
    from evoom_guard.signing import SigningUnavailableError

    if any(value == "-" for value in (args.finalizer_bundle, args.provenance)):
        _machine_report(
            out,
            {
                "format": ARTIFACT_DIGEST_BINDING_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": "finalizer bundle and provenance must be regular files, not standard input",
            },
        )
        return 2
    try:
        expected_source = _read_external_finalizer_object(
            args.expected_source, label="expected source"
        )
        expected_context = _read_external_finalizer_object(
            args.expected_context, label="expected context"
        )
    except (OSError, UnicodeError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": ARTIFACT_DIGEST_BINDING_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": f"unusable external trust input: {exc}",
            },
        )
        return 2
    try:
        sealed = seal_artifact_digest_admission(
            args.subject_kind,
            args.subject_digest,
            args.provenance,
            args.provenance_identity,
            args.finalizer_bundle,
            args.out,
            trusted_finalizer_public_key_path=args.finalizer_pub,
            expected_finalizer_source=expected_source,
            expected_finalizer_context=expected_context,
            private_key_path=args.sign_key,
            force=args.force,
        )
    except ArtifactDigestAdmissionError as exc:
        _machine_report(
            out,
            {
                "format": ARTIFACT_DIGEST_BINDING_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "INVALID_INPUT",
                "error": str(exc),
            },
        )
        return 1
    except (OSError, ValueError, SigningUnavailableError) as exc:
        _machine_report(
            out,
            {
                "format": ARTIFACT_DIGEST_BINDING_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    _machine_report(
        out,
        {
            "format": ARTIFACT_DIGEST_BINDING_FORMAT,
            "ok": True,
            "sealed": True,
            "status": "SEALED",
            "decision": "ALLOW",
            "binding": sealed.binding_path,
            "subject": sealed.subject.as_dict(),
            "provenance_reference": sealed.provenance_reference.as_dict(),
            "finalizer": sealed.payload["finalizer"],
            "key_id": sealed.payload["authentication"]["key_id"],
        },
    )
    return 0


def cmd_verify_artifact_digest_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Verify V2 with external subject, provenance, and finalizer inputs."""

    from evoom_guard.artifact_digest_admission import (
        ARTIFACT_DIGEST_BINDING_FORMAT,
        ArtifactDigestAdmissionError,
        verify_artifact_digest_admission,
    )
    from evoom_guard.signing import SigningUnavailableError

    if any(value == "-" for value in (args.binding, args.finalizer_bundle, args.provenance)):
        _machine_report(
            out,
            {
                "format": ARTIFACT_DIGEST_BINDING_FORMAT,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": "binding, finalizer bundle, and provenance must be regular files, not standard input",
            },
        )
        return 2
    try:
        expected_source = _read_external_finalizer_object(
            args.expected_source, label="expected source"
        )
        expected_context = _read_external_finalizer_object(
            args.expected_context, label="expected context"
        )
    except (OSError, UnicodeError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": ARTIFACT_DIGEST_BINDING_FORMAT,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": f"unusable external trust input: {exc}",
            },
        )
        return 2
    try:
        verified = verify_artifact_digest_admission(
            args.binding,
            args.subject_kind,
            args.subject_digest,
            args.provenance,
            args.provenance_identity,
            args.finalizer_bundle,
            trusted_public_key_path=args.trusted_pub,
            trusted_finalizer_public_key_path=args.finalizer_pub,
            expected_finalizer_source=expected_source,
            expected_finalizer_context=expected_context,
        )
    except ArtifactDigestAdmissionError as exc:
        _machine_report(
            out,
            {
                "format": ARTIFACT_DIGEST_BINDING_FORMAT,
                "ok": False,
                "verified": False,
                "status": "INVALID",
                "error": str(exc),
            },
        )
        return 1
    except (OSError, ValueError, SigningUnavailableError) as exc:
        _machine_report(
            out,
            {
                "format": ARTIFACT_DIGEST_BINDING_FORMAT,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    _machine_report(
        out,
        {
            "format": ARTIFACT_DIGEST_BINDING_FORMAT,
            "ok": True,
            "verified": True,
            "status": "VERIFIED",
            "decision": "ALLOW",
            "subject": verified.subject.as_dict(),
            "provenance_reference": verified.provenance_reference.as_dict(),
            "finalizer": verified.inspection.finalizer,
            "key_id": verified.inspection.payload["authentication"]["key_id"],
        },
    )
    return 0


def _github_attestation_policy_kwargs(
    args: argparse.Namespace,
) -> _GitHubAttestationPolicyKwargs:
    """Return only the exact policy inputs accepted by the provider adapter."""

    return {
        "repository": args.repo,
        "signer_workflow": args.signer_workflow,
        "signer_digest": args.signer_digest,
        "source_ref": args.source_ref,
        "source_digest": args.source_digest,
        "cert_oidc_issuer": args.cert_oidc_issuer,
    }


def _github_attestation_provider_isolation(
    args: argparse.Namespace,
) -> GitHubAttestationProviderIsolation | None:
    """Build the optional all-or-nothing POSIX provider-isolation contract."""

    from evoom_guard.github_attestation import (
        GitHubAttestationError,
        github_attestation_provider_isolation,
    )

    digest = args.gh_executable_sha256
    uid = args.provider_isolation_uid
    gid = args.provider_isolation_gid
    supplied = (digest is not None, uid is not None, gid is not None)
    if not any(supplied):
        return None
    if not all(supplied):
        raise GitHubAttestationError(
            "--gh-executable-sha256, --provider-isolation-uid, and "
            "--provider-isolation-gid must be supplied together"
        )
    return github_attestation_provider_isolation(
        args.gh_executable,
        digest,
        uid=uid,
        gid=gid,
    )


def cmd_github_attestation_receipt(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Run the narrow provider verifier and retain its exact bounded evidence."""

    from evoom_guard.github_attestation import (
        GITHUB_ATTESTATION_RECEIPT_FORMAT,
        GitHubAttestationError,
        create_github_attestation_receipt,
    )

    try:
        created = create_github_attestation_receipt(
            args.artifact,
            args.receipt_out,
            args.raw_output_out,
            **_github_attestation_policy_kwargs(args),
            gh_executable=args.gh_executable,
            timeout_seconds=args.timeout_seconds,
            provider_isolation=_github_attestation_provider_isolation(args),
        )
    except GitHubAttestationError as exc:
        _machine_report(
            out,
            {
                "format": GITHUB_ATTESTATION_RECEIPT_FORMAT,
                "ok": False,
                "verified": False,
                "status": "REJECTED",
                "error": str(exc),
            },
        )
        return 1
    except (OSError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": GITHUB_ATTESTATION_RECEIPT_FORMAT,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    _machine_report(
        out,
        {
            "format": GITHUB_ATTESTATION_RECEIPT_FORMAT,
            "ok": True,
            "verified": True,
            "status": "PROVIDER_VERIFIED",
            "verification_scope": "fresh-provider-gh-attestation-verify",
            "receipt": created.receipt_path,
            "raw_output": created.raw_output_path,
            "artifact": created.artifact.as_dict(),
            "verification_policy": created.policy.as_dict(),
            "verified_attestation_count": created.verified_attestation_count,
        },
    )
    return 0


def cmd_verify_github_attestation_receipt(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Check retained evidence continuity without making a live provider call."""

    from evoom_guard.github_attestation import (
        GITHUB_ATTESTATION_RECEIPT_FORMAT,
        GitHubAttestationError,
        verify_github_attestation_receipt,
    )

    try:
        verified = verify_github_attestation_receipt(
            args.receipt,
            args.artifact,
            args.raw_output,
            **_github_attestation_policy_kwargs(args),
        )
    except GitHubAttestationError as exc:
        _machine_report(
            out,
            {
                "format": GITHUB_ATTESTATION_RECEIPT_FORMAT,
                "ok": False,
                "verified": False,
                "status": "INVALID",
                "error": str(exc),
            },
        )
        return 1
    except (OSError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": GITHUB_ATTESTATION_RECEIPT_FORMAT,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    _machine_report(
        out,
        {
            "format": GITHUB_ATTESTATION_RECEIPT_FORMAT,
            "ok": True,
            "verified": True,
            "status": "RETAINED_RECEIPT_VERIFIED",
            "verification_scope": "retained-byte-continuity-only",
            "live_provider_reverification": False,
            "artifact": verified.artifact.as_dict(),
            "verification_policy": verified.policy.as_dict(),
        },
    )
    return 0


def cmd_reverify_github_attestation_receipt(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Make a fresh constrained GitHub CLI verification for a retained receipt."""

    from evoom_guard.github_attestation import (
        GITHUB_ATTESTATION_RECEIPT_FORMAT,
        GitHubAttestationError,
        reverify_github_attestation_receipt,
    )

    try:
        fresh = reverify_github_attestation_receipt(
            args.receipt,
            args.artifact,
            **_github_attestation_policy_kwargs(args),
            gh_executable=args.gh_executable,
            timeout_seconds=args.timeout_seconds,
            provider_isolation=_github_attestation_provider_isolation(args),
        )
    except GitHubAttestationError as exc:
        _machine_report(
            out,
            {
                "format": GITHUB_ATTESTATION_RECEIPT_FORMAT,
                "ok": False,
                "verified": False,
                "status": "REJECTED",
                "error": str(exc),
            },
        )
        return 1
    except (OSError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": GITHUB_ATTESTATION_RECEIPT_FORMAT,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    _machine_report(
        out,
        {
            "format": GITHUB_ATTESTATION_RECEIPT_FORMAT,
            "ok": True,
            "verified": True,
            "status": "FRESH_PROVIDER_REVERIFIED",
            "verification_scope": "fresh-provider-gh-attestation-verify",
            "artifact": fresh.artifact.as_dict(),
            "verification_policy": fresh.policy.as_dict(),
            "verified_attestation_count": fresh.verified_attestation_count,
            "reverification": "fresh-gh-attestation-verify",
        },
    )
    return 0


def cmd_seal_github_attestation_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Freshly verify provider evidence, then bind it to a finalizer ALLOW.

    This command intentionally owns no shortcut around the provider policy,
    external finalizer source/context, or separate V2 admission key.  In
    particular it exposes no overwrite switch: a protected job must choose
    fresh, reviewable evidence paths for every run.
    """

    from evoom_guard.artifact_digest_admission import ARTIFACT_DIGEST_BINDING_FORMAT
    from evoom_guard.github_attestation import (
        GitHubAttestationError,
        seal_github_attestation_admission,
    )
    from evoom_guard.signing import SigningUnavailableError

    regular_paths = (
        args.artifact,
        args.finalizer_bundle,
        args.receipt_out,
        args.raw_output_out,
        args.out,
        args.finalizer_pub,
        args.sign_key,
    )
    if any(value == "-" for value in regular_paths):
        _machine_report(
            out,
            {
                "format": ARTIFACT_DIGEST_BINDING_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": (
                    "artifact, finalizer bundle, receipt, raw output, binding, and key "
                    "paths must be regular files, not standard input/output"
                ),
            },
        )
        return 2
    try:
        expected_source = _read_external_finalizer_object(
            args.expected_source, label="expected source"
        )
        expected_context = _read_external_finalizer_object(
            args.expected_context, label="expected context"
        )
    except (OSError, UnicodeError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": ARTIFACT_DIGEST_BINDING_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": f"unusable external trust input: {exc}",
            },
        )
        return 2
    try:
        sealed = seal_github_attestation_admission(
            args.artifact,
            args.receipt_out,
            args.raw_output_out,
            args.finalizer_bundle,
            args.out,
            **_github_attestation_policy_kwargs(args),
            trusted_finalizer_public_key_path=args.finalizer_pub,
            expected_finalizer_source=expected_source,
            expected_finalizer_context=expected_context,
            private_key_path=args.sign_key,
            gh_executable=args.gh_executable,
            timeout_seconds=args.timeout_seconds,
            provider_isolation=_github_attestation_provider_isolation(args),
        )
    except GitHubAttestationError as exc:
        _machine_report(
            out,
            {
                "format": ARTIFACT_DIGEST_BINDING_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "REJECTED",
                "error": str(exc),
            },
        )
        return 1
    except (OSError, ValueError, SigningUnavailableError) as exc:
        _machine_report(
            out,
            {
                "format": ARTIFACT_DIGEST_BINDING_FORMAT,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    _machine_report(
        out,
        {
            "format": ARTIFACT_DIGEST_BINDING_FORMAT,
            "ok": True,
            "sealed": True,
            "status": "SEALED",
            "decision": "ALLOW",
            "verification_scope": (
                "fresh-provider-gh-attestation-verify-plus-trusted-finalizer-allow"
            ),
            "receipt": sealed.receipt.receipt_path,
            "raw_output": sealed.receipt.raw_output_path,
            "binding": sealed.admission.binding_path,
            "artifact": sealed.receipt.artifact.as_dict(),
            "verification_policy": sealed.receipt.policy.as_dict(),
            "subject": sealed.admission.subject.as_dict(),
            "provenance_reference": sealed.admission.provenance_reference.as_dict(),
            "finalizer": sealed.admission.payload["finalizer"],
            "key_id": sealed.admission.payload["authentication"]["key_id"],
        },
    )
    return 0


def cmd_verify_github_attestation_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Verify retained provider bytes and their V2 finalizer-bound relation."""

    from evoom_guard.artifact_digest_admission import ARTIFACT_DIGEST_BINDING_FORMAT
    from evoom_guard.github_attestation import (
        GitHubAttestationError,
        verify_github_attestation_admission,
    )
    from evoom_guard.signing import SigningUnavailableError

    regular_paths = (
        args.binding,
        args.artifact,
        args.receipt,
        args.raw_output,
        args.finalizer_bundle,
        args.trusted_pub,
        args.finalizer_pub,
    )
    if any(value == "-" for value in regular_paths):
        _machine_report(
            out,
            {
                "format": ARTIFACT_DIGEST_BINDING_FORMAT,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": (
                    "binding, artifact, receipt, raw output, finalizer bundle, and key "
                    "paths must be regular files, not standard input/output"
                ),
            },
        )
        return 2
    try:
        expected_source = _read_external_finalizer_object(
            args.expected_source, label="expected source"
        )
        expected_context = _read_external_finalizer_object(
            args.expected_context, label="expected context"
        )
    except (OSError, UnicodeError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": ARTIFACT_DIGEST_BINDING_FORMAT,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": f"unusable external trust input: {exc}",
            },
        )
        return 2
    try:
        verified = verify_github_attestation_admission(
            args.binding,
            args.artifact,
            args.receipt,
            args.raw_output,
            args.finalizer_bundle,
            **_github_attestation_policy_kwargs(args),
            trusted_public_key_path=args.trusted_pub,
            trusted_finalizer_public_key_path=args.finalizer_pub,
            expected_finalizer_source=expected_source,
            expected_finalizer_context=expected_context,
        )
    except GitHubAttestationError as exc:
        _machine_report(
            out,
            {
                "format": ARTIFACT_DIGEST_BINDING_FORMAT,
                "ok": False,
                "verified": False,
                "status": "INVALID",
                "error": str(exc),
            },
        )
        return 1
    except (OSError, ValueError, SigningUnavailableError) as exc:
        _machine_report(
            out,
            {
                "format": ARTIFACT_DIGEST_BINDING_FORMAT,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    _machine_report(
        out,
        {
            "format": ARTIFACT_DIGEST_BINDING_FORMAT,
            "ok": True,
            "verified": True,
            "status": "VERIFIED",
            "decision": "ALLOW",
            "verification_scope": "retained-provider-bytes-plus-trusted-finalizer-allow",
            "live_provider_reverification": False,
            "artifact": verified.receipt.artifact.as_dict(),
            "verification_policy": verified.receipt.policy.as_dict(),
            "subject": verified.admission.subject.as_dict(),
            "provenance_reference": verified.admission.provenance_reference.as_dict(),
            "finalizer": verified.admission.inspection.finalizer,
            "key_id": verified.admission.inspection.payload["authentication"]["key_id"],
        },
    )
    return 0


def cmd_verify_bundle(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Verify canonical bytes, external-key authenticity, context, and semantics."""

    from evoom_guard.evidence_bundle import (
        EvidenceBundleError,
        inspect_evidence_bundle,
        verify_bundle_context,
        verify_bundle_signature,
    )
    from evoom_guard.record_verifier import strict_json_loads, verify_record
    from evoom_guard.signing import SigningUnavailableError

    try:
        expected_context_bytes = _read_bounded_bytes(
            args.expect_context,
            limit=MAX_CONTEXT_INPUT_BYTES,
            label="expected context",
        )
        expected_context = strict_json_loads(expected_context_bytes.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_EVIDENCE_VERIFICATION_V1",
                "ok": False,
                "verified": False,
                "status": "INCOMPLETE",
                "error": f"unusable expected context: {exc}",
            },
        )
        return 2
    if not isinstance(expected_context, dict):
        _machine_report(
            out,
            {
                "format": "EVOGUARD_EVIDENCE_VERIFICATION_V1",
                "ok": False,
                "verified": False,
                "status": "INCOMPLETE",
                "error": "expected context JSON must be an object",
            },
        )
        return 2

    claims = {
        "canonical_container": "not_checked",
        "external_key_signature": "not_checked",
        "expected_context": "not_checked",
        "record_semantics": "not_checked",
    }
    try:
        inspected = inspect_evidence_bundle(args.bundle)
        claims["canonical_container"] = "pass"
    except EvidenceBundleError as exc:
        claims["canonical_container"] = "fail"
        _machine_report(
            out,
            {
                "format": "EVOGUARD_EVIDENCE_VERIFICATION_V1",
                "ok": False,
                "verified": False,
                "status": "INVALID",
                "claims": claims,
                "error": str(exc),
            },
        )
        return 1
    except OSError as exc:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_EVIDENCE_VERIFICATION_V1",
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "claims": claims,
                "error": str(exc),
            },
        )
        return 2

    try:
        verify_bundle_signature(
            inspected,
            trusted_public_key_path=args.trusted_pub,
        )
        claims["external_key_signature"] = "pass"
    except EvidenceBundleError as exc:
        claims["external_key_signature"] = "fail"
        _machine_report(
            out,
            {
                "format": "EVOGUARD_EVIDENCE_VERIFICATION_V1",
                "ok": False,
                "verified": False,
                "status": "INVALID",
                "claims": claims,
                "error": str(exc),
            },
        )
        return 1
    except (OSError, ValueError, SigningUnavailableError) as exc:
        _machine_report(
            out,
            {
                "format": "EVOGUARD_EVIDENCE_VERIFICATION_V1",
                "ok": False,
                "verified": False,
                "status": "INCOMPLETE",
                "claims": claims,
                "error": str(exc),
            },
        )
        return 2

    try:
        verify_bundle_context(inspected, expected_context=expected_context)
        claims["expected_context"] = "pass"
    except EvidenceBundleError as exc:
        claims["expected_context"] = "fail"
        _machine_report(
            out,
            {
                "format": "EVOGUARD_EVIDENCE_VERIFICATION_V1",
                "ok": False,
                "verified": False,
                "status": "INVALID",
                "claims": claims,
                "error": str(exc),
            },
        )
        return 1

    verdict_record = inspected.verdict
    record_report = verify_record(verdict_record)
    claims["record_semantics"] = "pass" if record_report["ok"] else "fail"
    verified = bool(record_report["ok"])
    decision = {
        field: verdict_record.get(field)
        for field in ("verdict", "passed", "reason_code", "exit_code")
    }
    pass_gate = (
        verified
        and verdict_record.get("verdict") == "PASS"
        and verdict_record.get("passed") is True
    )
    require_pass = bool(getattr(args, "require_pass", False))
    ok = verified and (pass_gate or not require_pass)
    status = "VERIFIED" if ok else ("DENIED" if verified else "INVALID")
    _machine_report(
        out,
        {
            "format": "EVOGUARD_EVIDENCE_VERIFICATION_V1",
            "ok": ok,
            "verified": verified,
            "status": status,
            "claims": claims,
            "decision": decision,
            "pass_gate": "ALLOW" if pass_gate else "DENY",
            "key_id": inspected.manifest["authentication"]["key_id"],
            "context": inspected.manifest["context"],
            "record": record_report,
        },
    )
    return 0 if ok else 1


def validate_pack(pack_dir: str) -> dict[str, object]:
    """Validate a verifier-pack directory; returns a report dict (see pack-doctor)."""
    report: dict[str, object] = {"pack": pack_dir, "ok": False, "problems": []}
    problems: list[str] = report["problems"]  # type: ignore[assignment]
    if not os.path.isdir(pack_dir):
        problems.append("not a directory")
        return report
    try:
        test_files = pack_test_files(pack_dir)
        report["test_files"] = sorted(test_files)
        if not test_files:
            problems.append(
                "no pytest test files (test_*.py) — the judge would have nothing to run"
            )
        report["manifest"] = load_pack_manifest(pack_dir)
        report["pack_sha256"] = pack_digest(pack_dir)
        report["pack_digest_format"] = PACK_DIGEST_FORMAT
    except PackManifestError as exc:
        problems.append(str(exc))
        report["test_files"] = []
        report["manifest"] = None
        report["pack_sha256"] = ""
        report["pack_digest_format"] = PACK_DIGEST_FORMAT
    report["ok"] = not problems
    return report


def cmd_pack_doctor(args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    """Execute ``evo-guard pack-doctor`` — validate a verifier pack (exit 0/1)."""
    report = validate_pack(args.pack)
    problems = report.get("problems")
    problems_list = problems if isinstance(problems, list) else []
    if getattr(args, "pack_json", False):
        out(json.dumps(report, indent=2))
    else:
        out(f"pack: {report['pack']}")
        mf = report.get("manifest")
        if isinstance(mf, dict):
            out(f"  manifest: id={mf.get('id')!r} version={mf.get('version')!r}")
        elif "manifest" in report:
            out("  manifest: none (optional — plain folder of judge tests)")
        tf = report.get("test_files")
        out(f"  test files: {len(tf) if isinstance(tf, list) else 0}")
        out(f"  pack sha256: {report.get('pack_sha256', '')}")
        for prob in problems_list:
            out(f"  PROBLEM: {prob}")
        out("  ok" if report["ok"] else "  INVALID")
    return 0 if report["ok"] else 1


def cmd_version(_args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    out(f"evo-guard {__version__}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """The ``evo-guard`` entry point. Returns a process exit code."""
    _configure_stdio()
    args = build_parser().parse_args(argv)
    if args.command == "guard":
        return cmd_guard(args)
    if args.command == "doctor":
        return cmd_doctor(args)
    if args.command == "init":
        return cmd_init(args)
    if args.command == "keygen":
        return cmd_keygen(args)
    if args.command == "verify-verdict":
        return cmd_verify_verdict(args)
    if args.command == "verify-record":
        return cmd_verify_record(args)
    if args.command == "bundle-evidence":
        return cmd_bundle_evidence(args)
    if args.command == "finalize-record":
        return cmd_finalize_record(args)
    if args.command == "finalizer-handoff":
        return cmd_finalizer_handoff(args)
    if args.command == "derive-finalizer-bindings":
        return cmd_derive_finalizer_bindings(args)
    if args.command == "verify-finalizer-bindings":
        return cmd_verify_finalizer_bindings(args)
    if args.command == "seal-finalizer":
        return cmd_seal_finalizer(args)
    if args.command == "verify-finalized":
        return cmd_verify_finalized(args)
    if args.command == "release-source-handoff":
        return cmd_release_source_handoff(args)
    if args.command == "seal-release-source-finalizer":
        return cmd_seal_release_source_finalizer(args)
    if args.command == "verify-release-source-finalized":
        return cmd_verify_release_source_finalized(args)
    if args.command == "derive-release-source-controls":
        return cmd_derive_release_source_controls(args)
    if args.command == "create-release-source-producer-receipt":
        return cmd_create_release_source_producer_receipt(args)
    if args.command == "verify-release-source-producer-receipt":
        return cmd_verify_release_source_producer_receipt(args)
    if args.command == "reverify-attested-release-source-producer-receipt":
        return cmd_reverify_attested_release_source_producer_receipt(args)
    if args.command == "seal-release-source-admission":
        return cmd_seal_release_source_admission(args)
    if args.command == "verify-release-source-admission":
        return cmd_verify_release_source_admission(args)
    if args.command == "seal-github-release-artifact-admission":
        return cmd_seal_github_release_artifact_admission(args)
    if args.command == "verify-github-release-artifact-admission":
        return cmd_verify_github_release_artifact_admission(args)
    if args.command == "seal-artifact-admission":
        return cmd_seal_artifact_admission(args)
    if args.command == "verify-artifact-admission":
        return cmd_verify_artifact_admission(args)
    if args.command == "seal-artifact-digest-admission":
        return cmd_seal_artifact_digest_admission(args)
    if args.command == "verify-artifact-digest-admission":
        return cmd_verify_artifact_digest_admission(args)
    if args.command == "github-attestation-receipt":
        return cmd_github_attestation_receipt(args)
    if args.command == "verify-github-attestation-receipt":
        return cmd_verify_github_attestation_receipt(args)
    if args.command == "reverify-github-attestation-receipt":
        return cmd_reverify_github_attestation_receipt(args)
    if args.command == "seal-github-attestation-admission":
        return cmd_seal_github_attestation_admission(args)
    if args.command == "verify-github-attestation-admission":
        return cmd_verify_github_attestation_admission(args)
    if args.command == "verify-bundle":
        return cmd_verify_bundle(args)
    if args.command == "pack-doctor":
        return cmd_pack_doctor(args)
    if args.command == "version":
        return cmd_version(args)
    return 2  # unreachable: subparser is required


if __name__ == "__main__":
    raise SystemExit(main())
