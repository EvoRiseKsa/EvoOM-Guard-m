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
  * ``evo-guard seal-artifact-admission`` — bind one file to a verified finalizer ALLOW.
  * ``evo-guard verify-artifact-admission`` — verify that file/finalizer binding.
  * ``evo-guard seal-artifact-digest-admission`` — bind one immutable digest to a finalizer.
  * ``evo-guard verify-artifact-digest-admission`` — verify that V2 digest relation.
  * ``evo-guard github-attestation-receipt`` — record one constrained GitHub verification.
  * ``evo-guard verify-github-attestation-receipt`` — check retained attestation bytes.
  * ``evo-guard reverify-github-attestation-receipt`` — make a fresh constrained GitHub check.
  * ``evo-guard version`` — print the EvoGuard version.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import platform
import re
import shutil
import sys
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from evoom_guard import __version__
from evoom_guard.pack_manifest import (
    PACK_DIGEST_FORMAT,
    PackManifestError,
    load_pack_manifest,
    pack_digest,
    pack_test_files,
)
from evoom_guard.strict_json import strict_json_loads

if TYPE_CHECKING:
    from evoom_guard.evidence_bundle import EvidenceMaterial

MAX_OFFLINE_RECORD_BYTES = 8 * 1024 * 1024
MAX_CONTEXT_INPUT_BYTES = 1 * 1024 * 1024
MAX_SIGNATURE_FILE_BYTES = 4096


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


class ConfigError(ValueError):
    """A present-but-invalid ``.evoguard.json`` — the run must NOT continue.

    The config file is part of the protected harness (a candidate cannot edit
    it), so it may carry security policy. A malformed file, an unknown key (a
    typo like ``require_report_isolation``), or a wrong-typed value used to be
    warned about and silently skipped — which meant Guard would keep running
    under WEAKER defaults than the repo owner wrote down (fail-open). An
    external review flagged this; the contract is now fail-closed: broken
    policy stops the run with exit 2, it never degrades it.
    """


# The full key vocabulary of .evoguard.json. Anything else is an error — a
# misspelled policy key must never be silently ignored.
_CONFIG_KEYS = frozenset({
    "test_command", "setup_command", "protected", "allow",
    "timeout", "mem_limit", "allow_new_tests", "trust_setup_on_host",
    "setup_output_globs",
    # Strict profile: immutable dependency/compiler manifests plus a required
    # non-empty structured test verdict.  The default stays false for adoption
    # compatibility; PR Actions load this only from the trusted base policy.
    "strict_harness",
    # Execution policy keys are accepted here so a pull_request Action can
    # obtain them from its verified base .evoguard.json rather than candidate
    # workflow ``with:`` inputs.
    "isolation", "docker_image", "docker_network",
    "blackbox", "blackbox_only",
    "diff_coverage", "baseline_evidence", "require_demonstrated_fix",
    "verifier_pack",
    "expect_verifier_pack_sha256",
    # Protected policy contract (enforced fail-closed by the engine):
    "require_report_integrity", "require_candidate_isolation",
    "min_diff_coverage",
    # Policy identity — surfaced in the attestation so a consumer knows which
    # policy produced the verdict:
    "policy_id", "policy_version",
})
_REPORT_INTEGRITY_VALUES = ("same_process_candidate_writable", "external_process_isolated")
_ISOLATION_VALUES = ("subprocess", "docker", "gvisor")
_GITHUB_ACTIONS_CREDENTIAL_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


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


def _load_config(
    path: str,
    *,
    required: bool = False,
    out: Callable[[str], None] = print,
) -> dict[str, object]:
    """Repo-level policy from ``.evoguard.json`` — **fail-closed**.

    Recognises ``test_command`` (string or token list), ``setup_command``
    (token list), ``protected`` / ``allow`` (glob lists), ``timeout`` /
    ``mem_limit`` (ints), ``allow_new_tests`` (bool), the protected assurance
    floors ``require_report_integrity`` / ``require_candidate_isolation``,
    execution/isolation controls, evidence gates, ``strict_harness`` and the
    policy identity ``policy_id`` / ``policy_version`` (strings).
    ``verifier_pack`` may name a judge-owned pack; relative paths resolve from
    the trusted policy file.

    A missing file yields no defaults. A present-but-broken file — unreadable
    JSON, a non-object, an unknown key, or a wrong-typed/invalid value —
    raises :class:`ConfigError` instead of degrading to weaker defaults. CLI
    flags still override valid config values. JSON (not TOML) keeps the core
    stdlib-only on Python 3.10, where ``tomllib`` is absent.
    """
    if not path or not os.path.exists(path):
        if required:
            raise ConfigError(f"trusted policy file does not exist: {path}")
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = strict_json_loads(f.read())
    except (OSError, ValueError) as exc:
        raise ConfigError(f"{path} is not readable JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a JSON object, got {type(data).__name__}")
    unknown = sorted(set(data) - _CONFIG_KEYS)
    if unknown:
        raise ConfigError(
            f"{path}: unknown key(s) {', '.join(unknown)} — a misspelled policy "
            "key must not be silently ignored; the accepted keys are: "
            + ", ".join(sorted(_CONFIG_KEYS))
        )

    def _bad(key: str, why: str) -> ConfigError:
        return ConfigError(f"{path}: invalid {key!r} — {why}")

    cfg: dict[str, object] = {}
    if "test_command" in data:
        tc = data["test_command"]
        if not isinstance(tc, (str, list)) or (
            isinstance(tc, list) and not all(isinstance(t, str) for t in tc)
        ):
            raise _bad("test_command", "expected a string or a list of strings")
        cfg["test_command"] = tc
    if "setup_command" in data:
        sc = data["setup_command"]
        if not isinstance(sc, list) or not all(isinstance(t, str) for t in sc):
            raise _bad("setup_command", "expected a list of strings (never a "
                       "shell string — splitting on spaces is unsafe for paths)")
        cfg["setup_command"] = sc
    for key in ("protected", "allow", "setup_output_globs"):
        if key in data:
            v = data[key]
            if not isinstance(v, list) or not all(isinstance(g, str) for g in v):
                raise _bad(key, "expected a list of glob strings")
            cfg[key] = v
    for key in ("timeout", "mem_limit"):
        if key in data:
            v = data[key]
            if not isinstance(v, int) or isinstance(v, bool):
                raise _bad(key, "expected an integer")
            if key == "timeout" and v < 1:
                raise _bad(key, "expected a positive integer")
            if key == "mem_limit" and v < 0:
                raise _bad(key, "expected a non-negative integer")
            cfg[key] = v
    for key in (
        "allow_new_tests", "trust_setup_on_host", "strict_harness",
        "blackbox", "blackbox_only", "diff_coverage", "baseline_evidence",
        "require_demonstrated_fix",
    ):
        if key in data:
            v = data[key]
            if not isinstance(v, bool):
                raise _bad(key, "expected true or false")
            cfg[key] = v
    if data.get("blackbox_only") is True and data.get("blackbox") is not True:
        raise _bad("blackbox_only", "requires blackbox: true")
    if "isolation" in data:
        v = data["isolation"]
        if v not in _ISOLATION_VALUES:
            raise _bad("isolation", f"expected one of {list(_ISOLATION_VALUES)}")
        cfg["isolation"] = v
    for key in ("docker_image", "docker_network"):
        if key in data:
            v = data[key]
            if not isinstance(v, str) or not v.strip() or "\x00" in v:
                raise _bad(key, "expected a non-empty string without NUL")
            cfg[key] = v
    if "verifier_pack" in data:
        v = data["verifier_pack"]
        if not isinstance(v, str) or not v.strip():
            raise _bad("verifier_pack", "expected a non-empty path string")
        cfg["verifier_pack"] = v
    if "expect_verifier_pack_sha256" in data:
        v = data["expect_verifier_pack_sha256"]
        if not isinstance(v, str) or re.fullmatch(r"[0-9a-fA-F]{64}", v) is None:
            raise _bad(
                "expect_verifier_pack_sha256",
                "expected exactly 64 hexadecimal SHA-256 characters",
            )
        cfg["expect_verifier_pack_sha256"] = v.lower()
    if "require_report_integrity" in data:
        v = data["require_report_integrity"]
        if v not in _REPORT_INTEGRITY_VALUES:
            raise _bad("require_report_integrity",
                       f"expected one of {list(_REPORT_INTEGRITY_VALUES)}")
        cfg["require_report_integrity"] = v
    if "require_candidate_isolation" in data:
        v = data["require_candidate_isolation"]
        if v not in _ISOLATION_VALUES:
            raise _bad("require_candidate_isolation",
                       f"expected one of {list(_ISOLATION_VALUES)}")
        cfg["require_candidate_isolation"] = v
    if "min_diff_coverage" in data:
        v = data["min_diff_coverage"]
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not (0 <= v <= 100):
            raise _bad("min_diff_coverage", "expected a number between 0 and 100")
        cfg["min_diff_coverage"] = float(v)
    for key in ("policy_id", "policy_version"):
        if key in data:
            v = data[key]
            if not isinstance(v, str) or not v.strip():
                raise _bad(key, "expected a non-empty string")
            cfg[key] = v
    return cfg


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
        "--min-diff-coverage is set. Executed is not asserted.",
    )
    coverage_group.add_argument(
        "--no-diff-coverage", dest="diff_coverage", action="store_const", const=False,
        help="explicitly override diff_coverage: true from a trusted policy",
    )
    g_p.add_argument(
        "--min-diff-coverage", dest="min_diff_coverage", type=float, default=None,
        help="gate: a PASS whose measured changed-line coverage is below this "
        "percentage becomes FAIL (diff_coverage_below_threshold); implies "
        "--diff-coverage",
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
        "--ref", default=f"v{__version__}",
        help="the EvoGuard action ref to pin (default: the matching release tag)",
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


def _github_attestation_policy_kwargs(args: argparse.Namespace) -> dict[str, str]:
    """Return only the exact policy inputs accepted by the provider adapter."""

    return {
        "repository": args.repo,
        "signer_workflow": args.signer_workflow,
        "signer_digest": args.signer_digest,
        "source_ref": args.source_ref,
        "source_digest": args.source_digest,
        "cert_oidc_issuer": args.cert_oidc_issuer,
    }


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
    if args.command == "verify-bundle":
        return cmd_verify_bundle(args)
    if args.command == "pack-doctor":
        return cmd_pack_doctor(args)
    if args.command == "version":
        return cmd_version(args)
    return 2  # unreachable: subparser is required


if __name__ == "__main__":
    raise SystemExit(main())
