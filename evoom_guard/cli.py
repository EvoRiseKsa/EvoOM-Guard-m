# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""The ``evo-guard`` command line — a focused front end for the patch verification gate.

Subcommands:

  * ``evo-guard guard`` — verify a candidate change against a repo's tests, rejecting
    any edit to the tests or their configuration (the AI patch gate).
  * ``evo-guard version`` — print the EvoGuard version.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import sys
from collections.abc import Callable

from evoom_guard import __version__
from evoom_guard.pack_manifest import (
    PACK_DIGEST_FORMAT,
    PackManifestError,
    load_pack_manifest,
    pack_digest,
    pack_test_files,
)


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


def _load_config(path: str, *, out: Callable[[str], None] = print) -> dict[str, object]:
    """Repo-level policy from ``.evoguard.json`` — **fail-closed**.

    Recognises ``test_command`` (string or token list), ``setup_command``
    (token list), ``protected`` / ``allow`` (glob lists), ``timeout`` /
    ``mem_limit`` (ints), ``allow_new_tests`` (bool), the protected assurance
    floors ``require_report_integrity`` / ``require_candidate_isolation``,
    ``min_diff_coverage`` (number, 0–100) and the policy identity
    ``policy_id`` / ``policy_version`` (strings).

    A missing file yields no defaults. A present-but-broken file — unreadable
    JSON, a non-object, an unknown key, or a wrong-typed/invalid value —
    raises :class:`ConfigError` instead of degrading to weaker defaults. CLI
    flags still override valid config values. JSON (not TOML) keeps the core
    stdlib-only on Python 3.10, where ``tomllib`` is absent.
    """
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
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
            cfg[key] = v
    if "allow_new_tests" in data:
        v = data["allow_new_tests"]
        if not isinstance(v, bool):
            raise _bad("allow_new_tests", "expected true or false")
        cfg["allow_new_tests"] = v
    if "trust_setup_on_host" in data:
        v = data["trust_setup_on_host"]
        if not isinstance(v, bool):
            raise _bad("trust_setup_on_host", "expected true or false")
        cfg["trust_setup_on_host"] = v
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evo-guard",
        description="EvoGuard — the merge gate an AI agent can't game the test harness.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ----- guard (AI patch verification gate) --------------------------- #
    g_p = sub.add_parser(
        "guard",
        help="verify a patch against a repo's tests, rejecting any edit to the tests/config (an AI patch gate)",
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
        help="baseline allowlist: globs exempt from the test/config/CI rejection (for a "
        "misclassified path or a known pre-existing hit; never auto-exec/unsafe). "
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
        "or modify. A verified snapshot runs as a separate mandatory pytest phase, "
        "so a narrowed repo command cannot skip it. Repo-native candidate imports "
        "share the judge process — the pack is not secret (use "
        "--blackbox with --isolation docker for that). See docs/VERIFIER_PACKS.md.",
    )
    g_p.add_argument(
        "--blackbox", dest="blackbox", action="store_true",
        help="external black-box judge (needs --verifier-pack): the verdict comes "
        "from the JUDGE's own pytest over the pack, which never imports the "
        "candidate — closing same-process report forgery (report_integrity: "
        "external_process_isolated). The pack invokes the candidate across a "
        "process boundary via $EVOGUARD_EXEC (which runs it under the delivered "
        "isolation). By default the repo's own suite is ALSO required to pass. "
        "See docs/BLACKBOX.md.",
    )
    g_p.add_argument(
        "--blackbox-only", dest="blackbox_only", action="store_true",
        help="with --blackbox, judge ONLY the external pack and skip the repo's own "
        "suite (for pure-CLI/service targets that have no in-repo tests). Without "
        "this, a failing repo suite blocks the merge even if the pack passes.",
    )
    g_p.add_argument(
        "--require-report-integrity", dest="require_report_integrity", default=None,
        choices=("same_process_candidate_writable", "external_process_isolated"),
        help="fail-closed policy: require at least this report_integrity level, or "
        "the run returns ERROR (assurance_requirement_not_met) instead of shipping "
        "a weaker guarantee. 'external_process_isolated' needs --blackbox.",
    )
    g_p.add_argument(
        "--require-candidate-isolation", dest="require_candidate_isolation", default=None,
        choices=("subprocess", "docker", "gvisor"),
        help="fail-closed policy: require at least this candidate isolation, or ERROR.",
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
    g_p.add_argument(
        "--baseline-evidence", dest="baseline_evidence", action="store_true",
        help="differential evidence (opt-in): also run the suite on the PRISTINE "
        "base (no candidate) and report repair_effect — 'demonstrated' only when "
        "the base fails and the candidate passes under the same judge/policy/env. "
        "Evidence only; the verdict is unchanged. Subprocess judge only.",
    )
    g_p.add_argument(
        "--require-demonstrated-fix", dest="require_demonstrated_fix", action="store_true",
        help="gate (opt-in, implies --baseline-evidence): a PASS whose repair "
        "effect is not demonstrated (the base already passed, or no clean "
        "baseline verdict) becomes FAIL (fix_not_demonstrated). For agent 'fix' "
        "PRs; do NOT use on ordinary feature PRs, which start from a green base.",
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
    g_p.add_argument(
        "--diff-coverage", dest="diff_coverage", action="store_true",
        help="measure which changed lines the suite actually executed (one extra "
        "suite run under coverage; needs the 'cov' extra). Evidence only unless "
        "--min-diff-coverage is set. Executed is not asserted.",
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
    g_p.add_argument(
        "--config", default=".evoguard.json",
        help="repo config (JSON) with defaults for test-command/protected/timeout/"
        "mem-limit; default: .evoguard.json in the cwd. CLI flags override it.",
    )
    g_p.add_argument(
        "--isolation", choices=("subprocess", "docker", "gvisor"), default="subprocess",
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
        "--docker-network", dest="docker_network", default="none",
        help="container network for --isolation docker/gvisor (default: 'none' — no "
        "network, the safe choice; pass a docker network name only if the suite "
        "genuinely needs it)",
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
        help="test command to embed in the workflow (default: python -m pytest -q — "
        "the -m form puts the repo root on sys.path so top-level packages import "
        "without an install/conftest)",
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
        "--evoguard-token-secret", dest="evoguard_token_secret",
        default="EVOGUARD_TOKEN",
        help="name of the Actions secret that holds the PAT for the private EvoGuard "
        "repo (default: EVOGUARD_TOKEN; only used with --private-evoguard)",
    )

    # ----- version ------------------------------------------------------- #
    sub.add_parser("version", help="print the EvoGuard version")

    return parser


def cmd_guard(args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    """Execute ``evo-guard guard`` — the AI patch verification gate."""
    from evoom_guard.guard import (
        blocks_from_dirs,
        guard,
        guard_from_diff,
        render_report,
        write_json,
        write_sarif,
    )

    # Effective settings: an explicit CLI flag wins; else .evoguard.json; else the
    # built-in default. All CLI defaults are None so "given" is distinguishable.
    # A present-but-broken config is fail-closed: exit 2, never weaker defaults.
    try:
        cfg = _load_config(args.config, out=out)
    except ConfigError as exc:
        out(f"config error (fail-closed): {exc}")
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

    # Auto-detect a Node.js project: V8 reserves huge virtual address space, which
    # makes RLIMIT_AS kill the test subprocess at startup. If package.json exists
    # and the user hasn't explicitly configured mem_limit (still at default 1024),
    # disable the address-space cap automatically.
    if mem_limit == 1024:
        _node_root = args.repo or args.head or args.base or os.getcwd()
        if os.path.isfile(os.path.join(_node_root, "package.json")):
            mem_limit = 0

    isolation = args.isolation
    docker_image = args.docker_image
    docker_network = args.docker_network
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
            verifier_pack=args.verifier_pack,
            expect_verifier_pack_sha256=expect_verifier_pack_sha256,
            diff_coverage=args.diff_coverage or min_diff_coverage is not None,
            min_diff_coverage=min_diff_coverage,
            blackbox=args.blackbox, blackbox_only=args.blackbox_only,
            require_report_integrity=require_report_integrity,
            require_candidate_isolation=require_candidate_isolation,
            base_sha=args.base_sha, head_sha=args.head_sha,
            base_tree_sha=args.base_tree_sha, head_tree_sha=args.head_tree_sha,
            policy_id=policy_id, policy_version=policy_version,
            baseline_evidence=args.baseline_evidence,
            require_demonstrated_fix=args.require_demonstrated_fix,
        )
    elif args.base and args.head:
        # Structured candidate: never round-trip file content through the
        # <<<FILE>>> text format (content containing a literal marker line
        # must survive intact — see guard.blocks_from_dirs).
        file_blocks, deleted = blocks_from_dirs(args.base, args.head)
        candidate = "\n".join(
            f"<<<FILE: {rel}>>>\n{new}\n<<<END FILE>>>"
            for rel, new in file_blocks.items()
        )
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
            verifier_pack=args.verifier_pack,
            expect_verifier_pack_sha256=expect_verifier_pack_sha256,
            diff_coverage=args.diff_coverage or min_diff_coverage is not None,
            min_diff_coverage=min_diff_coverage,
            blackbox=args.blackbox, blackbox_only=args.blackbox_only,
            require_report_integrity=require_report_integrity,
            require_candidate_isolation=require_candidate_isolation,
            base_sha=args.base_sha, head_sha=args.head_sha,
            base_tree_sha=args.base_tree_sha, head_tree_sha=args.head_tree_sha,
            policy_id=policy_id, policy_version=policy_version,
            baseline_evidence=args.baseline_evidence,
            require_demonstrated_fix=args.require_demonstrated_fix,
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
            verifier_pack=args.verifier_pack,
            expect_verifier_pack_sha256=expect_verifier_pack_sha256,
            diff_coverage=args.diff_coverage or min_diff_coverage is not None,
            min_diff_coverage=min_diff_coverage,
            blackbox=args.blackbox, blackbox_only=args.blackbox_only,
            require_report_integrity=require_report_integrity,
            require_candidate_isolation=require_candidate_isolation,
            base_sha=args.base_sha, head_sha=args.head_sha,
            base_tree_sha=args.base_tree_sha, head_tree_sha=args.head_tree_sha,
            policy_id=policy_id, policy_version=policy_version,
            baseline_evidence=args.baseline_evidence,
            require_demonstrated_fix=args.require_demonstrated_fix,
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


def _workflow_yaml(test_command: str, ref: str) -> str:
    """The EvoGuard GitHub Actions workflow that ``evo-guard init`` scaffolds.

    Pins the action to ``ref`` (the matching release tag by default) and embeds the
    given ``test_command``. Mirrors ``examples/evoguard.yml`` so the generated file
    is the same gate the docs describe.
    """
    return f"""\
# EvoGuard — generated by `evo-guard init`.
# Verifies each PR's source changes against the repo's own tests and REJECTS any
# edit to the tests or their configuration (an AI-patch reward-hack gate).
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
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0            # Guard needs the base commit to diff against

      - uses: EvoRiseKsa/EvoOM-Guard-m@{ref}
        with:
          test-command: "{test_command}"
          comment: "true"           # post the verdict as a PR comment
          fail-on: "any-non-pass"   # or "rejected-only" to gate only reward-hacks
"""


def _workflow_yaml_private(test_command: str, ref: str, token_secret: str = "EVOGUARD_TOKEN") -> str:
    """EvoGuard workflow for private EvoGuard repos — installs via pip + a PAT secret.

    Use when the EvoGuard repo is private and cannot be accessed by the default
    GITHUB_TOKEN (cross-repo private action access is not supported). The PAT must
    have at least read access to the EvoGuard repo and be stored as an Actions secret
    (Settings → Secrets and variables → Actions).
    """
    return f"""\
# EvoGuard — generated by `evo-guard init --private-evoguard`.
# EvoGuard is installed from a private GitHub repo via pip.
# Add a PAT with read access to the EvoGuard repo as the {token_secret} secret:
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
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0            # Guard needs the base commit to diff against

      - name: Install EvoGuard
        env:
          {token_secret}: ${{{{ secrets.{token_secret} }}}}
        run: pip install "git+https://x-access-token:${{{token_secret}}}@github.com/EvoRiseKsa/EvoOM-Guard-m.git@{ref}"

      - name: Run EvoGuard
        run: |
          git diff "origin/${{{{ github.base_ref }}}}...HEAD" | \\
            evo-guard guard . --diff - --test-command "{test_command}" \\
            --report evoguard.md --json evoguard.json
          cat evoguard.md >> "$GITHUB_STEP_SUMMARY"

      - name: Post verdict as PR comment
        if: always()
        uses: actions/github-script@v7
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


def cmd_init(args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    """Execute ``evo-guard init`` — scaffold a ready-to-use GitHub Actions workflow.

    Writes the workflow to ``--path`` (refusing to clobber an existing file unless
    ``--force``), or prints it with ``--stdout``. Pass ``--private-evoguard`` to
    generate a pip-install workflow for repos where the EvoGuard action is not
    accessible via the default GITHUB_TOKEN. Returns ``0`` on success, ``1`` if
    the target exists and ``--force`` was not given.
    """
    if getattr(args, "private_evoguard", False):
        token_secret = getattr(args, "evoguard_token_secret", "EVOGUARD_TOKEN")
        content = _workflow_yaml_private(args.test_command, args.ref, token_secret)
    else:
        content = _workflow_yaml(args.test_command, args.ref)
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
    out(f"wrote {path}")
    out(
        "next: commit it and open a PR — EvoGuard posts a verdict and fails the "
        "check on anything but PASS. Edit `test-command` for your suite."
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
    from evoom_guard.signing import verify_file

    sig = args.sig or (args.verdict + ".sig")
    try:
        ok = verify_file(args.verdict, sig, args.pub)
    except (OSError, ValueError) as exc:
        out(f"unusable input: {exc}")
        return 2
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
        with open(args.verdict, encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, ValueError) as exc:
        out(f"context: UNCHECKABLE — the verdict is not readable JSON ({exc})")
        return 1
    att = payload.get("attestation") or {}
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
    if args.command == "pack-doctor":
        return cmd_pack_doctor(args)
    if args.command == "version":
        return cmd_version(args)
    return 2  # unreachable: subparser is required


if __name__ == "__main__":
    raise SystemExit(main())
