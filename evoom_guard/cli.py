# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Sole owner & author: Mana Alharbi (مانع الحربي).
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
import shutil
import sys
from collections.abc import Callable

from evoom_guard import __version__


def _read_text(path: str) -> str:
    """Read a file, or stdin when *path* is ``-``."""
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as f:
        return f.read()


def _load_config(path: str, *, out: Callable[[str], None] = print) -> dict[str, object]:
    """Repo-level defaults from a ``.evoguard.json`` file, if present.

    Recognises ``test_command`` (a string or a token list), ``setup_command`` (a
    token list only — a string value is silently ignored since splitting on spaces
    is unsafe for paths), ``protected`` (a list of globs), ``timeout`` (int
    seconds), ``mem_limit`` (int MB) and ``allow_new_tests`` (bool — opt-in feature
    mode). A missing file yields no defaults; a
    present-but-invalid file — or a key of the wrong type — is warned about and
    skipped. Config never fails a run, and CLI flags always override it. JSON (not
    TOML) keeps the core stdlib-only on Python 3.10, where ``tomllib`` is absent.
    """
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        out(f"warning: ignoring {path}: not readable JSON ({exc})")
        return {}
    if not isinstance(data, dict):
        out(f"warning: ignoring {path}: expected a JSON object")
        return {}
    cfg: dict[str, object] = {}
    tc = data.get("test_command")
    if isinstance(tc, (str, list)):
        cfg["test_command"] = tc
    sc = data.get("setup_command")
    if isinstance(sc, list):
        cfg["setup_command"] = sc
    prot = data.get("protected")
    if isinstance(prot, list):
        cfg["protected"] = prot
    alw = data.get("allow")
    if isinstance(alw, list):
        cfg["allow"] = alw
    for key in ("timeout", "mem_limit"):
        v = data.get(key)
        if isinstance(v, int) and not isinstance(v, bool):
            cfg[key] = v
    ant = data.get("allow_new_tests")
    if isinstance(ant, bool):
        cfg["allow_new_tests"] = ant
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

    # ----- doctor -------------------------------------------------------- #
    d_p = sub.add_parser(
        "doctor",
        help="report the environment EvoGuard needs (version, platform, git/patch)",
    )
    d_p.add_argument(
        "--json", dest="doctor_json", action="store_true",
        help="emit the environment report as JSON instead of human text",
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
        "--test-command", dest="test_command", default="pytest -q",
        help="test command to embed in the workflow (default: pytest -q)",
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
        candidate_from_dirs,
        guard,
        guard_from_diff,
        render_report,
        write_json,
        write_sarif,
    )

    # Effective settings: an explicit CLI flag wins; else .evoguard.json; else the
    # built-in default. All CLI defaults are None so "given" is distinguishable.
    cfg = _load_config(args.config, out=out)

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
            protected=protected, allow=allow, allow_new_tests=allow_new_tests, timeout=timeout,
            mem_limit_mb=mem_limit, isolation=isolation, docker_image=docker_image,
            docker_network=docker_network,
        )
    elif args.base and args.head:
        candidate, deleted = candidate_from_dirs(args.base, args.head)
        result = guard(
            args.base, candidate,
            deleted=tuple(deleted),
            test_command=test_command, setup_command=setup_command,
            protected=protected, allow=allow, allow_new_tests=allow_new_tests, timeout=timeout,
            mem_limit_mb=mem_limit, isolation=isolation, docker_image=docker_image,
            docker_network=docker_network,
        )
        result.source = "base/head"
    elif args.repo and args.patch:
        result = guard(
            args.repo, _read_text(args.patch),
            test_command=test_command, setup_command=setup_command,
            protected=protected, allow=allow, allow_new_tests=allow_new_tests, timeout=timeout,
            mem_limit_mb=mem_limit, isolation=isolation, docker_image=docker_image,
            docker_network=docker_network,
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
    """Execute ``evo-guard verify-verdict`` — offline signature check (exit 0/1)."""
    from evoom_guard.signing import verify_file

    sig = args.sig or (args.verdict + ".sig")
    try:
        ok = verify_file(args.verdict, sig, args.pub)
    except (OSError, ValueError) as exc:
        out(f"unusable input: {exc}")
        return 2
    out("signature: VALID" if ok else "signature: INVALID — the verdict bytes changed after signing")
    return 0 if ok else 1


def cmd_version(_args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    out(f"evo-guard {__version__}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """The ``evo-guard`` entry point. Returns a process exit code."""
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
    if args.command == "version":
        return cmd_version(args)
    return 2  # unreachable: subparser is required


if __name__ == "__main__":
    raise SystemExit(main())
