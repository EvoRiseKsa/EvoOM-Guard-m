# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Sixth domain — repo-level evolution (S19).

The hypothesis is no longer a single function: it is a *set of file edits*
applied to a copy of a real repository, judged by the repository's own test
suite. The repo becomes the fitness landscape; the loop evolves patches.

Hypothesis format — full-file blocks, not unified diffs (LLM diffs break on
drifted line numbers; whole-file replacement is robust):

    <<<FILE: relative/path/to/file.py>>>
    ...the complete new content of that file...
    <<<END FILE>>>

Any number of blocks. Each block replaces (or creates) one file inside a
throwaway copy of the repo; the original repository is **never** touched.

Surgical-edit format — for changing a *large existing* file without rewriting it
whole (issue #15), a search/replace block applied via
:func:`evoom_guard.patch_applier.apply_patch` with a unique anchor:

    <<<PATCH: relative/path/to/file.py>>>
    <<<SEARCH>>>
    ...a unique anchor copied verbatim from the file...
    <<<REPLACE>>>
    ...its replacement...
    <<<END PATCH>>>

The anchor must occur **exactly once** in the file (else the patch is rejected
with ``AmbiguousMatchError``); a missing anchor is ``NoMatchError``. Both surface
as a precise diagnostic the loop feeds back, so the next generation can fix the
anchor. ``FILE`` and ``PATCH`` blocks may be mixed; patches apply in order, after
the file blocks.

Golden rule, enforced: the candidate may NOT modify the harness that judges it
— neither the tests nor their configuration. Paths under ``tests/``, files named
``test_*.py`` / ``*_test.py`` / ``conftest.py``, JavaScript/TypeScript colocated
test files (``*.test.ts``, ``*.spec.ts``, etc.), and any extra ``protected`` globs
are rejected outright, otherwise the loop would learn to delete its own judge. The
same rejection covers test-runner / build configuration (``pyproject.toml``,
``pytest.ini``, ``tox.ini``, ``setup.cfg``, ``vitest.config.*``, ``foundry.toml``,
…) and dependency lock files (``pnpm-lock.yaml``, ``package-lock.json``,
``yarn.lock``, ``Cargo.lock``, …): editing them is a *reward-hack* — a candidate
can make a failing suite report success WITHOUT fixing the code. See
:func:`is_protected_config`. EvoGuard's own ``.evoguard.json`` and the CI files
that run the gate (``.github/workflows/``, ``.github/actions/``) are rejected for
the same reason — editing them could rewrite the test command or disable the gate
outright (see :func:`is_protected_ci`). The dual-purpose ``package.json`` is not
rejected (it carries real dependencies and source metadata); instead its
test-harness fields (``scripts.test`` and embedded ``jest``/``vitest`` config) are
restored from the pristine original after a candidate edit — see
:func:`restore_judge_package_json`.

Score gradient (reuses :func:`evoom_guard.verifiers.grading.fraction_score`):

    0.02  no parseable file blocks
    0.05  unsafe / protected / config path (absolute, ``..`` escape, test or
          test-config files)
    0.10  test session failed to start (collection/usage error, no tests ran)
    0.25+ tests ran; score climbs with the fraction passed
    1.00  full pass (exit code 0)

SECURITY — the suite runs in a subprocess with a hard timeout and POSIX
rlimits, but it needs the repo's installed dependencies, so strong interpreter
isolation (``-I -S``, viable only for self-contained code) does not apply here.
Treat this as *basic* isolation: for untrusted targets or unattended VPS
operation, run it inside a network-less container with CPU/memory limits (see the
trust boundary in ``docs/GUARD.md``).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from fnmatch import fnmatch
from typing import Any, NamedTuple, TypedDict, cast

from evoom_guard.adapters import instrument_command
from evoom_guard.contracts import VerdictResult
from evoom_guard.pack_manifest import (
    PackManifestError,
    snapshot_pack,
    verify_pack_snapshot,
)
from evoom_guard.patch_applier import PatchError, apply_patch
from evoom_guard.verifiers.grading import fraction_score

try:  # POSIX-only; absent on Windows.
    import resource
except ImportError:  # pragma: no cover - platform dependent
    resource = None  # type: ignore[assignment]

# Directories never copied into the throwaway working copy.
COPY_IGNORE = (
    ".git", "__pycache__", ".venv", "venv", "node_modules",
    ".evo_runs", ".pytest_cache", ".mypy_cache", "dist", "build",
)


def judge_subprocess_env(workdir: str) -> dict[str, str]:
    """Minimal cross-platform environment for judge-owned subprocesses.

    Windows runtimes depend on a small set of OS variables even when the judged
    program does not.  In particular, current Node releases abort during CSPRNG
    initialization when ``SYSTEMROOT`` is absent.  Preserve only the OS plumbing
    needed to start tools; keep scratch paths inside the judge-owned workdir and
    continue excluding user Python startup state.
    """
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin"),
        "HOME": workdir,
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }
    if os.name == "nt":
        for key in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
            value = os.environ.get(key)
            if value:
                env[key] = value
        env["TEMP"] = workdir
        env["TMP"] = workdir
    return env

# Test-file basenames the candidate may not touch.
_PROTECTED_BASENAMES = (
    # Python
    "test_*.py", "*_test.py", "conftest.py",
    # JavaScript / TypeScript colocated test files (vitest / jest pattern).
    # These sit beside the source file rather than in a tests/ directory, so the
    # directory-segment rule alone misses them — an agent can otherwise freely
    # edit e.g. src/finance/rounding.test.ts without triggering REJECTED.
    "*.test.ts", "*.test.tsx", "*.test.js", "*.test.jsx",
    "*.spec.ts", "*.spec.tsx", "*.spec.js", "*.spec.jsx",
    "*.snap",
)

# Test-runner / build-configuration basenames the candidate may not touch. Editing
# the *harness configuration* (rather than the source under test) is a reward-hack:
# the candidate can make a failing suite report success WITHOUT fixing the code —
# e.g. a pytest ``[tool.pytest.ini_options] addopts = "-k <passing test>"`` that
# deselects the failing tests, an ``--ignore`` / ``--deselect`` of the failing
# module, or a JS runner's ``include`` narrowed to the passing specs. The
# candidate's job is to fix the SOURCE, never the harness that judges it. Matched
# on the basename anywhere in the tree, case-insensitively. (``conftest.py`` is
# already covered by ``_PROTECTED_BASENAMES`` above.)
_PROTECTED_CONFIG = (
    # EvoGuard's own per-repo config — editing it lets a candidate rewrite the
    # ``test_command`` / ``setup_command`` / ``protected`` globs to trivially pass
    # the gate without fixing anything. The gate's config is part of the harness.
    ".evoguard.json",
    # pytest / Python test configuration
    "pytest.ini", ".pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml",
    # JS/TS test-runner configuration (``package.json`` is dual-purpose — see
    # ``is_protected_config`` for why it is deliberately not rejected wholesale).
    "vitest.config.*", "vite.config.*", "jest.config.*", "jest.setup.*",
    ".mocharc.*", "karma.conf.*", "cypress.config.*", "playwright.config.*",
    "ava.config.*", ".nycrc", ".nycrc.*",
    # Ruby / RSpec configuration — ``.rspec`` can carry ``--tag`` / ``--exclude-pattern``
    # that deselects failing specs, exactly like pytest's ``addopts``.
    ".rspec",
    # Java/Maven — a Surefire ``<excludes>`` in ``pom.xml`` can deselect the failing
    # tests (a reward-hack), so it is treated as harness config. ``pom.xml`` also
    # carries dependencies, so an adopter who needs to edit deps in the same change
    # can exempt it with ``--allow pom.xml`` (a deliberate, reviewed baseline).
    "pom.xml",
    # Solidity / fuzzing toolchains
    "foundry.toml", "echidna.yaml", "slither.config.json",
    # Build/test *runners* that redefine how the suite is invoked when the
    # ``test_command`` shells out to them (``make test`` / ``nox`` / ``invoke`` /
    # ``rake test``). Editing one is the reward-hack equivalent of editing
    # ``addopts``: it lets a candidate point the judge at a passing target without
    # fixing the source.
    "Makefile", "GNUmakefile", "noxfile.py", "Justfile", "Rakefile", "rakefile",
    # Dependency lock files — swapping these substitutes the *actual library code*
    # that runs under the suite without touching a single source file.  A candidate
    # that replaces e.g. pnpm-lock.yaml with a version pinning a patched library
    # can make tests pass without fixing the real bug; this is a reward-hack as
    # potent as editing the test configuration. (``go.sum`` pins the cryptographic
    # hashes of Go module dependencies — rewriting it lets a candidate swap in a
    # patched dependency without touching a source file.)
    "pnpm-lock.yaml", "package-lock.json", "yarn.lock",
    "Cargo.lock", "Gemfile.lock", "poetry.lock", "go.sum",
)

# Files Python executes *inside the judge process itself* with no test ever naming
# them — so a candidate that writes one runs code in the judge, not in the program
# under test, and can subvert the verdict (force ``sys.exit(0)``, monkey-patch the
# runner, rewrite the report) without touching a single protected test/config file.
#   * ``sitecustomize.py`` / ``usercustomize.py`` are imported automatically during
#     interpreter start-up whenever they are importable on ``sys.path``;
#   * a ``*.pth`` file on the path may carry an executable ``import …`` line that
#     runs at start-up.
# These are rejected outright (the judge owns its own process), matched on the
# basename case-insensitively. See :func:`is_judge_autoexec`.
_PROTECTED_AUTOEXEC = ("sitecustomize.py", "usercustomize.py", "*.pth")

# CI definition paths the candidate may not modify: the workflow that *runs* the
# gate and any local composite action it calls. Editing these is a reward-hack as
# direct as deleting the tests — a candidate could disable the gate, swap the test
# command for a trivial one, or force a passing status without fixing the source.
# Matched on the repo-relative path prefix, case-insensitively. See
# :func:`is_protected_ci`.
_PROTECTED_CI_PREFIXES = (".github/workflows/", ".github/actions/")


class RepoProblem(TypedDict, total=False):
    """A repo-level problem definition."""

    name: str
    repo_path: str            # root of the target repository (never modified)
    description: str          # the task brief, in natural language
    test_command: list[str]   # judge command (default: pytest -q in the copy)
    setup_command: list[str]  # optional: runs before test_command inside the copy
                              # (e.g. ["pnpm", "install", "--frozen-lockfile"] for
                              # Node.js repos where COPY_IGNORE strips node_modules)
    target_files: list[str]   # generator hint: files to show the model first
    protected: list[str]      # extra globs the candidate may not modify
    allow: list[str]          # baseline allowlist: globs exempt from the test/config/
                              # CI rejection (never auto-exec or unsafe paths)
    allow_new_tests: bool     # opt-in "feature mode": allow *net-new* test files
                              # (existing-test / config / auto-exec edits stay rejected)
    deleted: list[str]        # paths the candidate deletes (from a base→head diff):
                              # safe source deletions are applied to the copy; a
                              # protected-harness deletion is rejected
    timeout: int              # per-candidate suite timeout (CLI uses this)
    mem_limit_mb: int         # address-space cap for the suite (CLI uses this);
                              # 0 disables the cap — required for node/V8 suites,
                              # whose virtual reservations exceed any sane RLIMIT_AS
    hide_tests: bool          # closed-book mode: the generator must not show the
                              # judging test files' content to the model
    file_blocks: dict[str, str]  # STRUCTURED candidate override: {relpath: content}.
                              # When present, the hypothesis text is NOT parsed for
                              # <<<FILE>>> blocks — this is how the dirs/diff path
                              # avoids the marker round-trip (a target file whose
                              # CONTENT legitimately contains "<<<END FILE>>>" must
                              # not terminate its own block; found by running Guard
                               # on Guard's own source, which embeds those markers).
    expect_verifier_pack_sha256: str  # optional V2 identity pin; mismatch fails closed
    # Container-judge fields used by Docker/gVisor isolation:
    docker_image: str         # runtime image, e.g. "node:22-slim"
    network: str              # "none" (default) or a docker network name
    judge_env: dict[str, str]  # explicit env passed into the container
    mounts_ro: list[str]      # "host:container" read-only binds
    tmpfs: list[str]          # container paths granted scratch (tmpfs) writes


_BLOCK_RE = re.compile(
    r"<<<FILE:\s*(?P<path>[^>\n]+?)\s*>>>\r?\n(?P<body>.*?)\r?\n?<<<END\s*FILE>>>",
    re.DOTALL,
)

# A surgical-edit block: one search/replace hunk for one file,
# applied with a unique anchor (issue #15). Multiple blocks apply in order.
_PATCH_BLOCK_RE = re.compile(
    r"<<<PATCH:\s*(?P<path>[^>\n]+?)\s*>>>\r?\n"
    r"<<<SEARCH>>>\r?\n(?P<search>.*?)\r?\n"
    r"<<<REPLACE>>>\r?\n(?P<replace>.*?)\r?\n?"
    r"<<<END\s*PATCH>>>",
    re.DOTALL,
)

# Lenient fallbacks — used ONLY when the strict parsers above find nothing.
_LENIENT_FILE_RE = re.compile(
    r"<+\s*FILE\s*:\s*(?P<path>[^>\n]+?)\s*>+\r?\n?"
    r"(?P<body>.*?)\r?\n?"
    r"<+\s*/?\s*(?:END\s*)?FILE\s*>+",
    re.DOTALL | re.IGNORECASE,
)
_LENIENT_PATCH_RE = re.compile(
    r"<+\s*PATCH\s*(?::\s*(?P<path>[^>\n]*?))?\s*>+\s*"
    r"<+\s*SEARCH\s*>+\r?\n?(?P<search>.*?)\s*(?:<+\s*/\s*SEARCH\s*>+\s*)?"
    r"<+\s*REPLACE\s*>+\r?\n?(?P<replace>.*?)\s*(?:<+\s*/\s*REPLACE\s*>+\s*)?"
    r"<+\s*/?\s*(?:END\s*)?PATCH\s*>+",
    re.DOTALL | re.IGNORECASE,
)

# pytest's summary line, e.g. "2 failed, 3 passed in 0.12s" / "1 error in 0.05s".
_PASSED_RE = re.compile(r"(\d+) passed")
_FAILED_RE = re.compile(r"(\d+) failed")
_ERROR_RE = re.compile(r"(\d+) errors?")

# Lines that carry the *essence* of a failure for the generator.
_DIAG_LINE_RE = re.compile(
    r"FAIL|×|✗|Expected|Received|expected|received|Counterexample|"
    r"AssertionError|Error:|assert|Tests\s|Test Files|=== |--- |E\s{3}"
)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def distill_diagnostics(output: str, *, max_chars: int = 1600) -> str:
    """Distill a test run's output to what the generator can act on."""
    clean = _ANSI_RE.sub("", output or "")
    picked = [ln.strip() for ln in clean.splitlines() if _DIAG_LINE_RE.search(ln)]
    picked = [ln for ln in picked if not ln.lstrip().startswith(("❯", "at "))]
    if not picked:
        return clean[-800:]
    text = "\n".join(picked)
    return text[-max_chars:]


def parse_file_blocks(hypothesis: str) -> dict[str, str]:
    """Extract ``{relative_path: content}`` from the hypothesis."""
    blocks: dict[str, str] = {}
    for m in _BLOCK_RE.finditer(hypothesis or ""):
        blocks[m.group("path").strip()] = m.group("body")
    return blocks


class PatchBlock(NamedTuple):
    """One unique-anchor search/replace edit for one file."""

    path: str
    search: str
    replace: str


def parse_patch_blocks(hypothesis: str) -> list[PatchBlock]:
    """Extract ordered ``<<<PATCH>>>`` edits from the hypothesis."""
    return [
        PatchBlock(m.group("path").strip(), m.group("search"), m.group("replace"))
        for m in _PATCH_BLOCK_RE.finditer(hypothesis or "")
    ]


def parse_blocks_lenient(
    hypothesis: str, default_path: str | None = None
) -> tuple[dict[str, str], list[PatchBlock]]:
    """Best-effort recovery of near-miss block formats."""
    files: dict[str, str] = {}
    for m in _LENIENT_FILE_RE.finditer(hypothesis or ""):
        files[m.group("path").strip()] = m.group("body")
    patches: list[PatchBlock] = []
    for m in _LENIENT_PATCH_RE.finditer(hypothesis or ""):
        path = (m.group("path") or "").strip() or (default_path or "")
        if path:
            patches.append(PatchBlock(path, m.group("search"), m.group("replace")))
    return files, patches


def is_safe_relpath(path: str) -> bool:
    """Is the path safe? Relative, normalized, and unable to escape the repo root."""
    if not path or os.path.isabs(path) or "\\" in path:
        return False
    parts = path.split("/")
    return all(p not in ("", ".", "..") for p in parts)


def is_protected(path: str, extra_globs: tuple[str, ...] = ()) -> bool:
    """Is this one of the files that judge the candidate?

    Protects anything in a ``tests``/``test`` directory segment, standard Python
    test-file names, JavaScript/TypeScript colocated test files (``*.test.ts``,
    ``*.spec.ts``, etc.), and caller-supplied globs — all matched
    **case-insensitively**, while still comparing whole segments/patterns so
    look-alikes (``latest/``, ``testing/``, ``contest.py``) are not over-matched.
    """
    parts = path.split("/")
    if any(p.lower() in ("tests", "test") for p in parts[:-1]):
        return True
    base = parts[-1]
    if any(fnmatch(base.lower(), pat.lower()) for pat in _PROTECTED_BASENAMES):
        return True
    return any(fnmatch(path.lower(), g.lower()) for g in extra_globs)


def is_protected_config(path: str) -> bool:
    """Is this a test-runner / build-config file the candidate may not modify?

    Editing the harness *configuration* (instead of the source under test) lets a
    candidate game the judge without fixing anything. Also covers dependency lock
    files, which substitute the actual library code that runs under the suite, and
    EvoGuard's own ``.evoguard.json``. Matched on the basename anywhere in the
    tree, case-insensitively.

    ``package.json`` is intentionally NOT rejected wholesale: it defines the whole
    JS project, so blocking every edit would reject legitimate source/dependency
    fixes. Its test-script / embedded-runner-config vector is handled via
    :func:`restore_judge_package_json`.
    """
    base = path.split("/")[-1].lower()
    return any(fnmatch(base, pat.lower()) for pat in _PROTECTED_CONFIG)


def is_judge_autoexec(path: str) -> bool:
    """Is this a file Python auto-executes inside the judge process?"""
    base = path.split("/")[-1].lower()
    return any(fnmatch(base, pat.lower()) for pat in _PROTECTED_AUTOEXEC)


def is_protected_ci(path: str) -> bool:
    """Is this a CI workflow / local action file that defines how the gate runs?

    Editing the workflow that *runs* EvoGuard (or a local composite action it
    calls) is a reward-hack as direct as deleting the tests: a candidate could
    disable the gate, swap the test command for a trivial one, or force a passing
    status without fixing the source. Matched on the repo-relative path prefix,
    case-insensitively.
    """
    p = path.lower()
    return any(p.startswith(prefix) for prefix in _PROTECTED_CI_PREFIXES)


def _matches_globs(path: str, globs: tuple[str, ...]) -> bool:
    """Does ``path`` match any of ``globs`` (case-insensitive)?"""
    return any(fnmatch(path.lower(), g.lower()) for g in globs)


# Test-like basenames that, although matched as "tests", are **auto-applied to the
# whole suite** rather than being a plain test module — pytest imports
# ``conftest.py`` as a plugin (fixtures/hooks/collection), so a net-new one runs
# code against *every* test. Never addable under feature mode (treated like an
# auto-exec judge file, not a plain new test).
_AUTOEXEC_TESTLIKE = ("conftest.py",)


def is_addable_new_test(path: str, extra: tuple[str, ...], *, is_new: bool) -> bool:
    """Feature mode (opt-in): may this changed path be allowed as a *net-new* test?

    ``True`` only when the path is **new** to the repo, is protected *solely*
    because it is a plain test file (a ``tests``/``test`` segment or a test-file
    name), and is **not** also an auto-applied ``conftest.py``, a caller-protected
    glob, a test/build config or lock file, an auto-executed judge file
    (``sitecustomize.py`` / ``*.pth`` / ``Makefile`` …), or a CI/gate file. Editing
    an *existing* test, or any of those harness files, stays rejected.

    This narrowly lets a feature PR ship its own brand-new tests. It does **not**
    make EvoGuard safe for untrusted code: a new test file's module/collection-time
    code still runs in the judge process, so feature mode is opt-in (default off)
    and for trusted authors — see ``docs/FEATURE_MODE.md`` for the threat analysis.
    """
    return (
        is_new
        and is_protected(path, ())
        and path.split("/")[-1].lower() not in _AUTOEXEC_TESTLIKE
        and not _matches_globs(path, extra)
        and not is_protected_config(path)
        and not is_judge_autoexec(path)
        and not is_protected_ci(path)
    )


# ``package.json`` keys/scripts that configure the JS test harness.
_PKG_RUNNER_KEYS = ("jest", "vitest", "mocha", "ava", "c8", "nyc")


def _is_judge_script(name: str) -> bool:
    """A ``scripts`` entry that runs/!wraps the test suite (so it judges)."""
    return name == "test" or name.startswith("test:") or name in ("pretest", "posttest")


def restore_judge_package_json(original_text: str | None, candidate_text: str) -> str:
    """Return the candidate ``package.json`` with the test-harness fields restored."""
    try:
        candidate = json.loads(candidate_text)
    except (ValueError, TypeError):
        return candidate_text
    if not isinstance(candidate, dict):
        return candidate_text
    try:
        original = json.loads(original_text) if original_text else {}
    except (ValueError, TypeError):
        original = {}
    if not isinstance(original, dict):
        original = {}

    changed = False

    for key in _PKG_RUNNER_KEYS:
        if key in original:
            if candidate.get(key) != original[key]:
                candidate[key] = original[key]
                changed = True
        elif key in candidate:
            del candidate[key]
            changed = True

    orig_scripts = original.get("scripts")
    orig_scripts = orig_scripts if isinstance(orig_scripts, dict) else {}
    cand_scripts_raw = candidate.get("scripts")
    cand_scripts = dict(cand_scripts_raw) if isinstance(cand_scripts_raw, dict) else {}
    scripts_changed = False
    for name in {n for n in (set(cand_scripts) | set(orig_scripts)) if _is_judge_script(n)}:
        if name in orig_scripts:
            if cand_scripts.get(name) != orig_scripts[name]:
                cand_scripts[name] = orig_scripts[name]
                scripts_changed = True
        elif name in cand_scripts:
            del cand_scripts[name]
            scripts_changed = True
    if scripts_changed:
        changed = True
        candidate["scripts"] = cand_scripts

    if not changed:
        return candidate_text
    return json.dumps(candidate, indent=2, ensure_ascii=False) + "\n"


def reject_unsafe_or_protected(
    paths: list[str],
    extra: tuple[str, ...],
    *,
    allow_new_tests: bool = False,
    new_paths: frozenset[str] = frozenset(),
    allow: tuple[str, ...] = (),
) -> VerdictResult | None:
    """Reject the first unsafe or judge path.

    With ``allow_new_tests`` (opt-in feature mode), a path protected *only* because
    it is a test file is allowed when it is net-new (in ``new_paths``) — see
    :func:`is_addable_new_test`. Editing an *existing* test, and every
    config / auto-exec / CI / lock-file path, stays rejected regardless.

    ``allow`` is an adopter-curated allowlist of globs (a *baseline*): a matching
    path is **exempt from the test / config / CI rejection** — for a file a built-in
    pattern misclassifies (e.g. a ``Makefile`` that runs no tests) or a known
    pre-existing hit. It does **not** exempt auto-exec judge files
    (``sitecustomize.py`` / ``*.pth``) or unsafe paths — those are never legitimate.
    """
    for path in paths:
        if not is_safe_relpath(path):
            return VerdictResult(
                passed=False,
                score=0.05,
                diagnostics=f"unsafe path rejected: {path}",
                artifact={"files_changed": []},
            )
        allowed = _matches_globs(path, allow)
        if is_protected(path, extra):
            if allow_new_tests and is_addable_new_test(path, extra, is_new=path in new_paths):
                continue  # net-new pure test file — allowed under feature mode
            if allowed:
                continue  # adopter-allowlisted (baseline) — a misclassified test path
            return VerdictResult(
                passed=False,
                score=0.05,
                diagnostics=(
                    f"modifying the judging tests is "
                    f"forbidden: {path}"
                ),
                artifact={"files_changed": []},
            )
        if is_protected_config(path):
            if allowed:
                continue  # adopter-allowlisted (baseline)
            return VerdictResult(
                passed=False,
                score=0.05,
                diagnostics=(
                    f"modifying the test/build configuration is forbidden: {path} — "
                    "fix the source under test, not the harness that judges it"
                ),
                artifact={"files_changed": []},
            )
        if is_protected_ci(path):
            if allowed:
                continue  # adopter-allowlisted (baseline)
            return VerdictResult(
                passed=False,
                score=0.05,
                diagnostics=(
                    f"modifying the CI workflow / local action that runs the gate is "
                    f"forbidden: {path} — fix the source under test, not the gate "
                    "that judges it"
                ),
                artifact={"files_changed": []},
            )
        if is_judge_autoexec(path):
            return VerdictResult(
                passed=False,
                score=0.05,
                diagnostics=(
                    f"writing an auto-executed judge file is forbidden: {path} — it "
                    "would run code inside the judge process itself (not the program "
                    "under test); fix the source instead"
                ),
                artifact={"files_changed": []},
            )
    return None


def _read_text_or_none(path: str) -> str | None:
    """Read a UTF-8 file, returning ``None`` if it does not exist / cannot be read."""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def copy_repo_tree(src: str, dst: str) -> None:
    """Copy a repository into a throwaway working copy, faithfully.

    ``symlinks=True`` keeps symlinks *as symlinks* (and regular files keep their
    permission bits via ``copy2``), which matters twice:

    * **No crash on dangling links.** Real repos routinely carry symlinks into
      directories ``COPY_IGNORE`` strips (``.venv/``, ``node_modules/``) or
      plain broken links; dereferencing (the ``symlinks=False`` default) makes
      ``copytree`` raise on those, crashing the judge instead of judging.
    * **No content smuggling.** Dereferencing would copy the link's *target
      content* into the copy — for an absolute link that means host files get
      materialized inside the tree that container isolation later mounts.

    Writing *through* a symlink is prevented separately at apply time — see
    :func:`_resolve_write_target`.
    """
    shutil.copytree(src, dst, symlinks=True, ignore=shutil.ignore_patterns(*COPY_IGNORE))


def _resolve_write_target(copy: str, rel: str) -> str | None:
    """The absolute path a candidate edit for ``rel`` may write inside ``copy``.

    Returns ``None`` when the write would land **outside** the copy through a
    symlinked directory (``lnkdir -> /outside`` + a ``lnkdir/x.py`` edit).
    A target that is itself a symlink is replaced by a regular file — the link
    is unlinked first, never written *through* — matching how git materializes
    a blob over a symlink and keeping every candidate byte inside the copy.
    """
    target = os.path.join(copy, *rel.split("/"))
    parent = os.path.dirname(target) or copy
    os.makedirs(parent, exist_ok=True)
    real_copy = os.path.realpath(copy)
    real_parent = os.path.realpath(parent)
    if real_parent != real_copy and not real_parent.startswith(real_copy + os.sep):
        return None
    if os.path.islink(target):
        os.unlink(target)
    return target


def apply_blocks_to_copy(
    copy: str, file_blocks: dict[str, str], patch_blocks: list[PatchBlock]
) -> str | None:
    """Materialize file blocks then patches into ``copy``."""
    pkg_paths = sorted(
        {p for p in file_blocks if p.split("/")[-1] == "package.json"}
        | {pb.path for pb in patch_blocks if pb.path.split("/")[-1] == "package.json"}
    )
    pkg_originals: dict[str, str | None] = {}
    for rel in pkg_paths:
        fp = os.path.join(copy, *rel.split("/"))
        pkg_originals[rel] = _read_text_or_none(fp)

    for path, content in file_blocks.items():
        target = _resolve_write_target(copy, path)
        if target is None:
            return (
                f"edit target escapes the repo copy through a symlinked "
                f"directory — refusing to write: {path}"
            )
        with open(target, "w", encoding="utf-8") as f:
            f.write(content)

    for pb in patch_blocks:
        target = _resolve_write_target(copy, pb.path)
        if target is None:
            return (
                f"edit target escapes the repo copy through a symlinked "
                f"directory — refusing to write: {pb.path}"
            )
        try:
            with open(target, encoding="utf-8") as f:
                source = f.read()
        except OSError:
            return (
                f"PATCH target not found: {pb.path} — "
                "use a <<<FILE>>> block "
                "to create new files"
            )
        try:
            patched = apply_patch(source, pb.search, pb.replace)
        except (PatchError, ValueError) as exc:
            return (
                f"PATCH did not apply to {pb.path}: "
                f"{type(exc).__name__}: {exc} — "
                ""
                "copy a unique anchor verbatim from the shown file"
            )
        with open(target, "w", encoding="utf-8") as f:
            f.write(patched)

    for rel in pkg_paths:
        fp = os.path.join(copy, *rel.split("/"))
        candidate_pkg = _read_text_or_none(fp)
        if candidate_pkg is None:
            continue
        restored = restore_judge_package_json(pkg_originals.get(rel), candidate_pkg)
        if restored != candidate_pkg:
            with open(fp, "w", encoding="utf-8") as f:
                f.write(restored)
    return None


def parse_pytest_counts(output: str) -> tuple[int, int]:
    """Read ``(passed, total)`` from a pytest/vitest run's *human* output.

    NOTE — this scrapes the runner's stdout/stderr and is therefore **forgeable**.
    Retained only to enrich diagnostic text; never used for the verdict.
    """
    lines = [ln for ln in (output or "").splitlines() if "Test Files" not in ln]
    text = "\n".join(lines)
    passed = sum(int(n) for n in _PASSED_RE.findall(text))
    failed = sum(int(n) for n in _FAILED_RE.findall(text))
    errors = sum(int(n) for n in _ERROR_RE.findall(text))
    return passed, passed + failed + errors


class JUnitCounts(NamedTuple):
    """Authoritative test counts read from a pytest JUnit-XML report."""

    passed: int
    total: int
    failures: int
    errors: int


def _count_testcases(root: ET.Element) -> JUnitCounts | None:
    """Count ``<testcase>`` elements directly — the unit every JUnit dialect emits."""
    cases = list(root.iter("testcase"))
    if not cases:
        return None
    failures = errors = skipped = 0
    for tc in cases:
        if tc.find("skipped") is not None:
            skipped += 1
        elif tc.find("error") is not None:
            errors += 1
        elif tc.find("failure") is not None:
            failures += 1
    total = len(cases)
    effective_total = max(0, total - skipped)
    passed = max(0, effective_total - failures - errors)
    return JUnitCounts(passed=passed, total=effective_total, failures=failures, errors=errors)


# A JUnit report is small (a few KB even for thousands of cases); anything much
# larger is pathological. Cap the input so a runaway/hostile report cannot exhaust
# memory or parse time.
_MAX_REPORT_CHARS = 8 * 1024 * 1024


def parse_junit_xml(xml_text: str) -> JUnitCounts | None:
    """Read authoritative test counts from a JUnit-XML report.

    **Hardened** against a hostile report — the candidate's *test process* can write
    to the report path, so this input is only semi-trusted. The input is
    **size-capped**, and any **DTD / ``DOCTYPE`` / ``ENTITY`` is refused**, which
    eliminates entity-expansion ("billion laughs") and external-entity vectors
    regardless of the host's ``expat`` version. A rejected report yields no counts —
    the run then grades as "no clean verdict" (``FAIL``) — never a parser hang.
    """
    if not xml_text or not xml_text.strip():
        return None
    if len(xml_text) > _MAX_REPORT_CHARS:
        return None
    # A JUnit report never legitimately needs a DTD; refuse it before expat parses.
    if "<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text:
        return None
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    by_case = _count_testcases(root)
    if by_case is not None:
        return by_case
    total = failures = errors = skipped = 0
    seen = False
    for suite in root.iter("testsuite"):
        seen = True
        try:
            total += int(suite.get("tests", 0))
            failures += int(suite.get("failures", 0))
            errors += int(suite.get("errors", 0))
            skipped += int(suite.get("skipped", 0))
        except (TypeError, ValueError):  # pragma: no cover - defensive
            return None
    if not seen:
        return None
    effective_total = max(0, total - skipped)
    passed = max(0, effective_total - failures - errors)
    return JUnitCounts(passed=passed, total=effective_total, failures=failures, errors=errors)


def parse_junit_dir(dirpath: str) -> JUnitCounts | None:
    """Merge every ``*.xml`` JUnit report in a directory into one count.

    For runners (Maven Surefire, …) that emit **one report file per test class**
    into a judge-owned *directory* rather than a single file. Each file is read
    through the hardened :func:`parse_junit_xml` (size-cap + DTD/``ENTITY`` refusal),
    and the per-file counts are summed. Returns ``None`` if the directory is absent
    or holds no parseable report — so the run then grades as "no clean verdict",
    never a crash on a stray non-report file.
    """
    if not dirpath or not os.path.isdir(dirpath):
        return None
    passed = total = failures = errors = 0
    seen = False
    for fn in sorted(os.listdir(dirpath)):
        if not fn.lower().endswith(".xml"):
            continue
        counts = parse_junit_xml(_read_text_or_none(os.path.join(dirpath, fn)) or "")
        if counts is None:
            continue
        seen = True
        passed += counts.passed
        total += counts.total
        failures += counts.failures
        errors += counts.errors
    if not seen:
        return None
    return JUnitCounts(passed=passed, total=total, failures=failures, errors=errors)


def grade_repo_run(
    returncode: int, junit: JUnitCounts | None, *, report_expected: bool
) -> tuple[bool, float, int, int]:
    """Turn a finished suite run into ``(passed, score, tests_passed, tests_total)``."""
    if junit is not None:
        if returncode == 0 and junit.total > 0 and junit.failures == 0 and junit.errors == 0:
            return True, 1.0, junit.passed, junit.total
        if returncode == 1 and junit.total > 0 and (junit.failures > 0 or junit.errors > 0):
            return False, fraction_score(junit.passed, junit.total), junit.passed, junit.total
        return False, 0.10, junit.passed, junit.total
    if report_expected:
        return False, 0.10, 0, 0
    if returncode == 0:
        return True, 1.0, 0, 0
    if returncode == 1:
        return False, 0.25, 0, 0
    return False, 0.10, 0, 0


def detect_tamper(returncode: int, junit: JUnitCounts | None, *, report_expected: bool) -> bool:
    """Is the suite's exit code *inconsistent* with its judge-owned JUnit report?"""
    if junit is None:
        return False
    all_pass = junit.total > 0 and junit.failures == 0 and junit.errors == 0
    has_failures = junit.failures > 0 or junit.errors > 0
    if all_pass and returncode != 0:
        return True
    if has_failures and returncode == 0:
        return True
    return False


_DEFAULT_SETUP_OUTPUT_DIRS = frozenset({
    ".cache", ".evoguard-setup", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".tox", ".venv", "build", "dist", "node_modules", "target", "venv",
    "vendor", "__pycache__",
})


class SetupFidelityError(RuntimeError):
    """The judge could not prove what setup changed; fail closed."""


def _docker_container_name(stage: str) -> str:
    """Collision-resistant name for concurrent setup/suite/pack containers."""
    safe_stage = re.sub(r"[^a-zA-Z0-9_.-]+", "-", stage).strip("-.") or "run"
    return f"evoguard_{safe_stage[:32]}_{secrets.token_hex(8)}"


def _is_default_setup_output(path: str) -> bool:
    return any(part in _DEFAULT_SETUP_OUTPUT_DIRS for part in path.split("/") if part)


def _fidelity_entry_state(path: str) -> tuple[str, int, str]:
    try:
        mode = os.lstat(path).st_mode
        permissions = stat.S_IMODE(mode)
        if stat.S_ISLNK(mode):
            return ("link", permissions, os.readlink(path))
        if stat.S_ISDIR(mode):
            return ("dir", permissions, "")
        if not stat.S_ISREG(mode):
            return ("special", permissions, str(stat.S_IFMT(mode)))
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return ("file", permissions, digest.hexdigest())
    except OSError as exc:
        raise SetupFidelityError(f"cannot read {path!r}: {exc}") from exc


def _setup_fidelity_snapshot(
    root: str,
    extra_output_globs: tuple[str, ...] = (),
    *,
    baseline: dict[str, tuple[str, int, str]] | None = None,
) -> dict[str, tuple[str, int, str]]:
    """Identity of files setup is not allowed to mutate.

    Every pre-existing file, directory, symlink and permission bit is bound,
    including content under conventional output directories. On the post-setup
    scan, only *new* entries below those conventional directories are ignored.
    This lets setup create ``node_modules``/``.venv``/``target`` without allowing
    it to rewrite a checked-in ``vendor`` or ``build`` tree. Explicit adopter
    globs are trusted exceptions and are omitted on both scans.
    """
    snapshot: dict[str, tuple[str, int, str]] = {}
    baseline_keys = frozenset(baseline or {})

    def walk_error(exc: OSError) -> None:
        raise SetupFidelityError(f"cannot inspect setup output tree: {exc}") from exc

    for dirpath, dirnames, filenames in os.walk(root, onerror=walk_error):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        kept: list[str] = []
        for dirname in sorted(dirnames):
            path = os.path.join(dirpath, dirname)
            rel = dirname if rel_dir == "." else f"{rel_dir}/{dirname}"
            if _matches_globs(rel, extra_output_globs) or _matches_globs(
                rel + "/", extra_output_globs
            ):
                continue
            if baseline is not None and _is_default_setup_output(rel) and rel not in baseline_keys:
                continue
            state = _fidelity_entry_state(path)
            snapshot[rel] = state
            if state[0] == "dir":
                kept.append(dirname)
        dirnames[:] = kept
        for filename in sorted(filenames):
            path = os.path.join(dirpath, filename)
            rel = filename if rel_dir == "." else f"{rel_dir}/{filename}"
            if _matches_globs(rel, extra_output_globs):
                continue
            if baseline is not None and _is_default_setup_output(rel) and rel not in baseline_keys:
                continue
            snapshot[rel] = _fidelity_entry_state(path)
    return snapshot


def _setup_fidelity_changes(
    before: dict[str, tuple[str, int, str]],
    after: dict[str, tuple[str, int, str]],
) -> list[str]:
    return sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))


class RepoVerifier:
    """Apply the hypothesis to a copy of the repo and judge it with its tests."""

    domain = "repo"

    def __init__(
        self,
        timeout: int = 120,
        mem_limit_mb: int = 1024,
        *,
        test_command: list[str] | None = None,
        setup_command: list[str] | None = None,
        protected: tuple[str, ...] = (),
        allow: tuple[str, ...] = (),
        allow_new_tests: bool = False,
        isolation: str = "subprocess",
        docker_image: str | None = None,
        docker_network: str = "none",
        docker_runtime: str | None = None,
        trust_setup_on_host: bool = False,
        setup_output_globs: tuple[str, ...] = (),
    ) -> None:
        self.timeout = timeout
        self.mem_limit_mb = mem_limit_mb
        self.test_command = test_command
        self.setup_command = setup_command
        self.protected = protected
        # Adopter-curated allowlist (baseline): globs exempt from the test/config/CI
        # rejection (never auto-exec or unsafe paths). See reject_unsafe_or_protected.
        self.allow = allow
        # Opt-in feature mode: allow net-new test files (see is_addable_new_test).
        self.allow_new_tests = allow_new_tests
        # isolation == "docker" runs the suite inside a short-lived, network-less,
        # read-only container (defence in depth for semi-trusted code); the default
        # "subprocess" path is unchanged. See ``_docker_command`` and docs/GUARD.md.
        # isolation == "gvisor" is the same container judge but through the gVisor
        # OCI runtime (`runsc`) — a user-space guest kernel, no /dev/kvm needed — so
        # the suite runs under a separate kernel. See docs/VM_ISOLATION.md.
        self.isolation = isolation
        self.docker_image = docker_image
        self.docker_network = docker_network
        self.docker_runtime = docker_runtime or ("runsc" if isolation == "gvisor" else None)
        self._resolved_docker_image: str | None = None
        # Explicit compatibility escape hatch. By default candidate-influenced
        # setup runs inside the same requested boundary as the suite.
        self.trust_setup_on_host = trust_setup_on_host
        self.setup_output_globs = setup_output_globs

    # ------------------------------------------------------------------ #
    def _limits(self):  # pragma: no cover - exercised in the child process
        """preexec hook: cap CPU seconds and address space before exec."""
        if resource is None:
            return None

        def apply() -> None:
            resource_api = cast(Any, resource)
            cpu = max(1, int(self.timeout) + 1)
            resource_api.setrlimit(resource_api.RLIMIT_CPU, (cpu, cpu))
            if self.mem_limit_mb <= 0:
                return
            mem = self.mem_limit_mb * 1024 * 1024
            try:
                resource_api.setrlimit(resource_api.RLIMIT_AS, (mem, mem))
            except (ValueError, OSError):
                pass

        return apply

    # ------------------------------------------------------------------ #
    def _command(self, problem: RepoProblem | dict) -> list[str]:
        cmd = self.test_command or problem.get("test_command")
        if isinstance(cmd, str):
            return cmd.split()
        if cmd:
            return list(cmd)
        python = "python" if self.isolation in ("docker", "gvisor") else sys.executable
        return [python, "-m", "pytest", "-q", "--color=no", "-p", "no:cacheprovider"]

    # ------------------------------------------------------------------ #
    def _docker_command(
        self, cmd: list[str], copy: str, outdir: str | None, name: str,
        report_env: dict[str, str] | None = None,
        *,
        work_writable: bool = False,
        pack_dir: str | None = None,
    ) -> list[str]:
        """Wrap ``cmd`` in a short-lived, isolated ``docker run`` for the docker /
        gvisor judge (``--runtime runsc`` is added when ``docker_runtime`` is set)."""
        docker = [
            "docker", "run", "--rm", "--name", name,
            "--network", self.docker_network,
            "--pids-limit", "256", "--cpus", "1", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--ulimit", "nofile=1024:1024",
            "--tmpfs", "/tmp:rw,exec",
            "-e", "HOME=/tmp", "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "LANG=C.UTF-8",
            "-v", f"{copy}:/work:{'rw' if work_writable else 'ro'}",
        ]
        if outdir is not None:
            docker += ["-v", f"{outdir}:/out:rw"]
        if pack_dir is not None:
            docker += ["-v", f"{pack_dir}:/verifier-pack:ro"]
        getuid = getattr(os, "getuid", None)
        getgid = getattr(os, "getgid", None)
        if callable(getuid) and callable(getgid):
            # Match ownership of the host-created work/report directories. This
            # lets us drop every capability without relying on root's DAC bypass.
            docker += ["--user", f"{getuid()}:{getgid()}"]
        docker += ["-w", "/work"]
        # A stronger OCI runtime (gVisor's `runsc`) gives the suite its own
        # user-space guest kernel without needing /dev/kvm.
        if self.docker_runtime:
            docker += ["--runtime", self.docker_runtime]
        # Reporter env a runner needs to reach the judge-owned report (jest-junit).
        for _k, _v in (report_env or {}).items():
            docker += ["-e", f"{_k}={_v}"]
        if self.mem_limit_mb > 0:
            docker += ["--memory", f"{self.mem_limit_mb}m"]
        return [*docker, str(self._resolved_docker_image or self.docker_image), *cmd]

    def _resolve_docker_image(self) -> str:
        """Resolve a tag once so setup and suite use the exact same image bytes."""
        if self._resolved_docker_image:
            return self._resolved_docker_image
        image = str(self.docker_image or "")
        inspect = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if inspect.returncode != 0:
            pull = subprocess.run(
                ["docker", "pull", image],
                capture_output=True,
                text=True,
                timeout=600,
            )
            if pull.returncode != 0:
                raise RuntimeError(
                    f"container image {image!r} could not be resolved: "
                    + distill_diagnostics(pull.stdout + "\n" + pull.stderr)
                )
            inspect = subprocess.run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", image],
                capture_output=True,
                text=True,
                timeout=60,
            )
        resolved = inspect.stdout.strip()
        if inspect.returncode != 0 or not resolved:
            raise RuntimeError(f"container image {image!r} has no resolvable image ID")
        self._resolved_docker_image = resolved
        return resolved

    def _run_docker(
        self, base_cmd, copy, workdir, *, pack_dir=None
    ):  # pragma: no cover - needs docker daemon
        """Run the suite inside the docker judge."""
        outdir = os.path.join(workdir, "out")
        os.makedirs(outdir, exist_ok=True)
        host_xml = os.path.join(outdir, "judge-result.xml")
        cmd, report_expected, report_env = instrument_command(base_cmd, "/out/judge-result.xml")
        name = _docker_container_name(os.path.basename(workdir.rstrip("/")))
        docker_cmd = self._docker_command(
            cmd, copy, outdir, name, report_env, pack_dir=pack_dir
        )
        try:
            r = subprocess.run(
                docker_cmd, capture_output=True, text=True,
                timeout=self.timeout, env=os.environ.copy(),
            )
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)
            raise
        return host_xml, r, report_expected

    # ------------------------------------------------------------------ #
    def verify(self, hypothesis: str, problem: RepoProblem | dict) -> VerdictResult:
        repo_path = str(problem.get("repo_path", ""))
        if not repo_path or not os.path.isdir(repo_path):
            raise ValueError(f"problem['repo_path'] is not a directory: {repo_path!r}")

        # Paths the candidate deletes (set by Guard from a base→head diff). A deleted
        # *source* file is applied to the copy so the verdict matches the merge; a
        # deleted protected harness file is rejected below (removing a check is a
        # reward-hack as direct as editing it).
        deleted_paths = [str(p) for p in problem.get("deleted", ()) if str(p).strip()]

        fb_override = problem.get("file_blocks")
        if isinstance(fb_override, dict) and fb_override:
            # Structured candidate (the dirs/diff path): trust the mapping, skip
            # the marker parse entirely — content containing literal block markers
            # must never terminate its own block.
            file_blocks = {str(k): str(v) for k, v in fb_override.items()}
            patch_blocks: list[PatchBlock] = []
        else:
            file_blocks = parse_file_blocks(hypothesis)
            patch_blocks = parse_patch_blocks(hypothesis)
            if not file_blocks and not patch_blocks:
                targets = [str(t) for t in problem.get("target_files", ()) if str(t).strip()]
                default_path = targets[0] if len(targets) == 1 else None
                file_blocks, patch_blocks = parse_blocks_lenient(hypothesis, default_path)
        if not file_blocks and not patch_blocks and not deleted_paths:
            return VerdictResult(
                passed=False,
                score=0.02,
                diagnostics=(
                    "no parseable blocks; expected "
                    "<<<FILE: path>>> … <<<END FILE>>> or "
                    "<<<PATCH: path>>> <<<SEARCH>>> … <<<REPLACE>>> … <<<END PATCH>>>"
                ),
                artifact={"files_changed": []},
            )

        extra = self.protected + tuple(problem.get("protected", ()))
        allow = self.allow + tuple(problem.get("allow", ()))
        changed = sorted(set(file_blocks) | {pb.path for pb in patch_blocks})
        allow_new_tests = self.allow_new_tests or bool(problem.get("allow_new_tests"))
        new_paths = frozenset(
            p for p in changed
            if is_safe_relpath(p) and not os.path.exists(os.path.join(repo_path, p))
        )
        rejection = reject_unsafe_or_protected(
            changed, extra, allow_new_tests=allow_new_tests, new_paths=new_paths, allow=allow,
        )
        if rejection is not None:
            return rejection
        # Deletions are never "new" and feature mode never exempts removing a check,
        # so a protected deletion is always rejected (defence in depth — Guard also
        # filters these before calling verify).
        if deleted_paths:
            del_rejection = reject_unsafe_or_protected(deleted_paths, extra, allow=allow)
            if del_rejection is not None:
                return del_rejection

        workdir = tempfile.mkdtemp(prefix="evo_repo_")
        copy = os.path.join(workdir, "repo")
        pack_workdir: str | None = None
        pack_snapshot: str | None = None
        try:
            copy_repo_tree(repo_path, copy)
            apply_error = apply_blocks_to_copy(copy, file_blocks, patch_blocks)
            if apply_error is not None:
                return VerdictResult(
                    passed=False,
                    score=0.08,
                    diagnostics=apply_error,
                    artifact={"files_changed": changed},
                )

            # Accept an Independent Verifier Pack into a separate judge-owned
            # snapshot outside both the candidate tree and HOME. The legacy mount
            # namespace remains reserved so a repo cannot pre-plant a shadow copy.
            pack_sha256 = None
            pack_manifest: dict | None = None
            pack_identity: tuple[str, dict | None] | None = None
            pack_dir = str(problem.get("verifier_pack", "") or "")
            expected_pack_sha256 = str(
                problem.get("expect_verifier_pack_sha256", "") or ""
            ).lower()
            if expected_pack_sha256 and not pack_dir:
                return VerdictResult(
                    passed=False,
                    score=0.0,
                    diagnostics=(
                        "an expected verifier-pack SHA-256 was configured but no "
                        "verifier pack was supplied"
                    ),
                    artifact={
                        "files_changed": changed,
                        "outcome": "pack_identity_mismatch",
                        "expected_verifier_pack_sha256": expected_pack_sha256,
                    },
                )
            if pack_dir:
                reserved = os.path.join(copy, "evoguard_verifier_pack")
                if os.path.lexists(reserved):
                    return VerdictResult(
                        passed=False, score=0.05,
                        diagnostics=(
                            "the repo already contains 'evoguard_verifier_pack/' — the "
                            "judge-owned pack mount point must not exist in the tree"
                        ),
                        artifact={"files_changed": changed},
                    )
                try:
                    # Keep the accepted snapshot outside both the candidate tree
                    # and its HOME. The repo suite never receives this path.
                    pack_workdir = tempfile.mkdtemp(prefix="evo_pack_snapshot_")
                    pack_snapshot = os.path.join(pack_workdir, "pack")
                    pack_identity = snapshot_pack(pack_dir, pack_snapshot)
                    pack_sha256, pack_manifest = pack_identity
                except PackManifestError as exc:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=str(exc),
                        artifact={"files_changed": changed, "outcome": "pack_invalid"},
                    )
                if expected_pack_sha256 and pack_sha256.lower() != expected_pack_sha256:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=(
                            "verifier-pack identity mismatch: expected "
                            f"{expected_pack_sha256}, observed {pack_sha256}"
                        ),
                        artifact={
                            "files_changed": changed,
                            "outcome": "pack_identity_mismatch",
                            "expected_verifier_pack_sha256": expected_pack_sha256,
                            "verifier_pack_sha256": pack_sha256,
                            "verifier_pack_manifest": pack_manifest,
                        },
                    )

            # Apply deletions to the copy so the verdict reflects the real merge
            # (a removed source file should be *absent* when the suite runs).
            for rel in deleted_paths:
                if not is_safe_relpath(rel):
                    continue  # never escape the copy (already gated; belt-and-braces)
                target = os.path.join(copy, *rel.split("/"))
                try:
                    os.remove(target)
                except IsADirectoryError:
                    shutil.rmtree(target, ignore_errors=True)
                except OSError:
                    pass  # already absent — nothing to verify against

            env = judge_subprocess_env(workdir)

            container_mode = self.isolation in ("docker", "gvisor")
            if container_mode and not self.docker_image:
                return VerdictResult(
                    passed=False,
                    score=0.0,
                    diagnostics=f"{self.isolation} isolation requires a docker image (--docker-image)",
                    artifact={"files_changed": changed, "outcome": "isolation_unavailable"},
                )
            resolved_image: str | None = None
            if container_mode:
                try:
                    resolved_image = self._resolve_docker_image()
                    # Tests may stub the resolver; pin its returned ID explicitly
                    # so setup, suite and pack all use the same image reference.
                    self._resolved_docker_image = resolved_image
                except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"{self.isolation} isolation unavailable: {exc}",
                        artifact={
                            "files_changed": changed,
                            "outcome": "isolation_unavailable",
                        },
                    )

            # Run optional setup_command before the suite under the requested
            # container boundary by default (or a restricted host environment by
            # explicit compatibility opt-in). The suite stays restricted, and
            # the verdict is read only from the judge-owned JUnit report + the test
            # command's exit code — so setup's stdout can never inflate the verdict.
            setup_cmd_raw = self.setup_command or problem.get("setup_command")
            setup_isolation: str | None = None
            post_setup_fidelity: dict[str, tuple[str, int, str]] | None = None
            if setup_cmd_raw:
                if isinstance(setup_cmd_raw, str):
                    setup_cmd_raw = setup_cmd_raw.split()
                setup_tokens = [str(token) for token in setup_cmd_raw]
                setup_in_container = container_mode and not self.trust_setup_on_host
                setup_name: str | None = None
                if setup_in_container:
                    setup_isolation = self.isolation
                    setup_name = _docker_container_name("setup")
                    setup_run_cmd = self._docker_command(
                        setup_tokens,
                        copy,
                        None,
                        setup_name,
                        work_writable=True,
                    )
                    setup_cwd = None
                    setup_env = os.environ.copy()
                else:
                    setup_isolation = (
                        "subprocess_host_opt_in" if container_mode else "subprocess"
                    )
                    setup_run_cmd = setup_tokens
                    setup_cwd = copy
                    setup_env = dict(env)
                try:
                    setup_before = _setup_fidelity_snapshot(
                        copy, self.setup_output_globs
                    )
                except SetupFidelityError as exc:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"setup fidelity snapshot failed: {exc}",
                        artifact={
                            "files_changed": changed,
                            "outcome": "setup_failed",
                            "setup_isolation": setup_isolation,
                        },
                    )
                try:
                    r_setup = subprocess.run(
                        setup_run_cmd,
                        cwd=setup_cwd,
                        capture_output=True,
                        text=True,
                        timeout=self.timeout,
                        env=setup_env,
                    )
                except subprocess.TimeoutExpired:
                    if setup_name is not None:
                        subprocess.run(
                            ["docker", "rm", "-f", setup_name],
                            capture_output=True,
                            timeout=30,
                        )
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"setup command timed out after {self.timeout}s",
                        artifact={
                            "elapsed": self.timeout,
                            "files_changed": changed,
                            "outcome": "setup_timeout",
                            "setup_isolation": setup_isolation,
                        },
                    )
                except FileNotFoundError:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=(
                            f"{self.isolation} isolation requested but the docker CLI "
                            "was not found while starting setup_command"
                            if setup_in_container
                            else f"setup command not found: {setup_tokens[0]!r}"
                        ),
                        artifact={
                            "files_changed": changed,
                            "outcome": "setup_failed",
                            "setup_isolation": setup_isolation,
                        },
                    )
                if setup_in_container and r_setup.returncode == 125:
                    diag = distill_diagnostics(r_setup.stdout + "\n" + r_setup.stderr)
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=(
                            f"the {self.isolation} setup container could not be "
                            f"started (docker exit 125): {diag}"
                        ),
                        artifact={
                            "files_changed": changed,
                            "outcome": "isolation_unavailable",
                            "setup_isolation": "unavailable",
                        },
                    )
                if r_setup.returncode != 0:
                    diag = distill_diagnostics(r_setup.stdout + "\n" + r_setup.stderr)
                    hint = (
                        " (setup ran inside the container: the image must contain "
                        "the setup tool, and --docker-network none blocks registries)"
                        if setup_in_container
                        else ""
                    )
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=(
                            f"setup command failed (exit {r_setup.returncode}){hint}: {diag}"
                        ),
                        artifact={
                            "files_changed": changed,
                            "outcome": "setup_failed",
                            "setup_isolation": setup_isolation,
                        },
                    )
                try:
                    setup_after = _setup_fidelity_snapshot(
                        copy,
                        self.setup_output_globs,
                        baseline=setup_before,
                    )
                except SetupFidelityError as exc:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"setup fidelity verification failed: {exc}",
                        artifact={
                            "files_changed": changed,
                            "outcome": "setup_failed",
                            "setup_isolation": setup_isolation,
                        },
                    )
                setup_changes = _setup_fidelity_changes(setup_before, setup_after)
                if setup_changes:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=(
                            "setup_command modified the judged source/harness outside "
                            "declared setup outputs — refusing to run a suite against "
                            "a tree different from the candidate: "
                            + ", ".join(setup_changes[:20])
                        ),
                        artifact={
                            "files_changed": changed,
                            "outcome": "setup_failed",
                            "setup_isolation": setup_isolation,
                            "setup_fidelity_changes": setup_changes,
                        },
                    )
                post_setup_fidelity = setup_after

            # A mandatory pack must judge the same candidate tree the repo suite
            # received. In subprocess mode the suite can write to its working copy;
            # bind the post-setup tree so it cannot rewrite source into a
            # pack-passing implementation between the two phases. Conventional
            # caches/new dependency outputs remain allowed by the same contract.
            candidate_runtime_baseline: dict[str, tuple[str, int, str]] | None = None
            if pack_dir:
                if post_setup_fidelity is not None:
                    # Reuse the filtered post-setup identity. New conventional
                    # dependency/build outputs were deliberately omitted, while
                    # every pre-existing entry remains bound.
                    candidate_runtime_baseline = post_setup_fidelity
                else:
                    try:
                        candidate_runtime_baseline = _setup_fidelity_snapshot(
                            copy, self.setup_output_globs
                        )
                    except SetupFidelityError as exc:
                        return VerdictResult(
                            passed=False,
                            score=0.0,
                            diagnostics=f"candidate fidelity snapshot failed: {exc}",
                            artifact={
                                "files_changed": changed,
                                "outcome": "setup_failed",
                                "setup_isolation": setup_isolation,
                            },
                        )

            # The machine-readable verdict is written to a JUnit report the JUDGE
            # owns — a path *outside* the repo copy, so the candidate (restricted to
            # relative paths inside the copy) cannot pre-plant or overwrite it via an
            # edit. The score is read from this report and the exit code, never from
            # the candidate-influenced stdout.
            base_cmd = self._command(problem)
            t0 = time.perf_counter()
            try:
                if self.isolation in ("docker", "gvisor"):
                    host_xml, r, report_expected = self._run_docker(base_cmd, copy, workdir)
                else:
                    host_xml = os.path.join(workdir, "judge-result.xml")
                    cmd, report_expected, report_env = instrument_command(base_cmd, host_xml)
                    r = subprocess.run(
                        cmd,
                        cwd=copy,
                        capture_output=True,
                        text=True,
                        timeout=self.timeout,
                        env={**env, **report_env},
                        preexec_fn=self._limits() if os.name == "posix" else None,
                    )
            except subprocess.TimeoutExpired:
                return VerdictResult(
                    passed=False,
                    score=0.0,
                    diagnostics=f"test suite timed out after {self.timeout}s",
                    artifact={"elapsed": self.timeout, "files_changed": changed, "outcome": "test_timeout"},
                )
            except FileNotFoundError:
                return VerdictResult(
                    passed=False, score=0.0,
                    diagnostics=(
                        f"{self.isolation} isolation requested but the docker CLI was not found"
                        if container_mode
                        else f"test command not found: {base_cmd[0]!r}"
                    ),
                    artifact={
                        "files_changed": changed,
                        "outcome": (
                            "isolation_unavailable"
                            if container_mode
                            else "test_command_unavailable"
                        ),
                        "setup_isolation": setup_isolation,
                    },
                )
            elapsed = time.perf_counter() - t0

            if container_mode and r.returncode == 125:
                return VerdictResult(
                    passed=False,
                    score=0.0,
                    diagnostics=(
                        f"the {self.isolation} suite container could not be started "
                        "(docker exit 125): "
                        + distill_diagnostics(r.stdout + "\n" + r.stderr)
                    ),
                    artifact={
                        "files_changed": changed,
                        "outcome": "isolation_unavailable",
                        "setup_isolation": setup_isolation,
                    },
                )

            if candidate_runtime_baseline is not None:
                try:
                    candidate_after_suite = _setup_fidelity_snapshot(
                        copy,
                        self.setup_output_globs,
                        baseline=candidate_runtime_baseline,
                    )
                except SetupFidelityError as exc:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"candidate fidelity verification failed: {exc}",
                        artifact={
                            "files_changed": changed,
                            "outcome": "candidate_tree_changed",
                            "tamper": True,
                            "setup_isolation": setup_isolation,
                        },
                    )
                candidate_changes = _setup_fidelity_changes(
                    candidate_runtime_baseline, candidate_after_suite
                )
                if candidate_changes:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=(
                            "repo suite modified the candidate tree before verifier-pack "
                            "execution: " + ", ".join(candidate_changes[:20])
                        ),
                        artifact={
                            "files_changed": changed,
                            "outcome": "candidate_tree_changed",
                            "tamper": True,
                            "candidate_fidelity_changes": candidate_changes,
                            "verifier_pack_sha256": pack_sha256,
                            "verifier_pack_manifest": pack_manifest,
                            "setup_isolation": setup_isolation,
                        },
                    )

            xml_text = _read_text_or_none(host_xml) or ""
            junit = parse_junit_xml(xml_text)
            if junit is None:
                # Directory-based runners (Maven Surefire) write one report file per
                # test class into a judge-owned dir derived as ``<report>.d``.
                junit = parse_junit_dir(host_xml + ".d")
            passed, score, tests_passed, tests_total = grade_repo_run(
                r.returncode, junit, report_expected=report_expected
            )
            tampered = detect_tamper(r.returncode, junit, report_expected=report_expected)
            output = r.stdout + "\n" + r.stderr
            combined_junit = xml_text
            verdict_source = "junit+exit" if junit is not None else "exit"
            pack_tests_passed: int | None = None
            pack_tests_total: int | None = None

            # A copied pack is not evidence that its checks ran. Execute it as a
            # separate mandatory phase, explicitly addressed by path, then
            # compose both outcomes. This works even when the repo command is
            # narrowed (for example ``pytest tests/``) or is a custom command.
            if pack_dir:
                assert pack_snapshot is not None and pack_identity is not None
                try:
                    verify_pack_snapshot(pack_snapshot, pack_identity)
                except PackManifestError as exc:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"verifier pack was changed before execution: {exc}",
                        artifact={
                            "files_changed": changed,
                            "outcome": "pack_snapshot_changed",
                            "tamper": True,
                            "verifier_pack_sha256": pack_sha256,
                            "verifier_pack_manifest": pack_manifest,
                            "setup_isolation": setup_isolation,
                        },
                    )
                pack_phase = os.path.join(workdir, "pack-phase")
                os.makedirs(pack_phase, exist_ok=True)
                pack_cmd = [
                    "python" if container_mode else sys.executable,
                    "-m", "pytest", "-q", "--color=no", "-p", "no:cacheprovider",
                    "/verifier-pack" if container_mode else pack_snapshot,
                ]
                try:
                    if container_mode:
                        pack_xml, pack_run, pack_report_expected = self._run_docker(
                            pack_cmd, copy, pack_phase, pack_dir=pack_snapshot
                        )
                    else:
                        pack_xml = os.path.join(pack_phase, "judge-result.xml")
                        instrumented, pack_report_expected, pack_report_env = (
                            instrument_command(pack_cmd, pack_xml)
                        )
                        pack_run = subprocess.run(
                            instrumented,
                            cwd=copy,
                            capture_output=True,
                            text=True,
                            timeout=self.timeout,
                            env={**env, **pack_report_env},
                            preexec_fn=self._limits() if os.name == "posix" else None,
                        )
                except subprocess.TimeoutExpired:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"verifier pack timed out after {self.timeout}s",
                        artifact={
                            "files_changed": changed,
                            "outcome": "test_timeout",
                            "setup_isolation": setup_isolation,
                        },
                    )
                except FileNotFoundError:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics="verifier pack needs pytest/python in the judge environment",
                        artifact={
                            "files_changed": changed,
                            "outcome": "test_command_unavailable",
                            "setup_isolation": setup_isolation,
                        },
                    )
                if container_mode and pack_run.returncode == 125:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=(
                            f"the {self.isolation} verifier-pack container could not "
                            "be started (docker exit 125): "
                            + distill_diagnostics(pack_run.stdout + "\n" + pack_run.stderr)
                        ),
                        artifact={
                            "files_changed": changed,
                            "outcome": "isolation_unavailable",
                            "setup_isolation": setup_isolation,
                        },
                    )
                try:
                    verify_pack_snapshot(pack_snapshot, pack_identity)
                except PackManifestError as exc:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"verifier pack changed while executing: {exc}",
                        artifact={
                            "files_changed": changed,
                            "outcome": "pack_snapshot_changed",
                            "tamper": True,
                            "verifier_pack_sha256": pack_sha256,
                            "verifier_pack_manifest": pack_manifest,
                            "setup_isolation": setup_isolation,
                        },
                    )
                assert candidate_runtime_baseline is not None
                try:
                    candidate_after_pack = _setup_fidelity_snapshot(
                        copy,
                        self.setup_output_globs,
                        baseline=candidate_runtime_baseline,
                    )
                except SetupFidelityError as exc:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"candidate fidelity verification failed: {exc}",
                        artifact={
                            "files_changed": changed,
                            "outcome": "candidate_tree_changed",
                            "tamper": True,
                            "setup_isolation": setup_isolation,
                        },
                    )
                candidate_changes = _setup_fidelity_changes(
                    candidate_runtime_baseline, candidate_after_pack
                )
                if candidate_changes:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=(
                            "verifier-pack execution modified the candidate tree: "
                            + ", ".join(candidate_changes[:20])
                        ),
                        artifact={
                            "files_changed": changed,
                            "outcome": "candidate_tree_changed",
                            "tamper": True,
                            "candidate_fidelity_changes": candidate_changes,
                            "verifier_pack_sha256": pack_sha256,
                            "verifier_pack_manifest": pack_manifest,
                            "setup_isolation": setup_isolation,
                        },
                    )
                pack_xml_text = _read_text_or_none(pack_xml) or ""
                pack_junit = parse_junit_xml(pack_xml_text)
                pack_passed, pack_score, pack_tests_passed, pack_tests_total = grade_repo_run(
                    pack_run.returncode,
                    pack_junit,
                    report_expected=pack_report_expected,
                )
                if not pack_tests_total:
                    pack_passed = False
                    pack_score = 0.0
                    output += "\nverifier pack collected zero tests"
                passed = passed and pack_passed
                score = min(score, pack_score)
                tampered = tampered or detect_tamper(
                    pack_run.returncode,
                    pack_junit,
                    report_expected=pack_report_expected,
                )
                tests_passed += pack_tests_passed or 0
                tests_total += pack_tests_total or 0
                output += "\n" + pack_run.stdout + "\n" + pack_run.stderr
                combined_junit = (
                    "repo\0" + xml_text + "\0verifier-pack\0" + pack_xml_text
                )
                verdict_source = "composite:repo+verifier-pack"

            return VerdictResult(
                passed=passed,
                score=score,
                diagnostics=distill_diagnostics(output),
                artifact={
                    "returncode": r.returncode,
                    "elapsed": elapsed,
                    "tests_passed": tests_passed,
                    "tests_total": tests_total,
                    "files_changed": changed,
                    "files_deleted": deleted_paths,
                    "verdict_source": verdict_source,
                    "tamper": tampered,
                    "junit_sha256": hashlib.sha256(
                        combined_junit.encode("utf-8")
                    ).hexdigest() if combined_junit else None,
                    "junit_digest_format": (
                        "EVOGUARD_JUNIT_COMPOSITE_V1"
                        if pack_dir
                        else "JUNIT_XML_SHA256"
                    ) if combined_junit else None,
                    "verifier_pack_sha256": pack_sha256,
                    "expected_verifier_pack_sha256": expected_pack_sha256 or None,
                    "verifier_pack_manifest": pack_manifest,
                    "verifier_pack_tests_passed": pack_tests_passed,
                    "verifier_pack_tests_total": pack_tests_total,
                    "setup_isolation": setup_isolation,
                    "setup_fidelity": "verified" if setup_cmd_raw else "not_applicable",
                    "candidate_fidelity": "verified" if pack_dir else "not_applicable",
                    "image_digest": resolved_image,
                    "isolation_evidence": {
                        "requested": self.isolation,
                        "delivered": self.isolation,
                        "image_digest": resolved_image,
                        "network": self.docker_network if container_mode else None,
                        "runtime": self.docker_runtime if container_mode else None,
                    } if container_mode else None,
                },
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
            if pack_workdir is not None:
                shutil.rmtree(pack_workdir, ignore_errors=True)
