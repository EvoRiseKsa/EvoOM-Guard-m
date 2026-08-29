#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Build and verify the Apache-2.0 core-only distribution (``evoom-guard-core``).

The umbrella ``evoom-guard`` distribution ships the whole tree under the
restrictive package-level license umbrella (see LICENSING.md).  This tool
produces the complementary consumer artifact: a wheel containing only the
Apache-2.0 core, suitable for PyPI, whose every shipped Python file carries
the Apache SPDX header and none carries the EvoRise source-available header.

The platform exclusion set is not duplicated here: it is parsed from
``tests/architecture/test_license_boundaries.py``, the same single source of
truth the import-boundary architecture test enforces.  If a new platform
module is added without being classified there, that test fails first; if it
is classified there, this tool excludes it automatically.

Stages:

1. stage    — copy ``evoom_guard/`` minus platform packages/modules/CLI owners
              into a staging tree with core packaging metadata.
2. audit    — every staged ``*.py`` must carry the Apache SPDX marker and must
              not carry the source-available marker (fail-closed drift check).
3. build    — ``pip wheel`` the staging tree into ``dist/core/``.
4. verify   — (``--verify``) fresh venv: install the wheel, prove the core
              surface works (version, imports, a real PASS and a real REJECTED
              guard verdict on a synthetic repo) and the platform surface is
              absent (imports fail; a platform command refuses with exit 2 and
              the documented message, never a traceback or a verdict).

This is packaging/verification tooling only.  It grants nothing: the Apache
license of the staged files is established by LICENSING.md and per-file
headers, not by this script.
"""

from __future__ import annotations

import argparse
import ast
import shutil
import subprocess
import sys
import tempfile
import venv
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BOUNDARIES = ROOT / "tests" / "architecture" / "test_license_boundaries.py"
DIST_DIR = ROOT / "dist" / "core"
APACHE_MARKER = "SPDX-License-Identifier: Apache-2.0"
PLATFORM_MARKER = "Source-available"
REFUSAL_MARKER = "not included in this installation"
CORE_DOCS = ("README.md", "LICENSE-APACHE", "LICENSING.md", "NOTICE")

CORE_PYPROJECT = """\
[build-system]
requires = ["setuptools>=64"]
build-backend = "setuptools.build_meta"

[project]
name = "evoom-guard-core"
description = "EvoOM Guard core (Apache-2.0): the evidence-bound verification gate that rejects test-harness tampering by untrusted changes."
readme = "README.md"
requires-python = ">=3.10"
authors = [{ name = "Mana Alharbi (\\u0645\\u0627\\u0646\\u0639 \\u0627\\u0644\\u062d\\u0631\\u0628\\u064a)" }]
maintainers = [{ name = "Mana Alharbi (\\u0645\\u0627\\u0646\\u0639 \\u0627\\u0644\\u062d\\u0631\\u0628\\u064a)" }]
keywords = ["ai", "agents", "ci", "testing", "reward-hacking", "patch", "verification"]
license = { text = "Apache-2.0" }
classifiers = [
    "License :: OSI Approved :: Apache Software License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Software Development :: Testing",
    "Topic :: Software Development :: Quality Assurance",
]
dependencies = []
dynamic = ["version"]

[project.urls]
Repository = "https://github.com/EvoRiseKsa/EvoOM-Guard-m"
Issues = "https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues"

[project.scripts]
evo-guard = "evoom_guard.cli:main"

[project.optional-dependencies]
sign = ["cryptography>=41"]
cov = ["coverage>=7"]

[tool.setuptools]
license-files = ["LICENSE-APACHE", "LICENSING.md", "NOTICE"]

[tool.setuptools.packages.find]
include = ["evoom_guard*"]

[tool.setuptools.package-data]
evoom_guard = ["schemas/*.json", "templates/**/*.json", "templates/**/*.yml"]

[tool.setuptools.dynamic]
version = { attr = "evoom_guard.__version__" }
"""


class CoreBuildError(RuntimeError):
    """The core distribution cannot be built or verified as specified."""


def _fail(message: str) -> None:
    raise CoreBuildError(message)


def platform_exclusions() -> tuple[frozenset[str], frozenset[str]]:
    """Parse (package names, module names) from the boundary test constants."""

    tree = ast.parse(BOUNDARIES.read_text(encoding="utf-8"))
    found: dict[str, frozenset[str]] = {}
    wanted = {"PLATFORM_PACKAGES", "PLATFORM_FLAT_MODULES", "PLATFORM_CLI_OWNERS"}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id not in wanted:
            continue
        value = node.value
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "frozenset"
            and len(value.args) == 1
        ):
            value = value.args[0]
        found[target.id] = frozenset(ast.literal_eval(value))
    missing = wanted - found.keys()
    if missing:
        _fail(f"boundary constants not found in {BOUNDARIES}: {sorted(missing)}")
    packages = found["PLATFORM_PACKAGES"]
    modules = found["PLATFORM_FLAT_MODULES"] | found["PLATFORM_CLI_OWNERS"]
    return packages, modules


def _module_relpath(dotted: str, *, package: bool) -> Path:
    parts = dotted.split(".")
    if parts[0] != "evoom_guard":
        _fail(f"unexpected platform module outside evoom_guard: {dotted}")
    relative = Path(*parts)
    return relative if package else relative.with_suffix(".py")


def stage(staging: Path) -> Path:
    packages, modules = platform_exclusions()
    package_root = staging / "evoom_guard"
    shutil.copytree(
        ROOT / "evoom_guard",
        package_root,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    for dotted in sorted(packages):
        target = staging / _module_relpath(dotted, package=True)
        if not target.is_dir():
            _fail(f"platform package missing from source tree: {dotted}")
        shutil.rmtree(target)
    for dotted in sorted(modules):
        target = staging / _module_relpath(dotted, package=False)
        if not target.is_file():
            _fail(f"platform module missing from source tree: {dotted}")
        target.unlink()
    for name in CORE_DOCS:
        shutil.copy2(ROOT / name, staging / name)
    (staging / "pyproject.toml").write_text(CORE_PYPROJECT, encoding="utf-8")
    return staging


def audit(staging: Path) -> int:
    audited = 0
    for path in sorted((staging / "evoom_guard").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(staging)
        if APACHE_MARKER not in text:
            _fail(f"staged file lacks the Apache SPDX header: {relative}")
        if PLATFORM_MARKER in text[:600]:
            _fail(f"staged file carries a source-available header: {relative}")
        audited += 1
    if audited < 50:
        _fail(f"implausibly small core staging tree ({audited} modules)")
    return audited


def build(staging: Path) -> Path:
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(DIST_DIR),
            str(staging),
        ],
        check=True,
    )
    wheels = sorted(DIST_DIR.glob("evoom_guard_core-*.whl"))
    if len(wheels) != 1:
        _fail(f"expected exactly one core wheel in {DIST_DIR}, found {len(wheels)}")
    return wheels[0]


def audit_wheel(wheel: Path) -> None:
    packages, modules = platform_exclusions()
    banned = {_module_relpath(d, package=True).as_posix() + "/" for d in packages}
    banned |= {_module_relpath(d, package=False).as_posix() for d in modules}
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
    for name in names:
        for entry in banned:
            if name == entry or name.startswith(entry):
                _fail(f"platform path leaked into the core wheel: {name}")
    for required in (
        "evoom_guard/cli/__init__.py",
        "evoom_guard/guard.py",
        "evoom_guard/verifiers/junit_oracle.py",
        "evoom_guard/runners/pytest.py",
        "evoom_guard/schemas/",
    ):
        if not any(name.startswith(required) for name in names):
            _fail(f"expected core path missing from the wheel: {required}")


def _run(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=600)


def _must(condition: bool, message: str, completed: subprocess.CompletedProcess[str]) -> None:
    if not condition:
        _fail(f"{message}\nrc={completed.returncode}\nstdout={completed.stdout}\nstderr={completed.stderr}")


def verify(wheel: Path, work: Path) -> None:
    # Every venv command runs from ``work``: a neutral directory that contains
    # no ``evoom_guard/`` tree, so imports resolve against site-packages (the
    # installed wheel) and never against the repository working tree.
    work.mkdir(parents=True, exist_ok=True)
    env_dir = work / "coreenv"
    venv.EnvBuilder(with_pip=True).create(env_dir)
    bin_dir = env_dir / ("Scripts" if sys.platform == "win32" else "bin")
    py = str(bin_dir / "python")
    guard = str(bin_dir / "evo-guard")
    install = _run([py, "-m", "pip", "install", "--quiet", str(wheel), "pytest"], cwd=work)
    _must(install.returncode == 0, "core wheel failed to install", install)

    version = _run([guard, "version"], cwd=work)
    _must(version.returncode == 0, "evo-guard version failed", version)

    core_import = _run([py, "-c", "import evoom_guard.cli, evoom_guard.guard"], cwd=work)
    _must(core_import.returncode == 0, "core imports failed", core_import)

    for absent in ("evoom_guard.finalizer", "evoom_guard.admission",
                   "evoom_guard.trusted_finalizer",
                   "evoom_guard.cli.evidence_sealing_commands"):
        leak = _run([py, "-c", f"import {absent}"], cwd=work)
        _must(leak.returncode != 0, f"platform module importable in core install: {absent}", leak)

    refusal = _run(
        [guard, "bundle-evidence", "--out", "o.json", "--context", "ctx",
         "--sign-key", "k.pem", "v.json"],
        cwd=work,
    )
    _must(refusal.returncode == 2, "platform command did not refuse with exit 2", refusal)
    _must(REFUSAL_MARKER in refusal.stdout, "refusal message missing", refusal)
    _must("Traceback" not in refusal.stderr, "refusal leaked a traceback", refusal)

    repo = work / "smoke-repo"
    repo.mkdir()
    (repo / "mod.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (repo / "test_mod.py").write_text(
        "import mod\n\n\ndef test_add():\n    assert mod.add(2, 3) == 5\n",
        encoding="utf-8",
    )
    git = ["git", "-c", "user.name=core-smoke", "-c", "user.email=core@example.invalid"]
    for command in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "base"]):
        completed = _run([*git, *command], cwd=repo)
        _must(completed.returncode == 0, f"git {command[0]} failed", completed)

    # ``--diff`` mode expects the working tree at the HEAD (candidate-applied)
    # state; the gate reverse-applies the diff to reconstruct the base. So each
    # scenario applies its change, leaves it applied, and diffs against HEAD.
    (repo / "mod.py").write_text(
        "def add(a, b):\n    return a + b\n\n\ndef sub(a, b):\n    return a - b\n",
        encoding="utf-8",
    )
    honest = _run([*git, "diff"], cwd=repo)
    (work / "honest.diff").write_text(honest.stdout, encoding="utf-8")
    passed = _run(
        [guard, "guard", str(repo), "--diff", str(work / "honest.diff"),
         "--test-command", f"{py} -m pytest -q", "--no-config"],
        cwd=work,
    )
    _must(passed.returncode == 0 and "**PASS**" in passed.stdout,
          "honest change did not PASS in the core install", passed)

    reset = _run([*git, "checkout", "--", "."], cwd=repo)
    _must(reset.returncode == 0, "git checkout failed", reset)
    (repo / "test_mod.py").write_text(
        "import mod\n\n\ndef test_add():\n    assert True\n", encoding="utf-8"
    )
    tamper = _run([*git, "diff"], cwd=repo)
    (work / "tamper.diff").write_text(tamper.stdout, encoding="utf-8")
    rejected = _run(
        [guard, "guard", str(repo), "--diff", str(work / "tamper.diff"),
         "--test-command", f"{py} -m pytest -q", "--no-config"],
        cwd=work,
    )
    _must(rejected.returncode != 0 and "**REJECTED**" in rejected.stdout,
          "harness tampering was not REJECTED in the core install", rejected)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--verify", action="store_true",
                        help="after building, install into a fresh venv and run the acceptance matrix")
    parser.add_argument("--keep-staging", action="store_true",
                        help="print and keep the staging directory for inspection")
    args = parser.parse_args(argv)

    temp = Path(tempfile.mkdtemp(prefix="evoom-guard-core-"))
    try:
        staging = stage(temp / "staging")
        audited = audit(staging)
        wheel = build(staging)
        audit_wheel(wheel)
        print(f"core wheel built: {wheel} ({audited} Apache-audited modules)")
        if args.verify:
            verify(wheel, temp / "verify")
            print("core wheel verified: install, version, imports, platform refusal, "
                  "PASS and REJECTED verdicts all as specified")
        return 0
    finally:
        if args.keep_staging:
            print(f"staging kept at: {temp}")
        else:
            shutil.rmtree(temp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
