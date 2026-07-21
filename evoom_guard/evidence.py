# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Changed-line coverage evidence (the first non-test evidence source).

A suite can be green without ever *executing* the lines a patch changed — the
change is then simply unverified, however green the check looks. This module
answers one narrow question, as evidence rather than as a verdict:

    Of the lines this candidate changed, which did the suite actually execute?

Honesty contract (printed with the evidence, never dropped):

  * "executed" is NOT "asserted" — a test can run a line and check nothing
    about it. Executed-changed-lines is a *floor* of scrutiny, not a proof of
    correctness. (Mutation-on-diff, the follow-up evidence source, targets the
    asserted question.)
  * The collector and candidate execute in the same Python process. Candidate
    code can access ``Coverage.current()``, stop tracing, or mutate the in-memory
    ``CoverageData``. Isolated startup and an empty rcfile prevent repository
    module/config shadowing; they do NOT authenticate runtime coverage data.
    Treat this as a quality signal for non-hostile code, never as adversarial
    integrity evidence.
  * Only Python files are measured (``coverage.py``); changed lines in other
    languages are reported as unmeasured, not silently counted.
  * Non-executable changed lines (comments, blank lines, docstrings) are
    excluded using token/AST source classification. A changed physical code
    line needs direct coverage evidence to count as executed; source exclusion
    pragmas and unknown/continuation lines count as missed, never as a smaller
    denominator.

The measurement runs the suite ONE extra time in its own throwaway copy with
``coverage run`` wrapping the same pytest invocation, and reads a judge-owned
``coverage json`` written outside stdout. The import/configuration path is
judge-controlled, but the runtime coverage state remains candidate-writable.
It is opt-in (``--diff-coverage``) because it doubles suite runtime, and it
needs ``coverage`` importable by the isolated judge interpreter (the ``cov``
extra); when unavailable it degrades to an explicit "not measured".
The optional evidence request remains non-gating, while
``min_diff_coverage`` treats an unavailable measurement as an unmet required
assurance rather than as a silent pass.
"""

from __future__ import annotations

import ast
import difflib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import tokenize
from typing import Any

from evoom_guard.execution import (
    ProcessContainmentError as _SubprocessContainmentError,
)
from evoom_guard.execution import (
    ProcessOutputLimitExceeded as _SubprocessOutputLimitExceeded,
)
from evoom_guard.execution import (
    run_bounded_subprocess as _run_bounded_subprocess,
)
from evoom_guard.patch_applier import PatchError, apply_patch
from evoom_guard.verifiers.repo_verifier import (
    RepoVerifier,
    SetupFidelityError,
    apply_blocks_to_copy,
    copy_repo_tree,
    is_safe_relpath,
    judge_subprocess_env,
    parse_file_blocks,
    parse_patch_blocks,
    resolve_host_command,
    setup_fidelity_changes,
    setup_fidelity_snapshot,
)
from evoom_guard.workspace import UnsafeWorkspacePath, delete_path_within_root

# The honesty line shipped inside every measurement (report + JSON).
EXECUTED_IS_NOT_ASSERTED = (
    "executed is not asserted, and same-process coverage data is "
    "candidate-writable: candidate code can stop or mutate the collector. "
    "This is a quality/scrutiny signal for non-hostile code, not adversarial "
    "integrity evidence or proof of correctness"
)

# ``coverage json`` is written outside the candidate tree, but the test process
# can still try to replace or grow it through the judge's scratch directory.
# Coverage evidence is optional; refusing a pathological report is safer than
# allowing an unbounded evidence-only allocation.
_MAX_COVERAGE_REPORT_BYTES = 16 * 1024 * 1024

# Import the installed coverage package while isolated mode still excludes the
# candidate working directory. Only after that trusted import succeeds do we
# add the repository root for pytest/project imports. ``coverage`` remains
# pinned in ``sys.modules`` and cannot be replaced by ``coverage.py`` or a
# ``coverage/`` package from the candidate copy. This protects collector
# selection/configuration only. Candidate imports execute in the collector
# process and can still obtain/mutate its live CoverageData.
_TRUSTED_COVERAGE_LAUNCHER = (
    "import os, sys; "
    "from coverage.cmdline import main as coverage_main; "
    "sys.path.insert(0, os.getcwd()); "
    "raise SystemExit(coverage_main())"
)


def _coverage_file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    """The regular-file facts that must not change while a report is read."""
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_coverage_files(path: str) -> dict[str, Any] | None:
    """Return bounded ``coverage json`` file data, or no evidence.

    The path is judge-selected but candidate-influenced at runtime. Reject
    symlinks/special files and enforce the byte cap before decoding so a report
    cannot turn an opt-in coverage measurement into a host-memory allocation.
    """
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_COVERAGE_REPORT_BYTES:
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_COVERAGE_REPORT_BYTES:
            return None
        raw = bytearray()
        while len(raw) <= _MAX_COVERAGE_REPORT_BYTES:
            chunk = os.read(fd, min(1024 * 1024, _MAX_COVERAGE_REPORT_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
    except OSError:
        return None
    finally:
        os.close(fd)
    if (
        len(raw) > _MAX_COVERAGE_REPORT_BYTES
        or _coverage_file_identity(before) != _coverage_file_identity(after)
    ):
        return None
    try:
        decoded = json.loads(bytes(raw).decode("utf-8"))
        files = decoded.get("files", {})
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return files if isinstance(files, dict) else None


def _normalize_coverage_report_path(
    measured_path: object,
    repo_root: str,
) -> str | None:
    """Map an in-repository coverage path to the candidate's POSIX contract.

    Coverage reports can include imported helpers outside the throwaway repo.
    Such entries are irrelevant to changed-repository-line evidence and must be
    ignored. In particular, ``relpath`` raises ``ValueError`` for another drive
    on Windows; that must degrade by skipping the external entry, not abort the
    Guard run before it can emit a record.
    """
    normalized = str(measured_path)
    try:
        if os.path.isabs(normalized):
            normalized = os.path.relpath(normalized, repo_root)
    except (OSError, ValueError):
        return None
    normalized = normalized.replace("\\", "/")
    return normalized if is_safe_relpath(normalized) else None


def _new_content_map(repo_path: str, candidate: str) -> dict[str, str | None]:
    """Post-apply content per changed path (``None`` when a PATCH fails to apply).

    Mirrors the verifier's application order: whole FILE blocks first, then the
    surgical PATCH blocks in document order (possibly stacking on a FILE block
    for the same path).
    """
    out: dict[str, str | None] = dict(parse_file_blocks(candidate))
    for pb in parse_patch_blocks(candidate):
        base = out.get(pb.path)
        if base is None:
            try:
                with open(os.path.join(repo_path, *pb.path.split("/")), encoding="utf-8") as f:
                    base = f.read()
            except OSError:
                out[pb.path] = None
                continue
        try:
            out[pb.path] = apply_patch(base, pb.search, pb.replace)
        except (PatchError, ValueError):
            out[pb.path] = None
    return out


def changed_lines(
    repo_path: str,
    candidate: str,
    *,
    file_blocks: dict[str, str] | None = None,
) -> dict[str, set[int]]:
    """``{path: {1-indexed line numbers changed/added in the NEW file}}``.

    Computed against the base file at ``repo_path`` with :mod:`difflib` — the
    same ground truth the risk scorer uses. Paths whose patches do not apply
    are omitted (the main verdict already surfaces that failure). Structured
    ``file_blocks`` are authoritative when supplied, so literal edit-block
    marker text inside a real file cannot truncate the coverage diff.
    """
    out: dict[str, set[int]] = {}
    content_map = (
        dict(file_blocks)
        if file_blocks is not None
        else _new_content_map(repo_path, candidate)
    )
    for path, new in content_map.items():
        if new is None or not is_safe_relpath(path):
            continue
        try:
            with open(os.path.join(repo_path, *path.split("/")), encoding="utf-8") as f:
                old_lines = f.read().splitlines()
        except OSError:
            old_lines = []
        new_lines = new.splitlines()
        touched: set[int] = set()
        matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
        for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
            if tag in ("replace", "insert"):
                touched.update(range(j1 + 1, j2 + 1))
        if touched:
            out[path] = touched
    return out


def _source_code_lines(source: str) -> set[int]:
    """Return physical code-token lines, excluding comments/blanks/docstrings.

    Coverage often reports only the first line of a multi-line statement. That
    does not prove every continuation/subexpression executed (short-circuiting
    is one counterexample), so this model deliberately classifies source only;
    the caller requires direct coverage evidence for an executed line.

    Tokenization failure is fail-closed: every physical source line is returned
    as potentially executable. A malformed, unimported Python file must not turn
    a required denominator into zero merely because the lexer stopped early.
    """
    source_lines = source.splitlines()
    docstring_spans: list[tuple[tuple[int, int], tuple[int, int]]] = []
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        tree = None
    if tree is not None:
        owners = [tree, *ast.walk(tree)]
        for owner in owners:
            body = getattr(owner, "body", None)
            if not isinstance(body, list) or not body:
                continue
            first = body[0]
            if not (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                continue

            def character_column(line_number: int, byte_column: int) -> int:
                line = source_lines[line_number - 1]
                return len(
                    line.encode("utf-8")[:byte_column].decode("utf-8", "ignore")
                )

            docstring_spans.append(
                (
                    (
                        first.lineno,
                        character_column(first.lineno, first.col_offset),
                    ),
                    (
                        getattr(first, "end_lineno", first.lineno),
                        character_column(
                            getattr(first, "end_lineno", first.lineno),
                            getattr(first, "end_col_offset", first.col_offset),
                        ),
                    ),
                )
            )

    ignored_tokens = {
        tokenize.COMMENT,
        tokenize.DEDENT,
        tokenize.ENDMARKER,
        tokenize.INDENT,
        tokenize.NEWLINE,
        tokenize.NL,
    }
    code_lines: set[int] = set()
    try:
        for item in tokenize.generate_tokens(io.StringIO(source).readline):
            if item.type in ignored_tokens:
                continue
            if item.type == tokenize.OP and item.string == ";":
                continue
            if any(
                start <= item.start and item.end <= end
                for start, end in docstring_spans
            ):
                continue
            code_lines.update(range(item.start[0], item.end[0] + 1))
    except (IndentationError, tokenize.TokenError):
        return set(range(1, len(source_lines) + 1))

    return code_lines


def _classify_touched_lines(
    source: str | None,
    touched: set[int],
    entry: dict[str, Any],
) -> tuple[list[int], list[int], bool]:
    """Classify changed physical code lines without trusting source exclusions."""
    executed_known = set(entry.get("executed_lines", []))
    excluded_known = set(entry.get("excluded_lines", []))
    if source is None:
        code_lines = set(touched)
    else:
        code_lines = _source_code_lines(source)

    executed: list[int] = []
    missed: list[int] = []
    source_exclusion_seen = False
    for line in sorted(touched & code_lines):
        if line in excluded_known:
            missed.append(line)
            source_exclusion_seen = True
        elif line in executed_known:
            executed.append(line)
        else:
            # Missing and unknown executable lines both fail conservatively.
            # In particular, execution of a multi-line statement's first line
            # does not prove a short-circuited continuation was evaluated.
            missed.append(line)
    return executed, missed, source_exclusion_seen


def _pytest_command_parts(
    cmd: list[str],
) -> tuple[list[str], str, list[str], list[str]] | None:
    """Return wrapper, interpreter, interpreter options, and pytest arguments."""
    pytest_names = {"pytest", "pytest.exe", "py.test", "py.test.exe"}

    def interpreter_token(token: object) -> bool:
        name = os.path.basename(str(token)).lower()
        return (
            name.startswith("python")
            or name.startswith("pypy")
            or name in {"py", "py.exe"}
        )

    module_parts: tuple[list[str], str, list[str], list[str]] | None = None
    module_command_index: int | None = None
    for module_index in range(len(cmd) - 1):
        if str(cmd[module_index]) != "-m" or (
            os.path.basename(str(cmd[module_index + 1])).lower()
            not in pytest_names
        ):
            continue
        interpreter_index = next(
            (
                index
                for index in range(module_index - 1, -1, -1)
                if interpreter_token(cmd[index])
            ),
            None,
        )
        if interpreter_index is None:
            continue
        module_parts = (
            [str(token) for token in cmd[:interpreter_index]],
            str(cmd[interpreter_index]),
            [str(token) for token in cmd[interpreter_index + 1 : module_index]],
            [str(token) for token in cmd[module_index + 2 :]],
        )
        module_command_index = interpreter_index
        break

    executable_index = next(
        (
            index
            for index, token in enumerate(cmd)
            if os.path.basename(str(token)).lower() in pytest_names
            and (index == 0 or str(cmd[index - 1]) != "-m")
        ),
        None,
    )
    # Prefer whichever command form appears first. This distinguishes
    # ``python -m pytest pytest`` from ``pytest -m pytest``: the latter's
    # ``-m pytest`` is a pytest marker expression, not another interpreter.
    if module_parts is not None and (
        executable_index is None
        or (
            module_command_index is not None
            and module_command_index <= executable_index
        )
    ):
        return module_parts
    if executable_index is None:
        return None
    prefix = [str(token) for token in cmd[:executable_index]]
    # A shell command string is not a token-preserving pytest invocation. Do
    # not rewrite a word that belongs to ``sh -c``/``cmd /c``/PowerShell.
    shell_switches = {"-c", "-lc", "/c", "-command", "-encodedcommand"}
    if any(token.lower() in shell_switches for token in prefix):
        return None

    explicit_pytest = str(cmd[executable_index])
    if executable_index == 0:
        if os.path.dirname(explicit_pytest):
            executable_name = "python.exe" if os.name == "nt" else "python"
            interpreter = os.path.join(
                os.path.dirname(explicit_pytest), executable_name
            )
        else:
            interpreter = sys.executable
    else:
        interpreter = "python"
    return (
        prefix,
        interpreter,
        [],
        [str(token) for token in cmd[executable_index + 1 :]],
    )


def _coverage_wrap(cmd: list[str], data_file: str) -> list[str] | None:
    """Build a judge-owned coverage command; return ``None`` for non-pytest suites.

    Isolated mode prevents the candidate working directory and user site from
    shadowing the installed ``coverage`` package. An explicit empty rcfile also
    prevents repository-owned coverage settings from disabling or redirecting
    this judge measurement. Trusted interpreter/wrapper prefixes are preserved:
    ``venv/python -m pytest`` stays on that interpreter, and ``uv run pytest``
    becomes ``uv run python <isolated launcher>`` instead of silently switching
    environments.
    """
    parts = _pytest_command_parts(cmd)
    if parts is None:
        return None
    prefix, interpreter, interpreter_options, pytest_args = parts

    return [
        *prefix,
        interpreter,
        *interpreter_options,
        "-I",
        "-c",
        _TRUSTED_COVERAGE_LAUNCHER,
        "run",
        f"--rcfile={os.devnull}",
        f"--data-file={data_file}",
        "-m",
        "pytest",
        *pytest_args,
    ]


def _coverage_report_command(
    data_file: str,
    output_file: str,
    test_command: list[str] | None = None,
) -> list[str] | None:
    """Return an isolated report command in the run's selected environment."""
    if test_command is None:
        prefix: list[str] = []
        interpreter = sys.executable
        interpreter_options: list[str] = []
    else:
        parts = _pytest_command_parts(test_command)
        if parts is None:
            return None
        prefix, interpreter, interpreter_options, _pytest_args = parts
    return [
        *prefix,
        interpreter,
        *interpreter_options,
        "-I",
        "-c",
        _TRUSTED_COVERAGE_LAUNCHER,
        "json",
        f"--rcfile={os.devnull}",
        f"--data-file={data_file}",
        "-o",
        output_file,
        "-q",
    ]


def _judge_env(workdir: str) -> dict[str, str]:
    # Mirrors the verifier's restricted env (see RepoVerifier.verify).
    return judge_subprocess_env(workdir)


def _coverage_preexec(
    timeout: int,
    mem_limit_mb: int,
    *,
    platform: str | None = None,
) -> Any:
    """Return the same POSIX CPU/address-space limits used by the main suite."""
    if (os.name if platform is None else platform) != "posix":
        return None
    return RepoVerifier(timeout=timeout, mem_limit_mb=mem_limit_mb)._limits()


def _run_setup_for_coverage(
    copy: str,
    env: dict[str, str],
    setup_command: list[str],
    setup_output_globs: tuple[str, ...],
    *,
    timeout: int,
    preexec_fn: Any,
) -> str | None:
    """Replay a verified host setup in the coverage copy, or return a failure note."""
    try:
        before = setup_fidelity_snapshot(copy, setup_output_globs)
        command = resolve_host_command(list(setup_command), cwd=copy, env=env)
        completed = _run_bounded_subprocess(
            command,
            cwd=copy,
            env=env,
            timeout=timeout,
            preexec_fn=preexec_fn,
        )
        after = setup_fidelity_snapshot(
            copy, setup_output_globs, baseline=before
        )
    except _SubprocessOutputLimitExceeded:
        return "the coverage setup command output exceeded the judge capture limit"
    except _SubprocessContainmentError:
        return "the coverage setup command cleanup could not be proven"
    except SetupFidelityError as exc:
        return f"the coverage setup fidelity check failed: {exc}"
    except (OSError, subprocess.TimeoutExpired):
        return "the coverage setup command did not complete"
    if completed.returncode != 0:
        return f"the coverage setup command failed with exit {completed.returncode}"
    changes = setup_fidelity_changes(before, after)
    if changes:
        return (
            "the coverage setup command changed judged paths outside declared "
            "outputs: " + ", ".join(changes[:20])
        )
    return None


def collect_diff_coverage(
    repo_path: str,
    candidate: str,
    *,
    deleted: tuple[str, ...] = (),
    test_command: list[str] | None = None,
    setup_command: list[str] | None = None,
    setup_output_globs: tuple[str, ...] = (),
    timeout: int = 240,
    mem_limit_mb: int = 1024,
    file_blocks: dict[str, str] | None = None,
    require_passing_suite: bool = False,
) -> dict[str, Any]:
    """Measure changed-line coverage; always returns a dict with ``measured`` set.

    ``measured: False`` results carry a ``note`` naming the exact reason
    (coverage missing, non-pytest runner, nothing changed in Python files, the
    wrapped run failing) — explicit degradation, never a silent number.
    ``require_passing_suite`` is used by the threshold gate: partial coverage
    from a coverage-wrapped pytest failure cannot authorize a required floor.
    When the main judgment used ``setup_command``, the same setup is replayed
    under the same fidelity/output policy before the coverage-wrapped suite.
    """
    all_changed_lines = changed_lines(
        repo_path, candidate, file_blocks=file_blocks
    )
    lines_map = {p: s for p, s in all_changed_lines.items() if p.endswith(".py")}
    non_py = sorted(p for p in all_changed_lines if not p.endswith(".py"))
    new_contents = (
        dict(file_blocks)
        if file_blocks is not None
        else _new_content_map(repo_path, candidate)
    )
    base: dict[str, Any] = {
        "measured": False,
        "note": "",
        "unmeasured_files": non_py,
        "caveat": EXECUTED_IS_NOT_ASSERTED,
    }
    if not lines_map:
        base["note"] = "no changed Python lines to measure"
        return base
    cmd = (
        list(test_command)
        if test_command
        else [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--color=no",
            "-p",
            "no:cacheprovider",
        ]
    )
    workdir = tempfile.mkdtemp(prefix="evo_guard_cov_")
    try:
        data_file = os.path.join(workdir, "judge-coverage.db")
        wrapped = _coverage_wrap(cmd, data_file)
        if wrapped is None:
            base["note"] = "changed-line coverage currently supports pytest commands only"
            return base

        copy = os.path.join(workdir, "repo")
        copy_repo_tree(repo_path, copy)
        apply_error = apply_blocks_to_copy(
            copy,
            file_blocks if file_blocks else parse_file_blocks(candidate),
            [] if file_blocks else parse_patch_blocks(candidate),
        )
        if apply_error is not None:
            base["note"] = "candidate did not apply for the coverage run"
            return base
        try:
            for rel in deleted:
                if not is_safe_relpath(rel):
                    continue
                delete_path_within_root(copy, rel)
        except (OSError, UnsafeWorkspacePath) as exc:
            base["note"] = f"candidate deletion could not be applied safely: {exc}"
            return base

        env = _judge_env(workdir)
        preexec_fn = _coverage_preexec(timeout, mem_limit_mb)
        if setup_command:
            setup_failure = _run_setup_for_coverage(
                copy,
                env,
                setup_command,
                setup_output_globs,
                timeout=timeout,
                preexec_fn=preexec_fn,
            )
            if setup_failure is not None:
                base["note"] = setup_failure
                return base
        try:
            coverage_run = _run_bounded_subprocess(
                wrapped,
                cwd=copy,
                env=env,
                timeout=timeout,
                preexec_fn=preexec_fn,
            )
        except _SubprocessOutputLimitExceeded:
            base["note"] = "the coverage-wrapped suite output exceeded the judge capture limit"
            return base
        except _SubprocessContainmentError:
            base["note"] = "the coverage-wrapped suite cleanup could not be proven"
            return base
        except (OSError, subprocess.TimeoutExpired):
            base["note"] = "the coverage-wrapped suite run did not complete"
            return base
        if coverage_run.returncode != 0 and require_passing_suite:
            base["note"] = (
                "the required isolated coverage-wrapped pytest run did not pass — install "
                "the 'cov' extra in the judge interpreter and verify the suite "
                "under coverage"
            )
            return base

        cov_json = os.path.join(workdir, "judge-coverage.json")
        try:
            report_command = _coverage_report_command(data_file, cov_json, cmd)
            if report_command is None:
                base["note"] = "the pytest environment could not generate a coverage report"
                return base
            r = _run_bounded_subprocess(
                report_command,
                cwd=copy,
                env=env,
                timeout=60,
                preexec_fn=preexec_fn,
            )
        except _SubprocessOutputLimitExceeded:
            base["note"] = "the coverage report command output exceeded the judge capture limit"
            return base
        except _SubprocessContainmentError:
            base["note"] = "the coverage report command cleanup could not be proven"
            return base
        except (OSError, subprocess.TimeoutExpired):
            base["note"] = "the coverage report command did not complete"
            return base
        if r.returncode != 0 or not os.path.exists(cov_json):
            base["note"] = "coverage produced no report (suite may not have started)"
            return base
        raw_files = _read_coverage_files(cov_json)
        if raw_files is None:
            base["note"] = "coverage report was unavailable or exceeded the judge size limit"
            return base
        # coverage.py emits platform-native path separators (and may emit
        # absolute paths depending on its config). The candidate contract is
        # always repo-relative POSIX-style paths, so normalize before lookup.
        files = {}
        for measured_path, entry in raw_files.items():
            if not isinstance(entry, dict):
                continue
            normalized = _normalize_coverage_report_path(measured_path, copy)
            if normalized is not None:
                files[normalized] = entry
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    per_file: dict[str, Any] = {}
    executed_total = 0
    measurable_total = 0
    for path, touched in sorted(lines_map.items()):
        entry = files.get(path)
        if entry is None:
            # Never imported during the run: source classification can still
            # remove comments/blanks/docstrings, but every physical code line
            # remains conservatively missed.
            executed, missed, _ = _classify_touched_lines(
                new_contents.get(path), touched, {}
            )
            per_file[path] = {
                "executed": executed,
                "missed": missed,
                "note": (
                    "file never imported by the suite "
                    "(executable changed lines shown)"
                ),
            }
            executed_total += len(executed)
            measurable_total += len(executed) + len(missed)
            continue
        executed, missed, source_exclusion_seen = _classify_touched_lines(
            new_contents.get(path), touched, entry
        )
        detail: dict[str, Any] = {"executed": executed, "missed": missed}
        if source_exclusion_seen:
            detail["note"] = (
                "changed statements excluded by source pragmas are counted as missed"
            )
        per_file[path] = detail
        executed_total += len(executed)
        measurable_total += len(executed) + len(missed)

    percent = round(100.0 * executed_total / measurable_total, 1) if measurable_total else 100.0
    return {
        "measured": True,
        "percent": percent,
        "executed": executed_total,
        "total": measurable_total,
        "files": per_file,
        "unmeasured_files": non_py,
        "caveat": EXECUTED_IS_NOT_ASSERTED,
    }
