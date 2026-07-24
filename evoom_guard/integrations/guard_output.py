# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available - see LICENSE for permitted use.
# Original creator: Mana Alharbi.
# -----------------------------------------------------------------------------
"""Markdown, JSON, and SARIF publication for a Guard result.

This high-level integration owns only projections and destination writes.  It
does not decide verdicts, execute candidate code, or reinterpret evidence.  The
historical :mod:`evoom_guard.guard` functions remain compatibility facades and
retain their public signatures. Publication hardening deliberately does not
preserve incidental module-global lookup timing.
"""

from __future__ import annotations

import json
import math
import os
import stat
import tempfile
import unicodedata
from collections.abc import Callable, Mapping
from typing import Any, Protocol, TextIO, cast
from urllib.parse import quote


class GuardResultView(Protocol):
    """Structural result surface required by output projections."""

    verdict: str
    passed: bool
    reason: str
    files_changed: list[str]
    protected_violations: list[str]
    risk_level: str
    risk_score: float
    tests_passed: int | None
    tests_total: int | None
    verdict_source: str | None
    diagnostics: str
    source: str | None
    base_reconstruction: str | None
    reason_code: str
    isolation: str
    diff_coverage: dict[str, Any] | None
    baseline: dict[str, Any] | None
    attestation: dict[str, Any] | None
    assurance: dict[str, Any] | None
    test_command_ran: bool | None
    execution_state: str
    execution_phase: str

    def to_dict(self) -> dict[str, Any]:
        """Return the versioned machine record owned by the producer."""


BadgeProvider = Callable[[], Mapping[str, str]]
ValueProvider = Callable[[], str]
SarifConverter = Callable[[GuardResultView], dict[str, Any]]
JsonDump = Callable[..., None]
TextWriter = Callable[[TextIO], object]


class OutputDestinationError(RuntimeError):
    """An output path cannot safely receive an atomic publication."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


class SarifArtifactPathError(ValueError):
    """A result path cannot be represented as a repository SARIF URI."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


DEFAULT_BADGES: Mapping[str, str] = {
    "PASS": "✅ PASS",
    "REJECTED": "⛔ REJECTED",
    "FAIL": "❌ FAIL",
    "ERROR": "⚠️ ERROR",
    "TAMPERED": "🚨 TAMPERED",
}


def _constant(value: str) -> ValueProvider:
    return lambda: value


def _default_badge_provider() -> Mapping[str, str]:
    return DEFAULT_BADGES


_PASS_PROVIDER = _constant("PASS")
_FAIL_PROVIDER = _constant("FAIL")
_ERROR_PROVIDER = _constant("ERROR")
_TAMPERED_PROVIDER = _constant("TAMPERED")
_STATIC_GATE_PROVIDER = _constant("static_gate")
_NOT_STARTED_PROVIDER = _constant("not_started")
_STARTED_INCOMPLETE_PROVIDER = _constant("started_incomplete")


def _is_unsafe_control(character: str) -> bool:
    """Whether a character can alter terminal/UI direction or structure."""

    return unicodedata.category(character) in {"Cc", "Cf"}


def _visible_inline_text(value: object, *, markdown: bool) -> str:
    """Return one visible line without losing attacker-controlled facts."""

    rendered: list[str] = []
    markdown_special = frozenset("\\`*_[]")
    for character in str(value):
        if character == "\n":
            rendered.append("\\n")
        elif character == "\r":
            rendered.append("\\r")
        elif character == "\t":
            rendered.append("\\t")
        elif _is_unsafe_control(character):
            rendered.append(f"\\u{ord(character):04x}")
        elif markdown and character == "&":
            rendered.append("&amp;")
        elif markdown and character in markdown_special:
            rendered.append("\\" + character)
        elif markdown and character == "<":
            rendered.append("&lt;")
        elif markdown and character == ">":
            rendered.append("&gt;")
        else:
            rendered.append(character)
    return "".join(rendered)


def _markdown_text(value: object) -> str:
    """Escape untrusted text for an inline Markdown context."""

    return _visible_inline_text(value, markdown=True)


def _markdown_table_text(value: object) -> str:
    """Escape untrusted text for a Markdown table cell."""

    return _markdown_text(value).replace("|", "\\|")


def _markdown_code(value: object) -> str:
    """Render an untrusted value as a non-breakable inline code span."""

    text = _visible_inline_text(value, markdown=False)
    if "`" not in text:
        return f"`{text}`"
    longest = current = 0
    for character in text:
        current = current + 1 if character == "`" else 0
        longest = max(longest, current)
    fence = "`" * (longest + 1)
    return f"{fence} {text} {fence}"


def _markdown_table_code(value: object) -> str:
    """Render inline code without letting a pipe terminate its table cell."""

    return _markdown_code(value).replace("|", "\\|")


def _markdown_fenced_code(value: object) -> str:
    """Render diagnostics under a fence longer than every embedded run."""

    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    visible: list[str] = []
    for character in text:
        if character in {"\n", "\t"}:
            visible.append(character)
        elif _is_unsafe_control(character):
            visible.append(f"\\u{ord(character):04x}")
        else:
            visible.append(character)
    safe = "".join(visible)
    longest = current = 0
    for character in safe:
        current = current + 1 if character == "`" else 0
        longest = max(longest, current)
    fence = "`" * max(3, longest + 1)
    return f"{fence}\n{safe}\n{fence}"


def _require_nonnegative_int(value: object, *, field: str) -> int:
    """Return one evidence count without invoking an arbitrary formatter."""

    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _require_positive_int(value: object, *, field: str) -> int:
    """Return one one-based source line number."""

    line = _require_nonnegative_int(value, field=field)
    if line == 0:
        raise ValueError(f"{field} must be a positive integer")
    return line


def _require_percent(value: object, *, field: str) -> int | float:
    """Return one finite percentage in the closed interval [0, 100]."""

    if type(value) not in {int, float}:
        raise ValueError(f"{field} must be a finite number from 0 to 100")
    numeric = cast(int | float, value)
    if not math.isfinite(numeric) or not 0 <= numeric <= 100:
        raise ValueError(f"{field} must be a finite number from 0 to 100")
    return numeric


def _validated_missed_lines(diff_coverage: Mapping[str, Any]) -> dict[str, list[int]]:
    """Validate the dynamic changed-line evidence before Markdown projection."""

    raw_files = diff_coverage.get("files", {})
    if not isinstance(raw_files, Mapping):
        raise ValueError("diff_coverage.files must be an object")
    missed: dict[str, list[int]] = {}
    for path, raw_details in raw_files.items():
        if not isinstance(path, str):
            raise ValueError("diff_coverage.files keys must be strings")
        if not isinstance(raw_details, Mapping):
            raise ValueError(
                f"diff_coverage.files[{path!r}] must be an object"
            )
        raw_lines = raw_details.get("missed", [])
        if not isinstance(raw_lines, list):
            raise ValueError(
                f"diff_coverage.files[{path!r}].missed must be an array"
            )
        lines = [
            _require_positive_int(
                line,
                field=f"diff_coverage.files[{path!r}].missed",
            )
            for line in raw_lines
        ]
        if lines:
            missed[path] = lines
    return missed


def _windows_destination_error(path: str) -> tuple[str, str] | None:
    """Classify device names and namespaces before Windows path resolution."""

    normalized = path.replace("\\", "/")
    lowered = normalized.casefold()
    if (
        lowered.startswith("//?/")
        or lowered.startswith("//./")
        or lowered.startswith("/??/")
        or lowered.startswith("//?/globalroot/")
    ):
        return (
            "windows_namespace",
            "Windows device and extended-length namespaces are not output paths",
        )

    components = [component for component in normalized.split("/") if component]
    for index, component in enumerate(components):
        if index == 0 and len(component) == 2 and component[1] == ":":
            continue
        if ":" in component:
            return (
                "windows_namespace",
                "Windows alternate streams and device namespaces are not output paths",
            )
        canonical = component.rstrip(" .")
        stem = canonical.split(".", 1)[0].upper()
        if stem in {"CON", "PRN", "AUX", "NUL", "COM", "LPT"} or (
            len(stem) == 4
            and stem[:3] in {"COM", "LPT"}
            and stem[3] in "123456789"
        ):
            return (
                "windows_reserved_name",
                "Windows reserved device names are not output paths",
            )
    return None


def _validate_output_destination(
    path: str,
    *,
    platform_name: str = os.name,
) -> int | None:
    """Reject unsafe existing leaves and return portable mode bits."""

    if platform_name == "nt":
        destination_error = _windows_destination_error(path)
        if destination_error is not None:
            raise OutputDestinationError(*destination_error)
    try:
        observed = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(observed.st_mode):
        raise OutputDestinationError(
            "non_regular",
            "an existing output destination must be a regular file",
        )
    mode = stat.S_IMODE(observed.st_mode) & 0o777
    if mode & 0o222 == 0:
        raise OutputDestinationError(
            "read_only",
            "an existing output destination has no write mode bit",
        )
    return mode


def _add_exception_note(primary: BaseException, note: str) -> None:
    """Attach secondary failure context where the runtime supports notes."""

    add_note = getattr(primary, "add_note", None)
    if callable(add_note):
        add_note(note)


def _cleanup_atomic_temp(
    descriptor: int,
    temp_path: str,
    primary: BaseException,
) -> None:
    """Best-effort exact-file cleanup without masking the primary failure."""

    cleanup_failures: list[OSError] = []
    if descriptor >= 0:
        try:
            os.close(descriptor)
        except OSError as exc:
            cleanup_failures.append(exc)
    try:
        os.unlink(temp_path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        cleanup_failures.append(exc)
    for failure in cleanup_failures:
        _add_exception_note(
            primary,
            f"atomic output cleanup failed: {failure}",
        )


def _atomic_write(path: str, writer: TextWriter) -> None:
    """Commit one UTF-8 text file only after an fsynced temporary write.

    The temporary file is created exclusively in the destination directory.
    Existing non-regular and read-only leaves are rejected before staging and
    again immediately before replacement. Portable mode bits are carried from
    an existing regular destination. The parent directory must be trusted and
    quiescent; this function does not fsync it or claim crash/NFS durability.
    """

    initial_mode = _validate_output_destination(path)
    destination_path = os.path.abspath(path)
    if destination_path != path:
        absolute_mode = _validate_output_destination(destination_path)
        if initial_mode is None:
            initial_mode = absolute_mode
    directory = os.path.dirname(destination_path)
    descriptor, temp_path = tempfile.mkstemp(
        prefix=".evoguard-output-",
        suffix=".tmp",
        dir=directory,
    )
    try:
        stream = os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline=None,
        )
        primary: BaseException | None = None
        try:
            writer(stream)
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException as exc:
            primary = exc
        try:
            stream.close()
        except BaseException as close_failure:
            if primary is None:
                primary = close_failure
            else:
                _add_exception_note(
                    primary,
                    f"atomic output close failed: {close_failure}",
                )
        else:
            descriptor = -1
        if primary is not None:
            raise primary.with_traceback(primary.__traceback__)

        current_mode = _validate_output_destination(destination_path)
        replacement_mode = (
            current_mode if current_mode is not None else initial_mode
        )
        if replacement_mode is not None:
            os.chmod(temp_path, replacement_mode)
        os.replace(temp_path, destination_path)
    except BaseException as primary:
        _cleanup_atomic_temp(descriptor, temp_path, primary)
        raise


def write_markdown(report: str, path: str) -> None:
    """Atomically publish an already-rendered Markdown report."""

    _atomic_write(path, lambda destination: destination.write(report))


def _normalize_sarif_artifact_uri(path: str) -> str:
    """Return a canonical repository-relative URI or reject ambiguity."""

    if type(path) is not str:
        raise SarifArtifactPathError(
            "not_text",
            "SARIF artifact path must be text",
        )
    if any(unicodedata.category(character) == "Cs" for character in path):
        raise SarifArtifactPathError(
            "surrogate",
            "SARIF artifact path contains a Unicode surrogate",
        )
    if any(_is_unsafe_control(character) for character in path):
        raise SarifArtifactPathError(
            "control_or_format",
            "SARIF artifact path contains a control or format character",
        )
    if "\\" in path:
        raise SarifArtifactPathError(
            "backslash",
            "SARIF artifact path must use forward slashes",
        )
    if len(path) >= 2 and path[0].isalpha() and path[1] == ":":
        raise SarifArtifactPathError(
            "drive_prefix",
            "SARIF artifact path must not have a drive prefix",
        )
    segments = path.split("/")
    if (
        not path
        or path.startswith("/")
        or any(segment in {"", ".", ".."} for segment in segments)
    ):
        raise SarifArtifactPathError(
            "not_repository_relative",
            "SARIF artifact path must be normalized and repository-relative",
        )
    return quote(path, safe="/-._~")


def render_report(
    result: GuardResultView,
    *,
    deleted: list[str] | None = None,
    title: str = "EvoGuard",
    badge_provider: BadgeProvider = _default_badge_provider,
    pass_verdict_provider: ValueProvider = _PASS_PROVIDER,
    fail_verdict_provider: ValueProvider = _FAIL_PROVIDER,
    error_verdict_provider: ValueProvider = _ERROR_PROVIDER,
    tampered_verdict_provider: ValueProvider = _TAMPERED_PROVIDER,
    static_gate_provider: ValueProvider = _STATIC_GATE_PROVIDER,
    not_started_provider: ValueProvider = _NOT_STARTED_PROVIDER,
    started_incomplete_provider: ValueProvider = _STARTED_INCOMPLETE_PROVIDER,
) -> str:
    """Render a result as a Markdown report suitable for a PR comment."""

    r = result
    tests = (
        f"{r.tests_passed}/{r.tests_total}"
        if r.tests_total is not None else "—"
    )
    badge = badge_provider().get(r.verdict, r.verdict)
    lines = [
        f"## {_markdown_text(title)} — {_markdown_text(badge)}",
        "",
        f"**{_markdown_text(r.reason)}**",
        "",
        "| | |",
        "|---|---|",
        f"| Verdict | **{_markdown_table_text(r.verdict)}** |",
        f"| Tests passed | {tests} |",
        f"| Files changed | {len(r.files_changed)} |",
        f"| Blast radius | **{_markdown_table_text(r.risk_level)}** "
        f"({r.risk_score:.2f}) |",
        f"| Execution | {_markdown_table_code(r.execution_state)} · "
        f"phase {_markdown_table_code(r.execution_phase)} |",
        f"| Test command started | {'yes' if r.test_command_ran else 'no'} |",
        f"| Verdict source | "
        f"{_markdown_table_text(r.verdict_source or '—')} |",
    ]
    if r.source:
        lines.append(f"| Input | {_markdown_table_text(r.source)} |")
    if r.base_reconstruction:
        lines.append(
            f"| Base reconstruction | "
            f"{_markdown_table_text(r.base_reconstruction)} |"
        )
    if r.diff_coverage is not None:
        dc = r.diff_coverage
        if dc.get("measured"):
            executed = _require_nonnegative_int(
                dc.get("executed"),
                field="diff_coverage.executed",
            )
            total = _require_nonnegative_int(
                dc.get("total"),
                field="diff_coverage.total",
            )
            percent = _require_percent(
                dc.get("percent"),
                field="diff_coverage.percent",
            )
            if executed > total:
                raise ValueError(
                    "diff_coverage.executed must not exceed "
                    "diff_coverage.total"
                )
            lines.append(
                f"| Changed lines executed | {executed}/{total} "
                f"({percent}%) |"
            )
        else:
            lines.append(
                "| Changed lines executed | not measured — "
                f"{_markdown_table_text(dc.get('note', ''))} |"
            )
    if r.baseline is not None:
        b = r.baseline
        raw_baseline_total = b.get("tests_total")
        raw_baseline_passed = b.get("tests_passed")
        if raw_baseline_total is None:
            if raw_baseline_passed is not None:
                raise ValueError(
                    "baseline.tests_passed requires baseline.tests_total"
                )
            btests = ""
        else:
            baseline_total = _require_nonnegative_int(
                raw_baseline_total,
                field="baseline.tests_total",
            )
            baseline_passed = _require_nonnegative_int(
                raw_baseline_passed,
                field="baseline.tests_passed",
            )
            if baseline_passed > baseline_total:
                raise ValueError(
                    "baseline.tests_passed must not exceed "
                    "baseline.tests_total"
                )
            btests = f" ({baseline_passed}/{baseline_total})"
        bverdict = b.get("verdict") or "not measured"
        lines.append(
            "| Baseline (pristine base) | "
            f"{_markdown_table_text(bverdict)}{btests} |"
        )
        lines.append(
            f"| Repair effect | "
            f"**{_markdown_table_text(b.get('repair_effect'))}** |"
        )
    if r.attestation and r.attestation.get("policy_id"):
        pv = r.attestation.get("policy_version")
        lines.append(
            f"| Policy | {_markdown_table_code(r.attestation['policy_id'])}"
            + (
                f" v{_markdown_table_text(pv)}"
                if pv else ""
            )
            + " |"
        )
    if r.attestation and r.attestation.get("verifier_pack_sha256"):
        lines.append(
            "| Verifier pack | "
            f"{_markdown_table_code(str(r.attestation['verifier_pack_sha256'])[:12] + '…')} |"
        )
    if r.assurance:
        a = r.assurance
        lines.append(
            f"| Assurance | harness {_markdown_table_code(a['harness_integrity'])} · "
            f"report {_markdown_table_code(a['report_integrity'])} · "
            f"isolation {_markdown_table_code(a['candidate_isolation'])} |"
        )
    if (
        r.verdict == pass_verdict_provider()
        and r.assurance
        and r.assurance.get("report_integrity") == "same_process_candidate_writable"
    ):
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
            *[f"- {_markdown_code(path)}" for path in r.protected_violations],
            "",
            "A patch must fix the **source under test**, never the tests or their "
            "configuration. This is rejected before the suite runs.",
        ]
    if r.diff_coverage is not None and r.diff_coverage.get("measured"):
        missed = _validated_missed_lines(r.diff_coverage)
        if missed:
            lines += [
                "",
                "<details><summary>Changed lines the suite never executed</summary>",
                "",
                *[
                    f"- {_markdown_code(path)}: lines "
                    f"{', '.join(map(str, line_numbers))}"
                    for path, line_numbers in sorted(missed.items())
                ],
                "",
                f"<sub>{_markdown_text(r.diff_coverage.get('caveat', ''))}</sub>",
                "</details>",
            ]
    if deleted:
        lines += [
            "",
            "> Note: these files were **deleted** in head and applied to the verified "
            "tree (a deletion of a test/config/CI/auto-exec file is instead "
            "**REJECTED**): "
            + ", ".join(_markdown_code(path) for path in deleted),
        ]
    if r.files_changed and not r.protected_violations:
        shown = ", ".join(
            _markdown_code(path) for path in r.files_changed[:15]
        )
        more = "" if len(r.files_changed) <= 15 else f" (+{len(r.files_changed) - 15} more)"
        lines += ["", f"<details><summary>Files changed</summary>\n\n{shown}{more}\n</details>"]
    if r.verdict == tampered_verdict_provider():
        lines += [
            "",
            "### 🚨 Tamper signature: exit code ⟷ JUnit report disagree",
            "",
            "The process exit code and the judge-owned JUnit report — the two signals "
            "the candidate cannot forge via stdout — **disagree**. This is treated as "
            "tampering and is never read as a pass.",
        ]
    if r.diagnostics and r.verdict in (
        fail_verdict_provider(),
        error_verdict_provider(),
        tampered_verdict_provider(),
    ):
        diag = r.diagnostics.strip()[:1200]
        lines += [
            "",
            "<details><summary>Diagnostics</summary>\n",
            _markdown_fenced_code(diag),
            "</details>",
        ]
    judge = {
        "docker": "in a network-less, read-only container (defence in depth — but a "
                  "container shares the host kernel, so not a complete boundary)",
        "gvisor": "in a network-less container under the gVisor (runsc) runtime — a "
                  "separate user-space guest kernel (for untrusted code)",
    }.get(
        r.isolation,
        "in a subprocess with rlimits + a timeout — fine for trusted repos, not a "
        "sandbox for untrusted code; isolate it further (--isolation docker|gvisor) for that",
    )
    if r.execution_state == static_gate_provider():
        execution_note = (
            "EvoGuard decided this result from the pre-execution diff gate; the "
            "suite was not started, so no test command, JUnit report, or runtime "
            "isolation was delivered."
        )
    elif r.execution_state == not_started_provider():
        execution_note = (
            "Runtime verification stopped before any test command started "
            f"(furthest phase: {_markdown_text(r.execution_phase)}); "
            "no suite/report isolation "
            "is claimed."
        )
    elif r.execution_state == started_incomplete_provider():
        execution_note = (
            "A verification command started but the required execution sequence "
            "did not complete (furthest phase: "
            f"{_markdown_text(r.execution_phase)}); therefore "
            "there is no clean verdict source."
        )
    else:
        execution_note = (
            "EvoGuard reads the verdict from a judge-owned JUnit report + the "
            "process exit code (not stdout), and rejects any edit to the tests or "
            f"their config. The judge runs the suite {judge}."
        )
    lines += [
        "",
        f"<sub>{execution_note} See docs/GUARD.md.</sub>",
    ]
    return "\n".join(lines)


def write_json(
    result: GuardResultView,
    path: str,
    *,
    deleted: list[str] | None = None,
    json_dump: JsonDump = json.dump,
) -> None:
    """Atomically write the producer-owned record without reinterpreting it."""

    payload = result.to_dict()
    if deleted:
        payload["deleted"] = deleted
    _atomic_write(
        path,
        lambda destination: json_dump(payload, destination, indent=2),
    )


def to_sarif(
    result: GuardResultView,
    *,
    pass_verdict_provider: ValueProvider = _PASS_PROVIDER,
    version_provider: ValueProvider,
) -> dict[str, Any]:
    """Render one result as a minimal SARIF 2.1.0 view."""

    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    if result.verdict != pass_verdict_provider():
        rule_id = result.reason_code or result.verdict.lower()
        located = result.protected_violations or result.files_changed
        locations = [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": _normalize_sarif_artifact_uri(path)
                    }
                }
            }
            for path in located
            if path
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
                        "version": version_provider(),
                        "informationUri": "https://github.com/EvoRiseKsa/EvoOM-Guard-m",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(
    result: GuardResultView,
    path: str,
    *,
    converter: SarifConverter,
    json_dump: JsonDump = json.dump,
) -> None:
    """Convert SARIF completely, then commit it through the atomic writer."""

    payload = converter(result)
    _atomic_write(
        path,
        lambda destination: json_dump(payload, destination, indent=2),
    )
