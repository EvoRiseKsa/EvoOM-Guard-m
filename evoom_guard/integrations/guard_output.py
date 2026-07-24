# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available - see LICENSE for permitted use.
# Original creator: Mana Alharbi.
# -----------------------------------------------------------------------------
"""Markdown, JSON, and SARIF publication for a Guard result.

This high-level integration owns only projections and destination writes.  It
does not decide verdicts, execute candidate code, or reinterpret evidence.  The
historical :mod:`evoom_guard.guard` functions remain compatibility facades and
inject their live wire constants, JSON dumper, and SARIF converter at the
original lookup positions.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any, Protocol


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
JsonDump = Callable[..., Any]
JsonDumpProvider = Callable[[], JsonDump]

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


def _default_json_dump_provider() -> JsonDump:
    return json.dump


_PASS_PROVIDER = _constant("PASS")
_FAIL_PROVIDER = _constant("FAIL")
_ERROR_PROVIDER = _constant("ERROR")
_TAMPERED_PROVIDER = _constant("TAMPERED")
_STATIC_GATE_PROVIDER = _constant("static_gate")
_NOT_STARTED_PROVIDER = _constant("not_started")
_STARTED_INCOMPLETE_PROVIDER = _constant("started_incomplete")


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
    lines = [
        f"## {title} — {badge_provider().get(r.verdict, r.verdict)}",
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
        lines += ["", "<details><summary>Diagnostics</summary>\n", "```", diag, "```", "</details>"]
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
            f"(furthest phase: {r.execution_phase}); no suite/report isolation "
            "is claimed."
        )
    elif r.execution_state == started_incomplete_provider():
        execution_note = (
            "A verification command started but the required execution sequence "
            f"did not complete (furthest phase: {r.execution_phase}); therefore "
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
    json_dump_provider: JsonDumpProvider = _default_json_dump_provider,
) -> None:
    """Write the producer-owned JSON record without reinterpreting it."""

    payload = result.to_dict()
    if deleted:
        payload["deleted"] = deleted
    with open(path, "w", encoding="utf-8") as destination:
        json_dump_provider()(payload, destination, indent=2)


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
            {"physicalLocation": {"artifactLocation": {"uri": path}}}
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
    json_dump_provider: JsonDumpProvider = _default_json_dump_provider,
) -> None:
    """Write SARIF while resolving the injected converter after destination open."""

    with open(path, "w", encoding="utf-8") as destination:
        json_dump_provider()(converter(result), destination, indent=2)
