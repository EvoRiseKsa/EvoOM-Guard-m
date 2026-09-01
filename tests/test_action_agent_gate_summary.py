# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Characterize the bounded GitHub Action Agent Gate summary."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ACTION = Path(__file__).parents[1] / "action.yml"
START = "        # BEGIN AGENT_GATE_SUMMARY_PY\n"
END = "        # END AGENT_GATE_SUMMARY_PY\n"


def _summary_program() -> str:
    text = ACTION.read_text(encoding="utf-8")
    start = text.index(START) + len(START)
    end = text.index(END, start)
    return textwrap.dedent(text[start:end])


def _render_summary(
    tmp_path: Path,
    *,
    record: dict[str, object] | None,
    verdict: str = "ERROR",
    origin: str = "",
    setup_code: str = "",
    setup_message: str = "",
    raw_receipt: bytes | None = None,
    require_receipt: bool = True,
    guard_code: int | None = None,
    receipt_directory: bool = False,
) -> tuple[str, Path]:
    receipt = tmp_path / "guard.json"
    if receipt_directory:
        assert raw_receipt is None and record is None
        receipt.mkdir()
    elif raw_receipt is not None:
        assert record is None
        receipt.write_bytes(raw_receipt)
    elif record is not None:
        record_verdict = record.get("verdict")
        complete_record: dict[str, object] = {
            "schema_version": "1.12",
            "tool": "evoguard",
            "tool_version": "4.7.0",
            "verdict": record_verdict,
            "passed": record_verdict == "PASS",
            "exit_code": 0 if record_verdict == "PASS" else 1,
            "reason_code": "fixture",
            "reason": "fixture",
            "assurance": {},
            "attestation": None,
        }
        complete_record.update(record)
        receipt.write_text(
            json.dumps(complete_record, ensure_ascii=False),
            encoding="utf-8",
            newline="\n",
        )
    if guard_code is None:
        guard_code = 0 if verdict == "PASS" else 1
        if record is not None and record.get("verdict") == "PASS":
            guard_code = 0
        if not require_receipt:
            guard_code = -1
    summary = tmp_path / "summary.md"
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-",
            str(receipt),
            str(summary),
            "a" * 40,
            origin,
            verdict,
            setup_code,
            setup_message,
            str(tmp_path / "receipt.sha256"),
            str(require_receipt).lower(),
            str(guard_code),
        ],
        input=_summary_program(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return summary.read_text(encoding="utf-8"), receipt


@pytest.mark.parametrize(
    "verdict, badge",
    [
        ("PASS", "✅"),
        ("REJECTED", "⛔"),
        ("FAIL", "❌"),
        ("TAMPERED", "🚨"),
        ("ERROR", "⚠️"),
    ],
)
def test_summary_preserves_all_five_verdicts(
    tmp_path: Path,
    verdict: str,
    badge: str,
) -> None:
    summary, _ = _render_summary(
        tmp_path,
        record={"verdict": verdict, "reason_code": "fixture", "reason": "fixture"},
    )

    assert f"## EvoOM Agent Gate — {badge} {verdict}" in summary
    assert f"| Verdict | **{verdict}** |" in summary


def test_summary_surfaces_bounded_evidence_without_overclaiming(
    tmp_path: Path,
) -> None:
    record: dict[str, object] = {
        "verdict": "PASS",
        "reason_code": "tests_passed",
        "reason": "accepted | <judge>\nsecond line",
        "assurance": {
            "report_integrity": "same_process_candidate_writable",
            "candidate_isolation": "subprocess",
            "verifier_pack": {"snapshot_sha256": "e" * 64},
        },
        "attestation": {
            "head_sha": "b" * 40,
            "candidate_sha256": "c" * 64,
            "policy_sha256": "d" * 64,
        },
    }
    summary, receipt = _render_summary(
        tmp_path,
        record=record,
        origin="codex | <script>alert(1)</script>",
    )
    receipt_sha256 = hashlib.sha256(receipt.read_bytes()).hexdigest()

    assert f"| Candidate commit | <code>{'b' * 40}</code> |" in summary
    assert f"| Candidate change digest | <code>{'c' * 64}</code> |" in summary
    assert f"| Policy SHA-256 | <code>{'d' * 64}</code> |" in summary
    assert (
        "| Report integrity | <code>same_process_candidate_writable</code> |"
        in summary
    )
    assert "| Candidate isolation | <code>subprocess</code> |" in summary
    assert f"| Verifier pack SHA-256 | <code>{'e' * 64}</code> |" in summary
    assert "| Agent origin status | <code>DECLARED_UNVERIFIED</code> |" in summary
    assert "codex &#124; &lt;script&gt;alert(1)&lt;/script&gt;" in summary
    assert "<strong>accepted &#124; &lt;judge&gt; second line</strong>" in summary
    assert "<script>" not in summary
    assert f"| Receipt SHA-256 | <code>{receipt_sha256}</code> |" in summary
    assert "| Receipt parser | <code>strict_json_accepted</code> |" in summary
    assert (tmp_path / "receipt.sha256").read_text(encoding="ascii").strip() == (
        receipt_sha256
    )
    assert (tmp_path / "receipt.verdict").read_text(encoding="ascii").strip() == (
        "PASS"
    )
    assert (tmp_path / "receipt.policy").read_text(encoding="ascii").strip() == (
        "d" * 64
    )
    assert "byte digest only; sign/finalize in a separate trusted lane" in summary
    assert "or proof of independent judgment" in summary
    assert "Judge integrity" not in summary


def test_summary_sidecars_are_exact_lf_bytes_for_git_bash(
    tmp_path: Path,
) -> None:
    record: dict[str, object] = {
        "verdict": "PASS",
        "attestation": {"policy_sha256": "d" * 64},
    }
    _, receipt = _render_summary(tmp_path, record=record, verdict="PASS")
    receipt_sha256 = hashlib.sha256(receipt.read_bytes()).hexdigest()

    assert (tmp_path / "receipt.verdict").read_bytes() == b"PASS\n"
    assert (tmp_path / "receipt.policy").read_bytes() == ("d" * 64 + "\n").encode(
        "ascii"
    )
    assert (tmp_path / "receipt.sha256").read_bytes() == (
        receipt_sha256 + "\n"
    ).encode("ascii")


def test_setup_error_summary_is_stable_without_a_receipt(tmp_path: Path) -> None:
    summary, _ = _render_summary(
        tmp_path,
        record=None,
        verdict="ERROR",
        setup_code="base_ref_unavailable",
        setup_message="base | missing\nretry",
        require_receipt=False,
    )

    assert "## EvoOM Agent Gate — ⚠️ ERROR" in summary
    assert "| Reason code | <code>base_ref_unavailable</code> |" in summary
    assert f"| Candidate commit | <code>{'a' * 40}</code> |" in summary
    assert "| JSON receipt | not emitted |" in summary
    assert "| Receipt parser | <code>not_emitted_for_setup_error</code> |" in summary
    assert "| Receipt SHA-256 | <code>not available</code> |" in summary
    assert "base &#124; missing retry" in summary


def test_setup_error_ignores_a_stale_pass_receipt(tmp_path: Path) -> None:
    summary, _ = _render_summary(
        tmp_path,
        record={"verdict": "PASS"},
        verdict="ERROR",
        setup_code="base_ref_unavailable",
        setup_message="current setup failed",
        require_receipt=False,
    )

    assert "## EvoOM Agent Gate — ⚠️ ERROR" in summary
    assert "| Reason code | <code>base_ref_unavailable</code> |" in summary
    assert "| JSON receipt | not emitted |" in summary
    assert not (tmp_path / "receipt.sha256").exists()


def test_malformed_verdict_fails_closed_in_the_summary(tmp_path: Path) -> None:
    summary, _ = _render_summary(
        tmp_path,
        record={"verdict": ["PASS"], "reason": "malformed verdict"},
        verdict="PASS",
    )

    assert "## EvoOM Agent Gate — ⚠️ ERROR" in summary
    assert "| Verdict | **ERROR** |" in summary
    assert (tmp_path / "receipt.verdict").read_text(encoding="ascii").strip() == (
        "ERROR"
    )


def test_missing_required_receipt_does_not_reuse_fallback_pass(tmp_path: Path) -> None:
    summary, _ = _render_summary(
        tmp_path,
        record=None,
        verdict="PASS",
        require_receipt=True,
    )

    assert "## EvoOM Agent Gate — ⚠️ ERROR" in summary
    assert "| Reason code | <code>receipt_not_emitted</code> |" in summary
    assert (tmp_path / "receipt.verdict").read_text(encoding="ascii").strip() == (
        "ERROR"
    )


def test_minimal_json_cannot_claim_a_pass_receipt(tmp_path: Path) -> None:
    summary, _ = _render_summary(
        tmp_path,
        record=None,
        raw_receipt=b'{"verdict":"PASS"}',
        verdict="PASS",
        guard_code=0,
    )

    assert "## EvoOM Agent Gate — ⚠️ ERROR" in summary
    assert "receipt_semantic_envelope_invalid" in summary
    assert not (tmp_path / "receipt.sha256").exists()


def test_pass_receipt_cannot_disagree_with_guard_exit(tmp_path: Path) -> None:
    summary, _ = _render_summary(
        tmp_path,
        record={"verdict": "PASS"},
        verdict="PASS",
        guard_code=1,
    )

    assert "## EvoOM Agent Gate — ⚠️ ERROR" in summary
    assert "receipt_semantic_envelope_invalid" in summary


def test_nonpass_receipt_cannot_disagree_with_guard_exit(tmp_path: Path) -> None:
    summary, _ = _render_summary(
        tmp_path,
        record={"verdict": "FAIL"},
        verdict="FAIL",
        guard_code=2,
    )

    assert "## EvoOM Agent Gate — ⚠️ ERROR" in summary
    assert "receipt_semantic_envelope_invalid" in summary


def test_receipt_display_fields_are_bounded_without_changing_byte_digest(
    tmp_path: Path,
) -> None:
    reason = "x" * (2 * 1024 * 1024)
    summary, receipt = _render_summary(
        tmp_path,
        record={
            "verdict": "FAIL",
            "reason": reason,
            "reason_code": "failure",
            "assurance": {
                "report_integrity": "y" * 4096,
                "candidate_isolation": "z" * 4096,
            },
        },
        verdict="FAIL",
        guard_code=1,
    )

    assert len(summary.encode("utf-8")) < 16 * 1024
    assert summary.count("[truncated; sha256=") == 3
    receipt_digest = hashlib.sha256(receipt.read_bytes()).hexdigest()
    assert f"<code>{receipt_digest}</code>" in summary


def test_non_regular_receipt_is_rejected(tmp_path: Path) -> None:
    summary, _ = _render_summary(
        tmp_path,
        record=None,
        receipt_directory=True,
    )

    assert "## EvoOM Agent Gate — ⚠️ ERROR" in summary
    assert "receipt_not_regular_file" in summary


@pytest.mark.parametrize(
    "origin",
    [
        "x" * 257,
        " codex",
        "codex ",
        "cafe\u0301",
        "codex\u202e",
        "codex\nforged",
    ],
)
def test_agent_origin_display_rejects_unbounded_or_ambiguous_text(
    tmp_path: Path,
    origin: str,
) -> None:
    summary, _ = _render_summary(
        tmp_path,
        record={"verdict": "PASS"},
        verdict="PASS",
        origin=origin,
    )

    assert (
        "| Declared agent origin | <code>invalid declaration rejected</code> |"
        in summary
    )


@pytest.mark.parametrize("constant", [b"NaN", b"Infinity", b"-Infinity", b"1e9999"])
def test_summary_rejects_nonfinite_json_numbers(
    tmp_path: Path,
    constant: bytes,
) -> None:
    raw = b'{"verdict":"PASS","risk_score":' + constant + b"}"
    summary, receipt = _render_summary(
        tmp_path,
        record=None,
        raw_receipt=raw,
        verdict="PASS",
    )

    assert receipt.is_file()
    assert "## EvoOM Agent Gate — ⚠️ ERROR" in summary
    assert "| Reason code | <code>receipt_json_invalid</code> |" in summary
    assert "| Receipt parser | <code>receipt_json_invalid</code> |" in summary
    assert not (tmp_path / "receipt.sha256").exists()
    assert (tmp_path / "receipt.verdict").read_text(encoding="ascii").strip() == (
        "ERROR"
    )


def test_summary_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    summary, _ = _render_summary(
        tmp_path,
        record=None,
        raw_receipt=b'{"verdict":"PASS","verdict":"ERROR"}',
        verdict="PASS",
    )

    assert "## EvoOM Agent Gate — ⚠️ ERROR" in summary
    assert "| Reason code | <code>receipt_json_invalid</code> |" in summary
    assert not (tmp_path / "receipt.sha256").exists()
    assert (tmp_path / "receipt.verdict").read_text(encoding="ascii").strip() == (
        "ERROR"
    )


def test_summary_checks_receipt_size_before_bounded_read(tmp_path: Path) -> None:
    limit = 8 * 1024 * 1024
    summary, receipt = _render_summary(
        tmp_path,
        record=None,
        raw_receipt=b" " * (limit + 1),
        verdict="PASS",
    )

    assert receipt.stat().st_size == limit + 1
    assert "## EvoOM Agent Gate — ⚠️ ERROR" in summary
    assert "| Reason code | <code>receipt_size_limit_exceeded</code> |" in summary
    assert "| Receipt parser | <code>receipt_size_limit_exceeded</code> |" in summary
    assert not (tmp_path / "receipt.sha256").exists()
    assert (tmp_path / "receipt.verdict").read_text(encoding="ascii").strip() == (
        "ERROR"
    )


def test_action_exposes_only_bounded_origin_and_receipt_metadata() -> None:
    text = ACTION.read_text(encoding="utf-8")
    origin = text[text.index("\n  agent-origin:") : text.index("\n  isolation:")]
    receipt = text[text.index("\n  receipt-sha256:") : text.index("\nruns:")]

    assert "display-only" in origin
    assert "DECLARED_UNVERIFIED" in origin
    assert "never shapes the verdict" in origin
    assert "not a signature or provenance attestation" in receipt
    assert "MAX_RECEIPT_BYTES = 8 * 1024 * 1024" in text
    assert "object_pairs_hook=unique_object" in text
    assert "parse_constant=reject_constant" in text
    assert 'write_agent_gate_summary "ERROR" "" "" "true" "$GUARD_CODE"' in text
    assert 'VERDICT="$STRICT_VERDICT"' in text
    assert 'json.load(open(sys.argv[1]' not in text
    assert "receipt_path.lstat()" in text
    assert 'getattr(os, "O_NOFOLLOW", 0)' in text
    assert 'getattr(os, "O_NONBLOCK", 0)' in text
    assert 'getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024)' in text
    assert '"st_reparse_tag"' in text
    assert "os.fstat(handle.fileno())" in text
    assert "rm -f --" in text
    assert '"$RUNNER_TEMP/guard.json"' in text
    assert "INPUT_AGENT_ORIGIN: ${{ inputs.agent-origin }}" in text
    assert text.count("INPUT_AGENT_ORIGIN") == 2
    assert "--agent-origin" not in text
    assert 'echo "receipt-sha256=$RECEIPT_SHA256" >> "$GITHUB_OUTPUT"' in text
