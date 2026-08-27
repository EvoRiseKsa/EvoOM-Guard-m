#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Runnable end-to-end demo of the blind independent-evaluation protocol.

This drives the real three-phase protocol in ``tools/evaluation/blind_protocol.py``
(``commit-labels`` → ``freeze-predictions`` → ``score-reveal``) against a small
worked corpus, so anyone can *see the whole protocol compose* in one command and
then adapt it with their own held-out corpus and keys::

    python -m tools.evaluation.blind_eval_demo --out-dir ./blind-eval-demo-out

It generates three cryptographically distinct Ed25519 role keys (label authority,
verdict finalizer, execution freezer), a five-case example manifest that exercises
every outcome cell (true/false accept-block plus an abstention), signs a verdict
per case, runs all three phases, and prints the resulting confusion matrix with
Wilson 95% intervals for both the gate and the ordinary-CI baseline.

**What this demo IS:** proof the protocol runs end to end, and an exact,
copy-adaptable template of every file format each phase consumes and emits.

**What this demo is NOT:** an independent evaluation. Independence comes from
*who* runs it, not from the code. In a real round (see
``docs/INDEPENDENT_EVALUATION.md``):

* an external **label authority** — not the product team — chooses and labels a
  held-out, multi-project, multi-ecosystem corpus and keeps the labels + salt
  secret until after the freeze;
* an external **execution authority** runs the audited gate to produce a signed
  verdict per case (via a Trusted Finalizer for untrusted candidate code), and
  freezes the predictions before any label is revealed;
* the three keys are held by organizationally separate parties.

This demo stands in for those parties with local keys and a canned corpus purely
to exercise the byte/relation integrity the tool enforces; it deliberately reuses
two committed reference verdict records (``tests/baseline/v4.0.1/evidence``) rather
than re-running the gate, exactly as the protocol's own test fixture does, because
signing is (correctly) refused for untrusted profiles outside a Trusted Finalizer.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from evoom_guard.policy import effective_policy_sha256
from evoom_guard.signing import generate_keypair, sign_bytes
from tools.evaluation.blind_protocol import (
    commit_labels,
    freeze_predictions,
    score_reveal,
)

_ROOT = Path(__file__).resolve().parents[2]
_BASELINE_RECORDS = _ROOT / "tests" / "baseline" / "v4.0.1" / "evidence"
_PASS_CANDIDATE_SHA256 = "e12f32b54c5d0d671849574807d2157e5b6c2b47e596cf69eb52096f90d59409"
_FAIL_CANDIDATE_SHA256 = "76b2b97b6d21e9a6ca6ac44635a8a4dc38945c2eaad1d7be332cf880a470bc72"

# A worked five-case corpus. Each row is (case id, ecosystem, truth, the gate
# verdict the case's signed record carries, baseline exit code | None). Together
# they populate every confusion cell plus an abstention, so the demo report shows
# a full matrix rather than a single number.
_CORPUS: list[tuple[str, str, str, str | None, int | None]] = [
    ("attack-blocked", "python", "block", "FAIL", 1),      # true positive
    ("attack-missed", "node", "block", "PASS", 1),         # false negative (gate accepted an attack)
    ("legitimate-accepted", "java", "accept", "PASS", 0),  # true negative
    ("legitimate-blocked", "go", "accept", "FAIL", 0),     # false positive (gate blocked a legit change)
    ("attack-abstained", "rust", "block", None, None),     # no verdict — runner timed out
]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, ensure_ascii=False), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")


def _build_inputs(out: Path) -> dict[str, Path]:
    """Materialise every protocol input into ``out`` and return their paths."""

    case_root = out / "case-bundles"
    case_root.mkdir(parents=True)
    verdict_dir = out / "verdicts"
    verdict_dir.mkdir()

    # Two committed reference verdict records, re-stamped to schema 1.12 under the
    # local profile — the same construction the protocol's test fixture uses.
    pass_record = json.loads((_BASELINE_RECORDS / "record-pass-repo.json").read_text("utf-8"))
    fail_record = json.loads((_BASELINE_RECORDS / "record-fail-repo.json").read_text("utf-8"))
    effective_policy = pass_record["attestation"]["effective_policy"]
    effective_policy["operating_profile"] = "local"
    policy_digest = effective_policy_sha256(effective_policy)
    for record in (pass_record, fail_record):
        record["schema_version"] = "1.12"
        record["attestation"]["effective_policy"] = effective_policy
        record["attestation"]["policy_sha256"] = policy_digest
    record_for_verdict = {"PASS": pass_record, "FAIL": fail_record}
    candidate_for_verdict = {"PASS": _PASS_CANDIDATE_SHA256, "FAIL": _FAIL_CANDIDATE_SHA256}

    # Three cryptographically distinct role keys.
    keys = {
        name: (out / f"{name}.pem", out / f"{name}.pub")
        for name in ("label-authority", "verdict-finalizer", "execution-freezer")
    }
    for priv, pub in keys.values():
        generate_keypair(str(priv), str(pub))

    cases: list[dict[str, object]] = []
    labels: list[dict[str, object]] = []
    predictions: list[dict[str, object]] = []
    for index, (case_id, ecosystem, truth, verdict, exit_code) in enumerate(_CORPUS):
        payload = f"opaque project bundle for {case_id}".encode()
        bundle_file = f"{case_id}.tar.zst"
        (case_root / bundle_file).write_bytes(payload)
        base_commit = f"{index + 1:040x}"
        head_commit = f"{index + 101:040x}"
        candidate_sha256 = (
            candidate_for_verdict[verdict]
            if verdict is not None
            else hashlib.sha256(f"timed-out candidate {case_id}".encode()).hexdigest()
        )
        cases.append({
            "id": case_id,
            "ecosystem": ecosystem,
            "source_repository": f"https://example.invalid/{case_id}",
            "base_commit": base_commit,
            "head_commit": head_commit,
            "candidate_sha256": candidate_sha256,
            "bundle_file": bundle_file,
            "bundle_sha256": hashlib.sha256(payload).hexdigest(),
        })
        labels.append({"id": case_id, "truth": truth})

        baseline_path = out / f"{case_id}-baseline.json"
        _write_json(baseline_path, {
            "schema_version": "evoguard-ordinary-ci-result-v2",
            "case_id": case_id,
            "case_bundle_sha256": hashlib.sha256(payload).hexdigest(),
            "command_sha256": hashlib.sha256(b"pytest -q").hexdigest(),
            "environment_sha256": hashlib.sha256(b"sanitized-env-v1").hexdigest(),
            "toolchain_sha256": hashlib.sha256(b"python-3.12").hexdigest(),
            "timeout_seconds": 300,
            "execution_binding_status": "declaration_not_runtime_attestation",
            "exit_code": exit_code,
            "execution_error_code": None if verdict is not None else "runner_timeout",
        })

        if verdict is None:
            predictions.append({
                "id": case_id,
                "verdict_file": None,
                "verdict_signature_file": None,
                "execution_error_code": "runner_timeout",
                "baseline_result_file": str(baseline_path),
            })
            continue

        record = json.loads(json.dumps(record_for_verdict[verdict]))
        record["attestation"]["base_sha"] = base_commit
        record["attestation"]["head_sha"] = head_commit
        verdict_path = verdict_dir / f"{case_id}.json"
        _write_json(verdict_path, record)
        signature_path = verdict_path.with_suffix(".json.sig")
        signature_path.write_bytes(
            base64.b64encode(sign_bytes(verdict_path.read_bytes(), str(keys["verdict-finalizer"][0]))) + b"\n"
        )
        predictions.append({
            "id": case_id,
            "verdict_file": str(verdict_path),
            "verdict_signature_file": str(signature_path),
            "execution_error_code": None,
            "baseline_result_file": str(baseline_path),
        })

    manifest = out / "cases.json"
    _write_json(manifest, {
        "schema_version": "evoguard-blind-case-manifest-v1",
        "evaluation_id": "demo-round-1",
        "cases": cases,
    })
    labels_path = out / "private-labels.jsonl"
    _write_jsonl(labels_path, labels)
    salt_path = out / "private-labels.salt"
    salt_path.write_bytes(hashlib.sha256(b"demo-salt-not-for-production").digest())
    predictions_path = out / "private-predictions.jsonl"
    _write_jsonl(predictions_path, predictions)
    policy_path = out / "effective-policy.json"
    _write_json(policy_path, effective_policy)
    # The gate artifact is only hashed for identity, never executed by the protocol.
    guard_artifact = out / "evo-guard.pyz"
    guard_artifact.write_bytes(b"demo guard artifact placeholder - build the real one with ops/build_pyz.py")

    return {
        "cases": manifest, "labels": labels_path, "salt": salt_path,
        "case_root": case_root, "predictions": predictions_path,
        "policy": policy_path, "guard_artifact": guard_artifact,
        "label_priv": keys["label-authority"][0], "label_pub": keys["label-authority"][1],
        "verdict_priv": keys["verdict-finalizer"][0], "verdict_pub": keys["verdict-finalizer"][1],
        "exec_priv": keys["execution-freezer"][0], "exec_pub": keys["execution-freezer"][1],
    }


def _run(out: Path) -> dict[str, Any]:
    p = _build_inputs(out)
    commitment = out / "public-label-commitment.json"
    commitment_sig = out / "public-label-commitment.json.sig"
    frozen = out / "frozen-predictions.json"
    frozen_sig = out / "frozen-predictions.json.sig"
    report = out / "score-report.json"

    print("  [1/3] commit-labels  - label authority signs a commitment to hidden labels")
    commit_labels(
        p["cases"], p["labels"], p["salt"], commitment,
        label_authority="Demo Independent Lab",
        conflict_disclosure="Demo only — no independence is claimed.",
        label_private_key_path=p["label_priv"], signature_output_path=commitment_sig,
    )
    print("  [2/3] freeze-predictions - execution authority binds the signed verdicts (labels still hidden)")
    freeze_predictions(
        p["cases"], commitment, commitment_sig, p["predictions"], p["case_root"],
        p["guard_artifact"], p["policy"], frozen,
        profile="local", baseline_id="ordinary-ci-exit-v1",
        execution_authority="Demo Execution Lab",
        label_public_key_path=p["label_pub"], verdict_public_key_path=p["verdict_pub"],
        execution_private_key_path=p["exec_priv"], signature_output_path=frozen_sig,
    )
    print("  [3/3] score-reveal   - labels revealed; scorer re-derives predictions and scores")
    result = score_reveal(
        p["cases"], commitment, commitment_sig, frozen, frozen_sig,
        p["exec_pub"], p["label_pub"], p["verdict_pub"], p["labels"], p["salt"], report,
    )
    return result


def _print_metrics(name: str, m: dict[str, Any]) -> None:
    print(f"\n  {name}:")
    print(f"    confusion   tp={m['tp']} fn={m['fn']} tn={m['tn']} fp={m['fp']} "
          f"abstain={m['abstain']} (block={m['abstain_block']}, accept={m['abstain_accept']})")
    print(f"    coverage    {m['coverage']}  (classified {m['classified']}/{m['total']})")
    print(f"    accuracy    {m['accuracy']}  95% CI [{m['accuracy_ci95_low']}, {m['accuracy_ci95_high']}]")
    print(f"    false-neg   {m['false_negative_rate']}  95% CI "
          f"[{m['false_negative_rate_ci95_low']}, {m['false_negative_rate_ci95_high']}]")
    print(f"    false-pos   {m['false_positive_rate']}  95% CI "
          f"[{m['false_positive_rate_ci95_low']}, {m['false_positive_rate_ci95_high']}]")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="End-to-end demo of the blind independent-evaluation protocol.")
    ap.add_argument("--out-dir", required=True, type=Path,
                    help="a fresh, EMPTY output directory (the protocol refuses to overwrite outputs)")
    args = ap.parse_args(argv)
    out: Path = args.out_dir
    if out.exists() and any(out.iterdir()):
        print(f"error: {out} is not empty — the protocol's outputs are create-only; use a fresh directory")
        return 2
    out.mkdir(parents=True, exist_ok=True)

    print(f"\nBlind independent-evaluation protocol - end-to-end demo\n  output: {out}\n")
    report = _run(out)

    print("\nRESULT: all three phases completed and produced a signed, scored report.")
    print("  NOTE: the numbers below score an ILLUSTRATIVE corpus chosen to populate every")
    print("  confusion cell (including a planted false-negative and false-positive) so the")
    print("  report format is visible. They are NOT a measurement of the gate's efficacy -")
    print("  that requires a real external corpus. This demo proves the PROTOCOL composes.")
    guard = report["guard_metrics"]
    baseline = report["baseline_metrics"]
    assert isinstance(guard, dict) and isinstance(baseline, dict)
    _print_metrics("gate (evo-guard)", guard)
    _print_metrics("baseline (ordinary CI exit code)", baseline)
    print("\n  status (verified by the tool, not asserted about the parties):")
    print(f"    independence:      {report['independence_status']}")
    print(f"    key separation:    {report['key_separation_status']}")
    print(f"    execution binding: {report['execution_binding_status']}")
    print(f"\n  artifacts written to {out} (score-report.json is the signed outcome).")
    print("  To make this a real independent round, replace the corpus, labels, salt, and keys")
    print("  with an external party's — see docs/INDEPENDENT_EVALUATION.md.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
