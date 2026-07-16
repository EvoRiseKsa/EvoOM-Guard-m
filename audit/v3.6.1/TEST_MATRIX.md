<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# v3.6.1 review test matrix

Run these from a source checkout whose `HEAD` is exactly
`23c388773581e65501e733f88d158113e0095830`, after independently verifying
the release artifact with the companion scripts.  The commands map published
claims to existing regression tests; they are starting points for adversarial
review, not a substitute for it.

The base developer replay command remains:

```bash
python -m pip install -e ".[dev]"
python -m pytest tests/ -q
```

Its dependency and Docker-image limitations are documented in
[`README.md`](README.md#known-reproducibility-gap).  Record all dependency,
image, OS, Python, Node, Docker, and Git versions in an audit report.

| Review property | Focused regression entry points | Additional reviewer work / expected boundary |
|---|---|---|
| Base-owned authority over policy, pack, harness, and Action configuration | `tests/test_action_security.py`, `tests/test_policy_consistency.py`, `tests/test_strict_harness.py`, `tests/test_safe_deletions.py` | Attempt candidate-controlled policy/workflow/pack substitutions, missing base references, and protected-file deletions. An ordinary candidate must fail closed; trusted policy maintenance is intentionally a separate path. |
| Static gate and structured verdict integrity | `tests/test_grading.py`, `tests/test_junit_hardening.py`, `tests/test_adversarial_integrity_boundaries.py`, `tests/test_report_integrity.py` | Attack JUnit/report parsing, duplicate or malformed XML, entity/DTD input, exit/report disagreement, stdout forgery, and lifecycle labels. Default same-process report integrity is a documented non-guarantee. |
| External black-box, pack identity, and delivered isolation evidence | `tests/test_blackbox.py`, `tests/test_blackbox_composite_contract.py`, `tests/test_candidate_invocation_evidence.py`, `tests/test_pack_validation.py`, `tests/test_runtime_identity.py`, `tests/test_blackbox_docker_e2e.py`, `tests/test_docker_isolation.py` | Run the Docker lane against a real daemon. Confirm the verifier pack exercises the candidate and distinguish container host protection from a hostile-code VM boundary. |
| Record and evidence-bundle verification | `tests/test_record_verifier.py`, `tests/test_evidence_bundle.py`, `tests/test_evidence_containment.py`, `tests/test_signing.py` | Mutate canonical bytes, context, signatures, archive structure, record semantics, and externally supplied key/context. `verify-bundle --require-pass` must not treat an authenticated denial as ALLOW. |
| Trusted Finalizer replay, handoff, and signing separation | `tests/test_trusted_finalizer.py`, `tests/test_finalizer_workflow_security.py` | Test cross-PR/run/attempt swaps, stale base/head/tree values, control/artifact substitution, partial reruns, key exposure, and candidate execution in the sealing job. v3.6.1 does **not** independently derive candidate/effective-policy/pack digests in the sealer; that is outside its guarantee. |
| GitHub Action and release supply chain | `tests/test_release_security.py`, `tests/test_zipapp.py`, `tests/test_docs_version.py` | Verify the immutable release asset and GitHub attestation first. Review Action pins, workflow permissions, draft/publication split, asset-set checks, and whether Marketplace reference behavior matches the claimed release. |
| Contract universality and published fixtures | `tests/test_reason_code_coverage.py`, `tests/test_contract_compatibility.py`, `tests/test_json_contract.py` | Search for any producer input yielding a record rejected by `verify-record`, including config-file and black-box error paths. Some corpus scenarios are declared stubbed producer-path coverage; do not relabel them as Docker E2E proof. |
| Case-study and benchmark evidence | `python examples/case-study-charset-normalizer/run_case_study.py`, `tests/test_benchmark.py` | Treat these as developer-owned fixtures. Try to alter frozen records, labels, or the case-study outcome without detection; do not derive real-world rates from them. |
| Cross-platform and resource bounds | `tests/test_locale_encoding_matrix.py`, `tests/test_vitest_oracle.py`, `tests/test_node_oracle.py`, `tests/test_baseline_bounded_capture.py`, `tests/test_runtime_containment.py` | Test the claimed OS/runtime explicitly. Native Windows containment and POSIX resource limits have different documented guarantees; do not transpose one platform's assurance to the other. |

## Pilot operational evidence

The public pilot is useful to inspect deployment behavior, but it is outside the
frozen executable review target and is not independent validation:

- [PR #8](https://github.com/EvoRiseKsa/evoom-guard-finalizer-pilot/pull/8):
  v3.6.1 source-only ALLOW, externally verified by the owner.
- [PR #9](https://github.com/EvoRiseKsa/evoom-guard-finalizer-pilot/pull/9):
  expected signed DENY for a trust-root change before the narrow maintenance
  procedure.
- [PR #10](https://github.com/EvoRiseKsa/evoom-guard-finalizer-pilot/pull/10):
  post-governance source-only ALLOW, externally verified by the owner.

The pilot's `MANA-awam` reviewer is a second technical account controlled by the
same owner.  It provides role-separation exercise evidence only, not independent
review.  Raw workflow artifacts may have a retention period; an audit report
should preserve its own hashed copies of any evidence it relies on.
