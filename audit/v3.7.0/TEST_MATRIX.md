<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# v3.7.0 external review matrix

Run source tests only from a checkout whose HEAD is exactly
1f0ceae5009198b1bf161a3a07fced54c1f01337, after independently verifying the
released zipapp with the companion scripts. The commands below are
developer-authored regression entry points and starting points for adversarial
review; they are not evidence that a property is independently established.

The ordinary source replay is:

~~~
python -m pip install -e ".[dev]"
python -m pytest tests/ -q
~~~

Record resolver output, all dependency versions, OS, architecture, Python, Git,
GitHub CLI, Docker/runtime, and image digests. The dev dependency and container
reproduction limitations are in [README.md](README.md#evidence-collection-and-reproducibility-limits).

| Requested property | Focused regression entry points | Adversarial questions and expected boundary |
| --- | --- | --- |
| Base-owned authority and protected-harness refusal | tests/test_action_security.py, tests/test_policy_consistency.py, tests/test_strict_harness.py, tests/test_safe_deletions.py | Try candidate-controlled policy, pack, workflow, test-harness, protected-file deletion, and missing-base substitutions. An ordinary candidate must not turn such a substitution into a clean acceptance. Trust-root maintenance is deliberately outside the ordinary candidate path. |
| Verdict and evidence integrity | tests/test_grading.py, tests/test_junit_hardening.py, tests/test_adversarial_integrity_boundaries.py, tests/test_report_integrity.py, tests/test_record_verifier.py, tests/test_evidence_bundle.py, tests/test_evidence_containment.py, tests/test_signing.py | Mutate XML, canonical bytes, archive structure, signature, source/context, lifecycle fields, duplicate reports, entity/DTD input, and exit/report agreement. Verification must fail closed according to the published contract. An authenticated DENY must not be treated as ALLOW. |
| Assurance-boundary truthfulness | tests/test_blackbox.py, tests/test_blackbox_composite_contract.py, tests/test_candidate_invocation_evidence.py, tests/test_runtime_identity.py, tests/test_blackbox_docker_e2e.py, tests/test_docker_isolation.py | Confirm that a same-process repo-native verdict remains labelled candidate-writable. Test that blackbox-only cannot accept a forged external report and that claimed container invocation is backed by observed receipts. Do not convert container evidence into a VM-equivalence claim. |
| Verifier-pack identity and execution | tests/test_pack_validation.py, tests/test_blackbox.py, tests/test_candidate_invocation_evidence.py, tests/test_runtime_identity.py | Try pack mutation, digest mismatch, missing pack, a pack that never invokes the candidate, and post-snapshot drift. A clean pass requires the configured identity and completed required execution; it does not prove an arbitrary pack specification is sufficient. |
| Trusted Finalizer v3.7 raw-Git derivation | tests/test_trusted_finalizer.py, tests/test_finalizer_workflow_security.py, tests/test_finalizer_derivation.py | Exercise stale, cross-PR, cross-run, and cross-attempt records; replacement control or handoff artifacts; raw-Git text, deletion, policy, and pack mismatches; partial reruns; candidate execution in the seal job; and any route to key access before binding comparison. The reference workflows are templates and require a separately protected consumer configuration to make a merge decision. |
| Artifact Admission V1 | tests/test_artifact_admission.py, tests/test_trusted_finalizer.py | Try a different regular file with the same-looking context, altered byte length/hash, stale finalizer context, embedded-key substitution, finalizer DENY, and key-identity reuse. A verified V1 record is only a regular-file-to-pre-merge-finalizer relation, not build provenance or deployment evidence. |
| Action and release supply chain | tests/test_release_security.py, tests/test_zipapp.py, tests/test_docs_version.py | Verify the immutable release asset and attestation before inspection. Review Action inputs, permissions, immutable action references, release asset-set checks, and how a consumer pins the Action. Do not infer a Marketplace listing or a tag name alone proves the executed bytes. |
| Contract compatibility and edge paths | tests/test_contract_compatibility.py, tests/test_json_contract.py, tests/test_reason_code_coverage.py | Search for producer inputs that create a record rejected by the independent verifier, including configuration, malformed evidence, blackbox error, and bounded-output paths. Record unsupported or untested producers explicitly. |

## Suggested release-asset checks

Use the released zipapp, not a rebuilt source artifact, for externally visible
CLI and parser tests:

~~~
python -I release/evo-guard.pyz version
python -I release/evo-guard.pyz doctor
python -I release/evo-guard.pyz --help
~~~

For a finding involving a consumer finalizer deployment, retain only safe
metadata: the public key fingerprint, exact expected source/context JSON,
verdict/bundle hashes, policy and verifier-pack identity, workflow run/attempt,
and Check Run identity. Never retain or request a private key or token.

## What this matrix cannot establish

Passing the listed tests does not quantify false positives or false negatives,
prove a hostile runner cannot escape, prove Docker/gVisor is VM-equivalent,
prove a downstream workflow is protected correctly, or authenticate a later
build, OCI image, release, deployment, SBOM, or vulnerability scan. A reviewer
should include failed and incomplete paths as well as clean results.
