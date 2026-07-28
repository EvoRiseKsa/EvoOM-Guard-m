# Independent blind-evaluation protocol

> **Availability:** this protocol depends on the explicit operating-profile and
> schema `1.12` contracts in the current unreleased `4.4.0.dev0` development
> source. It is not a `v4.3.0` consumer interface, and publishing the protocol
> is not evidence that an independent party has run it.

`tools/evaluation/blind_protocol.py` makes a held-out evaluation auditable
without pretending that the project author is an independent evaluator. It
separates three events:

1. an external label authority freezes a case manifest, commits to hidden
   labels with a private random salt, and signs the exact commitment bytes;
2. an execution authority, without the labels or salt, verifies that commitment
   under an externally trusted label-authority key, verifies every case bundle's
   exact bytes/digest/size plus each full verdict record, detached verdict
   signature, effective policy, profile, and ordinary-CI result; it then signs a
   freeze that binds their digests, the exact signed commitment, and three
   distinct signing-key IDs to the declared Guard artifact;
3. the label authority reveals the labels and salt, and the scorer verifies the
   prior commitment, execution signature, and independently supplied
   verdict-finalizer public-key identity before calculating false positives,
   false negatives, abstentions, coverage, confidence intervals, and the
   declared baseline.

The signed-commitment, frozen-prediction, score-report, and ordinary-CI result
contracts are version 2. Version 1 evidence is intentionally rejected because
it lacks the signed commitment binding and complete baseline declaration.

The tool verifies bytes, signatures, and relations. It cannot observe which
executable a lab actually launched, so the signed artifact binding is an
execution-authority declaration, not hardware/runtime attestation. Nor can it
verify employment, funding, authorship, or other conflicts of interest; the
report therefore records `externally_declared_not_verified_by_tool` even when
named authorities differ. The tool verifies that the label-authority,
verdict-finalizer, and execution-freezer public keys are distinct. Distinct
keys do not prove distinct owners or organizational trust domains; that
separation remains externally declared and unverified.

Case bundles are opaque to this tool: it does not unpack them or independently
derive `source_repository`, base/head commits, or `candidate_sha256` from their
contents. It proves the declared bundle path, size, and digest binding.
Establishing that those bytes faithfully embody the declared source identities
is an external evaluator/launcher responsibility.

## Inputs

The UTF-8 case manifest is strict JSON:

```json
{
  "schema_version": "evoguard-blind-case-manifest-v1",
  "evaluation_id": "lab-round-2026-01",
  "cases": [
    {
      "id": "python-project-01-change-03",
      "ecosystem": "python",
      "source_repository": "https://example.org/project",
      "base_commit": "40- or 64-character lowercase Git object id",
      "head_commit": "40- or 64-character lowercase Git object id, or null",
      "candidate_sha256": "64 lowercase hexadecimal characters",
      "bundle_file": "python-project-01-change-03.tar.zst",
      "bundle_sha256": "64 lowercase hexadecimal characters"
    }
  ]
}
```

The label authority keeps a JSONL file with exactly `id` and `truth`
(`accept` or `block`) per case. Labels must cover the case manifest exactly.
The salt is at least 32 cryptographically random bytes and remains private
until the predictions are frozen.

The execution authority supplies JSONL with exactly:

```json
{
  "id": "python-project-01-change-03",
  "verdict_file": "private/run/verdict.json",
  "verdict_signature_file": "private/run/verdict.json.sig",
  "execution_error_code": null,
  "baseline_result_file": "private/run/ordinary-ci.json"
}
```

Exactly one of `verdict_file` and `execution_error_code` is non-null. An
execution failure is frozen as an `ERROR` abstention instead of being dropped.
At least one case in a freeze must contain a valid signed verdict so the round
has a concrete verdict-finalizer trust root; an all-error round is rejected.
The error code is restricted to `runner_timeout`, `runner_crash`,
`missing_verdict`, `invalid_verdict`, or `infrastructure_unavailable`; free-form
diagnostics and paths cannot enter the public freeze. Every present verdict must
be a complete supported verdict record that passes `verify-record`, must have a valid
detached Ed25519 signature under the externally supplied verdict-finalizer
public key, and must carry the exact effective-policy object and selected
operating profile supplied to the freeze. Because this protocol requires an
operating profile, conforming verdicts use schema `1.12`; schema `1.11` remains
accepted by `verify-record` only for legacy policies without that field.

`baseline_result_file` is strict JSON with exactly:

```json
{
  "schema_version": "evoguard-ordinary-ci-result-v2",
  "case_id": "python-project-01-change-03",
  "case_bundle_sha256": "64 lowercase hexadecimal characters",
  "command_sha256": "SHA-256 of a predeclared command descriptor",
  "environment_sha256": "SHA-256 of a sanitized environment descriptor",
  "toolchain_sha256": "SHA-256 of a pinned toolchain descriptor",
  "timeout_seconds": 900,
  "execution_binding_status": "declaration_not_runtime_attestation",
  "exit_code": 0,
  "execution_error_code": null
}
```

Exactly one result field is non-null. Exit 0 derives `accept`, another bounded
exit code derives `block`, and an allowlisted execution error derives
`abstain`. The case ID and bundle digest must match the case manifest. Command,
sanitized environment, and toolchain descriptors are represented only by
lowercase SHA-256 digests, and the positive timeout is capped at 24 hours.
Callers cannot submit a baseline prediction directly. The only currently
supported baseline ID is `ordinary-ci-exit-v1`. These fields make the
execution authority's declaration precise; they do not attest that the
declared command or environment actually ran.

`--policy` is the complete effective-policy JSON object found in
`attestation.effective_policy`, not a partial `.evoguard.json` configuration.

## Commands

Before any execution, the label authority runs:

```bash
python -m tools.evaluation.blind_protocol commit-labels \
  --cases cases.json \
  --labels private-labels.jsonl \
  --salt private-labels.salt \
  --label-authority "Independent Lab" \
  --conflict-disclosure "No funding or authorship relationship declared." \
  --label-sign-key private-label-authority.pem \
  --out public-label-commitment.json \
  --signature-out public-label-commitment.json.sig
```

Only `cases.json`, `public-label-commitment.json`, its detached signature, and
the externally trusted label-authority public key are shared. The labels,
salt, and private key remain with the label authority.

After running every case and the predeclared baseline, the execution authority
runs:

```bash
python -m tools.evaluation.blind_protocol freeze-predictions \
  --cases cases.json \
  --commitment public-label-commitment.json \
  --commitment-sig public-label-commitment.json.sig \
  --label-pub label-authority.pub \
  --predictions private-predictions.jsonl \
  --case-root case-bundles \
  --guard-artifact evo-guard.pyz \
  --policy effective-policy.json \
  --profile protected \
  --baseline-id ordinary-ci-exit-v1 \
  --execution-authority "Execution Lab" \
  --verdict-pub verdict-finalizer.pub \
  --execution-sign-key execution-freezer.pem \
  --out frozen-predictions.json \
  --signature-out frozen-predictions.json.sig
```

The label-authority, verdict-finalizer, and execution-freezer keys must be
cryptographically distinct. The freeze fails on an invalid label commitment or
signature, case digest mismatch, incomplete or inconsistent record, invalid
verdict signature, policy/profile mismatch, malformed baseline evidence, or
key reuse. It emits only allowlisted facts and digests; raw diagnostics, source
paths, command text, environment values, toolchain paths, and candidate
evidence are not copied.

Finally, after the frozen file has been published or otherwise timestamped, the
label authority reveals the labels and salt:

```bash
python -m tools.evaluation.blind_protocol score-reveal \
  --cases cases.json \
  --commitment public-label-commitment.json \
  --commitment-sig public-label-commitment.json.sig \
  --label-pub label-authority.pub \
  --verdict-pub verdict-finalizer.pub \
  --frozen frozen-predictions.json \
  --frozen-sig frozen-predictions.json.sig \
  --execution-pub execution-freezer.pub \
  --labels revealed-labels.jsonl \
  --salt revealed-labels.salt \
  --out score-report.json
```

The scorer verifies both authority signatures, derives the verdict-finalizer
key ID from the independently supplied `--verdict-pub`, requires an exact match
with the frozen verdict key ID, rechecks that all three trusted keys are
distinct, requires the exact commitment descriptor frozen by the execution
authority, and re-derives Guard and baseline predictions from their allowlisted
evidence. Every output is create-only.
Commitment/signature and freeze/signature outputs are reserved as pairs before
either payload is written. A failed pair publication intentionally leaves any
successfully reserved path in place, possibly empty or partial, for operator
inspection; the tool never unlinks a final path during failure cleanup. Remove
such reservations explicitly only after investigating the failure. Keep the
exact manifest, signed commitment, signed freeze,
reveal, score report, raw signed verdicts, Guard artifact, effective policy,
baseline results, public keys, and case bundles under the evaluator's retention
policy.

## What closes the production gate

Shipping this protocol does not close the independent-evaluation gate. Closure
requires an external party to:

- choose and label a held-out, multi-project and multi-ecosystem corpus before
  execution;
- keep labels and salt unavailable to the execution/product team until freeze;
- predeclare policy, profiles, baselines, timeouts, and exclusions;
- publish conflicts of interest and every abstention;
- retain the exact artifacts and execute the protocol above without changing
  the product against the held-out cases.
- use an independently controlled launcher or runtime attestation if the
  evaluation claim needs to prove that the declared artifact, rather than some
  other executable, actually produced the signed verdicts.

Until that record exists, EvoOM Guard has a runnable evaluation protocol and
bounded internal evidence, not independent validation.
