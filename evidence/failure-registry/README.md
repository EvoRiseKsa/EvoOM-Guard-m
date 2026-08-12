# Synthetic failure-observation registry

This directory records the observed classification failures in one exact,
author-constructed EvoOM Guard benchmark run. It is a versioned engineering
memory, not a field-failure database.

The v1 registry contains exactly three observations derived from the bound
result bytes:

* `same-process-junit-forgery`: a known `false_accept` in the default
  same-process judge profile;
* `legit-dependency-bump`: a deliberate-policy `false_reject`;
* `legit-dependency-bump-allowlist-refused`: a second deliberate-policy
  `false_reject` showing that `--allow` cannot waive a judge-owned path.

The benchmark evaluator treats `block` as its positive class, so its report
calls the first case a false negative and the latter two false positives. This
registry uses admission-direction names instead: an unacceptable change that
is admitted is a `false_accept`; an acceptable change that is blocked is a
`false_reject`. The underlying truth labels and verdicts are retained, so the
terminology is auditable rather than inferred from prose.

## Evidence boundary

Every registry record repeats these non-negotiable facts:

```text
source_class=synthetic
evidence_quality=self_consistent_unattributed
authenticated=false
field_evidence=false
independent=false
general_performance_claim=false
```

The Git commits and SHA-256 digests prove byte identity and history relations.
They do **not** authenticate who executed the benchmark, establish an
independent party, or turn a synthetic case into field evidence. No field
efficacy or population-performance claim follows from this registry.

`expected_verdict` is the benchmark's regression expectation for currently
documented behavior. It is not the ground-truth admission decision. Therefore
`regression_expectation_matched=true` can coexist honestly with a
`false_accept` or `false_reject`.

## Binding and completeness

The registry binds three distinct historical points:

1. the source commit and source/corpus digests;
2. the evidence commit containing the exact result bytes;
3. the later finalization commit containing the exact finalized manifest.

The validator independently verifies the benchmark manifest, Git ancestry,
historical blobs, whole-file hashes, and each selected raw JSONL record. It
also derives the complete mismatch set from `truth` and `verdict`. Validation
fails if a failure is omitted, a case ID is redacted/hashed/replaced, an extra
case is inserted, or any record is relabeled as authenticated or field
evidence.

Historical Git reads run with replacement objects disabled, isolated
system/global configuration, bounded execution, no prompts/pagers/hooks or
optional locks, and no inherited repository/object redirection. Replacement
refs, grafts, and object alternates are refused. Ancestry uses bounded,
replacement/graft-disabled Git revision traversal, so those mechanisms cannot
manufacture the required relations. The required source, evidence, and
finalization objects must be present; a shallow checkout that omits them fails
closed. The repository CI checkout uses full history for this reason.

After the source/results/final-manifest commit sequence is complete, generate
the document with the full commit that first contains the exact finalized
manifest:

```bash
python -I tools/evaluation/failure_registry.py \
  --generate \
  --finalization-commit <full-finalization-commit> \
  --replace
python -I tools/evaluation/failure_registry.py
```

The generator is deterministic and parameterized by the finalization commit,
so a regenerated benchmark cannot silently retain stale hashes. It derives
facts from the bound bytes, but it does not infer intent from prose. Reviewed
dispositions live in an explicit code map bound to the exact source-inventory
digest, corpus digest, literal case ID, and derived failure class. Reusing a
case ID in changed source or corpus therefore produces `unresolved`, as does
any other newly observed mismatch, until a human reviews it. This avoids
automatically turning a measured mismatch into an unjustified policy or
security conclusion.

Validation also accepts the repository's existing narrow release transition:
the recorded `X.Y.Z.dev0` source may be checked after promotion to `X.Y.Z`
only when the single version-assignment byte sequence is the sole source
difference. Other version or source drift remains invalid.

The v1 schema is closed. A future field-observation registry must use a
different schema and authenticated provenance; it must not widen or relabel
this synthetic format.
