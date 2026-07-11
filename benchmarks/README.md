# EvoOM Guard labelled-corpus benchmark

This benchmark measures classification quality; it does not claim that a PASS
proves correctness. Each JSONL row contains a stable case id, a ground-truth
label (`accept` or `block`), and the observed Guard verdict.

Run:

```bash
python benchmarks/evaluate.py benchmarks/sample.jsonl
```

For an independent evaluation, freeze the Guard version and policy, publish the
corpus hash, have a separate reviewer label cases before running Guard, then
publish the raw JSONL and generated metrics. Do not tune policy against the held-
out set.
