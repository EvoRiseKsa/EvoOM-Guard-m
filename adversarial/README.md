# Executable adversarial corpus

This directory is EvoOM Guard's executable security-boundary regression
corpus. It began as the Phase 2A characterization set and now records both the
subsequent fixes and the controls that were already enforced. It distinguishes
three states instead of treating every green test as a security guarantee:

- `enforced`: the test proves a control currently blocks or detects the case.
- `known_gap`: the test deliberately proves a limitation that still exists.
- `documented_exception`: trusted policy deliberately removes a path from the
  guarantee.

Every fixture is constrained to pytest's temporary directory. The registry
retains stable case IDs while recording each case's current observed state,
and deliberately includes owned `known_gap` rows. A known-gap test must remain
green only while it reproduces the documented limitation, and its
`target_phase` names the production work that owns closure. The corresponding
fix must invert the assertion and change the corpus status. Silently deleting,
omitting, or weakening a case is not an acceptable fix.

Run the executable corpus:

```bash
python -m tools.evaluation.run_adversarial_corpus
```

The runner derives its exact pytest node list from `corpus.jsonl`; it does not
maintain a second hand-written test list. Consequently, registered
`known_gap` tests run alongside `enforced` and `documented_exception` cases.
The registry contract tests separately reject duplicate or unresolved nodeids.

Run the environment-labelled snapshot microbenchmark before and after a
filesystem-hardening change with identical arguments:

```bash
python benchmarks/security_baseline.py \
  --files 1000 --bytes-per-file 1024 --rounds 5
```

The timing output is not a cross-machine claim. Compare it only under an
equivalent Python/OS/filesystem/toolchain environment.
