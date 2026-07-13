# Executable adversarial corpus

This directory is EvoOM Guard's executable security-boundary regression
corpus. It began as the Phase 2A characterization set and now records both the
subsequent fixes and the controls that were already enforced. It distinguishes
three states instead of treating every green test as a security guarantee:

- `enforced`: the test proves a control currently blocks or detects the case.
- `known_gap`: the test deliberately proves a limitation that still exists.
- `documented_exception`: trusted policy deliberately removes a path from the
  guarantee.

Every fixture is constrained to pytest's temporary directory. The v3.4.2
corpus has no unresolved `known_gap` rows. If a later investigation adds one,
its test must remain green only while it reproduces the documented limitation;
the corresponding fix must invert the assertion and change the corpus status.
Silently deleting or weakening a case is not an acceptable fix.

Run the executable corpus:

```bash
python -m pytest -q \
  tests/test_adversarial_corpus.py \
  tests/test_adversarial_toctou.py \
  tests/test_adversarial_setup_outputs.py \
  tests/test_adversarial_integrity_boundaries.py
```

Run the environment-labelled snapshot microbenchmark before and after a
filesystem-hardening change with identical arguments:

```bash
python benchmarks/security_baseline.py \
  --files 1000 --bytes-per-file 1024 --rounds 5
```

The timing output is not a cross-machine claim. Compare it only under an
equivalent Python/OS/filesystem/toolchain environment.
