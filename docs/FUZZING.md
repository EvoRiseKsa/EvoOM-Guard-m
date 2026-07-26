# Fuzzing

EvoGuard has two coverage-guided Python targets under `tools/fuzz/`:

- `strict_json_fuzzer` exercises the bounded strict-JSON decoder used by
  evidence consumers and checks semantic round trips for every accepted input.
- `junit_fuzzer` exercises candidate-influenced JUnit XML and checks
  deterministic, nonnegative, coherent counts.

`.github/workflows/cflite_pr.yml` builds and runs both targets on pull requests,
manual dispatch, and `main`-branch commits with the ClusterFuzzLite/
OSS-Fuzz Python builder under AddressSanitizer and UndefinedBehaviorSanitizer.
The workflow invokes the builder image directly by immutable digest; it does not
depend on the upstream wrapper actions because those wrappers currently select
mutable container tags. Checkout alone receives a read-only token and does not
persist it. Repository scripts and generated fuzzers run in containers with no
network, no token or secrets, no added capabilities, bounded memory/PIDs/CPU,
and read-only source mounts. Production branch protection must require both
`fuzz (address)` and `fuzz (undefined)` from the GitHub Actions app; the Release
Ledger v2 validator now requires those exact context/app identities.

Each target has a committed seed corpus, including valid, contradictory, and
malformed examples. `tests/test_fuzz_harnesses.py` executes every seed and a
fixed 1,000-input mutation stream on all supported local platforms. That smoke
test is reproducible; it complements rather than substitutes for the
coverage-guided PR run.

Reproduce the deterministic smoke:

```console
python -m pytest tests/test_fuzz_harnesses.py -q
```

Crashes found by the coverage-guided job fail the PR check. The committed
targets and corpus are part of the same pull request as the implementation, so
this check is a developer regression signal, **not independent adversarial
evidence**: a candidate can weaken its own target. Security release evidence
must instead use an externally controlled execution of the committed blind
evaluation protocol, or another judge-controlled harness selected outside the
candidate's authority. No external blind execution is currently claimed.
