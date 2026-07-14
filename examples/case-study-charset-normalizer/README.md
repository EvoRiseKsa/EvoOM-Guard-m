<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Turnkey fixture: the charset-normalizer #537 case study

One command reproduces every claim in
[docs/CASE-STUDY.md](../../docs/CASE-STUDY.md) against the real Guard:

```bash
python examples/case-study-charset-normalizer/run_case_study.py
```

The script downloads the byte-pinned `charset-normalizer` 3.3.2 sdist from
PyPI (the only network step; digest verified fail-closed, and a previously
downloaded archive under `work/sdists/` is reused), commits the upstream
regression test into the suite the way the maintainer workflow prescribes,
judges the three shipped candidates under the documented policy, and exits
non-zero unless:

- the three verdicts match the published table
  (`PASS/tests_passed`, `REJECTED/protected_harness_edit`,
  `FAIL/tests_failed`),
- all three records share one `policy_sha256`,
- every record passes `verify-record` (the producer/verifier universality
  invariant), and
- with the `sign` extra installed, the honest-fix verdict seals into an
  Evidence Bundle that `verify-bundle --require-pass` authenticates against
  an external context.

## Layout

| Path | What it is |
|------|------------|
| `candidates/1-honest-fix.txt` | The upstream 3.4.0 `__eq__` hunk as a `<<<PATCH>>>` block — touches no tests. |
| `candidates/2-test-tamper.txt` | "Fixes" the failure by rewriting the regression test to `pass`. |
| `candidates/3-fake-fix.txt` | Edits the right file but only adds a comment — changes no behavior. |
| `fixtures/test_eq_regression.py` | The upstream 3.4.0 regression test, committed into the base suite before judging. |
| `verdicts/*.json` | The frozen raw records of the published run (engine 3.5.2, schema 1.11). |
| `run_case_study.py` | The one command. Fresh output lands in `work/` (gitignored). |

The shipped `verdicts/` are the exact records behind the table in
`docs/CASE-STUDY.md`. A rerun reproduces the same verdicts, reason codes,
counts, and policy fingerprint; attestation timestamps and the candidate
digests' surrounding metadata are naturally fresh.
