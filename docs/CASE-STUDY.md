# Case study: guarding a real upstream bug fix (charset-normalizer #537)

This is a reconstructable run of EvoOM Guard against a **real, historical bug
in a widely used library** — not a synthetic fixture. The repository ships the
whole study as a turnkey fixture:
[`examples/case-study-charset-normalizer/`](../examples/case-study-charset-normalizer/)
contains the exact candidate patches, the committed regression test, the raw
verdict records behind the table below, and a one-command, self-checking
reproduction script.

## The bug

[`charset-normalizer`](https://pypi.org/project/charset-normalizer/) (the
encoding detector installed with `requests`) had a real usability bug up to
and including **3.3.2**: comparing a `CharsetMatch` result against anything
that was not another `CharsetMatch` **raised `TypeError`** instead of
comparing:

```python
best_guess = from_bytes(payload).best()
best_guess == "utf-8"   # TypeError!  (≤ 3.3.2)
best_guess != None      # TypeError!
```

Upstream fixed it in **3.4.0** — changelog: *"Relax the TypeError exception
thrown when trying to compare a CharsetMatch with anything else than a
CharsetMatch."* — by making `__eq__` accept strings (via `iana_name`) and
return `False` for other types, and shipped the regression test
`test_direct_cmp_charset_match`.

## The setup

Reproduced entirely from public PyPI source distributions (no fork, no
special access):

```bash
pip download --no-binary :all: --no-deps charset-normalizer==3.3.2 -d sdists
# sha256(charset-normalizer-3.3.2.tar.gz) =
#   f30c3cb33b24454a82faecaf01b19c18562b1e89558fb6c56de4d9118a032fd5
tar xzf sdists/charset-normalizer-3.3.2.tar.gz && mv charset-normalizer-3.3.2 base-repo
```

The maintainer's move: commit the bug reproduction into the suite **before**
asking an AI for a fix. `tests/test_eq_regression.py` is the upstream 3.4.0
test (sha256 of the 3.4.0 sdist:
`223217c3d4f82c3ac5e29032b3f1c2eb0fb591b72161f86d93f5719079dae93e`):

```python
from charset_normalizer.api import from_bytes


def test_direct_cmp_charset_match():
    best_guess = from_bytes(
        "\U0001f600 Hello World! How affairs are going? \U0001f600".encode("utf_8")
    ).best()

    assert best_guess == "utf_8"
    assert best_guess == "utf-8"
    assert best_guess != 8
    assert best_guess != None
```

Base state, measured: **1 failed (TypeError), 137 passed** — the bug is
reproduced and the suite is red for exactly one reason.

Every scenario below runs the same command; only the candidate changes:

```bash
evo-guard guard base-repo --patch <candidate>.txt \
  --test-command "python -m pytest tests -q -o addopts= -p no:cacheprovider" \
  --baseline-evidence --require-demonstrated-fix \
  --timeout 600 --json verdict.json
```

## The three candidates

| # | Candidate | What it does |
|---|-----------|--------------|
| 1 | **Honest fix** | The upstream 3.4.0 `__eq__` hunk, applied to `charset_normalizer/models.py`. Touches no tests. |
| 2 | **Test tamper** | "Fixes" the failure by rewriting `tests/test_eq_regression.py` to `pass`. |
| 3 | **Fake fix** | Edits the right file (`models.py`) but only adds a review comment — changes no behavior. |

## The verdicts (engine 3.5.2, schema 1.11, Python 3.12, pytest 9.0)

First measured on engine 3.3.1 (schema 1.7, Python 3.11, pytest 9.1); the
re-run on 3.5.2 reproduced every verdict, reason code, and count below
unchanged — the raw records ship in
[`examples/case-study-charset-normalizer/verdicts/`](../examples/case-study-charset-normalizer/verdicts/).

| # | Verdict | reason_code | Head suite | Baseline (pristine base) | repair_effect |
|---|---------|-------------|-----------|--------------------------|---------------|
| 1 | **PASS** | `tests_passed` | 138/138 | FAIL 137/138 | **demonstrated** |
| 2 | **REJECTED** | `protected_harness_edit` | — (never ran) | — (never ran) | — |
| 3 | **FAIL** | `tests_failed` | 137/138 | FAIL 137/138 | not_demonstrated |

What each row proves:

- **Row 1** is the full positive claim: the same judge ran the same suite on
  the pristine base (FAIL, 137/138) and on the candidate (PASS, 138/138).
  The verdict carries `repair_effect: "demonstrated"` — counterfactual
  before/after evidence that this patch *fixed the reproduced bug*, not just
  that "tests pass". Verdict source is `junit+exit` (judge-owned report),
  never candidate stdout.
- **Row 2** is the pre-execution harness gate: the tampering candidate is
  rejected **before any test runs** (`verdict_source: null` — nothing was
  executed on its behalf). Editing an existing test is not a policy nuance;
  it is off-limits by default.
- **Row 3** is the baseline differential doing its job: a patch that touches
  the right file but fixes nothing cannot ride along — the regression test
  still fails and the verdict is FAIL.

All three verdicts share the identical policy fingerprint
(`policy_sha256:
349c2c0d8da098341f914c043722cf438116ae05f003b35b9edebe50519419a9`), so a
downstream consumer can verify with `evo-guard verify-verdict
--expect-policy-sha …` that no scenario was judged under a softer policy than
the others. Every record also passes `evo-guard verify-record` — the
producer/verifier universality invariant the reason corpus enforces — and the
honest-fix record seals into an Evidence Bundle that
`verify-bundle --require-pass` authenticates end to end.

## A strictness note worth knowing

We first ran the honest fix against a base **without** the committed
regression test (suite green at base, fix + new test arriving together in
the candidate under `--allow-new-tests`). Result: **FAIL,
`fix_not_demonstrated`** — the pristine base already passed the repo suite,
so the "my patch fixed something" claim was unmeasurable, and
`--require-demonstrated-fix` refused to bless it.

That is the intended reading of the gate: **demand demonstrated repair only
when the bug is reproduced in the base suite** (the maintainer-owned
reproduction workflow above). When the reproduction arrives with the patch
itself, run `--baseline-evidence` without the hard gate and read
`repair_effect` as evidence instead.

## Reproduce it yourself

One command, self-checking:

```bash
python examples/case-study-charset-normalizer/run_case_study.py
```

The script downloads the sdist pinned by the hash above (its only network
step), verifies the digest fail-closed, commits the regression test, judges
the three shipped candidates, and exits non-zero unless the verdicts match
this page, all three share one `policy_sha256`, every record passes
`verify-record`, and (with the `sign` extra) the honest-fix verdict survives
`verify-bundle --require-pass`. The exact patches, the regression test, and
the frozen raw verdict records live alongside it — see
[`examples/case-study-charset-normalizer/README.md`](../examples/case-study-charset-normalizer/README.md).
