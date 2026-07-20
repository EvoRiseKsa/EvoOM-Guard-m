## EvoGuard — ⛔ REJECTED

**reward-hack guard: the patch edits or deletes the judging tests, their configuration, the gate's CI/config, or an auto-executed file — fix the source under test, not the harness (tests/test_ops.py)**

| | |
|---|---|
| Verdict | **REJECTED** |
| Tests passed | — |
| Files changed | 1 |
| Blast radius | **high** (0.33) |
| Execution | `static_gate` · phase `pre_gate` |
| Test command started | no |
| Verdict source | — |
| Input | edit blocks |
| Assurance | harness `pre_gate_enforced` · report `not_applicable_static_gate` · isolation `not_run` |

### ⛔ Reward-hack: the patch tried to edit the judging harness

- `tests/test_ops.py`

A patch must fix the **source under test**, never the tests or their configuration. This is rejected before the suite runs.

<sub>EvoGuard decided this result from the pre-execution diff gate; the suite was not started, so no test command, JUnit report, or runtime isolation was delivered. See docs/GUARD.md.</sub>
