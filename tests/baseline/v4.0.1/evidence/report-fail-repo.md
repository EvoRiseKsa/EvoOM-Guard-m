## EvoGuard — ❌ FAIL

**the repo's tests fail on this patch (1/2 passed)**

| | |
|---|---|
| Verdict | **FAIL** |
| Tests passed | 1/2 |
| Files changed | 1 |
| Blast radius | **low** (0.07) |
| Execution | `completed` · phase `repo_suite` |
| Test command started | yes |
| Verdict source | junit+exit |
| Input | edit blocks |
| Assurance | harness `pre_gate_enforced` · report `same_process_candidate_writable` · isolation `subprocess` |

<details><summary>Files changed</summary>

`calc/ops.py`
</details>

<details><summary>Diagnostics</summary>

```
================================== FAILURES ===================================
>       assert mul(2, 3) == 6
E       assert 7 == 6
E        +  where 7 = mul(2, 3)
tests\test_ops.py:9: AssertionError
=========================== short test summary info ===========================
FAILED tests/test_ops.py::test_mul - assert 7 == 6
```
</details>

<sub>EvoGuard reads the verdict from a judge-owned JUnit report + the process exit code (not stdout), and rejects any edit to the tests or their config. The judge runs the suite in a subprocess with rlimits + a timeout — fine for trusted repos, not a sandbox for untrusted code; isolate it further (--isolation docker|gvisor) for that. See docs/GUARD.md.</sub>
