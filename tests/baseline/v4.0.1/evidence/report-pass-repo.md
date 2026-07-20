## EvoGuard — ✅ PASS

**all repo tests pass and the patch leaves the test harness untouched**

| | |
|---|---|
| Verdict | **PASS** |
| Tests passed | 2/2 |
| Files changed | 1 |
| Blast radius | **low** (0.07) |
| Execution | `completed` · phase `repo_suite` |
| Test command started | yes |
| Verdict source | junit+exit |
| Input | edit blocks |
| Assurance | harness `pre_gate_enforced` · report `same_process_candidate_writable` · isolation `subprocess` |

> <sub>**Assurance note:** this PASS means the repo's suite passed and the test harness was left untouched. The result is read from a judge-owned report, which resists stdout forgery — but the code under test runs in the same process as the reporter, so a *deliberate* in-process forgery is not caught here (see [`docs/ASSURANCE.md`](docs/ASSURANCE.md)). For untrusted authors, gate on this in review.</sub>

<details><summary>Files changed</summary>

`calc/ops.py`
</details>

<sub>EvoGuard reads the verdict from a judge-owned JUnit report + the process exit code (not stdout), and rejects any edit to the tests or their config. The judge runs the suite in a subprocess with rlimits + a timeout — fine for trusted repos, not a sandbox for untrusted code; isolate it further (--isolation docker|gvisor) for that. See docs/GUARD.md.</sub>
