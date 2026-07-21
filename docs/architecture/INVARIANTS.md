# Invariants and security contracts

The implementation must preserve these invariants across every refactor PR.

1. `PASS` means static and runtime checks reported by trusted signal sources passed.
2. `REJECTED` means a policy violation is confirmed.
3. `FAIL` means environment/runtime failure that blocks trust.
4. `TAMPERED` means evidence/report mismatch or integrity failure.
5. `ERROR` paths must remain fail-closed.
6. Docker isolation must preserve process cleanup evidence and terminate non-delivered artifacts.
7. Verifier pack execution and validation must be non-empty for mandatory pathways.
8. Digest and policy must be materialized in each decision lifecycle.
9. Finalizer trust chain must include raw Git, handoff, and source identity.
   Raw-Git derivation must select its repository explicitly, ignore ambient
   `GIT_*` process state, and read literal object IDs without replacement refs.
10. Byte-level evidence and canonical signing bytes must remain stable per format.
11. External context must be pinned and validated.
12. Verdicts, reason codes and exit codes must remain aligned.
13. Canonical JSON and archive member order must remain deterministic.
14. Process-tree lifecycle evidence must include parent/child/cleanup path. After
    a successful process launch, every later failureâ€”including a partial
    stdout/stderr reader startupâ€”must enter bounded lifecycle cleanup. POSIX
    execution attempts process-group cleanup even after leader exit, and a
    normal verdict requires that cleanup to be proven; an abort preserves its
    active exception even when cleanup proof fails. The bounded non-POSIX
    fallback handles only a live leader and makes no descendant-group claim.
    Every path makes a bounded attempt to join each reader whose startup was
    attempted, closes only pipes whose readers are proven stopped or whose
    startup was never attempted, and preserves the original active exception.
    Cleanup never infers safety from a missing `Thread.ident` and never
    synchronously closes a pipe while its reader may still be blocked.
    A caller that requires cleanup proof for managed, non-detached descendants
    must request that capability explicitly. Unsupported hosts reject such a
    request before process launch; `CREATE_NEW_PROCESS_GROUP` and `taskkill`
    alone are not treated as a durable Windows containment boundary. This
    process-group contract is lifecycle containment, not filesystem, network,
    credential, or `setsid()` isolation.
15. Same-process and isolated execution modes must be explicit and named in state transitions.
16. Record verifier is the trusted producer of lifecycle evidence checks.

Violations of these invariants are treated as security regressions and block release
except with explicit emergency exception process.
