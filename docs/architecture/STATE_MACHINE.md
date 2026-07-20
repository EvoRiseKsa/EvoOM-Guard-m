# State machine and reason-code contracts

## Guard pipeline state order

1. RECEIVED
2. POLICY_VALIDATED
3. CANDIDATE_RESOLVED
4. STATIC_GATE_COMPLETED
5. WORKSPACE_READY
6. SETUP_STARTED
7. SETUP_COMPLETED
8. REPO_STARTED
9. REPO_COMPLETED
10. PACK_STARTED
11. PACK_COMPLETED
12. CLEANUP_VERIFIED
13. DECISION_COMPOSED
14. EVIDENCE_BOUND

## Result and reason states in refactor scope

- `not_started`
- `started_incomplete`
- `completed`

## Decision/Reason states currently in scope

- PASS
- REJECTED
- FAIL
- TAMPERED
- ERROR

State transitions are part of evidence and must remain serializable and
backward-compatible with the existing schema versions.

