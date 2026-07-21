# ADR-0003 Execution kernel extraction

## Status

Accepted; phase 1 (bounded native process), phase 2 (Docker control, identity,
and cleanup), phase 3 (candidate-boundary preparation), phase 4
(candidate-invocation receipt transport), and phase 5 (black-box judge-process
lifecycle) are implemented behind typed contracts.

## Decision
Create explicit execution and isolation backends behind typed contracts,
including cleanup and output limits. The judge-process adapter belongs to the
execution layer; command construction, report interpretation, and verdict
policy remain in the black-box compatibility module.

## Rationale
Current monolithic execution paths mix process launch, isolation policy, and verdict logic.

## Consequences
- Enables independent failure-domain testing.
- Enables deterministic cleanup assertions.
- Named-container cleanup is a fail-closed, positive absence proof: a bounded
  filtered `docker container ls --all` query must succeed and omit the exact
  validated name. The cleanup path reconciles repeatedly and requires a final
  stable sequence of absent observations so a late daemon-side create is found
  and removed within one 10-second monotonic control-plane budget. An exhausted
  budget or unverifiable observation fails immediately. This proves bounded
  snapshot stability, not permanent future absence. A failed Docker query is not
  absence evidence because daemon, authorization, and client failures are
  indistinguishable from not-found.
- `repo_verifier.py` retains private compatibility names while delegating to
  the typed `evoom_guard.execution` and `evoom_guard.isolation` contracts.
- Candidate and black-box execution code no longer obtain process primitives
  from the concrete repository verifier.
- Generic process requests can opt into a typed process-group cleanup-proof
  requirement. The kernel rejects that requirement before `Popen` unless POSIX
  process-group cleanup is available. This is a fail-closed capability
  preflight, not a claim that a later cleanup attempt cannot fail. The default
  remains off for trusted cross-platform control commands, and the runtime
  proof covers only non-detached descendants in the managed group; it is not a
  sandbox claim. An unexpected abort still preserves its active exception when
  a secondary cleanup attempt fails.
- `isolation/docker.py` owns bounded Docker control commands, image-identity
  observations, named-container lifecycle cleanup, and candidate-CID cleanup.
- Named repo-verifier containers and black-box candidate CID containers remain
  distinct contracts: one proves cleanup of a known name, while the other
  discovers only validated runtime-written IDs before proving absence.
- Repo-verifier Docker argv/mount construction, isolation policy, evidence
  composition, and verdict wording remain with their existing callers; the
  candidate-specific launch plan moves with candidate-boundary preparation.
- `isolation/candidate.py` owns launcher materialization and candidate-boundary
  preparation. The legacy `candidate_runner.py` surface keeps its public
  signatures and test seams while delegating implementation; runtime invocation
  observation and verdict wording remain in `blackbox.py`.
- The black-box invocation receiver bounds every receive-lock hold to 256
  datagrams and checks its stop signal within the batch. Host candidates that
  share the judge UID can therefore cause conservative missing evidence, but
  cannot hold verdict or cleanup indefinitely by continuously flooding invalid
  datagrams. A setup failure after a successful bind also removes the socket
  pathname; a failed bind never deletes a pre-existing path.
- `isolation/invocation.py` owns that judge-side receipt transport and cumulative
  exact-token observation. `blackbox.py` retains an exact compatibility alias
  and remains solely responsible for composing receipts with validated runtime
  CIDs, evidence, and verdicts.
- `execution/judge.py` owns `JudgeProcessRequest`, `JudgeProcessLimits`,
  `JudgeProcessResult`, and the bounded judge-process execution lifecycle.
  `blackbox.py` retains its established private patch seams and adapts the typed
  result to its existing subprocess-facing contract. This is an internal,
  behavior-preserving ownership change; command construction, report grading,
  evidence, verdicts, and public CLI/API behavior are unchanged.
- Once the black-box judge process is launched, reader construction or partial
  `Thread.start()` failure cannot escape lifecycle handling: on POSIX the
  process-group cleanup is attempted even when its leader has already exited,
  and it must be proven before a normal verdict; an abort retains its active
  exception if cleanup proof itself fails. The bounded non-POSIX fallback
  handles a live leader without making a descendant-group claim. Attempted
  readers are joined boundedly and independently, only proven safe diagnostic
  pipes receive a best-effort close, and cleanup failures do not replace the
  original startup exception. Missing `Thread.ident` is not treated as
  non-start proof, so a pipe is never synchronously closed while its reader may
  remain blocked on that pipe.
