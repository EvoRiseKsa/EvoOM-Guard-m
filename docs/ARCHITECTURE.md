<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# EvoOM Guard — architecture

A map of the codebase for anyone reading or extending it. The core is **stdlib-only**;
the whole gate is a thin, model-free composition of a policy-bound judge and a
blast-radius scorer.

## One-paragraph mental model

Given a code change, EvoOM Guard applies it to a **throwaway copy** of the repo, runs
the repo's **own test suite** in that copy, and reads the verdict from a **JUnit
report the judge owns** (a path *outside* the copy) plus the **process exit code** —
never from the candidate's stdout. Before running anything, it **rejects** a
candidate edit/deletion that targets a conventionally recognized judge path or
an exact regular base file explicitly declared in `harness_inputs`. This is a
finite path-policy decision, not transitive command-graph discovery. If an
Independent Verifier Pack is configured, Guard snapshots and identifies
it outside the candidate tree, then requires a **separate pack phase** as well as the
repo suite; merely copying a pack or collecting zero pack tests is never enough. The
result is one verdict (`PASS` / `REJECTED` / `FAIL` / `TAMPERED` / `ERROR`), an exit
code, a JSON record, a Markdown report, and an optional SARIF document. Separate
offline consumers can validate the record's internal semantics or authenticate a
canonical evidence envelope against external key and run-context inputs.

## Module map (`evoom_guard/`)

| Module | Responsibility |
|---|---|
| `domain/verification.py` | Dependency-free authoritative JUnit counts and typed repository/pack phase evidence/results. Legacy verifier modules re-export the same class objects. |
| `domain/execution.py` | Dependency-free immutable execution-lifecycle snapshots and per-phase isolation observations. It contains no process launch, verdict, or wire-serialization logic. |
| `domain/isolation.py` | Dependency-free vocabulary and fail-closed validation for the only supported execution modes: `subprocess`, `docker`, and `gvisor`. Unknown strings are rejected before provider lookup, workspace creation, or process launch. |
| `domain/verdict.py` | Dependency-free frozen verdict names, execution lifecycle, reason codes, and read-only reason compatibility semantics. Versioned policy/wire fields stay in their schema contract. |
| `domain/policy.py` | Immutable, dependency-free `EffectivePolicy` value plus producer-side operating-profile constraint validation and pack-digest shape checking. It contains no hashing, serialization, or schema logic; `verifiers/record_policy.py` independently re-derives profile semantics for offline records. |
| `domain/harness.py` | Dependency-free exact-path normalization, matching, setup-exclusion conflict detection, and the shared `HarnessInputPolicyError` contract for explicit `harness_inputs`. It performs no filesystem inspection or command/dependency discovery. |
| `domain/request.py` | Frozen composition of repository, candidate, source-identity, effective-policy, verifier-pack, and coverage inputs for one Guard judgment. The public `guard()` signature remains the compatibility boundary. |
| `policy/effective.py` | Canonical construction, versioned schema-1.11/1.12 payload projection, and frozen JSON digest for effective policy. An absent operating profile and empty `harness_inputs` preserve the exact 1.11 payload; either 1.12-only field is digest-bound when present. Guard retains compatibility facades; the raw-Git finalizer consumes this public owner directly. |
| `policy/harness.py` | Compatibility façade that re-exports the dependency-free `domain/harness.py` contracts through the public policy package. |
| `application/request_preparation.py` | Typed validation and preparation of one public `guard()` invocation: immutable `GuardRequest` capture, supported-isolation validation, canonical policy construction/payload, and an owned projection back to the historical orchestrator values. Constructors and policy providers are injected by the `guard.py` facade at each use; path admission, delivered-isolation decisions, execution, and evidence remain outside this boundary. |
| `application/repo_judgment.py` | Stdlib-only coordination of the repo-native initial judgment after preflight and shared problem construction: optional repository verification, raw-artifact evidence projection, deletion-aware blast-radius completion, risk scoring, and construction of the initial `VerificationPipeline`. Every runtime owner is injected through a live provider at its historical lookup position; unsupported-policy/preflight handling, black-box runtime, finalization, and public `GuardResult` construction remain in `guard.py`. |
| `application/repo_finalization.py` | Ordered repo-native post-decision coordination: coverage and pristine-baseline effects, repair-effect annotation, lifecycle/pack evidence projection, attestation placement, assurance profile construction, and the final lazy assurance gate. Runtime operations are injected through live providers; post-cleanup black-box coordination has its own application owner, `GuardResult` remains in `guard.py`, and the baseline runtime effect is owned by `verifiers/repo_baseline.py`. |
| `application/blackbox_finalization.py` | Ordered post-cleanup black-box coordination: delivered-invocation interpretation, optional repo-native composition, decision/reason projection, phase/count evidence, unsupported evidence markers, eager assurance evaluation, then attestation. The external judge, candidate/container cleanup, risk implementation, repo verifier, and compatibility builders are injected; the module imports no runtime owner. |
| `application/diff_verification.py` | Typed unified-diff application coordinator: ordered fail-closed preflight, throwaway base reconstruction, changed-path projection, candidate serialization, and delegation to the existing Guard judgment. Filesystem/process/error/result operations are injected through live providers; baseline, coverage, verifier execution, CLI policy loading, and `GuardResult` remain in their established owners. |
| `contracts.py` | Foundation-owned, dependency-free `Verifier` Protocol + `VerdictResult` / `Problem` domain-agnostic interface. Its stable flat import path is retained. |
| `verifiers/repo_verifier.py` | **The compatibility orchestrator.** Coordinates repository admission/materialization, effect/provider timing, repository-plus-pack phase composition, and the outer cleanup `finally`. Candidate/pack workspace-path lifetime bookkeeping delegates to `workspace/repository_lifetime.py`; cleanup effect/provider coordination delegates to `repo_cleanup.py`; sticky evidence and completed artifact projection delegate to `repo_result`; live snapshot/runtime-identity providers remain injected into the two bounded continuity owners. For container runs it resolves a fresh canonical immutable image ID per verification and keeps that pin context-local across setup, suite, and pack phases. |
| `verifiers/repo_cleanup.py` | Dependency-free repository-judgment cleanup effect coordinator. It resolves the workspace algorithm, recursive remover, and diagnostic-note providers in historical order, then forwards the exact active primary exception. `repo_verifier` retains both compatibility facades and the outer `finally`; `workspace/repository.py` retains removal sequencing and absence-proof semantics. |
| `verifiers/repo_execution.py` | Typed mutable builder for repository-verifier lifecycle observations plus the sole projection back to the unchanged artifact keys. Pack identity and repository-phase results remain separate verification evidence. |
| `verifiers/repo_result.py` | Typed, effect-free repository result owner. It defensively binds sticky pack identity and completed repo-phase evidence, projects completed pack fields, preserves exact key order/overwrite behavior and configured-pack presence-versus-null rules, and builds the unchanged final artifact. It owns no provider lookup, trace mutation, process/container execution, clock, workspace, or cleanup operation. |
| `verifiers/repo_materialization.py` | Contained FILE-then-PATCH materialization transaction with fail-closed reads/writes and restoration of judge-owned `package.json` fields. Filesystem, patch, and restoration operations are injected; `repo_verifier` retains the public dynamic compatibility facade. |
| `verifiers/repo_pack_intake.py` | Immutable request/result boundary for optional verifier-pack admission: required-pin consistency, reserved-mount collision, judge-owned snapshot creation, manifest validation, digest binding, and rejection evidence. It does not execute the pack. |
| `verifiers/repo_pack.py` | Typed verifier-pack owner. It executes host/docker/gVisor branches through injected live services, freezes terminal process evidence, and separately interprets judge-owned JUnit only after the pack/runtime continuity owners complete their post-execution checks. It does not own pack admission/identity, continuity state, sticky evidence, composition, final projection, or cleanup. |
| `verifiers/repo_pack_continuity.py` | Typed judgment-local owner for an accepted verifier-pack identity plus its pre-execution and post-completion snapshot checks. The accepted manifest is defensively frozen, providers remain live at both checkpoints, and phase/failure state cannot skip, repeat, or recover. Controlled snapshot drift maps to the unchanged `pack_snapshot_changed` facade result; unexpected provider failures are re-raised unchanged for outer cleanup precedence. It does not launch the pack, read JUnit, project wire evidence, compose a verdict, or clean workspaces. |
| `verifiers/repo_baseline.py` | Typed pristine repository-suite runner. It owns copied-base setup/suite execution, the setup-fidelity gate, bounded host-process enforcement, judge-owned JUnit interpretation, and baseline workspace cleanup. Guard supplies live compatibility effects; repair-effect classification and decision demotion remain in `application/repo_finalization.py`. |
| `verifiers/repo_suite.py` | Typed repository-suite owner. It executes host/docker/gVisor branches through injected live services, freezes terminal evidence, and separately interprets judge-owned JUnit after the continuity owner verifies the runtime tree. It does not execute packs or own runtime identity/cleanup. |
| `verifiers/repo_runtime_continuity.py` | Typed judgment-local owner for mandatory-pack runtime continuity: post-setup baseline capture, suite/pack drift verification, elapsed identity-scan accumulation, monotonic phase/failure state, and immutable `RuntimeIdentityEvidence` projection. Providers remain live at each operation; the pack checkpoint cannot skip the suite checkpoint, and a failure cannot later become delivered. It does not launch processes/containers, inspect pack snapshots, interpret JUnit, compose verdicts/sticky evidence, or clean workspaces. A container read-only claim is downgraded to a snapshot-boundary claim when setup actually ran through the explicit trusted-host escape hatch. |
| `verifiers/blackbox_pack.py` | Typed black-box pack-phase owner. It preserves pre/post pack identity checks, live provider ordering, bounded-process failure classification, and judge-owned JUnit/exit interpretation. Candidate preparation, workspace lifetime, and the public result ABI stay in `blackbox.py`; candidate runtime evidence/cleanup sequencing has its own owner. |
| `verifiers/blackbox_candidate_runtime.py` | Strict-typed, stdlib-only owner of candidate launcher/CID evidence retries and candidate-container cleanup coordination. Scanner/sleeper providers remain live per retry; observed CIDs mutate monotonically before sorting; cleanup captures the kernel before freezing known IDs exactly once, resolves later providers in historical order, preserves `BaseException` identity, and adapts only the facade-owned `CandidateContainerCleanupError`. Concrete Docker request/result/kernel types and compatibility identities are injected by `blackbox.py`. |
| `execution/process.py` | Typed generic bounded-process requests/results, shared output capture, timeouts, and native process-tree cleanup. Cancellation preserves the exact active `BaseException`; every generic runner abort-cleanup stage that raises or is not positively proven is attached as a bounded secondary note, including a machine-readable Python 3.10 fallback. Safe diagnostic helpers are reusable, but the generic owner does not own the specialized judge, raw-Git finalizer, or GitHub-Attestation lifecycles; each retains a separate contract. |
| `execution/judge.py` | Typed black-box judge-process lifecycle: bounded stdout/stderr capture, timeout handling, reader lifecycle, and process-group cleanup. Cancellation preserves the exact active `BaseException` through a bare re-raise, attempts process-group and pipe-reader abort cleanup independently, accepts only each owner's exact positive proof, and attaches ordered, bounded diagnostics for every raised or non-proven outcome with a Python 3.10/hostile-`add_note` fallback. It does not build judge commands or interpret verdict evidence. |
| `execution/command.py` | Shell-free host-command resolution. On Windows it resolves trusted `PATHEXT` shims while excluding candidate-controlled relative `PATH` entries for bare commands. |
| `github_attestation.py` | Experimental protected-boundary adapter, released in v3.8.0, that freezes one artifact, invokes a constrained `gh attestation verify` pinned to one repository, signer workflow/digest, source ref/digest, GitHub Actions OIDC issuer, SLSA predicate, and hosted runners, retains a canonical receipt/raw output, and can bind that receipt through V2. GitHub CLI performs cryptographic attestation verification; EvoOM Guard does not parse untrusted predicate data or independently recreate GitHub/Sigstore verification. This module also owns its specialized process lifecycle: on abort, the exact primary `BaseException` remains authoritative; subprocess-tree and output-reader cleanup are attempted independently in that order; exact `True` is the only positive proof; and false or raised outcomes become ordered bounded secondary diagnostics. This does not extend the existing Windows departed-root cleanup claim or imply coverage of the generic, judge, or raw-Git lifecycle owners. |
| `isolation/docker.py` | Typed bounded Docker control, image inspection/pull, named-container execution, and cleanup. Image inspection output is accepted only as canonical `sha256:` plus 64 lowercase hexadecimal characters; tags and arbitrary CLI-looking strings never become the execution image argument. |
| `candidate/` | Dependency-free candidate input ownership: typed edit blocks, strict/lenient block parsers, and pure unique-anchor patch transforms. It performs no filesystem or process effects. |
| `blackbox.py` | Black-box orchestration and compatibility surface: pack intake, judge-command construction, candidate preparation, workspace lifetime, outer cleanup precedence, `BlackboxResult` projection, and the historical runtime/error patch seams. Pack-phase sequencing/interpretation delegates to `verifiers/blackbox_pack.py`, candidate evidence/cleanup coordination delegates to `verifiers/blackbox_candidate_runtime.py`, and historical private process seams delegate to `execution/judge.py`. |
| `workspace/` | Contained workspace I/O: atomic descriptor-relative/no-follow operations on POSIX; reparse rejection plus pre/post parent/object identity checks as a non-atomic Windows fallback. `candidate_tree.py` owns bounded base/head intake, `repository.py` owns filtered, symlink-preserving repository copying and cleanup exception precedence, and `repository_lifetime.py` owns one judgment's candidate/pack path registration plus exact cleanup-target order. Windows repository copying rejects a symlink/reparse root plus observed child junctions/non-symlink reparse objects, but still requires a quiescent source; it is not an atomic snapshot. A recursive-cleanup `FileNotFoundError` is accepted only after a fresh root-absence observation, without claiming stable absence against later recreation. Historical `repo_verifier` facades preserve their API and live monkeypatch seams. |
| `runtime_identity.py` | Workspace-owned canonical post-setup runtime-tree identity (`EVOGUARD_RUNTIME_TREE_V1`), including setup-created outputs. Its stable flat import path is retained. |
| `verifiers/fidelity.py` | Public setup-fidelity snapshot/change contracts and drift details; setup output exceptions are scoped to this validation step. |
| `verifiers/harness_policy.py` | Public deterministic protected-harness and glob policy contracts used before candidate execution. |
| `verifiers/junit_oracle.py` | Hardened JUnit parsing/grading. Directory report sets fail closed if any XML sibling is untrusted or invalid. |
| `pack_manifest.py` | Verifier-owned canonical pack contract: strict `pack.json`, regular-file-only inventory, framed `EVOGUARD_PACK_V2` digest, verified snapshots, and pack test discovery. Its stable flat import path is retained. |
| `candidate_runner.py` | The shell-free `$EVOGUARD_EXEC` launcher and delivered-isolation evidence for black-box candidates. |
| `verifiers/grading.py` | The pure score gradient (`fraction_score`). |
| `runners/` | Per-runner report wiring (`RunnerAdapter` + `instrument_command`). One adapter owner per runner plus a registry keeps the judgment engine runner-agnostic. |
| `adapters.py` | Compatibility facade that preserves the historical runner-adapter surface and live monkeypatch timing while delegating ownership to `runners/`. |
| `verdict_contract_v1_11.py` / `verdict_contract_v1_12.py` | Frozen schema-1.11 vocabulary plus the versioned 1.12 extension for digest-bound operating profiles and explicit harness-input path declarations. They contain no producer or verifier algorithm. |
| `guard.py` | **Producer compatibility facade.** `guard()` / `guard_from_diff()` / `candidate_from_dirs()`, live effect wiring, black-box runtime invocation, public `GuardResult`, and unchanged Markdown / JSON / SARIF output facades. Unified-diff, repo-native, and post-cleanup black-box sequencing delegate to their separate application owners; pristine-baseline execution delegates through `_run_baseline_suite` to `verifiers/repo_baseline.py`, and output projection/publication delegates to `integrations/guard_output.py`. Unprofiled records retain schema 1.11; explicit operating profiles select schema 1.12. |
| `integrations/guard_output.py` | Typed, stdlib-only owner of Markdown projection plus Markdown/JSON/SARIF publication. It consumes a structural result view and makes no verdict decision. Candidate-derived Markdown fields are context-escaped (including `&`, so character references cannot recreate hidden structure); top-level test counts, risk score, and dynamic evidence are type/range checked; and SARIF accepts only forward-slash repository-relative paths, rejecting controls, format characters, surrogates, ASCII drive prefixes, and backslashes while rendering message controls visibly. Publication stages an fsynced same-directory temporary file, rejects an observed symlink/directory/special/read-only destination both before staging and immediately before `os.replace`, and preserves an existing regular file's portable `rwx` mode bits. The text wrapper is opened with `closefd=False`; the writer retains exclusive ownership of the raw descriptor, releases the wrapper reference, disarms the cleanup slot, and attempts the raw close exactly once before unlink cleanup. This prevents both reused-descriptor closure and a Windows temporary-file handle leak when wrapper close fails. The parent directory must be trusted and quiescent between destination checks. Ownership, ACLs, xattrs, Windows security descriptors/alternate streams, and other non-portable metadata are not preserved. The parent directory is not fsynced, so this is single-file visibility/rollback hardening, not a power-loss, crash, NFS/distributed-filesystem, or multi-file transaction guarantee. `guard.py` retains the four historical public signatures and preserves benign wire bytes. |
| `patch_applier.py` | Compatibility facade for the historical patch API; implementation ownership is in `candidate/patch.py`. |
| `patchmin.py` | Pure, model-free helpers: delta-debugging (`minimize_patch`) plus `blast_radius_score`; the historical `risk_score` name remains an identity alias for compatibility. |
| `record_verifier.py` | Public bounded schema-1.11/1.12 semantic-verification API and ordered claim-family orchestration. It checks consistency against the declared contract; it does not rerun the judged change. |
| `verifiers/record_report.py` / `verifiers/record_isolation.py` / `verifiers/record_policy.py` / `verifiers/record_policy_types.py` | Explicit verifier-layer owners for the stable record-check envelope/schema-support pin, isolation-parity checks, independently re-derived operating-profile semantics, and the immutable ordered effective-policy type/shape projection. `record_policy.py` deliberately does not import the producer's policy predicate. `record_policy_types.py` performs no I/O, cleanup, process execution, hashing, report mutation, or verdict decision; the public facade retains contract selection and the profile-decision call. |
| `strict_json.py` | Foundation-owned, dependency-free fail-closed JSON decoding limits shared by policy and offline evidence consumers (duplicates, numbers, nesting, and Unicode). Its stable flat import path is retained. |
| `evidence.py` | Evidence-layer owner for bounded changed-line coverage measurement. It explicitly remains a candidate-writable quality signal for non-hostile code, not authenticated adversarial evidence or a verdict. |
| `evidence_bundle.py` | Canonical, bounded evidence envelopes: exact verdict/material bytes, manifest digests, Ed25519 authentication, and exact external context binding. Structural inspection does not imply authentication. |
| `finalizer_derivation.py` | No-checkout raw-Git reader and canonical `EVOGUARD_FINALIZER_GIT_BINDINGS_V1` derivation for candidate text, ordered deletions, effective policy, and verifier-pack identity. It compares those results with an untrusted verdict before finalizer signing. On cancellation, this owner preserves the exact primary `BaseException`, independently attempts process-tree then output-reader cleanup, accepts only exact `True` proof, and attaches ordered bounded secondary diagnostics for every false or raised outcome. This changes neither normal Git results nor verdict schemas and does not cover the separate GitHub-Attestation process owner. |
| `release_source_finalizer.py` | Finalizer-layer owner for exact protected-branch release-source handoffs, raw-Git binding comparison, and the separately keyed evidence envelope. Its output remains non-admitting until a later trusted admission step authenticates the execution. |
| `change_attempt_observation.py` | Deterministic advisory projection of one authenticated Trusted Finalizer `ALLOW` or `DENY`. It preserves closed source/outcome/assurance identities, treats all five evidence channels as one correlated source, exports no raw code/log/policy content, and grants no admission or external-action authority. |
| `artifact_admission.py` | Narrow detached-signature `.eab` records that bind one regular file's SHA-256 and size to an externally verified Trusted Finalizer `ALLOW`. It deliberately does not implement build provenance, OCI, publication, or deployment claims. |
| `artifact_digest_admission.py` | Experimental opt-in V2 records, released in v3.8.0, that bind one exact generic or OCI manifest-or-index SHA-256 digest plus opaque provenance-reference bytes to an externally verified Trusted Finalizer `ALLOW`. It does not parse or verify provenance, OCI registry state, build, publication, or deployment semantics. |
| `admission/artifact_provider_v3.py` | Unreleased library-only provider adapter for one canonical digest-qualified public GHCR subject. It requires one exact GitHub Artifact Attestation result for a direct same-revision branch build and exact builder run/attempt, relates it to external Trusted Finalizer repository/head context, retains canonical provider evidence, and uses unchanged V2 to sign the subject/receipt/finalizer relation. Retained verification is byte continuity; only explicit fresh reverification contacts the provider. Isolated mode inherits no ambient Docker config, so the registry-auth path is not yet demonstrated. It has no CLI, protected reference workflow, live OCI pilot, registry-retention, publication, deployment, reproducibility, safety, vulnerability, or SLSA-compliance claim. |
| `schemas/` | Packaged JSON Schema 2020-12 contracts for verdict records, evidence contexts/manifests, and artifact bindings; shipped in both wheel and zipapp artifacts. |
| `signing.py` | Optional Ed25519 byte/file signatures and stable DER-SPKI key identities. `cryptography` remains a lazy `sign` extra, not a core dependency. |
| `cli/` | The `evo-guard` command package. `cli/__init__.py` remains the public compatibility facade and dispatch surface. Typed stdlib-only owners now contain the orchestration for all 41 CLI handlers: `guard`, initialization/workflow generation, signing-key generation, diagnostic/version/pack inspection, the Agent Change family, the Trusted Finalizer family, the record family (`verify-verdict`, `verify-record`, `bundle-evidence`, `finalize-record`, `verify-bundle`), Artifact Admission V1, Artifact Digest Admission V2, the GitHub attestation receipt create/retained-verify/fresh-reverify trio, the GitHub attestation admission seal/retained-verify pair, the four-command Release Source Finalizer family, the three-command non-admitting producer-receipt family, the Release Source Admission V2 seal/offline-verify pair, and the Release Artifact Admission online-seal/detached-verify pair. The facade retains dependency lookup timing, trusted `.evoguard.json` loading, flag/config precedence, and shared GitHub policy/isolation helpers. |
| `cli/diagnostic_commands.py` | Stdlib-only, dependency-injected owner for environment diagnostics, verifier-pack inspection/reporting, and version output. The public facades retain live runtime/tool/pack provider lookup and byte-compatible text/JSON output. |
| `cli/init_command.py` | Stdlib-only, dependency-injected owner for credential-name validation, byte-exact public/private workflow generation, policy-path inference, and initialization write sequencing. The public facades inject callable providers so the owner retains every live path/filesystem/JSON lookup, including the historical callable-before-argument evaluation order, plus the historical helper names and output contract. |
| `cli/signing_commands.py` | Stdlib-only, dependency-injected owner for `keygen` sequencing and its exact no-clobber/error projection. The public `cmd_keygen` facade snapshots the lazy signing provider before any command-argument read. |
| `cli/record_commands.py` | Dependency-injected orchestration for exact-byte signature verification, semantic record verification, evidence creation, trusted record finalization, and ordered offline bundle verification. It performs no domain imports or direct filesystem/crypto effects; `cli/__init__.py` injects the established entry-time snapshots and live compatibility seams. |
| `cli/artifact_admission_commands.py` | Strictly typed, stdlib-only owner for the Artifact Admission V1 seal/verify command state machines. Domain callables, format, and exception classes are snapshotted by the public facade at entry; external-trust readers and the machine reporter remain live per use. Separate metadata/domain error boundaries, catch precedence, eager argument reads, projections, exit codes, and detached offline verification behavior are frozen by a pre-extraction vector and focused mutations. |
| `cli/artifact_digest_admission_commands.py` | Strictly typed, stdlib-only owner for the Artifact Digest Admission V2 seal/verify command state machines. It preserves entry-snapshotted domain values, live-per-use trust readers and reporting, eager stdin tuple reads, metadata/domain error separation, subclass catch precedence, exact projections, retained partial outputs, and the verifier's closed-world offline argument boundary. |
| `cli/github_attestation_receipt_commands.py` | Strictly typed, stdlib-only owner for GitHub attestation receipt creation, retained-byte verification, and fresh provider re-verification. Domain callables, format, and the domain exception remain entry snapshots; policy, online provider isolation, and reporting remain live-per-use facade seams. The retained verifier has no GitHub executable or provider-isolation service, imports no environment/filesystem/process implementation, and preserves its closed-world offline boundary. |
| `cli/github_attestation_admission_commands.py` | Strictly typed, stdlib-only owner with two independent state machines for freshly sealing and later verifying the finalizer-bound GitHub attestation admission. Function-local format/domain/error/signing imports remain facade entry snapshots; trust readers, policy, sealing isolation, and reporting remain live-per-use providers. The retained verifier service has no GitHub executable, timeout, provider-isolation, network, signing-key, or output-mutation seam. |
| `cli/release_source_finalizer_commands.py` | Strictly typed, stdlib-only owner for release-source handoff creation, protected sealing, detached verification, and raw-Git control derivation. Domain values and callables remain entry snapshots; external trust readers, path projection, and reporting remain live-per-use facade seams. The owner preserves exact stdin rejection, metadata/domain/signing classifications, `ALLOW`/`DENY` opt-in exits, ordered source-then-context publication with historical partial output, and the local raw-Git boundary without adding network or checkout behavior. |
| `cli/release_source_producer_receipt_commands.py` | Strictly typed, stdlib-only owner for unsigned producer-receipt creation, local/raw-Git verification, and fresh provider re-verification. Domain values and callables remain entry snapshots; the shared external-input helper, trust reader, path projection, and reporting remain live facade seams. Verification remains deliberately non-admitting (`verified=true`, `ok=false`) unless archive-only exit success is explicitly requested; no admission key, provider-isolation builder, or executable-pin capability is added to these command services. |
| `cli/release_source_admission_commands.py` | Strictly typed, stdlib-only owner with separate Release Source Admission V2 seal and detached-verify state machines. The seal service alone receives protected-runtime identity, pinned raw-Git, isolated GitHub verification, provider-evidence, signing, and preflight seams. The verifier service structurally has no environment, Git/GitHub execution, provider isolation, private key, preflight, or publication authority. Function-local domain values remain entry snapshots while trusted readers, compatibility helpers, environment lookup, and reporting remain live at their historical use sites. |
| `cli/release_artifact_admission_commands.py` | Strictly typed, stdlib-only owner with separate online-seal and detached-offline verification state machines for Release Artifact Admission. Function-local domain callables, formats, error classes, signing-key identity, Git pinning, and provider-isolation builders remain facade entry snapshots; environment, path preflight, nested expectations, external readers, key separation, and reporting remain live-per-use providers. The verifier service structurally exposes no environment, Git/gh executable, repository, provider-isolation, private-key, signing-operation, or output-mutation capability. |

## Contract ownership and independence

The shared contract is deliberately **data, not a shared decision engine**. The
producer and semantic verifier may use the same immutable names and compatibility
table, but they must not call the same lifecycle, policy-digest, assurance, or
admission implementation. Otherwise one defect could make both sides agree on a
false claim. Compatibility is guarded by an external frozen fixture that is not
generated from the contract module.

```text
frozen vocabulary ─┬─► producer logic ─► verdict record
                   └─► independent semantic checks ─► verification report

external golden fixture ─► compares vocabulary + schema + producer API + verifier output
```

The record's major claim families have intentionally bounded meanings:

| Claim family | Producer evidence | What offline verification establishes | What it does not establish |
|---|---|---|---|
| Subject identity | Candidate/tree/revision digests observed by the judge | Field shape, parity, and documented digest relationships inside the record/bundle | That an external repository currently has those bytes unless supplied and re-hashed |
| Policy binding | Complete `effective_policy` plus canonical `policy_sha256` | Recomputed policy digest and policy↔runtime consistency | That the policy was organizationally approved |
| Execution lifecycle | Phase/state receipts repeated across result, assurance, and attestation | Cross-field consistency for `static_gate`, `not_started`, `started_incomplete`, or `completed` | That execution occurred merely because JSON says it did; authentication/runtime evidence remain separate |
| Isolation delivery | Observed launcher/container receipts and effective boundary | Consistency of top-level, assurance, attestation, and invocation semantics | Independent remote attestation of the host, kernel, or container runtime |
| Report integrity | Judge-owned report channel, exit code, and report digests | Verdict/count/source consistency and impossible-combination rejection | Quality or completeness of the tests themselves |
| Verifier-pack identity | Manifest, snapshot digest, phase receipts, and counts | Pack identity/count/lifecycle consistency; bundle verification can re-hash enclosed material | Secrecy of a same-host pack or correctness of its assertions |
| Admission | Verdict, reason code, counts, source, and assurance | The frozen reason/verdict/lifecycle truth table and related cross-field rules | Complete software correctness, absence of vulnerabilities, or author intent |

JSON Schema remains an independent structural publication; semantic verification
remains code; signature/context verification remains a third boundary. None is a
substitute for the others.

## Data flow (a `--diff` run)

```
git diff ─► guard_from_diff(head_dir, diff_text)
  │   application/diff_verification.py owns the ordered coordination;
  │   guard.py supplies every filesystem/process/verdict effect live
  │   reject empty / binary / unsafe-path diffs up front (clear ERROR, no apply)
  │   copy head → base ; reverse-apply the diff to reconstruct "base"
  ▼
candidate_from_dirs(base, head) ─► <<<FILE>>> blocks (add/modify) + deleted[]
  ▼
guard(base, candidate, deleted=…)
  │   validate runtime scalars; snapshot GuardRequest; construct canonical policy
  │   pre-gate: unsafe path → ERROR ; effective-policy protected edit/deletion → REJECTED
  ▼
RepoVerifier.verify(candidate, problem)
  │   copytree(base) → copy   (original never touched)
  │   apply FILE/PATCH blocks ; apply safe deletions ; restore package.json harness fields
  │   snapshot + identify verifier pack outside candidate tree (when configured)
  │   optional setup_command:
  │     subprocess mode → host subprocess (temporary HOME/minimal env; not sandboxed)
  │     docker/gvisor → resolve one canonical image ID for this verification;
  │                     writable setup container by default; verify setup fidelity
  │   if a repo-native pack is configured: identify the complete post-setup
  │     runtime tree (including setup-created outputs) as EVOGUARD_RUNTIME_TREE_V1
  │   instrument_command → splice a judge-owned JUnit reporter (per adapter)
  │   run repo suite: subprocess (POSIX rlimits + timeout) | docker | gvisor(runsc)
  │   if pack configured: run it as a separate mandatory pytest phase
  │   container suite + pack mounts are read-only; verify candidate/pack snapshots
  │   read judge-owned report(s) + exit code(s), compose both phases
  │     directory JUnit: any invalid/symlink/special XML invalidates the whole set
  ▼
grade_repo_run + detect_tamper ─► VerdictResult
  ▼
GuardResult ─► verdict + exit code + JSON + Markdown + SARIF

exact verdict bytes ─► verify-record ─► structural/cross-field report
exact verdict + trusted context/key ─► bundle-evidence ─► canonical .evb
.evb + external public key/context ─► verify-bundle ─► authenticated semantic result
```

## The two invariants that make it reward-hack-resistant

1. **Judge-owned verdict path.** The structured report is written to a path *outside*
   the repo copy, so a patch cannot pre-plant it through an edit block. The verdict
   comes from that report + the exit code, **never** from candidate stdout — so a
   forged `"N passed"` does nothing. An exit-code/report disagreement is surfaced as
   `TAMPERED`. Repo-native code still shares the reporter process and therefore has
   `report_integrity: same_process_candidate_writable`; black-box mode is the stronger
   external-process boundary.
2. **Harness-edit pre-gate.** Any edit *or deletion* of a test, its config, a lock
   file, the gate's CI, or an auto-exec file (`sitecustomize.py`, `*.pth`, `Makefile`,
   …) is `REJECTED` before the suite runs. See `is_protected*` / `is_judge_autoexec`
   in `repo_verifier.py`.

## How to extend it

- **Add a test runner:** add one owner module under `evoom_guard/runners/`
  (a `RunnerAdapter` with a `matches` + `instrument` pair that wires a JUnit
  reporter to an **absolute, judge-owned** path), then append it to
  `runners.registry.INNER_ADAPTERS`. Keep shared executable grammar in
  `runners/_command.py`; `evoom_guard.adapters._INNER_ADAPTERS` is only the
  historical live compatibility seam. Add its config/lock files to
  `_PROTECTED_CONFIG`.
  A runner whose only machine-readable output is stdout does **not** qualify (stdout
  is forgeable) — leave it on exit-code grading. A runner that emits **one file per
  test class** (Maven Surefire) points its reports directory at `<report_path>.d`;
  the verifier falls back to `parse_junit_dir` to merge them. The directory is one
  evidence set: an unreadable, malformed, oversized, DTD/entity-bearing,
  symlinked, or special XML sibling invalidates the whole set. Add adapter unit
  tests in `tests/test_adapters.py`.
- **Add an isolation backend:** extend `RepoVerifier` (`_docker_command` / `_run_docker`
  are the pattern) and keep the pre-gate running *before* any sandbox starts.
- **Change pack behavior in one place:** extend `pack_manifest.py`; every consumer
  must use the same manifest parser, V2 identity, snapshot verification and non-zero
  test requirement.
- **Never read the verdict from stdout**, and **keep the core dependency-free** —
  third-party needs live in the runner image or the adapter, not the core.

## Trust boundary (short)

The default `subprocess` judge uses a wall timeout everywhere and CPU/memory rlimits
on POSIX; it is for **trusted** repos, not a sandbox. Every black-box isolation
mode uses the same POSIX executable launcher and fails closed on native Windows
before subprocess, Docker, or gVisor delivery (use Linux/GitHub Actions or WSL).
`--isolation docker` runs setup inside the
resolved image by default, then runs suite and pack containers against read-only
mounts; `gvisor` adds a separate user-space guest kernel. Explicit
`setup_output_globs` are trusted policy exceptions to the general setup-fidelity
scan, but never exempt declared `harness_inputs` or their ancestors. Other
exceptions do not remove content from pack-backed post-setup runtime identity.
Repo-native and black-box paths (including `--blackbox-only`) bind explicit
`harness_inputs` before materialization and recheck them at their documented
runtime boundaries. In the black-box path, inability to establish that initial
trusted binding is an `ERROR`; only a subsequent materialized/runtime mismatch
is `TAMPERED`. Subprocess continuity is a boundary snapshot check—not filesystem
isolation or continuous immutability—while Docker/gVisor can
claim read-only enforcement only without host setup opt-in. POSIX workspace
operations are descriptor-relative/no-follow;
Windows performs best-effort pre/post identity checks because stdlib lacks an
atomic equivalent. `trust_setup_on_host` deliberately weakens effective
isolation. A Firecracker
microVM backend is documented as a future design but is not built. See
[`GUARD.md`](GUARD.md) and [`VM_ISOLATION.md`](VM_ISOLATION.md).
