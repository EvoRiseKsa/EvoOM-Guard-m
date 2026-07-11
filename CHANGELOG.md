<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Changelog

All notable changes to EvoOM Guard are recorded here. The format is loosely based
on [Keep a Changelog](https://keepachangelog.com/), and the project follows
semantic versioning (`vMAJOR.MINOR.PATCH`).

## [3.2.0] — 2026-07-11

A second review reproduced four false-`PASS` paths in the v3.1 black-box mode and
was **correct**: `candidate_isolation` was written from the requested flag, not
what ran; deletions were never applied to the judged tree; the pack replaced the
repo's own suite instead of adding to it; and the attestation was partial. This
release closes all four — the black-box judge now delivers a **real** isolation
boundary and reports only what it delivered.

### Fixed (security / correctness)
- **Delivered isolation, fail-closed.** A new `CandidateRunner`
  (`evoom_guard/candidate_runner.py`) runs the candidate under an *actual*
  boundary and returns evidence of what ran. `candidate_isolation` is that
  delivered value — never the requested flag. Request `--isolation docker` with
  no daemon / a missing image and Guard returns `ERROR`
  (`assurance_requirement_not_met`, isolation `unavailable`) instead of a `PASS`
  mislabelled `docker`. No silent fallback to a weaker boundary.
- **Deletions are applied in black-box mode.** A removed file is absent in the
  judged copy (matching the real merge); the attestation records
  `deleted_paths_applied`.
- **Composite verdict.** `--blackbox` now requires the repo's own suite **and**
  the external pack to pass — a green pack can no longer mask an internal
  regression. `--blackbox-only` opts pure-CLI/service targets out of the repo
  suite.
- **Container pack separation.** In a container boundary the repo copy is mounted
  read-only and the judge-owned pack is not mounted into the candidate at all, so
  candidate code cannot reach it or write the host. The subprocess boundary
  reports `verifier_pack.secrecy: reachable_same_host` honestly.

### Added
- **Complete black-box attestation**: `isolation_evidence` (requested/delivered/
  image_digest/network/runtime), `deleted_paths_applied`, `repo_suite_passed`,
  `repo_suite_junit_sha256`, `junit_sha256`, and `base_sha`/`head_sha` (extracted
  only when the diff carries them; never fabricated).
- **Pack protocol**: `$EVOGUARD_EXEC`, a launcher that runs the candidate under
  the delivered isolation with the repo copy as the working root. The example
  pack is isolation-agnostic and import-safe.
- Adversarial tests for every fixed path (`tests/test_assurance_policy.py`):
  fake-docker → `ERROR`; docker floor vs subprocess delivery → `ERROR`; deletion
  actually applied; repo-suite failure blocks a passing pack.

### Changed
- `python -m pytest -q` on the whole repo is green again: `testpaths = ["tests"]`
  scopes the repo's own suite, and the black-box example pack self-skips when not
  run by the judge (it was crashing collection on a missing `EVOGUARD_TARGET`).
- `schema_version` → **1.5**.

## [3.1.0] — 2026-07-10

Hardening from a deep architectural review — turns two `assurance` weaknesses it
found into enforced guarantees, without the risky big-architecture rebuild
(that's an explicit post-launch direction in `ROADMAP.md`).

### Added
- **Enforceable assurance policy** (`--require-report-integrity`,
  `--require-candidate-isolation`; Action inputs too). Fail-closed: if the run's
  *actual* assurance is below the requirement, the verdict is refused with
  `ERROR` / `assurance_requirement_not_met` — Guard can never claim a level it
  did not enforce. The check is against what ran, never the requested value.
- **Black-box verdicts now carry a full attestation** (the review's gap):
  `candidate_sha256`, `policy_sha256`, `verifier_pack_sha256`, the pack
  `manifest`, and `mode: "blackbox"`. The pack's content digest binds the
  verdict to exactly which protocol tests judged it.
- **Adversarial test**: a candidate CLI that returns a wrong answer *and* forges
  its own JUnit report cannot flip the black-box verdict — the judge grades by
  its own exit code, so a child's forged report only touches counts.

### Changed
- `schema_version` → 1.4 (attestation `mode`; the new reason code). Attestation
  is now built by one shared helper for both the repo and black-box paths.
- Docs: ASSURANCE gains an *enforcing* + *composing external/internal* section;
  ROADMAP names the real next major direction (an artifact-bound candidate
  sandbox) and marks it as post-adopter work, not a pre-launch cram.

## [3.0.0] — 2026-07-10

**The external black-box judge — the report-integrity boundary is now closeable.**

v2.3.0 disclosed, with a proof, that the default same-process judge can be
forged: a patch that writes an `atexit` hook + `os._exit(0)` + a fake
`--junitxml` fakes a `PASS`. This release ships the fix.

### Added
- **`--blackbox` external judge** (needs `--verifier-pack`): the verdict comes
  from the **judge's own pytest** over a pack of judge-owned tests that **never
  import the candidate**. The candidate is exercised only across a process
  boundary — the pack invokes it as a subprocess via `$EVOGUARD_TARGET` /
  `$EVOGUARD_PYTHON` and asserts on its outputs. Forgery code in the candidate's
  source runs only in those child processes and cannot reach the judge's report.
  `report_integrity` becomes **`external_process_isolated`** and
  `overall_profile` **`black_box_external_judge`**.
  See [`docs/BLACKBOX.md`](docs/BLACKBOX.md) and `examples/blackbox-pack/`.
- **Before/after proof** (`tests/test_blackbox.py`): the *identical* forgery that
  `tests/test_report_integrity.py` shows faking a `PASS` under the default judge
  is **caught** (`FAIL`) under `--blackbox`. Harness-integrity rejection still
  applies in black-box mode.
- GitHub Action gains a `blackbox` input.

### Changed
- README leads the honest-boundary callout to the `--blackbox` fix; ASSURANCE and
  ROADMAP mark the external judge as shipped (hardening — container-per-candidate,
  HTTP/DB helpers — is the next step). Marketing updated: the pitch is now
  "closes the forgery hole for CLI/service targets", not a qualified caveat.

### Note
- Major version bump: `--blackbox` changes the trust story materially (a real
  `report_integrity` guarantee for protocol targets). The default judge, the JSON
  contract (`schema_version` 1.3), and every existing flag are unchanged and
  backward-compatible.

## [2.3.0] — 2026-07-10

An adversarial review demonstrated a real forgery of the core verdict; this
release makes the boundary honest and machine-readable rather than papering over
it. No behavioural regression — the reward-hacks Guard blocked before, it still
blocks.

### Security / honesty (the important part)
- **Corrected the "cannot be forged" claim.** A patch that runs in the test
  process can register an `atexit` hook, overwrite the judge-owned JUnit report,
  and call `os._exit(0)` — forging a `PASS` on a genuinely failing test. This is
  now **proven by an adversarial test** (`tests/test_report_integrity.py`) and
  named plainly everywhere. Guard still blocks the reward-hacks agents do in
  practice (harness edits/deletions, config deselects, stdout forgery — all with
  tests); it does not stop deliberate in-process report forgery, which the
  container modes do **not** fix (they isolate the host, not the report).
- **New `assurance` object on every verdict** (`schema_version` → 1.3):
  `harness_integrity` (`pre_gate_enforced` — robust), `report_integrity`
  (`same_process_candidate_writable` — the honest boundary), `candidate_isolation`,
  `verifier_pack`, `overall_profile`. A `PASS` report now spells out the caveat
  inline. See the new [`docs/ASSURANCE.md`](docs/ASSURANCE.md).
- **ROADMAP**: the **external black-box judge** (candidate never runs in the
  judge's process) is now the explicit headline direction — the only thing that
  turns `report_integrity` into a real guarantee.

### Changed
- README mechanism 2 reworded from "the verdict cannot be forged" to "the result
  is judge-owned, not scraped from stdout", with a prominent honest-boundary
  callout. Marketing materials updated to match (no "unforgeable").

## [2.2.1] — 2026-07-10

Launch-hardening from an adversarial review — no new surface, higher fidelity.

### Fixed
- **`evo-guard init` now scaffolds `python -m pytest -q`** (was bare `pytest -q`),
  matching the documented default so a generated workflow imports top-level
  packages without an install/conftest.
- **Timeouts and setup failures get their own reason codes** — `test_timeout`,
  `setup_timeout`, `setup_failed` — instead of being mislabelled
  `patch_apply_failed` (the patch *did* apply; the run timed out).
- **Deletions now count toward the blast-radius score** — a change that removes
  source files no longer reads as *lower* risk than one that edits them.

### Added
- **GitHub Action exposes the v2.2 evidence flags**: `verifier-pack`,
  `diff-coverage`, `min-diff-coverage` inputs, forwarded to the CLI (with the
  `cov` extra installed only when coverage is requested). A parity test fails if
  any gate-relevant CLI flag is missing from the Action.
- **Optional `pack.json` manifest** for a Verifier Pack (`id` / `version` /
  `description`) — surfaced in the verdict attestation for auditable policy
  versioning.

### Changed (honesty)
- **Verifier Pack docs/help corrected**: a pack is **tamper-proof, not secret**.
  The running test code *can* read the pack off disk, so it is an integrity
  control (org-owned, unmodifiable invariants), not a hidden oracle. New
  `docs/VERIFIER_PACKS.md` states the guarantee and its limit; an adversarial
  test pins the limitation so the claim cannot silently drift back to "hidden".
- Action description: "Unforgeable verdict" → "Judge-owned verdict" (no absolute
  claim beyond what the design supports).

## [2.2.0] — 2026-07-10

**The first evidence release** — the gate starts its evolution from deny-rules
toward an evidence-based change-integrity engine (see `ROADMAP.md`).

### Added
- **Changed-line coverage evidence** (`--diff-coverage`, the `cov` extra): one
  extra suite run under a judge-owned `coverage` measurement answers *which
  changed lines did the suite actually execute?* Non-executable changed lines
  are excluded via coverage's own statement knowledge; non-Python files are
  reported as unmeasured, never silently counted. Evidence by default;
  `--min-diff-coverage PCT` turns it into a gate — a hollow `PASS` (suite green,
  changed lines unexecuted) becomes `FAIL` with the new reason code
  `diff_coverage_below_threshold`. The output carries its own honesty line:
  *executed is not asserted*.
- **Independent Verifier Pack** (`--verifier-pack DIR`): judge-owned tests /
  invariants the **patch cannot modify** (org-owned checks injected at judgment
  time), mounted into the throwaway copy at `evoguard_verifier_pack/` and
  collected with the suite (pytest runners). Counters visible-test overfitting;
  a candidate that writes under the mount point is `REJECTED`; the pack's content
  digest — and an optional `pack.json` manifest (id/version) — land in the
  attestation. Honest scope: **tamper-proof, not secret** — the running code can
  read the pack; the guarantee is that the patch cannot change the checks (see
  `docs/VERIFIER_PACKS.md`).
- **Attestation block** in every verdict JSON: `candidate_sha256`,
  `policy_sha256`, `junit_sha256`, `verifier_pack_sha256`, timestamps and
  versions — a signed verdict is now bound to what was judged and under which
  policy, not only to its own bytes (the step before in-toto/Sigstore).
- JSON contract moves to `schema_version` **1.2** (additive fields + one new
  reason code).

## [2.1.2] — 2026-07-10

### Changed
- **Action description shortened** to satisfy the GitHub Marketplace 125-character
  limit (surfaced by the Marketplace validation on the v2.1.1 release form). The
  full description lives in the README; no behavior change.

## [2.1.1] — 2026-07-10

### Added
- **GitHub Marketplace branding** on the composite Action (`branding: shield /
  red`) — required for the Marketplace listing; no behavior change.

## [2.1.0] — 2026-07-10

### Added
- **Signed verdicts** (the `sign` extra — the core stays stdlib-only):
  `evo-guard keygen` generates an Ed25519 judge keypair; `evo-guard guard …
  --json v.json --sign-key key.pem` writes a detached base64 signature of the
  verdict file's exact bytes to `v.json.sig`; `evo-guard verify-verdict` checks
  it offline (exit 0 valid / 1 invalid). A post-signing byte change — the
  `FAIL`→`PASS` artifact forgery — flips verification to invalid (adversarial
  test included). See `docs/SIGNED_VERDICTS.md`.
- **`ROADMAP.md`**: the patch gate placed inside the agent-governance picture
  (signed evidence chains, capability ledgers).
- **`docs/PROOFS.md`**: a second live proof on a hard, ungameable counting
  benchmark (fresh-randomized suite, oracle-free huge-`n` identities, strict
  time budget): the cheat patch is `REJECTED` before the suite runs; an honest
  `O(log n · m²)` solution earns `PASS` under the exit-code oracle.

## [2.0.0] — 2026-07-10

**Consolidation release.** This repository's v0.1.0 was a fresh extraction of the
guard core from the EvoOM platform; in parallel, the same gate had already evolved
through eight releases (v1.1.0 → v1.8.0) in the internal **EvoGuard** repository.
v2.0.0 replaces the v0.1.0 code with that mature engine — one project, one
history, going forward developed here.

### Added (relative to v0.1.0 of this repository)
- **`TAMPERED` verdict**: an exit-code ⟷ JUnit-report disagreement is surfaced as
  its own verdict (a forgery signature), never read as a pass.
- **Deletions are gated**: a patch that *deletes* a protected test/config/CI/
  auto-exec file is `REJECTED`; safe source deletions are applied to the verified
  copy and tested (they were previously reported but unverified).
- **Eight structured-verdict runners** via `evoom_guard/adapters.py`: pytest,
  `node --test`, vitest, jest, gotestsum (Go), rspec (Ruby), mocha, and
  Maven/Surefire (Java) — each with judge-owned `junit+exit` verdicts and real
  test counts. Custom commands still grade by exit code (never stdout).
- **Isolation modes**: `--isolation docker` / `gvisor` run the suite in a
  network-less, read-only container (`--docker-image`, `--docker-network`).
- **Machine-readable JSON contract**: stable `schema_version` and fixed
  `reason_code` vocabulary for every verdict (see `docs/JSON_SCHEMA.md`), plus
  **SARIF 2.1.0** output (`--sarif`) for GitHub code scanning.
- **Hardened JUnit parsing**: per-file size cap and DTD/`ENTITY` refusal;
  directory-of-reports merging for Maven Surefire.
- **CLI subcommands**: `evo-guard guard` / `doctor` / `init` / `version`,
  project config via `.evoguard.json`, `--allow` baseline allowlist, and
  `--allow-new-tests` feature mode (brand-new test files allowed; edits to
  existing harness still rejected).
- **Sticky PR comment**: the GitHub Action upserts one marker-keyed comment
  instead of appending a new one per push.
- **Single-file build**: `ops/build_pyz.py` produces a zero-dependency
  `evo-guard.pyz` zipapp.
- Docs imported: `GUARD.md`, `ADOPTION.md`, `ARCHITECTURE.md`, `JSON_SCHEMA.md`,
  `REWARD_HACKING_CATALOG.md`, `PROOFS.md`, `VM_ISOLATION.md`, `FEATURE_MODE.md`.

### Changed
- Python package renamed `evogu` → `evoom_guard`; the CLI keeps this repo's
  `evo-guard` name (now subcommand-based: `evo-guard guard …`). The composite
  Action stays at the repository root (`uses: EvoRiseKsa/EvoOM-Guard-m@<ref>`).
- The v1.x history below is imported verbatim from the internal EvoGuard
  repository (module paths/CLI names appear as renamed here; version links
  point to that internal repo and are omitted).

---

# Imported history — EvoGuard v1.x (internal repository)

## [1.8.0] — 2026-06-17

A **feature** release that widens language coverage and closes the deletions gap.
The verdict names and the `reason_code` vocabulary are unchanged; the JSON contract
moves to `schema_version` **`1.1`** for the one rename noted below.

### Added
- **Four more structured-verdict runners.** The judge-owned `junit+exit` path now
  covers **Go** via `gotestsum --junitfile`, **Ruby** via
  `rspec --format RspecJunitFormatter --out`, **mocha** via `mocha-junit-reporter`,
  and **Java/Maven** via `mvn test` (Surefire's `-Dsurefire.reportsDirectory`) —
  bringing the total to eight (pytest, `node --test`, vitest, jest, gotestsum,
  rspec, mocha, maven), each with real counts and the exit⟷report tamper check.
  Bare `go test -json` stays exit-code-only by design (its only machine-readable
  output is forgeable stdout). New adapters live in `evoom_guard/adapters.py`; one class
  per runner, the core stays runner-agnostic.
- **Directory-of-reports JUnit reading** (`parse_junit_dir`). Maven Surefire writes
  one `TEST-*.xml` per class into a *directory*; the adapter redirects it to a
  judge-owned `<report>.d` (outside the repo copy) and the verifier merges every
  `*.xml` there through the same hardened per-file parser (size-cap + DTD/`ENTITY`
  refusal).
- **`--docker-network`** to set the container network for `--isolation
  docker`/`gvisor` (default `none`, the safe choice) — exposed on **both** the CLI
  and the GitHub Action (`docker-network` input), with a new test that asserts every
  gate-relevant CLI flag is forwarded by the Action so parity can't silently regress.
- **`docs/ARCHITECTURE.md`** — a codebase map (module responsibilities, data flow,
  the two invariants, how to extend).

### Changed
- **Deletions are now gated (the one breaking JSON change → `schema_version` `1.1`).**
  A change that **deletes a protected harness file** (a test, its config, the gate's
  CI, or an auto-exec file) is now `REJECTED` — removing a check is as much a
  reward-hack as editing one. A deleted **source** file is **applied to the verified
  tree**, so the verdict matches the real merge (previously deletions were ignored,
  and the suite ran against a tree that still contained them). The optional JSON
  array `deleted_not_gated` is renamed to `deleted` to reflect this.
- **More protected harness files** for the new runners: `go.sum` (Go dependency
  hashes — a lock file), `.rspec` (RSpec config — can deselect specs),
  `Rakefile`/`rakefile` (a test-task runner like `Makefile`), and `pom.xml` (a
  Maven Surefire `<excludes>` can deselect failing tests — use `--allow pom.xml`
  to permit dependency edits in the same change).

### Docs
- Refreshed `docs/DEVELOPMENT_PLAN.md` and `docs/README.md` to the current code
  (removed stale references to internal names that no longer exist; the structured
  path is adapter-based and covers seven runners).
- Documented that `setup_command` runs on the **host**, not inside the container,
  under `--isolation docker`/`gvisor` (`docs/GUARD.md`).

## [1.7.0] — 2026-06-17

A **feature + hardening** release. Backward-compatible: the JSON contract
(`schema_version` stays `1.0`), the verdict names, and the `reason_code` vocabulary
are unchanged.

### Security
- **Hardened JUnit-report parsing.** `parse_junit_xml` now **size-caps** the input
  and **refuses any DTD / `DOCTYPE` / `ENTITY`** before parsing — eliminating
  entity-expansion ("billion laughs") and external-entity DoS vectors on the report
  path (which the candidate's *test process* can write to). A rejected report yields
  no counts (the run grades as `FAIL`), never a parser hang. No change for
  legitimate reports.

### Added
- **GitHub Action ↔ CLI parity.** The composite action (`.github/actions/evoguard`)
  now exposes the full gate: `isolation` (docker/gvisor), `docker-image`, `sarif`,
  `allow` (baseline allowlist), `allow-new-tests` (feature mode), `timeout`, and
  `mem-limit` — previously only `test-command` / `protected` were reachable, so
  Action adopters could not enable the isolation / SARIF / allowlist features.
- **Release integrity.** `publish-pyz` now also generates and attaches a
  `SHA256SUMS` asset alongside `evogu.pyz`, so the single-file binary can be
  verified (`sha256sum -c SHA256SUMS`) before running a security gate.

### Changed
- README clarifies that `evogu.pyz` is **convenience packaging, not source
  protection** (a `.pyz` is a readable zip; access control is the private repo).

### Docs
- Added `docs/README.md` — a documentation index that establishes
  a **single source of truth**: it separates *canonical* docs (current, v1.6.0) from
  *forward design* (not implemented) and *historical / point-in-time records* (kept
  but not maintained), and states the distribution / source-protection decision
  plainly. (Review rec 5; rec 4 positioning.)

### CI
- New **`e2e-runners`** job runs the structured-verdict oracle **end-to-end against
  real runners** (vitest + `node --test`), not just the adapter wiring — installing
  the vitest CLI so its e2e test no longer skips. (docker e2e already runs on the
  hosted runner; jest and gVisor remain environment-gated for documented reasons.)

## [1.6.0] — 2026-06-17

A **feature** release. Backward-compatible: the JSON contract (`schema_version`
stays `1.0`), the verdict names, and the `reason_code` vocabulary are unchanged.

### Added
- **Baseline allowlist (`allow`)** — adopter-curated globs (`--allow` or
  `.evoguard.json`) that **exempt** a path from the test / config / CI rejection,
  for a built-in pattern's false positive (e.g. a `Makefile` that runs no tests) or
  a known pre-existing hit. It **never** exempts an auto-exec judge file
  (`sitecustomize.py` / `*.pth`) or an unsafe path — those stay rejected regardless.
  The inverse of `protected`; use it deliberately (allowlisting a real judging test
  reopens that hole). (Phase 4 / DX.)

## [1.5.0] — 2026-06-17

A **feature** release. Backward-compatible: the JSON contract (`schema_version`
stays `1.0`), the verdict names, and the `reason_code` vocabulary are unchanged.

### Added
- **`--sarif <file>`** — write a **SARIF 2.1.0** report so the verdict surfaces in
  GitHub **code-scanning** (the Security tab + inline PR annotations). A clean
  `PASS` emits no results (no alert); any non-`PASS` becomes one `error`-level
  result keyed on the stable `reason_code`, located on the offending files. SARIF
  is only a *view* — the decision stays the verdict + exit code. (Phase 4 / DX.)
- **`--isolation gvisor`** — a third isolation mode: the container judge run through
  the gVisor `runsc` OCI runtime, giving the suite its own **user-space guest kernel**
  (no `/dev/kvm` / nested virtualization needed) for a separate-kernel boundary on
  untrusted code. Reuses the docker judge verbatim (network-less, read-only, caps,
  judge-owned report) plus `--runtime runsc`; needs docker with the `runsc` runtime.
  Implements Phase 2d-i — see `docs/VM_ISOLATION.md`. **Validated live** on a real
  KVM-guest VPS (gVisor `4.19.0-gvisor` kernel): clean → `PASS` (`junit+exit`),
  reward-hack → `REJECTED` — recorded in `docs/PROOFS.md`.

### Changed
- The Markdown report footer now describes the **actual** judge (subprocess /
  network-less container / gVisor `runsc` guest kernel) instead of always saying
  "subprocess" — an accuracy fix surfaced by the first live `--isolation gvisor` run.

## [1.4.0] — 2026-06-16

A **feature** release. Backward-compatible: the JSON contract (`schema_version`
stays `1.0`), the verdict names, and the `reason_code` vocabulary are unchanged.

### Added
- **jest** joins the native structured-verdict oracle (`verdict_source: junit+exit`,
  real counts + the exit⟷report tamper check), alongside pytest, `node --test`, and
  vitest. A new `JestAdapter` splices `--reporters=default --reporters=jest-junit`
  and — because jest has no CLI option for a per-reporter output path — hands the
  **judge-owned** report path to `jest-junit` via the `JEST_JUNIT_OUTPUT_FILE`
  environment variable (`jest-junit` must be resolvable in the repo, e.g. installed
  by `setup_command`). The verdict is still read only from the judge-owned file,
  never candidate stdout. `instrument_command` now also returns the reporter env the
  caller merges into the suite's environment; the subprocess and docker judges both
  apply it.
- **Feature mode (`allow_new_tests`, opt-in, default off)** — lets a change add
  **brand-new** test files while still rejecting any edit to an *existing* test or
  to the harness (config / lock files / auto-exec / `conftest.py` / CI / caller
  `protected` globs), so a feature PR can ship its own tests without reopening the
  existing-test reward-hack. Enable per repo via `.evoguard.json`
  (`{"allow_new_tests": true}`) or per run via `--allow-new-tests`. New test code
  still runs in the judge process, so it is for trusted authors — see
  `docs/FEATURE_MODE.md` for the threat analysis.
- **Single-file binary distribution.** Each release now attaches a zero-dependency
  `evogu.pyz` (a Python zipapp, built by `ops/build_pyz.py` and published by CI on a
  version tag) so adopters can run the gate **without cloning the private source or
  installing anything** — only Python ≥ 3.10 is needed. The archive carries a
  hand-written `__main__` so the CLI's exit code propagates (a non-`PASS` verdict
  still exits non-zero and gates CI).

## [1.3.0] — 2026-06-16

A **feature + hardening** release, driven by applying EvoGuard to a real
TypeScript/pnpm monorepo. Backward-compatible: the JSON contract
(`schema_version` stays `1.0`), the verdict names, and the `reason_code`
vocabulary are unchanged.

### Added
- **`setup_command`** — an optional step that runs inside the repo copy *before*
  the test suite (e.g. `["pnpm", "install", "--frozen-lockfile"]`). It solves the
  "`node_modules` is not copied into the throwaway repo" problem without fusing
  install + test into a single shell string, keeping the token-list
  `test_command` clean. Available on the `guard()` / `guard_from_diff()` API, the
  `evo-guard guard` CLI (via `.evoguard.json`), and `RepoVerifier`. A **failing setup
  is never a PASS**, and **setup stdout can never influence the verdict** (which
  still comes only from the judge-owned JUnit report + the test command's exit
  code).
- **`ShellAdapter`** — unwraps `["sh", "-c", "… && vitest run"]` (and
  bash/zsh/dash), instruments the inner runner, and reassembles the shell string.
  This restores the judge-owned-report verdict (and the exit⟷report tamper check)
  for Node.js suites that use the fused `install && test` shell form.
- **`evo-guard init --private-evoguard`** — scaffolds a pip-install workflow (PAT in
  an Actions secret) for repos where the private EvoGuard action can't be reached
  with the default `GITHUB_TOKEN`. `--evoguard-token-secret` names the secret
  (default `EVOGUARD_TOKEN`).
- **Automatic Node.js memory handling** — when a `package.json` is present and
  `mem_limit` was left at the default, the address-space cap is disabled
  automatically (V8 reserves far more virtual memory than any sane `RLIMIT_AS`,
  which would otherwise kill the suite at start-up).

### Changed / Security
- **A string `test_command` containing shell operators** (`&&`, `||`, `;`, `|`,
  `>`, `<`, `$(`, `` ` ``) is now wrapped in `sh -c` instead of being naively
  split on spaces — previously it produced wrong tokens and lost the pipeline
  semantics.
- **More harness-edit reward-hacks are rejected by default** (verdict `REJECTED`,
  before the suite runs):
  - colocated TS/JS test files (`*.test.ts`, `*.spec.tsx`, `*.snap`, …);
  - dependency lock files (`pnpm-lock.yaml`, `package-lock.json`, `yarn.lock`,
    `Cargo.lock`, `Gemfile.lock`, `poetry.lock`) — swapping one substitutes the
    actual library code that runs under the suite;
  - **EvoGuard's own `.evoguard.json`** — editing it could rewrite
    `test_command` / `setup_command` / `protected` to trivially pass;
  - **CI definitions** under `.github/workflows/` and `.github/actions/` —
    editing the workflow that *runs* the gate could disable it or swap the test
    command.
  - *Adopter note:* a PR that legitimately changes a CI workflow or the
    `.evoguard.json` will now be `REJECTED` and needs explicit human review.

## [1.2.0] — 2026-06-15

A **feature** release. Backward-compatible: the JSON contract (`schema_version`
stays `1.0`), the verdict names, and the `reason_code` vocabulary are unchanged, so
existing integrations keep working. It captures the multi-runner, isolation, and
DX work merged on `main` since `1.1.1`.

### Added
- **Multi-runner core-native verdicts.** Beyond pytest, the EvoGuard *core* now
  reads a judge-owned JUnit report (`verdict_source: junit+exit`, real counts, and
  the exit⟷report tamper check) for node's built-in **`node --test`** and for
  **vitest** — not just the exit code. Other runners (and `npm test` wrappers) still
  grade on the exit code alone.
- **Per-runner adapter layer** (`evoom_guard/adapters.py`): a small `RunnerAdapter`
  registry so a new runner is one localized class; `parse_junit_xml` is now
  dialect-agnostic (counts `<testcase>` elements).
- **Optional docker-isolated judge** — `--isolation docker --docker-image <img>`
  runs the suite in a short-lived, **network-less, read-only** container with
  CPU/PID/memory caps and a separate judge-owned report mount (defence in depth for
  semi-trusted code; not a complete boundary — see `docs/GUARD.md`).
- **`evo-guard init`** scaffolds a ready-to-use GitHub Actions workflow in one command.
- **`.evoguard.json`** repo config for per-repo defaults (test-command / protected /
  timeout / mem-limit); explicit CLI flags override it.
- **Reproducible campaigns** v2–v5 (Python `mathkit`, Node/TS `node_mathkit`,
  real-repo `six` / `escape-string-regexp`, and core-native `node --test` + vitest
  incl. a real-repo target) — each with an independent verifier and a negative
  self-check; plus the private-runner deployment plan + threat model.
- **Adoption docs:** `docs/ADOPTION.md` (one-page runbook) and
  `docs/REWARD_HACKING_CATALOG.md` (the catalogue of reward-hacks caught, with
  reproducible evidence), and `docs/DEVELOPMENT_PLAN.md`.

### Changed
- Dropped the unused heritage `CodeVerifier`; the shared score gradient now lives in
  `evoom_guard/verifiers/grading.py`. No behaviour change.
- Tightened the README claim from the absolute "cannot game" to the scoped, accurate
  "can't game the test harness" (+ an honest "guarantee is scoped" note).

## [1.1.1] — 2026-06-14

A private-alpha **maintenance** release. No new features; no changes to the core
verdict engine, the JSON contract (`schema_version` stays `1.0`), verdict names,
or reason codes. It captures the CI/Action and documentation work done on `main`
since `1.1.0`.

### Changed
- **GitHub Action PR comment now uses sticky/upsert behavior.** Instead of posting
  a new comment on every run, the Action updates one EvoGuard comment in place
  (keyed on a stable hidden marker `<!-- evoguard-report -->`), creating a comment
  only when none exists. Verified live (one comment updated across two runs).
- **`release-tag-guard` now runs on version tags.** The CI workflow triggers on
  `push: tags: ['v*']`, so the version⟷tag consistency check actually executes on
  a tagged build (previously the job was gated on tag refs the workflow never ran
  on).
- **Report wording clarified** around the trusted subprocess judge vs. a sandbox:
  the Markdown report footer no longer implies a "container judge" that this build
  does not ship; it now describes the judge-owned JUnit + exit-code verdict and the
  subprocess `rlimits`/timeout (not a sandbox), pointing to `docs/GUARD.md`.

### Added
- **Validation reports** documenting the alpha shake-out, under `docs/`:
  - `REAL_REPO_VALIDATION.md` — real-repo / fixtures validation.
  - `REAL_AI_PATCH_VALIDATION.md` — real AI-authored patches validation.
  - `GITHUB_ACTION_LIVE_VALIDATION.md` — live GitHub Action validation.
- A scoped `examples/live_demo` fixture + `evoguard-live` workflow used to exercise
  the Action live on real PRs (runs only on `evoguard-live/*` branches).

## [1.1.0] — 2026-06-14

- Initial extracted, focused EvoGuard release: the reward-hack-resistant patch
  verification gate (CLI + GitHub Action), with the `PASS` / `REJECTED` / `FAIL` /
  `TAMPERED` / `ERROR` verdict contract, a stable machine-readable JSON record
  (`schema_version` `1.0`), the `evo-guard doctor` command, and the judge-owned
  JUnit + exit-code verdict path.
