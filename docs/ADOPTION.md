<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
  Maintained and released by Mana Alharbi (مانع الحربي).
-->

# Adopting EvoGuard — a one-page runbook

EvoGuard is a CI gate that evaluates whether an untrusted code change
(with **AI-agent PRs** as the primary use case) satisfied the selected judge
without gaming its evidence. It is a single verdict + exit code; drop it into any
pipeline.

## 1. Turn it on (one command)

From the repo you want to protect (needs repo access — EvoGuard is private; pin a
release tag):

```bash
pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m.git@v3.5.0"
evo-guard init --test-command "python -m pytest -q"     # writes .github/workflows/evoguard.yml
git add .github/workflows/evoguard.yml && git commit -m "ci: add EvoGuard" && git push
```

That's it. On the next PR, the Action diffs it against the base, runs your suite,
posts a verdict comment, and **fails the check on anything but `PASS`**.

> No-action alternative — the two-line `git diff | evo-guard guard --diff -` form, or
> `evo-guard init --stdout` to review the workflow first. See [`GUARD.md`](GUARD.md).

> **No repo access / no pip?** Download the single-file `evo-guard.pyz` from the
> release assets and run `python evo-guard.pyz …` — the core is stdlib-only, so it
> needs no clone and no install (see the README "Install" section).
>
> Verify that download against the release's `SHA256SUMS`. A local rebuild is
> deterministic when it uses the same source bytes and an equivalent
> Python/OS/ZIP-zlib toolchain, but Windows and Linux builds are not promised to
> be bit-identical. This does not weaken release immutability: rerunning the
> release workflow cannot replace an existing asset with different bytes.

## 2. Read the verdict (what to do on each)

| Verdict | Exit | Meaning | Action |
|---|---|---|---|
| ✅ `PASS` | 0 | tests pass, harness untouched | merge |
| ❌ `FAIL` | 1 | the change's tests genuinely fail | send back to fix the **source** |
| ⛔ `REJECTED` | 1 | the change edits tests/config/auto-exec — a reward-hack | **block**; the fix must touch the source, not the harness |
| 🚨 `TAMPERED` | 1 | exit/JUnit disagreement, or candidate/pack snapshot drift during judgment | **block**; never read as a pass |
| ⚠️ `ERROR` | 1 | no trustworthy run: invalid diff/pack, setup failure, unavailable command/isolation, timeout or unmet policy | fix the reported prerequisite/policy error and rerun |

Every run also emits a machine-readable JSON record (`--json`) with a stable
`schema_version` and a fixed `reason_code` — integrations key off those. See
[`JSON_SCHEMA.md`](JSON_SCHEMA.md). What each verdict defends is catalogued in
[`REWARD_HACKING_CATALOG.md`](REWARD_HACKING_CATALOG.md).

`--sarif <file>` writes a **SARIF 2.1.0** report so the verdict surfaces in GitHub
**code-scanning** (the Security tab + an inline PR annotation): a clean `PASS`
yields no alert; any non-`PASS` becomes one `error` keyed on its `reason_code`,
located on the offending files. Upload it with `github/codeql-action/upload-sarif`.

## 3. Configure per repo (optional)

Drop a `.evoguard.json` at the repo root so you don't repeat flags:

```json
{ "test_command": "python -m pytest -q", "protected": ["migrations/*"], "timeout": 180 }
```

Explicit CLI flags always override it. `protected` adds globs the patch may not
touch, on top of the built-in tests/config/auto-exec set.

**Baseline allowlist (`allow`).** The inverse of `protected`: globs **exempt** from
the test / config / CI rejection — for a path a built-in pattern misclassifies (e.g.
a `Makefile` that runs no tests) or a known pre-existing hit. It **never** exempts an
auto-exec file (`sitecustomize.py` / `*.pth`) or an unsafe path. Curate it by hand
(`--allow` or `.evoguard.json`) — allowlisting a real judging test reopens that hole.

**Adding new tests (`allow_new_tests`).** By default *any* test-file change is
rejected — great for bug-fix PRs, but it blocks a feature PR that ships its own
new tests. Opt in with `{ "allow_new_tests": true }` (or `--allow-new-tests`) to
allow **brand-new** test files while still rejecting edits to existing tests, the
config, lock files, `conftest.py`, auto-exec, and CI. New test code still runs in
the judge process, so it's for **trusted authors + review** — see
[`FEATURE_MODE.md`](FEATURE_MODE.md).

## 3½. The protected policy contract (`.evoguard.json`)

`.evoguard.json` is itself protected harness (a candidate that edits it is
REJECTED), so it can carry the *security policy* — not just runner settings —
as a repository-contained contract no patch can weaken:

```json
{
  "policy_id": "org/production-strong",
  "policy_version": "1",
  "test_command": ["python", "-m", "pytest", "-q"],
  "require_report_integrity": "same_process_candidate_writable",
  "require_candidate_isolation": "docker"
}
```

For the stronger end-to-end `external_process_isolated` floor, invoke the gate
with `--blackbox --blackbox-only --verifier-pack ...` (or the equivalent Action
inputs). The default black-box composite intentionally cannot satisfy that
floor because it also requires the weaker repo-native report channel.

> **Mode-consistency (fail-closed in v3.4.0):** `min_diff_coverage` and
> `require_demonstrated_fix` run under the **subprocess judge only** today.
> Adding them to a policy that also demands a container/black-box judge makes
> every run `ERROR policy_requirement_unsupported` — deliberately: Guard
> refuses to return a verdict that silently drops a requirement it could not
> enforce. Keep coverage/baseline gates in a subprocess-judge policy:
>
> ```json
> {
>   "policy_id": "org/agent-fix-gate",
>   "policy_version": "1",
>   "min_diff_coverage": 80
> }
> ```

The `policy_id`/`policy_version` land in the verdict's attestation, so a
consumer knows exactly which policy produced a PASS (and
`verify-verdict --expect-policy-id …` can demand it). **Fail-closed:** a
present-but-broken config — unreadable JSON, an unknown key (a misspelled
floor!), a wrong-typed value — stops the run with exit 2; it never silently
degrades to weaker defaults. CLI flags still override valid config values.

## 3¾. Hardening the setup command (the "setup mutation" surface)

`setup_command` runs in the throwaway copy before tests. In ordinary
`subprocess` mode it is a host subprocess with a temporary HOME, minimal
environment and wall timeout — **not a sandbox**. With docker/gVisor it
runs **inside the resolved image by default**, with `/work` writable; the repo
suite and configured verifier pack then run in separate containers with `/work`
read-only. The default container network is `none`, so dependency acquisition
must come from the image/cache or from a deliberately configured network.

Guard snapshots the candidate tree before and after setup. New conventional
outputs such as `node_modules`, `.venv`, `build`, `dist`, `target` and caches are
allowed, while changes to judged source/harness fail closed. Additional outputs
can be declared in protected `.evoguard.json`:

```json
{
  "setup_command": ["pnpm", "install", "--frozen-lockfile"],
  "setup_output_globs": ["generated/**"]
}
```

`setup_output_globs` are **trusted exceptions**, not discoveries: matching paths
are omitted from fidelity comparison. Keep patterns narrow. Setting
`"trust_setup_on_host": true` under docker/gVisor is an explicit compatibility
opt-in; the verdict records it and lowers effective candidate isolation to
`subprocess`.

Today `setup_command` and `--blackbox` are deliberately not composable: Guard
returns `ERROR policy_requirement_unsupported` instead of silently preparing
only one side of the composite run. Put black-box runtime dependencies in the
environment/image until that boundary has an explicit implementation.

### Candidate lifecycle scripts are still executable code

Setup fidelity detects persistent changes to judged source/harness paths; it
does not make an installer inert. A candidate can add or edit an npm
`postinstall`/`prepare` entry in `package.json`, and an unqualified install
command will execute it during setup. In JavaScript ecosystems, remove that
surface when dependencies do not require install hooks:

```json
{ "setup_command": ["npm", "install", "--ignore-scripts", "--no-audit"] }
```

`--ignore-scripts` is available in npm/pnpm/yarn; vitest/jest remained
functional in the tested
[Node-workspace fixture](https://github.com/EvoRiseKsa/evoom-guard-demo).
Only omit it for a reviewed dependency that genuinely needs an install script.
For host isolation use the default container setup path; for report integrity
use black-box judgment and bake its dependencies into the image/environment.
Neither setup fidelity nor an installer flag is a security sandbox.

### Independent Verifier Packs: run and pin them

When `--verifier-pack` is supplied, Guard snapshots the pack outside the
candidate tree and executes it as a **separate mandatory pytest phase** after
the repo suite. Both phases must pass and the pack must collect at least one
test. Validate and capture its canonical identity first:

```bash
evo-guard pack-doctor /secure/org-pack
# Set PACK_SHA256 to the reported "pack sha256" in protected CI/policy.
evo-guard guard . --diff patch.diff \
  --verifier-pack /secure/org-pack \
  --expect-verifier-pack-sha256 "$PACK_SHA256"
```

The V2 identity binds typed directory/file paths and content; symlinks and
special files are rejected. The expected digest can also live in
`.evoguard.json` as `expect_verifier_pack_sha256`, or in the Action input
`expect-verifier-pack-sha256`. The attestation records the observed digest,
manifest and pack test counts.

## 4. Supported test runners — the compatibility matrix

Eight runners get the **structured** verdict (`junit+exit`: real pass/fail counts
read from a judge-owned JUnit report, cross-checked against the exit code, with
the `TAMPERED` mismatch check). Anything else still runs — it grades on the
**exit code alone** (stdout forgery is still ignored, but there are no counts and
no exit⟷report mismatch check).

| Runner | Matched command | Verdict source | Extra requirement in the repo/image |
|---|---|---|---|
| **pytest** | `pytest` / `python -m pytest` | `junit+exit` | none (the default judge) |
| **`node --test`** | `node --test` | `junit+exit` | Node with the `junit` test reporter (Node ≥ 21; tested on 22) |
| **vitest** | `vitest run` (or `.bin/vitest`) | `junit+exit` | the `vitest` CLI |
| **jest** | `jest` (or `.bin/jest`) | `junit+exit` | `jest-junit` resolvable (e.g. installed by `setup_command`) |
| **gotestsum** (Go) | `gotestsum [--] go test …` | `junit+exit` | the `gotestsum` binary on PATH (bare `go test -json` is stdout-only → not trusted) |
| **RSpec** (Ruby) | `rspec` / `bundle exec rspec` | `junit+exit` | `rspec_junit_formatter` in the bundle |
| **mocha** | `mocha` (or `.bin/mocha`) | `junit+exit` | `mocha-junit-reporter` resolvable |
| **Maven Surefire** (Java/Kotlin) | `mvn test` / `./mvnw test` | `junit+exit` | none beyond Maven (reports directory is redirected judge-side) |
| `sh -c "setup && <runner>"` | the last segment is one of the above | `junit+exit` | same as the inner runner |
| any other / `npm test` wrapper | — | `exit` (exit code only) | coarse: no counts, no `TAMPERED` check — prefer invoking the runner binary directly |

The report's `Verdict source` row always states which path judged the run — a
`junit+exit` verdict is strictly stronger evidence than an `exit` one.

### In a workspace / monorepo (pnpm · yarn · npm)

The verdict stays `junit+exit` **only if EvoGuard can see the runner** in your
`test_command`. Two rules, both learned validating EvoGuard live on a real
TypeScript/pnpm monorepo:

1. **Invoke the runner binary, not a package script.** Use
   `pnpm --filter <pkg> exec vitest run` — **not** `pnpm --filter <pkg> vitest run`
   (pnpm reads `vitest` as a *script* name, fails with
   `ERR_PNPM_RECURSIVE_RUN_NO_SCRIPT`, and the suite never starts → EvoGuard
   reports `FAIL` with `verdict_source: exit`). A `package.json` `test`-script
   wrapper (`pnpm test`) does run the suite, but hides the runner, so the verdict
   drops to exit-only. `exec vitest run` keeps the `vitest` token visible, so the
   adapter splices in its judge-owned JUnit reporter.
2. **Install in `setup_command`, don't fuse it into the test command.** EvoGuard's
   repo copy excludes `node_modules`, so restore it *before* the suite:

   ```json
   {
     "setup_command": ["pnpm", "install", "--frozen-lockfile"],
     "test_command": ["pnpm", "--filter", "@scope/pkg", "exec", "vitest", "run"],
     "mem_limit": 0
   }
   ```

   Under docker/gVisor, this setup runs in the image while the later suite mount
   is read-only. Ensure setup has completely materialized every dependency/build
   output the suite needs; tools that insist on writing inside the repo during
   tests need a compatible pre-build workflow, not a broad fidelity exception.

   `mem_limit: 0` is applied automatically when a `package.json` is present (V8
   reserves far more virtual memory than a sane `RLIMIT_AS`); set it explicitly to
   be safe. With this shape a clean source change verdicts `PASS` (`junit+exit`,
   real counts) and an edit to a colocated `*.test.ts` is `REJECTED` before the
   suite runs.

## 5. Untrusted / fork PRs

The default judge runs PR-authored code in a subprocess (rlimits + timeout) — fine
for **trusted** repos, **not** a sandbox. For public repos accepting fork PRs:

- Run on `pull_request` (not `pull_request_target`) so untrusted code never sees
  your secrets.
- Add `--isolation docker --docker-image <img>` for a **network-less, read-only**
  container judge (defence in depth; not a complete boundary — see
  [`GUARD.md`](GUARD.md)). The image must carry your test runner (e.g.
  `node:22-slim` for `node --test`).
- For **untrusted** input, prefer **`--isolation gvisor`** — the same container judge
  through the gVisor `runsc` runtime (a user-space guest kernel, **no `/dev/kvm`**), so
  the suite runs under a separate kernel. Needs docker with the `runsc` runtime; see
  [`VM_ISOLATION.md`](VM_ISOLATION.md).

Every black-box isolation mode uses the same shell-free POSIX executable
launcher. On native Windows it fails closed before subprocess, Docker, or gVisor
delivery; run black-box mode on Linux/GitHub Actions or under WSL. Repo-native
Guard still runs on Windows, with a wall timeout but without POSIX CPU/memory
rlimits.

## 6. Pin the version

EvoGuard is a *gate*, so pin what you run: `@v3.5.0` (a release tag) or `@<sha>`
(immutable, strictest for CI). Track `@main` only for a quick look.

## What it does not do

It does not write the fix (it judges one), does not vouch that your tests are
*good* (a weak suite still `PASS`es), and is not a general sandbox for hostile
code. See the honest scope in [`REWARD_HACKING_CATALOG.md`](REWARD_HACKING_CATALOG.md).
