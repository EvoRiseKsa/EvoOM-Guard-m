<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
  Maintained and released by Mana Alharbi (مانع الحربي).
-->

# Adopting EvoGuard — a one-page runbook

EvoGuard is a CI gate that evaluates whether a code change (with **AI-agent
PRs** as the primary use case) satisfied the selected judge under the recorded
policy and assurance boundary. It blocks the explicitly modelled
evidence-gaming paths; it is not a universal hostile-code proof. It is a single
verdict + exit code for a pipeline.

## 1. Turn it on (one command)

[`v4.2.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.2.0)
is the current published immutable GitHub Release. For a stricter CI pin, use
the full commit SHA resolved from that release tag.

From the repo you want to protect (EvoGuard is public; pin an immutable release
tag):

```bash
pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m.git@v4.2.0"  # published release
evo-guard init --ref v4.2.0 --test-command "python -m pytest -q"  # writes workflow + .evoguard.json when absent
git add .github/workflows/evoguard.yml .evoguard.json
git commit -m "ci: add EvoGuard policy" && git push
```

That's it. On the next PR, the Action diffs it against the base, runs your suite,
posts a verdict comment, and **fails the check on anything but `PASS`**.

> No-action alternative — the two-line `git diff | evo-guard guard --diff -` form, or
> `evo-guard init --ref v4.2.0 --stdout` to review the workflow first. See [`GUARD.md`](GUARD.md).

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

For a local or deliberately trusted non-PR invocation, explicit CLI flags can
override it. Do **not** use that rule as a PR policy mechanism: a PR workflow is
candidate-controlled. On `pull_request`, the Action materializes the policy from
the verified base SHA and ignores judge-shaping `with:` inputs. `protected` adds
globs the patch may not touch, on top of the built-in tests/config/auto-exec set.

**Baseline allowlist (`allow`).**
This applies only to adopter-defined extra `protected` globs. It cannot
exempt built-in tests, test/build configuration, CI, or auto-executed judge files;
those changes require a separate trusted policy-maintenance path, not a candidate
PR exception.

Use it only for an adopter-defined extra protected path that was deliberately
classified by the repository owner. It is not a general harness override.

**Adding new tests (`allow_new_tests`).** By default *any* test-file change is
rejected — great for bug-fix PRs, but it blocks a feature PR that ships its own
new tests. Opt in with `{ "allow_new_tests": true }` (or `--allow-new-tests`) to
allow **brand-new** test files while still rejecting edits to existing tests, the
config, lock files, `conftest.py`, auto-exec, and CI. New test code still runs in
the judge process, so it's for **trusted authors + review** — see
[`FEATURE_MODE.md`](FEATURE_MODE.md).

## 3½. The protected policy contract (`.evoguard.json`)

For `--base/--head`, Guard loads `.evoguard.json` from the base directory. The
Marketplace Action materializes it from the verified PR base commit. Raw `--diff`
mode never loads it from the candidate checkout: provide a trusted external
`--config` or explicitly choose `--no-config`.

### GitHub Action PR trust model

The Action does not treat the workflow file in a PR as judge policy. It resolves
the event base SHA, materializes `$BASE:.evoguard.json`, and invokes Guard with
that temporary base-owned file. Therefore put the test command, path rules,
limits, assurance requirements, and verifier-pack policy in `.evoguard.json`,
not in Action `with:` fields. Candidate `with:` values that would shape the
judge are ignored; a conflicting base ref, fail mode, or verifier-pack input
fails closed.

For a PR verifier pack, use both fields together:

```json
{
  "test_command": ["python", "-m", "pytest", "-q"],
  "verifier_pack": "security/org-invariants",
  "expect_verifier_pack_sha256": "<64-hex-EVOGUARD_PACK_V2-digest>"
}
```

The path is repository-relative. The Action archives it from the verified base
commit into a temporary trusted directory before it runs candidate code. It
never takes the active pack from the candidate checkout. An absent digest,
invalid path, malformed base policy, or conflicting pack input is an error.

For a high-assurance verification lane, add `"strict_harness": true` to that
same base policy. It makes dependency/lock/compiler manifests immutable and
requires a non-empty structured JUnit verdict, so keep routine dependency and
toolchain upgrades in a separately reviewed maintenance lane. It is a harness
integrity control, not a substitute for an isolated black-box judge.

This trust boundary begins only once the workflow has started. Configure a
required workflow/status check (and appropriate review or CODEOWNERS controls
for `.github/workflows/`) so a PR cannot bypass the gate by removing or replacing
the workflow. Keep untrusted candidate checkouts on `pull_request`, not
`pull_request_target` with secrets. See
[`REPOSITORY_PROTECTION.md`](REPOSITORY_PROTECTION.md) for the required GitHub
controls and what the composite Action cannot enforce on its own.

`.evoguard.json` is itself protected harness (a candidate that edits it is
REJECTED), so it can carry the *security policy* — not just runner settings —
as a repository-contained contract no patch can weaken:

```json
{
  "policy_id": "org/production-strong",
  "policy_version": "1",
  "test_command": ["python", "-m", "pytest", "-q"],
  "protected": ["migrations/**"],
  "timeout": 180
}
```

For the stronger end-to-end `external_process_isolated` floor, invoke the gate
with `--blackbox --blackbox-only --verifier-pack ...`. On a PR, use the
protected base-policy settings supported by the installed Action release; do not
try to establish this requirement through candidate workflow inputs. The default
black-box composite intentionally cannot satisfy that floor because it also
requires the weaker repo-native report channel.

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

> **Version boundary:** published `v4.0.2` and later include the coverage options,
> fail-closed unavailable-measurement behavior, isolated collector startup,
> exact-ratio comparison, conservative physical-line denominator,
> setup/resource forwarding, and the explicit candidate-writable caveat below.

When `min_diff_coverage` is configured, measurement is mandatory: a missing
collector, failed wrapped run, invalid report, or other explicit
`measured: false` result becomes `ERROR assurance_requirement_not_met`. The installed
collector is imported before the candidate repository enters `sys.path`, and
repository coverage configuration is ignored. Evidence-only `diff_coverage`
keeps its non-gating behavior. Trusted runner/interpreter prefixes are retained;
the selected environment must provide `coverage`. A configured setup is replayed
under the same output-fidelity policy, and the extra processes receive the main
POSIX CPU/address-space limits plus the ordinary wall/output/cleanup bounds.
This hardening does not turn repo-native tests
into a separate-process trust boundary; candidate code and the collector still
execute in the same judged Python process. Candidate code can obtain
`Coverage.current()`, stop tracing, or mutate `CoverageData` to fabricate
executed lines. Isolated startup protects collector selection/configuration,
not the integrity of its live state. Consequently `min_diff_coverage` is a
quality gate only when candidate code is non-hostile. Do not make it an
admission authority for untrusted PRs; keep it advisory and require independent
external verifier/finalizer evidence for that decision. Source exclusion
pragmas and changed continuation/unknown executable lines cannot shrink a
required denominator;
they are conservatively recorded as missed. Lexer failure is also conservative,
while docstring filtering retains other code on the same line. Thresholds use
the exact executed/total ratio rather than the rounded display percentage.
Direct Python API calls follow the same implication and finite `0..100`
validation as CLI/config policy.

The `policy_id`/`policy_version` land in the verdict's attestation, so a
consumer knows exactly which policy produced a PASS (and
`verify-verdict --expect-policy-id …` can demand it). **Fail-closed:** a
present-but-broken config — unreadable JSON, an unknown key (a misspelled
floor!), a wrong-typed value — stops the run with exit 2; it never silently
degrades to weaker defaults. Explicit CLI flags override valid config only in a
local or otherwise trusted invocation; an Action PR does not forward
candidate-controlled judge overrides.

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
evo-guard guard . --diff patch.diff --no-config \
  --verifier-pack /secure/org-pack \
  --expect-verifier-pack-sha256 "$PACK_SHA256"
```

The V2 identity binds typed directory/file paths and content; symlinks and
special files are rejected. The expected digest can live in `.evoguard.json` as
`expect_verifier_pack_sha256`. For an Action PR it must accompany
`verifier_pack` in the verified base policy; an Action input does not establish
the pin. The attestation records the observed digest, manifest and pack test
counts.

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
- EvoGuard writes every report to the job summary. Its optional sticky PR comment
  is skipped for fork and Dependabot PRs because their `GITHUB_TOKEN` is read-only;
  a missing comment therefore cannot replace the Guard verdict with an HTTP 403.
- Configure container isolation through the protected base policy, never through candidate workflow `with:`. It creates a network-less, read-only
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

EvoGuard is a *gate*, so pin what you run: the published `@v4.2.0` release tag,
or `@<sha>` (immutable, strictest for CI). Track `@main` only for a quick look.

## What it does not do

It does not write the fix (it judges one), does not vouch that your tests are
*good* (a weak suite still `PASS`es), and is not a general sandbox for hostile
code. See the honest scope in [`REWARD_HACKING_CATALOG.md`](REWARD_HACKING_CATALOG.md).
