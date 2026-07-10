<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
  Sole owner & author: Mana Alharbi (مانع الحربي).
-->

# EvoGuard — an AI patch verification gate

> A CI gate that answers one objective question about a code change — produced by
> a human or, the motivating case, an **AI agent**: **does this patch fix the code
> *without gaming the tests*?** It is a thin, model-free composition of the project's
> reward-hack-resistant judge and its patch risk scorer.

## Why

Frontier agents have been observed **editing or skipping their own tests** to make
a suite pass, and self-modifying coding agents have **faked test logs** (documented
in the public literature). A patch-review gate the patch itself **can't game by
hacking the harness** is therefore a real need as agent-authored PRs become common. EvoGuard provides
it: the candidate is judged by the **repository's own tests**, the verdict is read
from a **judge-owned JUnit report + the process exit code** (never scraped from the
patch's stdout), and **any edit to the tests or their configuration is rejected**
before the suite runs.

## What it checks

| Verdict | Meaning |
|---|---|
| ✅ `PASS` | the repo's tests pass **and** the patch left the test harness untouched |
| ⛔ `REJECTED` | the patch edits the tests, their configuration, or an auto-executed file (`sitecustomize.py`, `*.pth`, `Makefile`, …) — a reward-hack; rejected before the suite runs |
| ❌ `FAIL` | the patch applied and the suite ran, but tests fail |
| 🚨 `TAMPERED` | the process exit code and the judge-owned JUnit report disagree — a desync/forced-exit signature; never read as a pass |
| ⚠️ `ERROR` | the patch did not apply, or produced no parseable edits |

The verdict and its stable `reason_code` are emitted as JSON for integrations — see
[`JSON_SCHEMA.md`](JSON_SCHEMA.md).

Every run also reports a **blast-radius risk** (`low`/`medium`/`high`) from the
files and lines touched and any protected-path hit, and the **verdict source**
(`junit+exit` for the hardened path).

A forged `9999 passed` printed by the patch's own code **cannot** flip the verdict —
the score comes from the structured JUnit report, cross-checked against the exit
code.

## Install

There are two ways to get Guard, depending on where you run it. EvoGuard is
proprietary and is **not published to PyPI** (`pip install evoom-guard` will not find
it) — both paths install it **from this repository**.

**In GitHub Actions — nothing to install.** Reference the composite action; the
runner fetches it and `pip install`s EvoGuard itself, so the only line your
workflow adds is the `uses:` (plus a full-history checkout):

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }                 # Guard needs the base commit to diff
- uses: EvoRiseKsa/EvoOM-Guard-m@v2.1.2   # a release tag; @<sha> is strictest, @main is latest
```

**As a CLI — install the `evo-guard` command from the repo** (the stdlib-only core has
no third-party dependencies, so this is a fast, clean install — no clone needed):

```bash
pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m.git@v2.1.2"   # a release tag — recommended
pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m.git@<sha>"    # the strictest, immutable pin
evo-guard guard --diff - --test-command "pytest -q" < pr.diff
```

> **Pinning.** Guard is a verification *gate*, so pin the version you run rather
> than tracking a moving branch — both for the `uses:` action ref and the `git+`
> pip URL:
> - **`@v2.1.2`** — a release tag. The recommended pin and the right choice for
>   trying Guard out: a real, named version rather than whatever is on `main`.
> - **`@<sha>`** — a full commit SHA. The **strictest, immutable** pin (a tag can
>   in principle be moved); best for CI, where the gate you run should be the exact
>   code you reviewed.
> - **`@main`** — always the latest, unreviewed code. Fine for a quick look, not
>   for a gate you depend on.
>
> If the repository is private, the usual GitHub access applies — a
> token-authenticated `git+https://…@<token>…` URL for `pip`, and repo read access
> for the `uses:` reference.

## CLI

```bash
# Easiest: pipe a normal git diff from your working tree (the head checkout).
# Guard reverse-applies it to reconstruct the base, then verifies — zero setup.
git diff main...HEAD | evo-guard guard --diff - --test-command "pytest -q"
evo-guard guard --diff pr.diff --report report.md --json guard.json

# Verify a candidate in EvoGuard's edit-block format against a repo:
evo-guard guard path/to/repo --patch candidate.txt
echo "<<<FILE: src/x.py>>> … <<<END FILE>>>" | evo-guard guard path/to/repo --patch -

# Verify a PR by diffing two explicit checkouts:
evo-guard guard --base path/to/base --head path/to/head --test-command "pytest -q"
```

`evo-guard guard` prints a Markdown report and exits **0 only on `PASS`**, non-zero
otherwise — drop it straight into any CI step.

- **`--diff <file|->`** (lowest friction): a `base...HEAD` unified diff, verified
  against the current checkout (the optional `<repo>` arg, else cwd) by
  **reverse-applying** it to reconstruct the base. So `git diff … | evo-guard guard --diff -`
  works straight from your tree — no second checkout, no worktree. Needs `git`
  (or `patch`) on the runner.
- **`--base/--head`** diffs two explicit trees into the block format.
- **`--patch`** takes the EvoGuard edit-block format directly.

Added/modified files are verified; deletions are surfaced in the report but not
gated. `--json` writes the machine-readable verdict. The report shows the `Input`
(`diff` / `base/head` / `edit blocks`) and, for `--diff`, the `Base reconstruction`
(`ok` / `failed`).

### `--diff` safety (for untrusted PRs)

- **The real working tree is never modified.** Guard reverse-applies the diff to a
  throwaway *copy*; `head_dir`/cwd is only ever read.
- **Unsafe paths are refused, not applied.** A diff that targets an absolute path,
  a `..` escape, or anything outside the repo root returns a clear `ERROR` *before*
  any apply (checked up front, on top of `git apply`'s own unsafe-path guard and the
  verifier's relpath gate).
- **Binary patches are not supported** — a diff containing a binary file change
  (`GIT binary patch` / `Binary files … differ`) returns a clear `ERROR`. Guard
  verifies text source changes only.
- A diff that does not reverse-apply (a stale base) returns `ERROR` with
  `Base reconstruction: failed`.

## GitHub Action

A composite action ships at [`.github/actions/evoguard`](../.github/actions/evoguard/action.yml).
Copy [`examples/evoguard.yml`](../examples/evoguard.yml) to
`.github/workflows/evoguard.yml` in the repo you want to protect:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }            # Guard needs the base commit to diff
- uses: EvoRiseKsa/EvoOM-Guard-m@v2.1.2   # pin a release (@<sha> strictest, @main latest)
  with:
    comment: "true"                   # post the verdict as a PR comment
    fail-on: "any-non-pass"           # or "rejected-only" to gate only reward-hacks
```

It writes the report to the **job summary**, posts it as a **PR comment**, exposes a
`verdict` output, and fails the step per `fail-on`. To gate only machine-made PRs,
add `if: github.event.pull_request.user.type == 'Bot'` to the job.

### Minimal workflow with a natural `git diff` (no action needed)

If you prefer no composite action, the `--diff` mode is a two-line gate:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }                       # Guard needs the base to diff
- run: pip install "git+https://github.com/EvoRiseKsa/EvoOM-Guard-m.git@v2.1.2"   # see Install; @<sha> strictest for CI
- run: |
    BASE="origin/${{ github.event.pull_request.base.ref }}"
    git fetch --no-tags origin "${{ github.event.pull_request.base.ref }}"
    git diff "$BASE...HEAD" | evo-guard guard --diff - --test-command "pytest -q" --report "$GITHUB_STEP_SUMMARY"
```

`evo-guard guard` returns a non-zero exit on anything but `PASS`, so the step fails the
check automatically.

## Trust boundary (honest)

By default Guard runs the repo's suite in a **subprocess** with rlimits and a
timeout. That is appropriate for **trusted** repositories — your own code, gating a
patch — and is **not** a general security sandbox: it does not confine filesystem or
network access. For **untrusted** code (e.g. fork PRs), treat this like any other
code-execution gate: run it where the patch's code cannot reach your secrets, and
isolate the runner. Guard never claims the subprocess is a sandbox.

**Optional containerised judge** — `--isolation docker --docker-image <img>` runs the
suite inside a short-lived container that is **network-less** (`--network none`),
**read-only** (writes confined to a `/tmp` tmpfs), non-root-cwd, and bounded by
`--cpus` / `--pids-limit` / `--memory`. The repo copy and the judge-owned JUnit
report are *separate* bind mounts, so the verdict path is read back from the host,
not from inside the candidate's tree. This is **defence in depth for semi-trusted
code** (filesystem + network confinement, trivial cleanup) — it cuts off the
network and the host filesystem, but a container shares the host kernel, so it is
**not** a complete boundary for hostile code.

> **`setup_command` runs on the host, not in the container.** Under
> `--isolation docker`/`gvisor` only the *test suite* runs inside the container; an
> optional `setup_command` (e.g. `npm install`) still runs in a host subprocess
> (it usually needs network, which the test container denies). So when the
> dependency source is itself untrusted, the install step is **not** isolated —
> treat `setup_command` input as trusted, or pre-build the image with deps baked in
> and skip `setup_command`. For untrusted/public input use
**`--isolation gvisor`** — the same judge through the gVisor `runsc` runtime (a
user-space guest kernel, no `/dev/kvm`), a separate-kernel boundary; a Firecracker
microVM backend is designed in `docs/VM_ISOLATION.md`. The image must carry the
repo's test runner (e.g. `node:22-slim` for `node --test`).

## What it is and is not

- **It is** an objective, reward-hack-resistant **verification gate**.
- **It is not** a generator, a fixer, or an agent. It does not write the patch; it
  judges one.
