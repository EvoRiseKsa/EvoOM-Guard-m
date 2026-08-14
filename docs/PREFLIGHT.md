<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see ../LICENSE for permitted use.
-->

# Preflight and staged adoption

> **Version boundary:** `evo-guard preflight` and `init --preset` are implemented
> in repository source after the ledger-recorded `v4.6.0` release. Confirm that
> the exact installed build lists these options in `--help`; do not copy these
> commands into a `v4.6.0`-pinned consumer and assume they exist there.

`preflight` is a static readiness check. It reads trusted repository policy and
host facts, but it does **not** apply a patch, start candidate code, run the test
command, or issue an admission verdict:

```bash
evo-guard preflight . --strict --json
```

`--strict` is recommended for rollout gates so unresolved warnings, including
an unpinned verifier-pack identity or mutable container reference, return a
non-zero status before the first Guard attempt. Informational limits—such as an
image-local executable that cannot be inspected without starting the image—are
reported separately and do not make a fully pinned strict preflight fail.

Use it before consuming a real Guard attempt. It catches deterministic setup
problems such as:

- a missing test launcher or container client;
- a POSIX-shell command on a standard Windows host;
- black-box mode on native Windows, or a missing `/usr/bin/env`/`python3`
  launcher dependency on a POSIX host;
- quoted string commands whose arguments would be lost by compatibility
  whitespace splitting;
- Python `-I`/`-E` without explicit `-B` when a repository suite must preserve
  exact tree identity before a verifier pack;
- pytest cache writes without `-p no:cacheprovider` in that same continuity
  boundary; and
- common Maven, Gradle, Cargo, Jest, and package-script output risks.

Exit `0` means no deterministic error was found. Exit `1` means the report has
an error, or has a warning when `--strict` is selected. Exit `2` is a CLI or
trusted-policy usage error. A ready report is not evidence that arbitrary tests
will make no writes and is never equivalent to `PASS`.

## Python command hygiene

Python isolated mode ignores `PYTHON*` environment variables. Therefore `-I`
or `-E` can also ignore the judge's `PYTHONDONTWRITEBYTECODE=1` setting. When a
suite and verifier pack share an exact runtime-tree continuity boundary, use an
explicit cache-safe argv:

```json
{
  "test_command": [
    "python", "-I", "-B", "-m", "pytest", "-q",
    "-p", "no:cacheprovider"
  ],
  "verifier_pack": "security/org-invariants",
  "expect_verifier_pack_sha256": "<64-hex-EVOGUARD_PACK_V2-digest>"
}
```

Guard does not silently add these flags because a test may intentionally
inspect interpreter flags. It also does not ignore, delete, or re-baseline
`__pycache__`, `.pytest_cache`, or build output after execution. Persistent
runtime-tree drift remains `TAMPERED`; preflight only helps prevent an avoidable
first attempt.

## Observe, then promote

For an exact build that contains the preset feature, generate a read-only
observation workflow first. The supported reference boundary is `v4.6.0` or a
later SemVer tag, or a reviewed full commit SHA; the selected ref must expose the
JSON and Markdown evidence-output contract:

```bash
evo-guard init --ref <immutable-release-tag-or-40-hex-SHA> --preset advisory \
  --path <workflow-path> --policy-path <trusted-policy-path>
```

The generated workflow still invokes the Action with
`fail-on: "any-non-pass"`. Step-level `continue-on-error` makes a *completed*
Guard non-`PASS` observational, then the workflow uploads the actual JSON and
Markdown evidence. A separate completeness step requires both files; missing
either the JSON verdict or Markdown report makes the job red. Checkout/setup
failures, Action crashes, or upload failures can also make the job red. It has read-only permissions,
does not comment, and receives no credential. Do not make this check required
in branch protection: doing so admits completed non-`PASS` verdicts by design.

After reviewing representative `PASS`, `FAIL`, `REJECTED`, `TAMPERED`, and
`ERROR` outcomes and fixing deterministic preflight problems, replace it with:

```bash
evo-guard init --ref <same-immutable-ref> --preset blocking --force \
  --path <same-workflow-path> --policy-path <same-trusted-policy-path>
```

Review the generated diff, merge it through the repository's trusted policy
maintenance path, then make the blocking check required. `blocking` is the
default and preserves the historical generated workflow bytes when `--preset`
is omitted.

## Explicit non-claims

- Preflight is not a sandbox, test run, security scan, or admission decision.
- Advisory mode does not turn a non-`PASS` verdict into `PASS`.
- Same-owner observation is not independent validation or field efficacy.
- Neither mode discovers transitive judge dependencies; declare trusted
  `harness_inputs` or use a digest-pinned external verifier pack.
- Runtime identity checks remain authoritative after execution; no cache or
  temporary-output allowlist is introduced by this feature.

See [Adoption](ADOPTION.md), [Guard](GUARD.md),
[Verifier packs](VERIFIER_PACKS.md), and [Assurance](ASSURANCE.md).
