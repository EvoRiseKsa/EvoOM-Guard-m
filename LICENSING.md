<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  This file is the authoritative license map for the repository.
-->

# Licensing map

EvoOM Guard is **open-core**. The repository is dual-licensed by path:

- The **core gate** — the engine that answers the one question *"did this change
  satisfy the selected judge without editing, deleting, or neutering a protected
  evidence path?"* — is licensed under the **Apache License 2.0**
  ([`LICENSE-APACHE`](LICENSE-APACHE)). It is free to use, including as a required
  CI/merge gate, in commercial and non-commercial settings.
- The **trust platform** — the multi-key signing, admission, finalizer, and
  release-trust machinery — remains **source-available under the EvoRise
  Source-Available License 1.0** ([`LICENSE`](LICENSE)); production/commercial use
  of the platform requires a separate agreement (see
  [`COMMERCIAL-LICENSING.md`](COMMERCIAL-LICENSING.md)).

This file governs. Where a source file's header and this map disagree during the
header migration, **this map is authoritative** for that path until the header is
brought into line (tracked as the header-migration change that follows this one).

## Core — Apache License 2.0 (`LICENSE-APACHE`)

The reward-hack-resistant test-oracle gate and everything it needs to run and to
emit/verify a verdict:

| Path | What it is |
|---|---|
| `evoom_guard/domain/` | Dependency-free verdict vocabulary and contracts |
| `evoom_guard/policy/` | `.evoguard.json` parsing and effective-policy build |
| `evoom_guard/candidate/` | Candidate patch parsing and application |
| `evoom_guard/verifiers/` | The judge: protected-path pre-gate, JUnit oracle, assertion-liveness, continuity |
| `evoom_guard/runners/` | The structured runner adapters (pytest, node, vitest, jest, gotestsum, rspec, mocha, maven) |
| `evoom_guard/execution/` | The stdlib-only bounded-process kernel (rlimits, timeouts, tree-kill) |
| `evoom_guard/isolation/` | Candidate isolation (subprocess / docker / gVisor) |
| `evoom_guard/workspace/` | Judge-owned throwaway-copy lifecycle and path containment |
| `evoom_guard/application/` | Pure decision composition, assurance, attestation |
| `evoom_guard/integrations/` | Verdict output projections (Markdown / JSON / SARIF) |
| `evoom_guard/guard.py` | The `guard()` entry point |
| `evoom_guard/signing.py` | Ed25519 primitives used to sign and verify a verdict |
| `evoom_guard/cli/` | The `evo-guard` command surface (dispatch layer) |
| `action.yml` | The GitHub Action wrapper |
| **Core CLI subcommands** | `guard`, `init`, `preflight`, `pack-doctor`, `doctor`, `version`, `keygen`, `verify-verdict`, `verify-record`, `verify-bundle` |

The `evoom_guard/cli/` dispatch layer is core (Apache-2.0). It can *invoke* the
platform subsystems below when they are installed, but those subsystems and the
subcommands that drive them are licensed as platform.

**Core top-level modules (Apache-2.0).** Beyond `guard.py` and `signing.py`, these
flat `evoom_guard/*.py` modules are part of the gate / verdict-emit-verify core
and import only core code: `__init__.py`, `contracts.py`, `strict_json.py`,
`adapters.py`, `patchmin.py`, `patch_applier.py`, `pack_manifest.py`,
`runtime_identity.py`, `candidate_runner.py`, `blackbox.py`, `evidence.py`,
`evidence_bundle.py`, `record_verifier.py`, `verdict_contract_v1_11.py`,
`verdict_contract_v1_12.py`.

**Core `cli/` files (Apache-2.0).** The dispatch/argparse layer plus the
core-command owners: `cli/__init__.py` is the exception — see below —; `cli/__main__.py`,
`cli/parser.py`, `cli/guard_command.py`, `cli/init_command.py`,
`cli/preflight_commands.py`, `cli/diagnostic_commands.py` (doctor/version/pack-doctor),
and `cli/signing_commands.py` (keygen).

**Two `cli/` files are deferred to the packaging change** and remain EvoRise
Source-Available until then, because each currently mixes core and platform code
and must be split first: `cli/record_commands.py` (holds the core `verify-verdict`/
`verify-record`/`verify-bundle` handlers *and* the platform `bundle-evidence`/
`finalize-record` handlers) and `cli/__init__.py` (the dispatch also inlines the
platform command thunks and eagerly imports the platform command owners). Splitting
those, and making the platform command imports lazy, is the packaging prerequisite
after which both become core.

## Platform — EvoRise Source-Available License 1.0 (`LICENSE`)

The multi-key trust, admission, finalizer, and release machinery. Not included in
the free core distribution; production/commercial use requires a separate
agreement.

| Path | What it is |
|---|---|
| `evoom_guard/finalizer/` | Trusted Finalizer deployment kit + static inspection |
| `evoom_guard/admission/` | Sealed ALLOW/DENY admission contracts (artifact / release-source / agent-change) |
| **Platform CLI subcommands** | The finalizer, admission, release-source, release-artifact, and GitHub-attestation `seal-*` / `verify-*` / `derive-*` / `reverify-*` families (the operator/auditor commands beyond the core set above) |
| `.github/workflows/evoguard-*.yml` | The protected release pipeline (reverify, seal, admit, promote, publish) |
| `tools/ci/assemble_release_ledger_v2.py`, `tools/ci/validate_release_ledger_v2.py` | Release-ledger assembly/validation |
| `security/release-ledger-roots/`, `evidence/release-ledgers/` | Release trust roots and ledgers |

## Everything else

Documentation, benchmarks, evaluation tooling, tests, and evidence remain under
the EvoRise Source-Available License 1.0 unless a file's header states otherwise,
per [`NOTICE`](NOTICE). Third-party material keeps its own license — see
[`THIRD_PARTY.md`](THIRD_PARTY.md). No trademark license is granted by either
license.

## Scope and status

This map records the open-core boundary. Core source files now carry
`SPDX-License-Identifier: Apache-2.0` headers (except the two `cli/` files noted
above, deferred to the packaging change); platform files keep their EvoRise
Source-Available headers. The core is still being prepared as a separately
installable distribution. This map remains the authoritative statement of which
license applies to which path.
