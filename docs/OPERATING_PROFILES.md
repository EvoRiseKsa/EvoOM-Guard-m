<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# Operating profiles

> **Availability:** operating profiles were introduced on the `4.4.0` source
> line and are inherited by the reviewed `4.4.1` contract. `v4.3.0` does not
> recognize `--operating-profile` or emit schema
> `1.12`. The immutable `v4.4.0` release is published without a valid
> protected-tree ledger. Repository presence alone is not ledger evidence;
> confirm the [release status](RELEASE_STATUS.md) and exact artifact you run.

On source versions that provide it, `--operating-profile` gives a Guard run an
explicit trust and runtime contract. It is optional: omitting it preserves the
historical CLI behavior, effective policy payload, and policy digest exactly.
When selected, the profile is stored in
`attestation.effective_policy.operating_profile` and covered by
`policy_sha256`; that record declares schema `1.12`. Unprofiled records continue
to use the frozen schema `1.11`.

The profile is a requested policy contract. The separate `assurance` and
`isolation` evidence still record what actually ran. A requested profile never
upgrades those delivered facts.

| Profile | Meaning | Enforced requirements |
|---|---|---|
| `local` | Trusted local/developer use | No extra runtime requirements. This is a scope label, not a sandbox claim. Stronger individual options remain available. |
| `protected` | Protected automation with an external report channel and a container boundary | `blackbox=true`, `blackbox_only=true`, Docker or gVisor isolation, a container image, network `none`, no setup command or host-setup opt-in, a verifier pack with an expected SHA-256, `external_process_isolated` report-integrity floor, and a candidate-isolation floor matching the selected isolation. |
| `hostile` | Candidate code is treated as hostile | Every protected requirement, plus `gvisor`/`runsc`, a `gvisor` candidate-isolation floor, and a non-zero memory limit. |

Guard rejects an incomplete or contradictory profile before executing any
candidate code. It does not silently turn weaker settings into stronger ones.
A missing Docker daemon, image, or gVisor runtime also fails closed; there is no
fallback to host subprocess execution.

## Trusted policy examples

A protected Docker policy:

```json
{
  "operating_profile": "protected",
  "blackbox": true,
  "blackbox_only": true,
  "isolation": "docker",
  "docker_image": "python:3.12-slim",
  "docker_network": "none",
  "verifier_pack": "security/judge-pack",
  "expect_verifier_pack_sha256": "<64-hex EVOGUARD_PACK_V2 digest>",
  "require_report_integrity": "external_process_isolated",
  "require_candidate_isolation": "docker"
}
```

A hostile policy changes the isolation floor and keeps an active memory cap:

```json
{
  "operating_profile": "hostile",
  "blackbox": true,
  "blackbox_only": true,
  "isolation": "gvisor",
  "docker_image": "python:3.12-slim",
  "docker_network": "none",
  "mem_limit": 1024,
  "verifier_pack": "security/judge-pack",
  "expect_verifier_pack_sha256": "<64-hex EVOGUARD_PACK_V2 digest>",
  "require_report_integrity": "external_process_isolated",
  "require_candidate_isolation": "gvisor"
}
```

The trusted configuration parser requires a profile-bearing policy to be
self-contained. CLI flags may also select a profile, but all of its companion
requirements must be present in the resulting effective settings.

## Key custody

Direct `guard --sign-key` is forbidden under `protected` and `hostile`, even
with the local-exposure acknowledgement. Candidate execution and final signing
must be separated; use the
[Trusted Finalizer](TRUSTED_FINALIZER.md). `local` retains the existing
acknowledged direct-signing workflow for trusted inputs.

## What the profiles do not claim

- `local` does not imply process, filesystem, network, report, or credential
  isolation.
- `protected` does not claim gVisor unless gVisor was selected and delivered.
- `hostile` does not claim that a requested runtime existed. The run must
  produce observed runtime evidence; otherwise it returns a non-PASS result.
- None of the profiles proves product correctness, complete test coverage, or
  verifier-pack quality. The pack must still exercise the candidate through
  `$EVOGUARD_EXEC` and assert meaningful external behavior.

Historical schema-1.11 records remain valid, but that frozen policy contract
does not permit `operating_profile`. Offline record verification rejects both a
profile placed in schema 1.11 and a schema-1.12 profile that contradicts its own
effective policy, such as `hostile` paired with Docker or subprocess isolation.
