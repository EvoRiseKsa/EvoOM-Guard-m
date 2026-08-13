<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# Aborted v4.6.0 artifact-admission attempt

This record describes a fail-closed attempt against commit
`1ef026249ae1a0737f71bfeb7712e13c3e576f13`. That commit was never tagged or
published as `v4.6.0` and is not authoritative release evidence for any later
successful operation.

The source side of the attempted chain completed successfully:

- A run [`31664667845`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/runs/31664667845), attempt 1: success;
- B run [`31664708930`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/runs/31664708930), attempt 1: success;
- C run [`31664728723`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/runs/31664728723), attempt 1: signed `ALLOW`; and
- its detached D verification: success, including all eleven negative controls.

E run [`31665202264`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/runs/31665202264),
attempt 1, built the candidate assets and provider attestations successfully.
F run [`31665249069`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/runs/31665249069),
attempt 1, then failed in the no-secret `verify-attestations` job while
semantically checking the SPDX attestation. F's protected `seal` job was
skipped. No F private signing key was loaded, no `RAAE` was produced, and G and
H did not run. There was no release, tag, publication, deployment authority, or
release-ledger member.

The failure was representational, not a failed cryptographic or hosted-runner
claim. The pinned GitHub CLI 2.97.0 successfully verified the exact artifact,
repository, workflow, source commit, OIDC issuer, SPDX predicate type, and
GitHub-hosted runner. It reports the verified signer-prefix regexp with Go-style
quoting:

```text
^https://github\.com/EvoRiseKsa/EvoOM-Guard-m/\.github/workflows/evoguard-build-release-artifact\.yml
```

GitHub CLI 2.90 reported the same literal prefix without regexp quoting. The
semantic adapter compared only the historical representation and therefore
failed closed with `verified identity is not GitHub-hosted`. The replacement
adapter accepts exactly those two observed encodings while continuing to bind
the certificate signer URI, workflow, repository, source digest, run identity,
hosted-runner value, subject digest, and predicate independently and exactly.

The retained F preflight artifact is
`evoguard-release-artifact-v1-preflight-controls-1`, artifact ID `9167665502`,
with GitHub artifact digest
`sha256:3c2ed49fb14411b86df182c750e3dda28ae7c189b6062e49df832fd9bf089644`.
Its `f-control-manifest.json` has SHA-256
`86810fdc4599775f61fc03850818861d3c4e26cf5518fc7c4267dd91e79b1c5e`
and binds the exact target, E and F workflows/runs, admitted source envelope,
artifact bytes, checksums, toolchain, authority roots, publication-key
fingerprint, and trusted verifier Git blob
`f7031269674eefacff4d06f4f445c46d230024c5`.

After this chain was abandoned, the release-source admission authority was
rotated before any replacement release run. GitHub records both the public
variable and protected-Environment secret as updated at
`2026-08-13T06:07:09Z`. The abandoned decision used key ID
`sha256:bae6a43e7701625b267ced91ef5ea8c22697ab30503b0e407c2227a49ff71fba`;
the replacement configured public identity has key ID
`sha256:2be731c51a406d5c7c1a7c2a2768fca7f4ebc5cb94f77ec803fca5892066bc3e`.
No replacement C run has yet proven that the protected secret matches that
configured public identity.
The old public PEM was not retained before the repository variable was
replaced, and the retained run artifacts carry its key ID rather than the PEM.
Consequently, the abandoned signed envelope is no longer independently
re-verifiable from the retained bundle alone. It is an explicitly incomplete
historical observation, is excluded from the eventual release ledger, and
must not be reused as evidence for a replacement candidate. A replacement
release operation must start again at A and produce a fresh C/D decision under
the replacement authority.

Operational copies of the source decision, E builder materials, and F preflight
controls are retained under `D:\EvoRise\release-v4.6.0`. They are secondary
operator custody, not repository authority or members of the eventual
successful release ledger. After the failure all three activation variables
were set to `false`; the unused temporary publication deploy key (GitHub ID
`160098514`) and its protected-Environment secret were deleted before repair
work began.
