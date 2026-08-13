<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# Aborted v4.6.0 source-admission attempt

This record describes a fail-closed attempt against commit
`a5c152bfcdd4d47fe24ed433ebc17825487045ab`. That commit was never tagged or
published as `v4.6.0` and is not the release target used by any later successful
operation.

The attempted chain was:

- A run [`31654078157`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/runs/31654078157), attempt 1: success;
- B run [`31654125074`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/runs/31654125074), attempt 1: success; and
- C run [`31654146756`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/runs/31654146756), attempts 1 and 2: failure.

Attempt 1 reached the protected C job after reviewer approval, then rejected
the preinstalled GitHub CLI executable before provider identity creation,
provider verification, private-key loading, signing, or sealed-envelope and
public-result artifact upload. Its
detached D job was skipped. Attempt 2 re-ran all C jobs and rejected the same
tool boundary in preflight before protected Environment access. There was no
signed `ALLOW`, detached verification, artifact admission, release, tag,
publication, or deployment authority.

The root cause was a mixed rollout of the mutable `ubuntu-24.04` image. Jobs in
the same operation received GitHub CLI 2.96.0 and 2.97.0 while the contract
correctly allowed one exact executable digest. The failure therefore exposed a
reliability defect without weakening the fail-closed decision boundary.

The replacement contract materializes GitHub CLI 2.97.0 independently in every
C, F, and H job that executes it. The workflow blob pins the official archive,
archive size, single extracted member, executable digest, executable size, and
root-owned path. It no longer discovers `gh` from the hosted-runner image.

Raw A/B artifacts, both C attempt logs, and the locally preserved C attempt-1
control set are retained in secondary operator custody under
`D:\EvoRise\release-v4.6.0\aborted-source-admission-20260813`. Its local
custody manifest has SHA-256
`528d4499706a269d9c6fa218e99691d98e9a7c5ba7d977cd64ccccddaaf9a3e1`
and binds all 25 retained files, including the preserved C controls. This path
is an operational copy, not repository authority or a member of the eventual
successful release ledger.
