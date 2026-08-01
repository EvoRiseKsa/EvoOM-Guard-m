# EvoOM Guard v4.5.0 release evidence

This directory retains the byte-exact evidence used to assemble the signed
EvoOM Guard v4.5.0 Release Ledger v2.

The directory is not self-authenticating. Verify it with the independently
pinned v4.5.0 ledger public key and the exact trusted parent repository by
following `docs/RELEASE_LEDGER_V2.md`. The GitHub Release contains only the
three public release assets; the RSAE, RAAEs, controls, observations, and trust
roots here are retained audit evidence.

The first H trigger, run `30703427155`, was intentionally skipped while the
target-bound publication variable remained disabled and created no tag or
Release. G run `30703412593` was then re-run as attempt 2 after its first
attempt's retained detached evidence was reviewed. The canonical successful
chain uses G run `30703412593` attempt 2 and H run `30703544535` attempt 1.
