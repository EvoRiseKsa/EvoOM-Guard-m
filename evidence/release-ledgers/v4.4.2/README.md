# EvoOM Guard v4.4.2 release evidence

This directory retains the byte-exact evidence used to assemble the signed
EvoOM Guard v4.4.2 Release Ledger v2.

The directory is not self-authenticating. Verify it with the independently
pinned v4.4.2 ledger public key and the exact trusted parent repository by
following `docs/RELEASE_LEDGER_V2.md`. The GitHub Release contains only the
three public release assets; the RSAE, RAAEs, controls, observations, and trust
roots here are retained audit evidence.

The successful workflow chain intentionally excludes build run `30442344092`,
which failed during preflight and produced no build artifacts. Publication run
`30442943655` is retained as attempt 2: attempt 1 failed before publication,
and its exact draft release and tag were removed before the successful rerun.
