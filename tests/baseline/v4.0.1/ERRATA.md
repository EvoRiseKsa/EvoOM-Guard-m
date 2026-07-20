# v4.0.1 baseline errata

This erratum corrects repository metadata after `v4.0.1` was published. The
immutable release, tag, and release assets were not changed.

The original `baseline-v1` manifest was collected before publication and kept
the values `pre-release`, `4.0.1-candidate`, and the capture commit
`00427917c03266f99a9cf99a21e82ed57c46f226`. The published release actually
targets `5ed7e84017619496521b813f859a6a8bf0a2b1df`. `baseline-v2` records both
facts separately instead of overloading one source-SHA field.

The signed-record fixture was committed with LF endings after having been signed
over CRLF bytes. Its detached Ed25519 signature therefore failed against the
committed file. The fixture now restores the original signed CRLF bytes and
`.gitattributes` marks that one path as opaque (`-text`). No key or signature was
replaced, and verification of the exact bytes is now a required test.

External release and provenance facts were re-checked on 2026-07-20. They are
recorded in `release-manifest.json`; offline tests verify their internal binding
to the frozen asset digest without claiming that a JSON record alone proves
GitHub's present online state.
