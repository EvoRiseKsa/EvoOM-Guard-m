# v4.4.2 post-ledger publication-authority operation

The exact write deploy key and publication Environment secret recorded by the
signed `v4.4.2` ledger were removed from GitHub after that ledger had been
committed and revalidated. The retained
[`PUBLICATION_AUTHORITY_RETIREMENT_OBSERVATION.json`](PUBLICATION_AUTHORITY_RETIREMENT_OBSERVATION.json)
records the bounded authenticated API observation made after removal.

This directory deliberately does **not** contain `KEY_RETIREMENT.json` or a
detached signature. The offline private key corresponding to the pinned
`v4.4.2` release-ledger public key was not available to this operation, so a
valid signed retirement receipt could not be created. The observation therefore
proves neither destruction of external key copies nor independent review, and it
must not be described as the signed retirement receipt required by
[`docs/RELEASE_LEDGER_V2.md`](../../../docs/RELEASE_LEDGER_V2.md).

The immutable signed ledger remains unchanged and correctly retains
`pending-post-ledger` as the state known at ledger-creation time.
