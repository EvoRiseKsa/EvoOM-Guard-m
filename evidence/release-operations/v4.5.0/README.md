# v4.5.0 publication-authority retirement

`KEY_RETIREMENT.json` is the canonical, separately signed post-ledger receipt
for the temporary publication authority named by the immutable `v4.5.0`
release ledger. `KEY_RETIREMENT.json.sig` is its detached Ed25519 signature
under the same independently pinned release-ledger public key.

The receipt binds the exact ledger and signature hashes and records successful,
fully paginated HTTP 200 observations after removal of:

- repository deploy key ID `158948115`; and
- Environment secret `EVOGUARD_RELEASE_TAG_DEPLOY_KEY` in
  `evoguard-release-publication`.

Validate it with the validator bytes and Git objects extracted from the
ledger's admitted trusted parent, plus an independently retained copy of the
pinned `v4.5.0` ledger public key:

```powershell
python -I <trusted-parent>\tools\ci\validate_release_ledger_v2.py validate-retirement `
  evidence\release-ledgers\v4.5.0 `
  evidence\release-operations\v4.5.0\KEY_RETIREMENT.json `
  evidence\release-operations\v4.5.0\KEY_RETIREMENT.json.sig `
  --trusted-ledger-pub <independent-v4.5.0-ledger-public-key> `
  --trusted-parent-repo <trusted-parent>
```

The required success result is `release-key-retirement-v1: VALID`.

This receipt is a signed, same-owner point-in-time GitHub API observation. It
does not prove secure erasure, absence of copies outside GitHub, simultaneous
global state, or prevention of later re-addition. It does not modify the closed
ledger: `pending-post-ledger` remains the correct state recorded at ledger
creation time.
