<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Signed verdicts — tamper-evident Guard evidence

A Guard verdict is only as trustworthy as its storage. The JSON report a CI job
uploads to an artifact bucket, a dashboard, or a compliance archive can be
edited *after the fact* — a `FAIL` quietly upgraded to a `PASS` leaves no
trace. Signing closes that hole: the judge holds an **Ed25519 private key** and
emits a **detached signature** next to every verdict; anyone holding the public
key can verify — offline, years later — that the verdict bytes are exactly what
the judge wrote.

Requires the `sign` extra (the core gate stays stdlib-only):

```bash
pip install "evoom-guard[sign] @ git+https://github.com/EvoRiseKsa/EvoOM-Guard-m@v2.2.0"
```

## Usage

```bash
# Once: generate the judge's identity. The private key is a CI secret;
# the public key goes wherever verdicts are consumed.
evo-guard keygen --key evoguard-signing.pem --pub evoguard-signing.pub

# Every run: sign the JSON verdict as it is written.
git diff main...HEAD | evo-guard guard --diff - \
    --test-command "python -m pytest -q" \
    --json verdict.json --sign-key evoguard-signing.pem
# -> verdict.json + verdict.json.sig (base64, detached)

# Anywhere, any time later: verify offline. Exit 0 = valid, 1 = tampered.
evo-guard verify-verdict verdict.json --pub evoguard-signing.pub
```

The signature covers the **exact bytes of the verdict file** — no
canonicalization step to get subtly wrong. Any post-signing change, down to a
single byte, flips verification to `INVALID` (see `tests/test_signing.py`,
which forges exactly the `FAIL`→`PASS` attack).

## What a signature proves — and what it does not

| Proves | Does not prove |
|---|---|
| The verdict was not altered after signing | That the run itself was honest |
| The signer held the private key | Who physically ran the job |

The run's honesty comes from Guard's own design (judge-owned report, harness
edits rejected — see the [README](../README.md)); the signature extends that
integrity from the *run* to the *record*. The chain is only as strong as key
custody: keep the private key a CI secret (it is the judge's identity, not the
patch author's), rotate it like any credential, and pin the public key at the
consumer.

## Where this is heading

Signed verdicts are the integration point for audit-trail systems: an
append-only log (e.g. a Merkle tree with signed roots, as built in the author's
**Sentinel AI** — the Agentic Trust Fabric) can ingest `verdict.json` +
`verdict.json.sig` pairs and answer, cryptographically, "which patches entered
this codebase, under which verdict, judged by whom?" — an evidence chain for
AI-authored code from patch to merge. See [`ROADMAP.md`](../ROADMAP.md).
