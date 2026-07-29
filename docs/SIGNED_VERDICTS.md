<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# Signed verdicts — tamper-evident Guard evidence

A Guard verdict is only as trustworthy as its storage. The JSON report a CI job
uploads to an artifact bucket, a dashboard, or a compliance archive can be
edited *after the fact* — a `FAIL` quietly upgraded to a `PASS` leaves no
trace. Signing closes that hole: the judge holds an **Ed25519 private key** and
emits a **detached signature** next to every verdict; anyone holding the public
key can verify — offline, years later — the exact bytes signed by that
private-key holder. The signature alone does not establish who operated the
key or whether the recorded run was honest.

<!-- BEGIN EVOGUARD_PROJECT_STATUS:SIGNED_VERDICTS_RELEASE_PIN -->
Requires the `sign` extra (the core gate stays stdlib-only). Install it from
ledger-recorded release `v4.4.2`:

```bash
pip install "evoom-guard[sign] @ git+https://github.com/EvoRiseKsa/EvoOM-Guard-m@v4.4.2"
```
<!-- END EVOGUARD_PROJECT_STATUS:SIGNED_VERDICTS_RELEASE_PIN -->

The pinned `v4.4.2` release includes the
`--acknowledge-local-key-exposure` flag and the descriptor/reservation
hardening documented below. Consult the documentation at the exact version
you run; the release ledger authenticates bytes and provenance, not key
custody or the honesty of a signing workflow.

## Usage

To run the repository-source example, install the current checkout in a
disposable trusted development environment:

```bash
python -m pip install -e ".[sign]"
```

```bash
# Once: generate the judge's identity. The private key is a CI secret;
# the public key goes wherever verdicts are consumed.
evo-guard keygen --key evoguard-signing.pem --pub evoguard-signing.pub

# Trusted local input only: sign the JSON verdict as it is written.
git diff main...HEAD | evo-guard guard --diff - --no-config \
    --test-command "python -m pytest -q" \
    --json verdict.json --sign-key evoguard-signing.pem \
    --acknowledge-local-key-exposure
# -> verdict.json + verdict.json.sig (base64, detached)

# Anywhere, any time later: verify offline.
# Exit 0 = valid; 1 = invalid/signature or expected-policy mismatch;
# exit 2 = unusable input or verification could not be performed.
evo-guard verify-verdict verdict.json --pub evoguard-signing.pub
```

`keygen` creates both final paths exclusively and never overwrites an existing
file, symlink, or reparse path. Portable filesystems do not provide one atomic
transaction for two output paths, so failure cleanup deliberately never unlinks
a final name. On the normal handled failure path, any written key bytes are
invalidated through the retained descriptors and one or both **zero-length
reservations can remain**. Inspect and explicitly remove those reservations
before retrying. If the error says invalidation could not be proven, treat every
created output as sensitive and incomplete until it is inspected and removed.
Descriptor-close failures are bounded. A descriptor number is never probed or
retried after `close()` reports an error because the runtime may already have
released and reused that number. Before the close attempt, EvoOM Guard makes a
safe duplicate. A `KeypairCloseError` or `OutputReservationCloseError` with
`descriptor_retained=True` owns only such proven-safe duplicate(s); call
`release_retained_descriptors()` and inspect its Boolean result rather than
looping without a bound. Recovery never follows a pathname. Separately,
`descriptor_ownership_indeterminate=True` (also exposed as
`process_exit_may_be_required=True`) means a failed close may have left an
unreachable descriptor open; no recovery API touches that ambiguous number,
and full release may require process exit.
Generate keys only in a trusted, quiescent parent directory; exclusive file
creation is not a security boundary against an actor that can rename entries in
that directory while generation is in progress.

`keygen` requests POSIX mode `0600` for the private key (`0644` for the public
key), and detached sidecar creation requests `0600`. These numeric mode bits are
a best-effort portable control, not a cross-platform access-control guarantee.
In particular, Python's creation mode does **not** install a restrictive Windows
DACL. On Windows, enforce an appropriate ACL or use a protected secret store for
the private key; apply the same operational protection to any other sensitive
paths.

File signing and verification read bounded, stable, regular non-link snapshots:
the signed file is limited to 64 MiB and the base64 signature sidecar to 4 KiB.
Signing reserves `<file>.sig` with exclusive creation, so an existing regular
file, symlink, dangling symlink, directory, or reparse path is never followed,
replaced, or truncated. It writes and `fsync`s the retained read/write
descriptor, reads back the exact expected bytes through that same descriptor,
checks stable size/link metadata, and binds the final path before returning.
This detects both an observed path replacement and an observed same-inode
content rewrite during the commit checks. The parent directory itself is not
`fsync`ed, and no portable file API can eliminate a race after the final check;
use a trusted, quiescent parent directory. A failed write can leave a new
incomplete sidecar reservation that must be inspected and removed explicitly
before retrying.

A post-commit descriptor-close fault raises `SignatureSidecarCloseError`
instead of reporting success. Its `sidecar_committed`,
`sidecar_invalidated`, `descriptor_retained`, and
`descriptor_ownership_indeterminate` fields distinguish a committed sidecar
from one durably truncated through a proven-safe duplicate and from a close
whose ownership cannot be resolved safely. If `descriptor_retained` is `True`,
call the bounded, descriptor-only `release_retained_descriptor()` method and
inspect its Boolean result. If ownership is indeterminate, treat process exit
as the only portable full-release boundary.

Input snapshots use the same rule. A failed descriptor close raises
`InputSnapshotCloseError`, preserving any proven-safe duplicate for bounded
release while reporting ambiguous close ownership separately.

The signature covers the **exact bytes of the verdict file** — no
canonicalization step to get subtly wrong. Any post-signing change, down to a
single byte, flips verification to `INVALID` (see `tests/test_signing.py`,
which forges exactly the `FAIL`→`PASS` attack).

`guard --sign-key` deliberately refuses to run without
`--acknowledge-local-key-exposure`. The acknowledgement is an explicit statement
that the candidate is trusted: in the default subprocess mode, candidate code
runs under the same OS identity that can read the private key. It is not key
separation and must not be used for hostile pull requests. For untrusted
candidates, use the split [Trusted Finalizer](TRUSTED_FINALIZER.md), whose
candidate job has no private key and whose protected sealing job never checks
out or executes candidate code.

## What a signature proves — and what it does not

| Proves | Does not prove |
|---|---|
| The verdict was not altered after signing | That the run itself was honest |
| The signer held the private key | Who physically ran the job |

For trusted local inputs, Guard's judge-owned report and effective-policy
protected-path admission shape the run; the signature extends record integrity
after the run. The chain
is only as strong as key custody. For untrusted inputs, direct signing cannot
make that custody claim because the candidate and signer share an OS identity;
use the Trusted Finalizer boundary instead. Rotate private keys like any
credential and pin the public key at the consumer.

## Where this is heading

Signed verdicts are an integration point for audit-trail systems: an append-only
log (for example a Merkle tree with signed roots) can ingest `verdict.json` +
`verdict.json.sig` pairs and answer which signed verdict records it retained,
under which key and bound context. Proving that a patch entered a codebase, the
human or workload identity that ran it, or a patch-to-merge chain additionally
requires authenticated SCM/admission events and external identity bindings.
The Guard signing primitive ships today; that ingestion and merge-provenance
system is out of scope for this repository.
