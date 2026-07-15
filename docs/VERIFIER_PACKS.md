<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Independent Verifier Packs

A Verifier Pack is a directory of **judge-owned pytest tests and invariants**
supplied at judgment time. The patch cannot include, replace, delete, or
deselect those files. In repo-native mode Guard runs the repo's own suite and
then runs the accepted pack snapshot as a **separate mandatory phase**; both
must pass.

```bash
evo-guard guard . --diff - --no-config --verifier-pack /secure/org-invariants
```

The judge copies the pack to a temporary snapshot **outside** the candidate
tree and its `HOME`, records its V2 content identity, and addresses that
snapshot explicitly with `python -m pytest`. A narrowed command such as
`pytest tests/unit` or a non-pytest repo command therefore cannot silently skip
the pack. Zero collected pack tests is not a pass.

`evoguard_verifier_pack/` remains a reserved candidate path: a patch that tries
to pre-plant or edit it is `REJECTED` before execution. It is no longer the
runtime location of the accepted pack, so pack code must resolve local data
relative to `__file__`, not a hard-coded injected directory.

## Pin the exact accepted content

`pack.json` gives a pack a human policy name/version; the security identity is
its `EVOGUARD_PACK_V2` SHA-256. Generate it before adoption:

```bash
evo-guard pack-doctor /secure/org-invariants --json
```

Then make that identity a fail-closed policy requirement:

```bash
evo-guard guard . --diff - --no-config \
  --verifier-pack /secure/org-invariants \
  --expect-verifier-pack-sha256 <64-hex-v2-digest>
```

Equivalent protected config and Action input:

```json
{
  "expect_verifier_pack_sha256": "<64-hex-v2-digest>"
}
```

```yaml
with:
  verifier-pack: /secure/org-invariants
  expect-verifier-pack-sha256: <64-hex-v2-digest>
```

The expected digest is checked before candidate code runs and is included in
`attestation.effective_policy`, so it also changes `policy_sha256`. A mismatch
is `ERROR` / `verifier_pack_identity_mismatch`; Guard does not run a different
pack and merely note the difference.

V2 is a portable **content/tree identity**. It hashes typed directory/file
records, normalized relative paths, lengths, and file bytes, including empty
directories. It rejects symlinks and special files because their targets are
not portable pack content. It does not claim to bind timestamps or filesystem
permission metadata. File bytes are exact: LF/CRLF conversion changes the
digest. Compute and pin the digest from the same canonical pack artifact used
by CI (or distribute an immutable archive) rather than relying on checkouts
with different Git line-ending policies. Recompute old stored digests when
upgrading from 3.3.x; the earlier concatenation digest is not a V2 identity.

## What a pack guarantees — and what it does NOT

**Guarantees (the real value):**

- **Patch-immutable checks.** The diff cannot edit, delete, or deselect the
  pack's tests: they live outside the repo and are added by the judge.
- **Observed snapshot fidelity.** The accepted snapshot is re-hashed
  immediately before and after its phase. Persistent drift is `TAMPERED` /
  `verifier_pack_snapshot_changed`, never accepted as evidence for the original
  digest.
- **Mandatory execution.** The repo suite and explicit pack phase are composed;
  both must pass. The attestation records separate pack counts, and
  `verdict_source` becomes `composite:repo+verifier-pack`.
- **Candidate-tree continuity.** With a pack, Guard compares the complete
  post-setup runtime tree before and after the repo and pack phases. Persistent
  drift anywhere in that prepared tree is `TAMPERED` /
  `candidate_tree_changed_during_run`.
- **Centralised, versioned invariants.** One pack of security/API/permission/
  regression checks can gate many repositories and remain owned by a security
  or platform team.
- **Overfitting pressure.** A patch that hard-codes answers to visible tests
  still has to satisfy independent checks over different inputs.

**Does NOT guarantee (state this plainly):**

- **Secrecy in repo-native mode.** The snapshot is outside the candidate tree,
  and the repo suite is not given its path. But the pack's pytest process may
  import candidate code; that code can inspect the process and read pack files.
  A pack is an integrity control, not a hidden oracle.
- **Same-process report integrity.** Pre/post file hashes detect persistent
  snapshot/tree drift; they do not stop in-memory monkeypatching or make the
  repo-native JUnit writer unforgeable. Its assurance remains
  `same_process_candidate_writable`.
- **A subprocess sandbox.** Under the default host subprocess, candidate and
  judge share the OS account. Pre/post checks are evidence of observed durable
  state, not an OS confinement boundary, and transient changes restored between
  observations are not claimed as impossible.
- **Scope of trusted setup exceptions.** `setup_output_globs` and newly
  generated conventional dependency/build outputs are excluded only from the
  setup-fidelity comparison. After setup, `EVOGUARD_RUNTIME_TREE_V1` binds the
  complete prepared tree, including those paths, before the repository suite
  and checks it again before and after verifier-pack execution. Never allowlist
  source, tests, policy, or harness paths: the exception still permits setup to
  replace those bytes before the runtime identity is captured.

For checks the running code genuinely cannot observe or modify, use the shipped
external black-box judge (`--blackbox`): the pack runs in the judge's own
process and never imports the candidate, and with `--isolation docker` the pack
is not mounted into the candidate at all. `setup_command` is not implemented by
the black-box judge today; requesting both fails closed with
`policy_requirement_unsupported`. See [`BLACKBOX.md`](BLACKBOX.md).

## Best used for

- organisation-wide **security invariants** and **API contracts**
- **permission / authorization** rules that must hold across services
- **regression tests distilled from real incidents**, owned centrally
- **version / dependency** policies

These are checks whose value is “this rule cannot be quietly removed in a PR”,
not checks whose value depends on the author never observing them.

## Optional manifest (`pack.json`)

Drop a `pack.json` at the pack root to make it a versioned, auditable artifact:

```json
{
  "id": "company-security-invariants",
  "version": "1.3.0",
  "description": "Organization security and API invariants",
  "target_type": "cli",
  "protocol": "argv-json"
}
```

If `pack.json` exists, `id` and `version` are required non-empty strings.
`description`, `target_type`, and `protocol` are optional strings. Duplicate
keys, unknown keys, malformed JSON, or wrong field types make the pack invalid
in `pack-doctor` and in both judges. These optional fields are attested metadata,
not operational routing: Guard does not infer a launcher or network policy from
`target_type`/`protocol`. Omitting `pack.json` entirely remains valid.

It surfaces in the verdict attestation next to the pack's content digest:

```json
"attestation": {
  "verifier_pack_sha256": "…",
  "verifier_pack_digest_format": "EVOGUARD_PACK_V2",
  "verifier_pack_manifest": {
    "id": "company-security-invariants",
    "version": "1.3.0"
  },
  "verifier_pack_tests_passed": 12,
  "verifier_pack_tests_total": 12
}
```

For a signed verdict this binds the accepted pack content and declared policy
version to the judgment. The manifest version alone is not a content identity.

## Constraints

- At least one regular `test_*.py` file is required.
- Python and pytest must exist in the host judge environment or container image,
  even if the repo's own suite uses Node, Go, Ruby, Java, or a custom command.
- Symlinks, special files/directories, unreadable paths, and a symlinked pack
  root are refused; they cannot be represented by the portable V2 contract.
- In Docker/gVisor repo-native mode, the candidate tree and pack snapshot are
  mounted read-only for their execution phases. The pack can still import the
  candidate in the same pytest process, so this protects storage/host state,
  **not** report integrity or secrecy. Use black-box mode for process separation.
