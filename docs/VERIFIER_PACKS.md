<!--
  Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Independent Verifier Packs

A Verifier Pack is a directory of **judge-owned tests and invariants** that a
patch **cannot modify**, injected into the verified copy at judgment time and
run alongside the repo's own suite.

```bash
evo-guard guard . --diff - --verifier-pack /secure/org-invariants
```

The pack is copied into the throwaway copy at `evoguard_verifier_pack/`, so
pytest collects it with everything else. A candidate that tries to write
anywhere under that path is `REJECTED` (it is attacking the harness). The pack's
content digest — and an optional manifest — are recorded in the verdict's
attestation, so you can prove *which* invariants judged a change.

## What a pack guarantees — and what it does NOT

**Guarantees (the real value):**

- **Tamper-proof checks.** The diff cannot edit, delete, or deselect the pack's
  tests — they live outside the repo and are added by the judge. This is exactly
  the property a per-repo `tests/` directory lacks once you let an agent touch it.
- **Centralised, versioned invariants.** One pack of security/API/permission/
  regression checks can gate PRs across many repositories, owned by the security
  or platform team rather than copied into each project.
- **Overfitting pressure.** A patch that hard-codes answers to the visible tests
  still has to satisfy the pack's independent checks, which exercise different
  inputs.

**Does NOT guarantee (state this plainly):**

- **Secrecy.** The pack files sit on disk in the same tree the test process runs
  in, so the code under test **can read them at runtime** (`open()`,
  `glob`, …). A deliberately adversarial patch can read a pack test, extract the
  expected value from an assertion, and return exactly that — passing without
  being correct. A Verifier Pack is an **integrity control, not a hidden oracle**.

If you need checks the running code genuinely cannot observe, that requires a
different architecture — running the program under test as a black box in a
separate process/host that never exposes the check code to it. That is on the
roadmap; the current pack feature does not claim it.

## Best used for

- organisation-wide **security invariants** and **API contracts**
- **permission / authorization** rules that must hold across services
- **regression tests distilled from real incidents**, owned centrally
- **version / dependency** policies

i.e. checks whose value is *"this rule cannot be quietly removed in a PR"* — not
checks whose value depends on the author not knowing them.

## Optional manifest (`pack.json`)

Drop a `pack.json` at the pack root to make it a versioned, auditable artifact:

```json
{
  "id": "company-security-invariants",
  "version": "1.3.0",
  "description": "Organization security and API invariants"
}
```

It surfaces in the verdict attestation next to the pack's content digest:

```json
"attestation": {
  "verifier_pack_sha256": "…",
  "verifier_pack_manifest": { "id": "company-security-invariants", "version": "1.3.0" }
}
```

so a signed verdict records precisely which policy version judged the change.

## Constraints

- **pytest runners** collect the pack today (it is added to the pytest rootdir).
- **Unique basenames.** A pack test file must not share a basename with a repo
  test file (e.g. two `test_utils.py`), or pytest's default import mode raises a
  collection error. Name pack files distinctly (e.g. `test_pack_*.py`).
- The pack's tests run **in the judge process**, like the repo's own tests — use
  the container isolation modes (`--isolation docker`) for semi-trusted code.
