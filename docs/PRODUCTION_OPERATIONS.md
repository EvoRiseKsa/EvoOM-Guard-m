# Production operations contract

This is the operator contract for a protected or hostile-profile deployment.
It is deliberately not evidence that any deployment has exercised these
procedures. Production status requires retained exercise records from the
actual storage, key, repository, runner, and incident-response authorities.

## Non-negotiable failure rule

Availability never weakens admission:

- a timeout, missing record, missing finalizer, unavailable isolation provider,
  telemetry outage, signature failure, or policy mismatch is `ERROR`, `DENY`, or
  no decision;
- no retry service may translate an absent result into `ALLOW`;
- only the finalizer can issue admission, and only over the exact immutable
  source, policy, runner, and evidence identities it verified;
- manual override is a separately authenticated policy event, never a rewritten
  Guard record.

For service objectives, measure availability as “a trustworthy terminal
decision was produced within the objective,” not “the merge remained
available.” An unavailable judge may consume the error budget; it may not
consume the security boundary.

## Immutable evidence storage

Use storage controlled by an evidence-publisher identity that cannot run the
candidate, select tests, change policy, or sign decisions. The required profile
is:

- create-only object names containing evaluation/repository, run, attempt, and
  exact record digest;
- provider-enforced object lock or equivalent append-only retention in a
  separate administrative account;
- encryption keys and deletion authority separate from the CI/finalizer
  identities;
- a declared minimum retention period covering records, raw verdicts, external
  context, signatures/public roots, policy and verifier-pack bytes, runner and
  image identities, workflow/run metadata, and audit events;
- inventory export with object version, size, digest, lock mode, expiry, and
  writer identity;
- documented legal deletion path requiring a distinct approval authority and a
  retained tombstone/audit event;
- a recovery drill that restores a random retained run into a clean account and
  completes detached verification using independently retrieved public roots.

GitHub Actions artifacts alone are temporary transfer storage and do not
satisfy this profile.

## Key lifecycle

Each authority domain uses a distinct key. Never rotate several domains by
copying one replacement private key.

1. Generate the new key outside candidate and judge identities.
2. Publish its public key and stable key ID through the protected policy
   authority while the old verification key remains trusted.
3. Verify the new public key through an independent channel.
4. Perform a non-production negative/positive sealing drill.
5. Activate the new signing key for exactly one domain and record the first
   admitted object.
6. Stop new signing with the old key, but retain its public key for historical
   verification through the evidence-retention period.
7. Revoke access to and destroy the old private key; retain provider audit
   evidence and a signed rotation receipt.
8. Test that an old-key signature cannot authorize a new run while an
   historical old-key record still verifies under its recorded policy epoch.

Suspected exposure skips normal rotation: disable admission, revoke the key,
freeze evidence, and follow incident response before re-enabling.

## Incident response

Triggers include an unexpected `ALLOW`, isolation escape/probe success,
candidate access to a token/key/policy/report path, signature mismatch, evidence
mutation, required-check bypass, unexplained policy change, or a surge in
`ERROR`/`TAMPERED`.

The response order is:

1. disable admission and publication flags; keep fail-closed required checks;
2. remove/revoke the affected private key, token, deploy key, runner grant, and
   environment approval path;
3. freeze the exact run, workflow, policy, pack, image, logs, records, and
   provider audit events without executing candidate bytes again;
4. identify every admission sharing the affected key/policy/runner epoch;
5. invalidate downstream deployment eligibility outside EvoOM Guard—retained
   signed bytes are never silently rewritten;
6. repair in a new policy/tool version, run the adversarial/conformance matrix,
   and obtain review from an authority that did not make the repair;
7. restore from the last admitted release and re-enable one authority at a
   time;
8. publish a scoped incident record and new trust roots. Preserve old public
   roots for forensic verification unless policy explicitly marks their epoch
   compromised.

## Telemetry and SLOs

Use `tools/telemetry/aggregate_verdicts.py` locally only to summarize existing,
pre-verified verdict records. It reports:

- `ERROR`/abstention rates and the `TAMPERED` count;
- allowlisted reason-code, isolation-delivery, operating-profile, and
  policy-version counts; and
- runtime-tree identity measurement latency when the record contains it.

Its denominator is supplied record files, not attempted runs. It does **not**
measure terminal-decision availability, end-to-end latency, runner counts,
missing records, finalizer/publisher failures, or evidence-retention lag.

Those production SLOs require an authoritative orchestrator inventory or
append-only event stream containing expected run/attempt identities and
decision, finalization, publication, and retention events. The production
integration must fail closed on missing, duplicate, late, or contradictory
events, join each expected attempt to one verified retained record, and expose
an operator-reviewed alert/export path. The operational telemetry gate remains
open until that source is deployed and exercised against the actual provider.
Export only reviewed aggregates.

Do not export candidate source, file paths, commands, diagnostics, raw evidence,
repository/customer identifiers, secrets, or free-form policy labels.

Recommended alerts are directional, not universal product promises:

- any `ALLOW` without a retained valid finalizer record: immediate incident;
- any hostile-profile delivery below gVisor/VM class: immediate incident;
- any evidence object missing after the configured publication window:
  admission disabled;
- any non-zero isolation escape or policy-tamper probe: admission disabled;
- `ERROR`/latency changes: operational investigation, never fail-open.

## Upgrade and rollback

Before upgrading:

- freeze the exact current artifact, policy, schema readers, workflow blobs,
  image/runtime, public roots, and last admitted release;
- prove the new reader accepts every supported historical schema and rejects an
  unknown/contradictory record;
- run runner and isolation conformance plus security mutation and fuzz gates;
- execute the same frozen pilot corpus on old and new versions and review every
  changed verdict/reason/policy digest;
- migrate policy in a separate protected change from workflow/tool migration;
- retain both verification readers during the declared compatibility window.

Rollback restores the last admitted artifact, its exact workflow/policy/pack,
and compatible public-root set. It does not move an immutable release tag,
rewrite evidence, reuse a revoked private key, or relabel a result from a weaker
profile. If the previous isolation image/runtime is no longer obtainable by
digest, rollback is unavailable and admission remains disabled.

## Required exercise record

For each production environment, retain a dated record naming:

- operator/reviewer identities and conflicts;
- repository/ruleset/environment snapshots;
- storage object-lock and recovery evidence;
- key rotation and compromised-key rejection evidence;
- incident disable/revoke/freeze/restore timings;
- upgrade/rollback artifacts and changed-verdict review;
- telemetry privacy review and alert delivery;
- exact commits, workflow blobs, image/runtime digests, commands, run IDs, and
  raw output digests.

A filled checklist without underlying provider evidence does not close the
operations gate. The production blueprint must continue to report the gate as
open until these drills have been completed on the intended deployment.
