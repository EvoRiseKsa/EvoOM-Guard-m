# v4.5.0 gVisor runtime observation

This directory preserves a bounded public subset of one **same-owner** run from
the private `EvoRiseKsa/evoom-guard-system-acceptance-private` repository. The
run was GitHub-hosted, used the exact published `v4.5.0` zipapp, selected
`runsc`, kept Docker networking at `none`, passed the nine required isolation
probes, accepted the honest two-test case, and rejected the deliberately broken
two-test case.

[`PUBLIC_RECORD.json`](PUBLIC_RECORD.json) is the governing public
interpretation and closed byte inventory. Its schema is
[`../runtime-observation-v1.schema.json`](../runtime-observation-v1.schema.json).
The files under [`raw/`](raw/) are byte-for-byte selections from Actions run
`31298956172`; some references inside the original `raw/observation.json` point
to private or unretained transfer files and are not part of this public
inventory.

The source-run record distinguishes the synthetic pull-request event merge
commit from the Git blob containing the workflow. The workflow path and blob
identity are bound in the record, but the private workflow bytes are not part
of this public subset; that binding is not an independent public review of the
workflow.

The GitHub Actions artifact (`9033891750`, digest
`sha256:3adeffcc910988b0f98f9e9970dcc5cfd16d5ab7902d349aa5c6c12a379b321b`)
was a temporary transfer carrier expiring on `2026-08-23T06:29:32Z`. Its exact
locator is retained in `PUBLIC_RECORD.json`, but this checked-in subset is the
durable source of truth. It contains no signing key, credential, customer
material, held-out label, or production policy.

## Boundary

This is not an independent review, production or field result, dedicated-host
or hostile-host proof, multi-host/non-forking-ledger proof, Firecracker/VM
proof, or proof that gVisor, Docker, GitHub's hosted runner, or the workflow is
invulnerable. The observed launcher receipts establish a non-zero invocation
fact only; their raw count is not an audited exact candidate-call count.

The release identity remains governed by the signed
[`v4.5.0` release ledger](../../release-ledgers/v4.5.0/RELEASE_LEDGER.json).
