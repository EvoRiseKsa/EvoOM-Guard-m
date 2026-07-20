## Change classification

Select exactly one class and state it in the PR title or summary.

- [ ] `R0-docs` — documentation or metadata only; runtime is unchanged.
- [ ] `R1-mechanical` — move or rename only; behavior is unchanged.
- [ ] `R2-compatible` — internal compatible change with stable public contracts.
- [ ] `R3-semantic` — changes verdict, policy, execution, or evidence semantics.
- [ ] `R4-trust-root` — changes signing, finalizers, workflows, releases, or trust inputs.

Selected class: `R?-...`

## Scope and purpose

Describe what changed, why it is needed, and what is explicitly out of scope.

## Compatibility evidence

- [ ] Public API/CLI/schema compatibility is unchanged, or the migration is documented.
- [ ] Golden/contract tests cover the affected surface.
- [ ] This PR does not mix a mechanical move with a semantic change.
- [ ] `main` remains releasable after merge.

For `R1-mechanical` and behavior-preserving `R2-compatible` changes:

- [ ] Apply the `no-behavior-change` label.

## Security review requirements

Required for `R3-semantic` and `R4-trust-root`; write `not applicable` only with a reason.

- Affected invariant(s):
- Threat model / attacker capability:
- Positive test:
- Negative or adversarial test:
- Compatibility note:
- Rollback plan:

## Validation

List the exact commands, CI runs, benchmarks, or evidence used to validate this change.

## Reviewer boundary

`@MANA-awam` and `@EvoRiseKsa` are controlled by the same project owner. Their
separation provides a GitHub workflow control and prevents self-approval; it is
not independent or third-party review.
