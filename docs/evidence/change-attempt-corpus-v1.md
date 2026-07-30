<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see ../../LICENSE for permitted use.
-->

# Change-attempt corpus V1 engineering evidence

## Status and claim boundary

On 2026-07-30, a restricted same-owner integration workspace generated,
replayed, and signed a five-case change-attempt corpus against an exact
development snapshot of EvoOM Guard and an exact private Cognitive consumer
snapshot.

This is an **engineering conformance record**, not an efficacy evaluation. The
cases are synthetic and author-selected, and the projects and reviewer
accounts have the same human controller. The record supports only the exact
outcomes and integrity checks stated below. It does not support an accuracy,
false-positive, false-negative, generalization, security, production-readiness,
or independent-validation claim.

The Guard source used here reports `4.5.0.dev0`. It is unreleased development,
not the latest consumer release. The latest ledger-recorded consumer release
remains the one identified in [release status](../RELEASE_STATUS.md).

## Frozen identities

| Object | Frozen identity |
| --- | --- |
| Guard source commit | [`766e040ff221e3a177f2873a8aa88772c16a3829`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/commit/766e040ff221e3a177f2873a8aa88772c16a3829) |
| Guard package-tree SHA-256 | `a1d722cc3768b0066efe1d05628211ef80dec8fc90ec0688290be137507da6bd` |
| Built Guard zipapp SHA-256 | `ea9a11b2e6145304ebab5b4dc043b31ff88b55be776a63256db85781873f69ef` |
| Cognitive source commit | `a366dd94572e4f9b00d40c560a556c9c2db782c0` |
| Cognitive source-tree SHA-256 | `0a8b2ac1444c1f1eb3c078540b7bc2960c43e126009667d5465bfe8940d32013` |
| Observation schema | `evorise.change-advisory.attempt-observation.v1` |
| Signed manifest SHA-256 | `02dd727abcfdbd2973822d72c8b0e892fba88bd19f9a30fdaf35756ed9ed895c` |
| Signature descriptor SHA-256 | `bcfd81f2979e5a9a67e316a28c2719e19e9244018d6083e28b5d3d273c30ea8b` |
| Corpus issuer | `Ed25519`, key ID `sha256:519da7896fc492a170bc4c0c29e8aaff967fc8f7d6ed055f464f7c360975929b` |

The Cognitive source and restricted corpus are intentionally not public
reproduction inputs. Their hashes are identity anchors, not independently
verifiable proof available to a public reader.

The [machine-readable public summary](change-attempt-corpus-v1.json) repeats
these identities and outcomes. It is a Git-tracked derived summary, not part
of the issuer-signed source manifest and not a replacement for the restricted
evidence.

## Observed result matrix

| Designed case | Guard verdict | Guard reason | Advisory decision | Observation SHA-256 | Cognitive report SHA-256 |
| --- | --- | --- | --- | --- | --- |
| passing change | `PASS` | `tests_passed` | `ALLOW` | `2375ef94cb5950f5a87656fa85370020cb2792f5199854c245ad8c4e8b42e808` | `6fcb80a2ef181c55f784369e510f395b060420b9ef020ba1fb59eea540a7a5f4` |
| protected-harness edit | `REJECTED` | `protected_harness_edit` | `DENY` | `441b65202110d74825f130b7623940c4ae68cead1b9a6e2ed1863009c1b1bc14` | `54c2ceb6a719f80e276d20a61b72762ddf3f1e49595203c11de661eeb217338b` |
| failing judge | `FAIL` | `tests_failed` | `DENY` | `744fb20e17195b50d07f43a2d2ed0bcec00a339291f735385956a7add11c32bb` | `849a945883fcdf0d84055e9d09ac841709dc3975c35014e3bb9fb8da89436b48` |
| unmet assurance floor | `ERROR` | `assurance_requirement_not_met` | `DENY` | `bb08c8d8ea8c5fdbdf8744322ace9f64765b2e5e4c2d27b1499025f777d07d52` | `a86e70d4aada378839036855bd0e2821e8c81801ca3d32e31d69dcb8335bfcb1` |
| candidate-tree mutation | `TAMPERED` | `candidate_tree_changed_during_run` | `DENY` | `2606ce8011cf52d2a214d0e3af3ee5c36a2005c0531fe8defb023596b0c574da` | `ee0c3da61d509b7eab59897f720676437f87129bd98fab592279127900bbf8a7` |

All five projections are advisory. `ALLOW` here is not merge, deployment,
release, or promotion authority.

## What was actually verified

The pull-request path verified the corpus issuer signature and retained Guard
evidence without access to the private Cognitive source. The post-merge path
then:

1. checked out the exact Guard and Cognitive commits;
2. rebuilt the Guard zipapp and rejected a digest or version mismatch;
3. passed the authenticated integration tests;
4. fully replayed the committed corpus through the pinned Cognitive consumer;
5. generated a fresh Linux corpus;
6. transferred only the unsigned corpus artifact to a separate signing job;
7. accessed the corpus issuer key only after candidate execution had ended;
8. signed the manifest and verified the signature against an externally
   supplied public root; and
9. uploaded the signed 52-file artifact.

The complete GitHub Actions run passed. The downloaded signed artifact was
then verified again locally against the exact Guard zipapp, Cognitive runtime,
and issuer public key; the verifier returned `ok: true` with the matrix above.
A targeted scan found no private-key marker, GitHub token marker, deployment
key variable, or corpus issuer private-key variable in those 52 files.

## Residual limits

- The same person controls the producer, reviewer accounts, Guard project,
  Cognitive project, corpus, and issuer key.
- The five designed cases exercise terminal-path wiring; they do not estimate
  behavior on a population of real pull requests.
- Cognitive source, raw corpus files, signing material, private workflow
  identifiers, and operational logs remain restricted. An external reader
  cannot replay the full pipeline from this page.
- The host runner and GitHub Actions service remain trusted infrastructure.
- A successful signature proves integrity and issuer possession for the
  signed manifest. It does not prove that the issuer is independent or that
  the software is correct.
- The corpus does not train, select, or validate a machine-learning model.

Stronger claims require a preregistered held-out corpus, independent labels,
independent reproduction, an explicit sampling population, and public
non-sensitive evidence as described in
[independent evaluation](../INDEPENDENT_EVALUATION.md).
