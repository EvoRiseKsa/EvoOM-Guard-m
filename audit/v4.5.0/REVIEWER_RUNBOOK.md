<!--
  Copyright (c) 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available - see LICENSE for permitted use.
-->

# v4.5.0 external-review runbook

This runbook scopes review of EvoOM Guard `v4.5.0`. It is not an audit result
and does not change the frozen product target.

## 1. Record the companion revision

Clone the repository and detach at the separately frozen companion tag. Do not
silently follow a later `main`:

```bash
git clone https://github.com/EvoRiseKsa/EvoOM-Guard-m.git evoguard-review-v450
git -C evoguard-review-v450 fetch --tags
git -C evoguard-review-v450 checkout --detach review-v4.5.0-r1
git -C evoguard-review-v450 rev-parse HEAD
cd evoguard-review-v450
bash audit/v4.5.0/reproduce.sh /tmp/evoguard-v4.5.0-review
```

Record the resolved companion commit. `review-v4.5.0-r1` freezes review
instructions only; it is not the product target. It is not evidence that an
independent review occurred.

## 2. Verify the immutable product identity

| Item | Exact identity |
| --- | --- |
| Product Release | `v4.5.0` (Release ID `363544789`) |
| Published | `2026-08-01T14:32:33Z`, immutable |
| Product commit | `6bb4c328e56661b661e50532886802c6ba36a997` |
| Product tree | `bd81a595ca8608ad7da04390f31d5e489f5083ef` |
| Commit signature state | `verified=false`, `reason=unsigned` |
| Runtime asset | 2,356,398 bytes, SHA-256 `44bf036666bc7bb2903b647f33b63254771771887de4f170c91e8cdd8307c89d` |
| SPDX asset | 99,797 bytes, SHA-256 `d073198e6a3a7d565895b3cf885c95386768670a243e05e5b1471636a0f8da4b` |
| Checksum asset | 166 bytes, SHA-256 `0172d35b903661328f16366517fe5a8f666aaf282cf26c5ec4e263da4abedd0f` |
| Tag CI | Run `30703985270`, successful, head `v4.5.0` at the product commit |

The reproduction script stops on any mismatch. The Release attestation and
the unsigned commit observation are separate facts; neither substitutes for
the other.

## 3. Review source tests from the product commit

Use a second checkout detached at `v4.5.0`, not the companion commit. The
release CI installed hash-locked dependencies as follows:

```bash
git clone --branch v4.5.0 --depth 1 \
  https://github.com/EvoRiseKsa/EvoOM-Guard-m.git evoguard-product-v450
cd evoguard-product-v450
python -m venv .venv
. .venv/bin/activate
python -m pip install --only-binary=:all: --require-hashes \
  -r requirements/ci.lock
python -m pip install --no-deps --no-build-isolation -e .
python -m pytest <selected paths from TEST_MATRIX.md> -q
```

Python 3.10 also needs `requirements/python310-compat.lock`, as recorded by the
frozen CI workflow. Record the resolver, package hashes, operating system,
architecture, and every selected or skipped test. Docker- or gVisor-gated
results are not reproduced unless that runtime really executed.

## 4. Validate the later Release Ledger separately

The ledger is a later-on-`main` evidence object, not a file in `v4.5.0`:

| Item | Exact identity |
| --- | --- |
| Ledger path | `evidence/release-ledgers/v4.5.0/RELEASE_LEDGER.json` |
| Added by commit | `a3f8c2a4ba561f041f133cc8da95251b873153a8` |
| Ledger SHA-256 | `9ee6c49e7a3c93d611c34e208f5e3936f147bf0ed0b8ff2c41b3e53b891da239` |
| Signature SHA-256 | `c27004b845a411e337e087db9fe1e6409a7818f0a20f8c0b359846c7545d985c` |
| Trusted parent | `7e20173cd7df6c7fe08e1b5cd6e76c2048abd929` |
| Trusted parent tree | `21c0b988ea31c2cae3ce59c2dfb94d0c3978e9d4` |
| External root SHA-256 | `159ff19305f536ce4932117624b7c91a6881ff6a4a78fda21fc5adf53c613c26` |

Follow `docs/RELEASE_LEDGER_V2.md`. The root must come from a previously
trusted channel outside the ledger directory, and the parent repository must
be a disjoint trusted checkout. A shape-only or in-root-key check is not
equivalent:

```bash
python -I tools/ci/validate_release_ledger_v2.py validate \
  evidence/release-ledgers/v4.5.0 \
  --trusted-ledger-pub /trusted-roots/v4.5.0-release-ledger.pub.pem \
  --trusted-parent-repo /trusted-checkouts/evoguard-v4.5-parent
```

Record the origin of the external root. A valid signature authenticates the
ledger bytes under that root; it does not make same-owner collection an
independent audit or convert recorded observations into universal proofs.

## 5. Classify the later gVisor record and Firecracker correctly

The public gVisor record was merged later on `main` by commit
`525736947ddb3cffccbc7a50509db56249136140`. It names private same-owner run
`31298956172/1`, one GitHub-hosted Linux environment, 9/9 required conformance
probes, an honest 2/2 PASS, and a deliberately broken 0/2 FAIL. Its durable
public subset is the checked-in record; the source run is not public evidence.

Do not label that record independent, production, hostile-host, field efficacy,
multi-host, non-forking-ledger, VM, or Firecracker evidence. Firecracker is an
unimplemented design in this target.

## 6. Authorized testing and result taxonomy

Inspect and download the public target. Execute adversarial tests only in a
disposable repository and runner you control or are expressly authorized to
test. Do not test third-party infrastructure, exfiltrate data, disrupt service,
retain credentials, or publish a working bypass before coordinated disclosure.

For every matrix row, report one of:

- `finding`;
- `tested-no-finding`;
- `partial`;
- `not-tested`; or
- `not-applicable`.

A negative result covers only the exercised paths. It is not a field error
rate, certification, general endorsement, or proof of immunity.

## 7. Reporting

Use [`REVIEW_REPORT_TEMPLATE.md`](REVIEW_REPORT_TEMPLATE.md). Disclose reviewer
identity, relationship, funding, and who controlled case selection, execution,
labels, and interpretation. Send security-sensitive findings through the
private route in [`SECURITY.md`](../../SECURITY.md). Never include keys, tokens,
cookies, Environment exports, credential-bearing URLs, or unredacted
secret-bearing logs.
