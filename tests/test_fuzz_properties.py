# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Seeded property fuzzing for the strict JSON parser and the bundle container.

Deterministic by design: every generator runs from a fixed seed, so a failure
reproduces byte-for-byte on any machine with the same Python — no third-party
fuzzing dependency, matching the project's stdlib-only philosophy. The
properties encode the fail-closed contracts the hand-written tests assert by
example:

- ``strict_json_loads`` agrees with the stdlib on every valid document it
  accepts, and rejects everything else with ``ValueError`` — never any other
  exception type, whatever bytes arrive.
- A byte flipped anywhere in a sealed evidence bundle must surface as
  ``EvidenceBundleError`` from verification — never a crash from an
  underlying layer and never a verified result.
"""

from __future__ import annotations

import json
import math
import random
import string

import pytest

from evoom_guard.evidence_bundle import (
    EvidenceBundleError,
    create_evidence_bundle,
    verify_evidence_bundle,
)
from evoom_guard.strict_json import (
    MAX_JSON_DEPTH,
    MAX_JSON_INTEGER_DIGITS,
    strict_json_loads,
)

try:
    import cryptography  # noqa: F401

    HAS_CRYPTO = True
except ImportError:  # pragma: no cover - exercised on minimal installs
    HAS_CRYPTO = False

_TEXT_ALPHABET = (
    string.ascii_letters
    + string.digits
    + " _-./\\\"'{}[]:,"
    + "éش中\U0001f600"  # accented, Arabic, CJK, astral
)


def _random_value(rng: random.Random, depth: int) -> object:
    choices = "sifbn" if depth <= 0 else "sifbnld"
    kind = rng.choice(choices)
    if kind == "s":
        return "".join(rng.choice(_TEXT_ALPHABET) for _ in range(rng.randrange(0, 12)))
    if kind == "i":
        return rng.randrange(-(10**18), 10**18)
    if kind == "f":
        return rng.randrange(-(10**9), 10**9) / 997.0
    if kind == "b":
        return rng.random() < 0.5
    if kind == "n":
        return None
    if kind == "l":
        return [_random_value(rng, depth - 1) for _ in range(rng.randrange(0, 4))]
    return {
        "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randrange(1, 8))):
            _random_value(rng, depth - 1)
        for _ in range(rng.randrange(0, 4))
    }


def test_strict_parser_agrees_with_stdlib_on_generated_documents() -> None:
    rng = random.Random(0x5EED_0001)
    for _ in range(300):
        value = _random_value(rng, depth=5)
        text = json.dumps(value, ensure_ascii=rng.random() < 0.5)
        parsed = strict_json_loads(text)
        assert parsed == json.loads(text)


def test_mutated_documents_never_raise_anything_but_value_error() -> None:
    rng = random.Random(0x5EED_0002)
    seeds = [
        json.dumps(_random_value(random.Random(0x5EED_0003 + i), depth=4))
        for i in range(10)
    ]
    mutation_alphabet = _TEXT_ALPHABET + " " + chr(0xD800) + chr(0x842C)
    for _ in range(600):
        text = list(rng.choice(seeds))
        for _ in range(rng.randrange(1, 4)):
            action = rng.randrange(3)
            position = rng.randrange(len(text) + 1)
            if action == 0 and text:
                text.pop(min(position, len(text) - 1))
            elif action == 1:
                text.insert(position, rng.choice(mutation_alphabet))
            elif text:
                text[min(position, len(text) - 1)] = rng.choice(mutation_alphabet)
        mutated = "".join(text)
        try:
            parsed = strict_json_loads(mutated)
        except ValueError:
            continue  # the one documented rejection channel
        stdlib = json.loads(mutated)  # must also be plain valid JSON
        assert parsed == stdlib


def test_duplicate_keys_are_rejected_wherever_they_hide() -> None:
    rng = random.Random(0x5EED_0004)
    for _ in range(100):
        key = "".join(rng.choice(string.ascii_lowercase) for _ in range(4))
        inner = f'{{"{key}": 1, "{key}": 2}}'
        for _ in range(rng.randrange(0, MAX_JSON_DEPTH // 4)):
            inner = f'[{inner}]' if rng.random() < 0.5 else f'{{"w": {inner}}}'
        with pytest.raises(ValueError):
            strict_json_loads(inner)


def test_documented_limits_hold_at_and_past_the_boundary() -> None:
    shallow = "[" * (MAX_JSON_DEPTH - 1) + "0" + "]" * (MAX_JSON_DEPTH - 1)
    assert strict_json_loads(shallow) is not None
    deep = "[" * (MAX_JSON_DEPTH + 1) + "0" + "]" * (MAX_JSON_DEPTH + 1)
    with pytest.raises(ValueError):
        strict_json_loads(deep)

    legal_int = "9" * MAX_JSON_INTEGER_DIGITS
    assert strict_json_loads(legal_int) == int(legal_int)
    with pytest.raises(ValueError):
        strict_json_loads("9" * (MAX_JSON_INTEGER_DIGITS + 1))

    for constant in ("NaN", "Infinity", "-Infinity"):
        with pytest.raises(ValueError):
            strict_json_loads(f'[{constant}]')
    assert math.isfinite(strict_json_loads("[1.5e300]")[0])  # type: ignore[index]
    with pytest.raises(ValueError):
        strict_json_loads("[1.5e400]")

    with pytest.raises(ValueError):
        strict_json_loads('"' + chr(0xD800) + ' unpaired"')


_CANDIDATE = "a" * 64
_POLICY = "b" * 64
_CONTEXT = {
    "repository": "owner/project",
    "repository_id": "12345",
    "run_id": "run-987",
    "run_attempt": 1,
    "base_sha": None,
    "head_sha": None,
    "base_tree_sha": None,
    "head_tree_sha": None,
    "candidate_sha256": _CANDIDATE,
    "policy_sha256": _POLICY,
    "verifier_pack_sha256": None,
    "guard_artifact_sha256": "c" * 64,
}


@pytest.mark.skipif(not HAS_CRYPTO, reason="bundle signing needs the 'sign' extra")
def test_any_flipped_byte_in_a_bundle_fails_closed(tmp_path) -> None:
    from evoom_guard.signing import generate_keypair

    verdict = tmp_path / "verdict.json"
    verdict.write_text(
        '{"schema_version":"1.11","tool":"evoguard",'
        '"tool_version":"3.5.2","verdict":"PASS",'
        '"attestation":{"candidate_sha256":"' + _CANDIDATE + '",'
        '"policy_sha256":"' + _POLICY + '",'
        '"verifier_pack_sha256":null,"base_sha":null,"head_sha":null}}\n',
        encoding="utf-8",
        newline="\n",
    )
    private = tmp_path / "key.pem"
    public = tmp_path / "key.pub"
    generate_keypair(str(private), str(public))
    sealed = tmp_path / "sealed.evb"
    create_evidence_bundle(
        str(verdict),
        str(sealed),
        context=dict(_CONTEXT),
        private_key_path=str(private),
        require_valid_record=False,
    )
    original = sealed.read_bytes()

    # The pristine container authenticates structurally (context/signature),
    # proving the flips below are what break it — semantics stay out of scope
    # because the minimal record is deliberately not schema-complete.
    from evoom_guard.evidence_bundle import authenticate_evidence_bundle, inspect_evidence_bundle

    authenticate_evidence_bundle(
        inspect_evidence_bundle(str(sealed)),
        trusted_public_key_path=str(public),
        expected_context=dict(_CONTEXT),
    )

    rng = random.Random(0x5EED_0005)
    positions = sorted(
        {0, 1, len(original) // 2, len(original) - 2, len(original) - 1}
        | {rng.randrange(len(original)) for _ in range(80)}
    )
    mutated_path = tmp_path / "mutated.evb"
    for position in positions:
        corrupted = bytearray(original)
        flip = rng.randrange(1, 256)
        corrupted[position] ^= flip
        mutated_path.write_bytes(bytes(corrupted))
        with pytest.raises(EvidenceBundleError):
            verify_evidence_bundle(
                str(mutated_path),
                trusted_public_key_path=str(public),
                expected_context=dict(_CONTEXT),
            )
