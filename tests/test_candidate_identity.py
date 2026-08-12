from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest

from evoom_guard.candidate.identity import (
    AGENT_CHANGE_CANDIDATE_IGNORED_BASENAMES,
    AGENT_CHANGE_CANDIDATE_SELECTION_PROFILE,
    CANDIDATE_TEXT_MAP_IDENTITY_FORMAT,
    CandidateIdentityError,
    agent_change_candidate_path_is_ignored,
    candidate_path_order_key,
    candidate_text_map_identity,
    candidate_text_map_identity_bytes,
)
from evoom_guard.workspace.candidate_tree import serialize_candidate_blocks


def test_v2_distinguishes_the_historical_file_marker_collision() -> None:
    embedded_marker = {"a": "x\n<<<END FILE>>>\n<<<FILE: b>>>\ny"}
    two_files = {"a": "x", "b": "y"}

    assert serialize_candidate_blocks(embedded_marker) == serialize_candidate_blocks(two_files)
    assert candidate_text_map_identity_bytes(embedded_marker) != candidate_text_map_identity_bytes(
        two_files
    )
    assert (
        candidate_text_map_identity(embedded_marker).sha256
        != candidate_text_map_identity(two_files).sha256
    )


def test_v2_golden_vector_is_domain_separated_and_length_prefixed() -> None:
    blocks = {"b.txt": "β\n", "a.txt": "alpha"}
    framed = candidate_text_map_identity_bytes(blocks)
    expected = (
        CANDIDATE_TEXT_MAP_IDENTITY_FORMAT.encode("ascii")
        + b"\0"
        + struct.pack(">Q", 2)
        + b"F"
        + struct.pack(">Q", 5)
        + b"a.txt"
        + struct.pack(">Q", 5)
        + b"alpha"
        + b"F"
        + struct.pack(">Q", 5)
        + b"b.txt"
        + struct.pack(">Q", 3)
        + "β\n".encode()
    )

    assert framed == expected
    assert candidate_text_map_identity(blocks).payload == {
        "format": "EVOGUARD_CANDIDATE_TEXT_MAP_V2",
        "sha256": hashlib.sha256(expected).hexdigest(),
        "size": len(expected),
        "file_count": 2,
    }


def test_v2_is_insertion_order_independent() -> None:
    assert candidate_text_map_identity_bytes({"b": "2", "a": "1"}) == (
        candidate_text_map_identity_bytes({"a": "1", "b": "2"})
    )


def test_v2_preserves_exact_utf8_without_unicode_normalization() -> None:
    composed = {"name": "é"}
    decomposed = {"name": "e\u0301"}

    assert candidate_text_map_identity_bytes(composed) != candidate_text_map_identity_bytes(
        decomposed
    )


@pytest.mark.parametrize(
    "blocks, message",
    [
        ({1: "content"}, "candidate path must be a string"),
        ({1: "content", "path": "other"}, "candidate path must be a string"),
        ({"path": 1}, "candidate content for 'path' must be a string"),
        ({"\ud800": "content"}, "candidate path must be valid Unicode"),
        ({"path": "\ud800"}, "candidate content for 'path' must be valid Unicode"),
    ],
)
def test_v2_rejects_values_without_a_canonical_utf8_representation(
    blocks: object, message: str
) -> None:
    with pytest.raises(CandidateIdentityError, match=message):
        candidate_text_map_identity_bytes(blocks)  # type: ignore[arg-type]


def _decode_v2(data: bytes) -> dict[str, str]:
    """Independent test decoder for the published framing, not production code."""

    domain = CANDIDATE_TEXT_MAP_IDENTITY_FORMAT.encode("ascii") + b"\0"
    assert data.startswith(domain)
    offset = len(domain)

    def take_u64() -> int:
        nonlocal offset
        value = struct.unpack(">Q", data[offset : offset + 8])[0]
        offset += 8
        return value

    result: dict[str, str] = {}
    for _ in range(take_u64()):
        assert data[offset : offset + 1] == b"F"
        offset += 1
        path_size = take_u64()
        path = data[offset : offset + path_size].decode("utf-8")
        offset += path_size
        content_size = take_u64()
        content = data[offset : offset + content_size].decode("utf-8")
        offset += content_size
        assert path not in result
        result[path] = content
    assert offset == len(data)
    return result


def test_published_cross_language_vectors_match_bytes_digest_and_round_trip() -> None:
    vector_path = (
        Path(__file__).parents[1] / "docs" / "vectors" / "candidate-text-map-v2.json"
    )
    document = json.loads(vector_path.read_text(encoding="utf-8"))
    assert document["format"] == CANDIDATE_TEXT_MAP_IDENTITY_FORMAT

    for vector in document["vectors"]:
        framed = candidate_text_map_identity_bytes(vector["input"])
        identity = candidate_text_map_identity(vector["input"])
        assert framed.hex() == vector["framed_hex"]
        assert _decode_v2(framed) == vector["input"]
        assert identity.sha256 == vector["sha256"]
        assert identity.size == vector["size"]
        assert identity.file_count == vector["file_count"]


def test_v2_orders_paths_by_utf8_bytes_not_utf16_code_units() -> None:
    framed = candidate_text_map_identity_bytes({"\U00010000": "second", "\ue000": "first"})
    assert list(_decode_v2(framed)) == ["\ue000", "\U00010000"]


def test_published_agent_change_selection_profile_vectors_are_exact() -> None:
    vector_path = (
        Path(__file__).parents[1]
        / "docs"
        / "vectors"
        / "agent-change-candidate-selection-v1.json"
    )
    document = json.loads(vector_path.read_text(encoding="utf-8"))
    assert document["profile"] == AGENT_CHANGE_CANDIDATE_SELECTION_PROFILE
    assert tuple(document["ignored_basenames"]) == AGENT_CHANGE_CANDIDATE_IGNORED_BASENAMES

    ordering = document["path_order"]
    assert [candidate_path_order_key(path).hex() for path in ordering["input"]] == ordering[
        "utf8_hex"
    ]
    assert sorted(ordering["input"], key=candidate_path_order_key) == ordering["expected"]

    selection = document["selection"]
    ignored = [
        path
        for path in selection["changed_paths"]
        if agent_change_candidate_path_is_ignored(path)
    ]
    selected = [
        path
        for path in selection["changed_paths"]
        if not agent_change_candidate_path_is_ignored(path)
    ]
    assert ignored == selection["ignored_paths"]
    assert selected == selection["selected_paths"]
