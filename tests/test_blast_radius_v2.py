from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evoom_guard.domain import (
    BLAST_RADIUS_V2_FORMAT,
    BlastRadiusV2ContractError,
    MaterializedChangeSetV2,
    MaterializedChangeV2,
    blast_radius_score_v2,
    canonical_materialized_change_v2_bytes,
    materialized_change_set_v2,
)
from evoom_guard.guard import _risk_score_with_deletions, guard
from evoom_guard.patchmin import (
    BlastRadiusScore,
    RiskScore,
    blast_radius_score,
    parse_unified_diff,
    risk_score,
)

ROOT = Path(__file__).resolve().parents[1]
GOLDEN_PATH = ROOT / "tests" / "fixtures" / "blast-radius-v2-golden.json"


def _block(path: str, content: str) -> str:
    return f"<<<FILE: {path}>>>\n{content}<<<END FILE>>>\n"


def _write(root: Path, relative: str, content: str) -> None:
    destination = root.joinpath(*relative.split("/"))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")


def _valid_add(path: str = "src/new.py") -> dict[str, Any]:
    return {
        "format": BLAST_RADIUS_V2_FORMAT,
        "changes": [
            {
                "operation": "add",
                "old_path": None,
                "new_path": path,
                "lines_added": 1,
                "lines_removed": 0,
                "binary": False,
            }
        ],
    }


def test_golden_vectors_are_exact() -> None:
    fixture = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    assert fixture["format"] == "EVOGUARD_BLAST_RADIUS_GOLDEN_V2"

    seen: set[str] = set()
    for vector in fixture["vectors"]:
        seen.add(vector["id"])
        if "expected_error" in vector:
            with pytest.raises(
                BlastRadiusV2ContractError,
                match=vector["expected_error"],
            ):
                blast_radius_score_v2(
                    vector["input"], protected=vector["protected"]
                )
            continue
        measured = blast_radius_score_v2(
            vector["input"], protected=vector["protected"]
        )
        assert measured.as_dict() == vector["expected"]

    assert seen == {
        "addition",
        "modification",
        "deletion",
        "rename-counts-both-paths",
        "copy-counts-destination-only",
        "mode-only",
        "decoded-git-quoted-unicode-path",
        "binary-modification",
        "malformed-unsupported-operation",
    }


def test_canonical_bytes_are_order_independent_and_round_trip() -> None:
    add = MaterializedChangeV2("add", None, "z/new.py", 2, 0)
    delete = MaterializedChangeV2("delete", "a/old.py", None, 0, 4)
    first = MaterializedChangeSetV2((add, delete))
    second = MaterializedChangeSetV2((delete, add))

    assert first.changes == second.changes
    assert canonical_materialized_change_v2_bytes(first) == (
        canonical_materialized_change_v2_bytes(second)
    )
    decoded = json.loads(canonical_materialized_change_v2_bytes(first))
    assert materialized_change_set_v2(decoded) == first
    assert [change["operation"] for change in decoded["changes"]] == [
        "delete",
        "add",
    ]


def test_raw_diff_and_raw_git_quoted_tokens_fail_closed() -> None:
    raw_diff = "--- a/old.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n"
    with pytest.raises(BlastRadiusV2ContractError, match="not raw diff text"):
        blast_radius_score_v2(raw_diff)

    raw_c_quoted = _valid_add('"docs/caf\\303\\251.md"')
    with pytest.raises(BlastRadiusV2ContractError, match="portable, normalized"):
        materialized_change_set_v2(raw_c_quoted)

    decoded = _valid_add("docs/café.md")
    assert blast_radius_score_v2(decoded).files_touched == 1


def test_contract_rejects_malformed_and_ambiguous_mutations() -> None:
    mutations: list[tuple[str, object, str]] = [
        ("wrong-root-type", [], "input must be"),
        (
            "wrong-format",
            {**_valid_add(), "format": "EVOGUARD_BLAST_RADIUS_V1"},
            "format must be",
        ),
        (
            "unknown-root-key",
            {**_valid_add(), "extra": True},
            "exactly format and changes",
        ),
        (
            "changes-not-array",
            {"format": BLAST_RADIUS_V2_FORMAT, "changes": ()},
            "changes must be an array",
        ),
        (
            "unknown-change-key",
            {
                **_valid_add(),
                "changes": [{**_valid_add()["changes"][0], "guess": True}],
            },
            "contain exactly",
        ),
        (
            "boolean-counter",
            {
                **_valid_add(),
                "changes": [{**_valid_add()["changes"][0], "lines_added": True}],
            },
            "must be an integer",
        ),
        (
            "negative-counter",
            {
                **_valid_add(),
                "changes": [{**_valid_add()["changes"][0], "lines_added": -1}],
            },
            "must be between",
        ),
        (
            "non-nfc-path",
            _valid_add("docs/cafe\u0301.md"),
            "NFC Unicode",
        ),
        ("dot-segment", _valid_add("src/../escape.py"), "portable, normalized"),
        ("git-admin", _valid_add("src/.git/config"), "Git administrative"),
        (
            "add-with-old-path",
            {
                **_valid_add(),
                "changes": [
                    {**_valid_add()["changes"][0], "old_path": "src/old.py"}
                ],
            },
            "add requires",
        ),
        (
            "binary-line-count",
            {
                **_valid_add(),
                "changes": [{**_valid_add()["changes"][0], "binary": True}],
            },
            "binary changes require",
        ),
        (
            "zero-line-text-modify",
            {
                "format": BLAST_RADIUS_V2_FORMAT,
                "changes": [
                    {
                        "operation": "modify",
                        "old_path": "src/app.py",
                        "new_path": "src/app.py",
                        "lines_added": 0,
                        "lines_removed": 0,
                        "binary": False,
                    }
                ],
            },
            "represented as mode",
        ),
        (
            "copy-removes-lines",
            {
                "format": BLAST_RADIUS_V2_FORMAT,
                "changes": [
                    {
                        "operation": "copy",
                        "old_path": "src/a.py",
                        "new_path": "src/b.py",
                        "lines_added": 1,
                        "lines_removed": 1,
                        "binary": False,
                    }
                ],
            },
            "copy requires",
        ),
    ]

    for _mutation_id, payload, message in mutations:
        with pytest.raises(
            BlastRadiusV2ContractError,
            match=message,
        ):
            materialized_change_set_v2(payload)


def test_contract_rejects_overlapping_and_case_colliding_affected_paths() -> None:
    payload = {
        "format": BLAST_RADIUS_V2_FORMAT,
        "changes": [
            _valid_add("Src/app.py")["changes"][0],
            _valid_add("src/APP.py")["changes"][0],
        ],
    }
    with pytest.raises(BlastRadiusV2ContractError, match="case collisions"):
        materialized_change_set_v2(payload)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"high_files": 0}, "high_files must be positive"),
        ({"medium_lines": True}, "medium_lines must be an integer"),
        ({"medium_files": 9, "high_files": 8}, "medium_files cannot exceed"),
        ({"medium_lines": 201, "high_lines": 200}, "medium_lines cannot exceed"),
        ({"protected": ["docs\\*"]}, "normalized repository-relative globs"),
    ],
)
def test_threshold_and_pattern_mutations_fail_closed(
    kwargs: dict[str, object], message: str
) -> None:
    with pytest.raises(BlastRadiusV2ContractError, match=message):
        blast_radius_score_v2(_valid_add(), **kwargs)  # type: ignore[arg-type]


def test_protected_matching_work_is_bounded_before_the_quadratic_scan() -> None:
    value = {
        "format": BLAST_RADIUS_V2_FORMAT,
        "changes": [
            {
                "operation": "add",
                "old_path": None,
                "new_path": f"src/generated-{index}.py",
                "lines_added": 1,
                "lines_removed": 0,
                "binary": False,
            }
            for index in range(2_001)
        ],
    }
    patterns = [f"protected-{index}/**" for index in range(1_000)]

    with pytest.raises(BlastRadiusV2ContractError, match="matching-work limit"):
        blast_radius_score_v2(value, protected=patterns)


def test_direct_v2_matches_guard_materialization_for_same_change(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo, "pkg/__init__.py", "")
    _write(repo, "pkg/big.py", "\n".join(f"x{i} = {i}" for i in range(300)) + "\n")
    _write(repo, "tests/test_ok.py", "def test_ok():\n    assert True\n")
    candidate = _block("pkg/note.py", "# note\n")
    touched = ["pkg/note.py", "pkg/big.py"]
    deleted = ["pkg/big.py"]
    protected = ("pkg/big.py",)

    v2 = blast_radius_score_v2(
        {
            "format": BLAST_RADIUS_V2_FORMAT,
            "changes": [
                {
                    "operation": "add",
                    "old_path": None,
                    "new_path": "pkg/note.py",
                    "lines_added": 1,
                    "lines_removed": 0,
                    "binary": False,
                },
                {
                    "operation": "delete",
                    "old_path": "pkg/big.py",
                    "new_path": None,
                    "lines_added": 0,
                    "lines_removed": 300,
                    "binary": False,
                },
            ],
        },
        protected=protected,
    )
    compatibility = _risk_score_with_deletions(
        str(repo),
        candidate,
        None,
        all_touched_paths=touched,
        deleted_paths=deleted,
        protected=protected,
    )
    result = guard(
        str(repo),
        candidate,
        deleted=tuple(deleted),
        protected=protected,
    )

    assert (
        v2.files_touched,
        v2.lines_added,
        v2.lines_removed,
        list(v2.protected_hits),
        v2.score,
        v2.level,
    ) == (
        compatibility.files_touched,
        compatibility.lines_added,
        compatibility.lines_removed,
        compatibility.protected_hits,
        compatibility.score,
        compatibility.level,
    )
    assert (result.risk_score, result.risk_level) == (v2.score, v2.level)


def test_v1_api_and_frozen_verdict_schemas_remain_characterized() -> None:
    deletion = "--- a/gone.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n"
    assert parse_unified_diff(deletion) == {}
    assert BlastRadiusScore is RiskScore
    assert blast_radius_score is risk_score

    for schema_name in (
        "verdict-record-1.11.schema.json",
        "verdict-record-1.12.schema.json",
    ):
        schema = json.loads(
            (ROOT / "evoom_guard" / "schemas" / schema_name).read_text(
                encoding="utf-8"
            )
        )
        assert "risk_score" in schema["properties"]
        assert "blast_radius_v2" not in schema["properties"]


def test_materialized_change_schema_is_valid_and_matches_golden_inputs() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (
            ROOT
            / "evoom_guard"
            / "schemas"
            / "blast-radius-materialized-change-2.schema.json"
        ).read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    fixture = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))

    for vector in fixture["vectors"]:
        errors = list(validator.iter_errors(vector["input"]))
        if "expected_error" in vector:
            assert errors
        else:
            assert errors == []
