#!/usr/bin/env python3
"""Validate the versioned synthetic failure-observation registry.

The registry is an index over the repository's committed synthetic benchmark
evidence.  It does not authenticate the recorded execution and must never be
accepted as field evidence.  Validation derives the complete set of observed
classification failures from the bound result bytes; a curator cannot hide a
case by omitting or replacing its literal case identifier.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.run_live import (  # noqa: E402
    BASELINE_DEFINITION,
    ENGINE_VERSION,
    RUN_SETTINGS,
    corpus_definition,
)
from benchmarks.run_manifest import (  # noqa: E402
    GIT_REDIRECT_ENV_KEYS,
    MAX_MANIFEST_BYTES,
    MAX_RESULTS_BYTES,
    build_execution_environment,
    load_run_manifest,
    read_stable_regular_file,
    verify_run_manifest,
)

SCHEMA_VERSION = "evoguard-synthetic-failure-observation-registry-v1"
SCHEMA_REFERENCE = "./synthetic-failure-observation-registry-v1.schema.json"
DEFAULT_REGISTRY = (
    ROOT / "evidence" / "failure-registry" / "synthetic-observations-v1.json"
)
DEFAULT_MANIFEST = ROOT / "benchmarks" / "run-manifest.json"
DEFAULT_RESULTS = ROOT / "benchmarks" / "results.jsonl"
REPOSITORY = "EvoRiseKsa/EvoOM-Guard-m"
MAX_REGISTRY_BYTES = 2 * 1024 * 1024
MAX_ANCESTRY_COMMITS = 100_000
GIT_TIMEOUT_SECONDS = 15
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
REGISTRY_ID = re.compile(
    r"^synthetic-benchmark-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
OBSERVATION_ID = re.compile(r"^SFO-[0-9]{4}$")
CASE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")

SYNTHETIC_SCOPE: dict[str, object] = {
    "source_class": "synthetic",
    "evidence_quality": "self_consistent_unattributed",
    "authenticated": False,
    "field_evidence": False,
    "independent": False,
    "general_performance_claim": False,
}

# These are reviewed interpretations, not properties derivable from a verdict.
# A newly observed mismatch remains ``unresolved`` until this map is reviewed.
REVIEWED_DISPOSITIONS: dict[tuple[str, str, str, str], str] = {
    (
        "20ecd170d61418e5fd7cd75ab0e7fa7e7b9c3bbda90d87eab4ca6ba491cc696b",
        "c473c62bf92c0faeb48bb56ec266d9b0d6adfe9f3ffb3ff45d91a813c3a1fd59",
        "same-process-junit-forgery",
        "false_accept",
    ): "known_security_gap",
    (
        "20ecd170d61418e5fd7cd75ab0e7fa7e7b9c3bbda90d87eab4ca6ba491cc696b",
        "c473c62bf92c0faeb48bb56ec266d9b0d6adfe9f3ffb3ff45d91a813c3a1fd59",
        "legit-dependency-bump",
        "false_reject",
    ): "deliberate_policy_tradeoff",
    (
        "20ecd170d61418e5fd7cd75ab0e7fa7e7b9c3bbda90d87eab4ca6ba491cc696b",
        "c473c62bf92c0faeb48bb56ec266d9b0d6adfe9f3ffb3ff45d91a813c3a1fd59",
        "legit-dependency-bump-allowlist-refused",
        "false_reject",
    ): "deliberate_policy_tradeoff",
}


class RegistryError(ValueError):
    """The registry is malformed, incomplete, or not bound to its evidence."""


def _reject_constant(value: str) -> None:
    raise RegistryError(f"non-finite JSON number is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RegistryError(f"duplicate JSON object key: {key!r}")
        value[key] = item
    return value


def _load_object(path: Path, *, limit: int, label: str) -> tuple[dict[str, Any], bytes]:
    snapshot = read_stable_regular_file(path, max_bytes=limit, label=label)
    try:
        decoded = json.loads(
            snapshot.payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegistryError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(decoded, dict):
        raise RegistryError(f"{label} must be a JSON object")
    return decoded, snapshot.payload


def _expect_exact_keys(value: object, expected: set[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RegistryError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        raise RegistryError(
            f"{label} keys differ: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    return value


def _expect_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or HEX_SHA256.fullmatch(value) is None:
        raise RegistryError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _expect_git_sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or GIT_SHA.fullmatch(value) is None:
        raise RegistryError(f"{label} must be a full lowercase SHA-1 Git commit")
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _parse_results(payload: bytes) -> list[tuple[dict[str, Any], bytes]]:
    if not payload or not payload.endswith(b"\n") or b"\r" in payload:
        raise RegistryError("benchmark results must use non-empty LF-terminated JSON Lines")
    rows: list[tuple[dict[str, Any], bytes]] = []
    for number, raw_line in enumerate(payload[:-1].split(b"\n"), 1):
        if not raw_line:
            raise RegistryError(f"benchmark results row {number} is empty")
        try:
            decoded = json.loads(
                raw_line.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RegistryError(f"benchmark results row {number} is invalid: {exc}") from exc
        if not isinstance(decoded, dict):
            raise RegistryError(f"benchmark results row {number} must be an object")
        rows.append((decoded, raw_line))
    return rows


def _failure_class(row: dict[str, Any], *, number: int) -> str | None:
    truth = row.get("truth")
    verdict = row.get("verdict")
    if truth not in {"accept", "block"}:
        raise RegistryError(f"benchmark results row {number} has invalid truth")
    predictions = {
        "PASS": "accept",
        "FAIL": "block",
        "REJECTED": "block",
        "TAMPERED": "block",
        "ERROR": "abstain",
    }
    if verdict not in predictions:
        raise RegistryError(f"benchmark results row {number} has invalid verdict")
    prediction = predictions[verdict]
    if prediction == "abstain" or prediction == truth:
        return None
    return "false_accept" if truth == "block" else "false_reject"


def _disposition(
    row: dict[str, Any],
    failure_class: str,
    *,
    source_inventory_sha256: str,
    corpus_sha256: str,
) -> str:
    case_id = row.get("id")
    if not isinstance(case_id, str):
        return "unresolved"
    return REVIEWED_DISPOSITIONS.get(
        (
            source_inventory_sha256,
            corpus_sha256,
            case_id,
            failure_class,
        ),
        "unresolved",
    )


def _expected_observations(
    rows: list[tuple[dict[str, Any], bytes]],
    *,
    source_inventory_sha256: str,
    corpus_sha256: str,
) -> list[dict[str, object]]:
    expected: list[dict[str, object]] = []
    seen_case_ids: set[str] = set()
    for number, (row, raw_line) in enumerate(rows, 1):
        case_id = row.get("id")
        if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
            raise RegistryError(f"benchmark results row {number} has no literal public case id")
        if case_id in seen_case_ids:
            raise RegistryError(f"benchmark results contain duplicate case id: {case_id!r}")
        seen_case_ids.add(case_id)
        failure_class = _failure_class(row, number=number)
        if failure_class is None:
            continue
        case_kind = row.get("case_kind")
        reason_code = row.get("reason_code")
        expected_verdict = row.get("expected_verdict")
        observed_verdict = row.get("verdict")
        if not all(
            isinstance(value, str)
            for value in (case_kind, reason_code, expected_verdict, observed_verdict)
        ):
            raise RegistryError(f"benchmark failure row {number} has invalid string fields")
        expected.append(
            {
                "observation_id": f"SFO-{len(expected) + 1:04d}",
                "case_id": case_id,
                "failure_class": failure_class,
                "disposition": _disposition(
                    row,
                    failure_class,
                    source_inventory_sha256=source_inventory_sha256,
                    corpus_sha256=corpus_sha256,
                ),
                "truth": row["truth"],
                "observed_verdict": observed_verdict,
                "expected_verdict": expected_verdict,
                "regression_expectation_matched": row.get("as_expected") is True,
                "case_kind": case_kind,
                "reason_code": reason_code,
                "result_row": number,
                "result_record_sha256": _sha256(raw_line),
                **SYNTHETIC_SCOPE,
            }
        )
    return expected


def _validate_structure(registry: dict[str, Any]) -> tuple[dict[str, Any], list[Any]]:
    _expect_exact_keys(
        registry,
        {
            "$schema",
            "schema_version",
            "registry_id",
            "scope",
            "benchmark_binding",
            "observations",
        },
        label="registry",
    )
    if registry["$schema"] != SCHEMA_REFERENCE:
        raise RegistryError("registry $schema reference is invalid")
    if registry["schema_version"] != SCHEMA_VERSION:
        raise RegistryError("registry schema_version is invalid")
    registry_id = registry["registry_id"]
    if not isinstance(registry_id, str) or REGISTRY_ID.fullmatch(registry_id) is None:
        raise RegistryError("registry_id is invalid")
    scope = _expect_exact_keys(registry["scope"], set(SYNTHETIC_SCOPE), label="scope")
    if scope != SYNTHETIC_SCOPE:
        raise RegistryError(
            "scope must remain synthetic, self_consistent_unattributed, "
            "unauthenticated, non-independent, non-field evidence"
        )
    binding = _expect_exact_keys(
        registry["benchmark_binding"],
        {
            "repository",
            "benchmark_id",
            "run_id",
            "engine_version",
            "source",
            "evidence",
            "finalization",
        },
        label="benchmark_binding",
    )
    observations = registry["observations"]
    if not isinstance(observations, list) or not observations:
        raise RegistryError("observations must be a non-empty array")
    return binding, observations


def _validate_binding(
    registry: dict[str, Any],
    binding: dict[str, Any],
    *,
    manifest: dict[str, Any],
    manifest_bytes: bytes,
    results_bytes: bytes,
    result_rows: list[tuple[dict[str, Any], bytes]],
) -> str:
    source = _expect_exact_keys(
        binding["source"],
        {"commit", "inventory_sha256", "corpus_sha256", "case_count"},
        label="benchmark_binding.source",
    )
    evidence = _expect_exact_keys(
        binding["evidence"],
        {"commit", "results_path", "results_sha256", "results_bytes", "result_rows"},
        label="benchmark_binding.evidence",
    )
    finalization = _expect_exact_keys(
        binding["finalization"],
        {"commit", "manifest_path", "manifest_sha256", "manifest_bytes"},
        label="benchmark_binding.finalization",
    )
    source_commit = _expect_git_sha(source["commit"], label="source.commit")
    evidence_commit = _expect_git_sha(evidence["commit"], label="evidence.commit")
    finalization_commit = _expect_git_sha(
        finalization["commit"], label="finalization.commit"
    )
    for label, value in (
        ("source.inventory_sha256", source["inventory_sha256"]),
        ("source.corpus_sha256", source["corpus_sha256"]),
        ("evidence.results_sha256", evidence["results_sha256"]),
        ("finalization.manifest_sha256", finalization["manifest_sha256"]),
    ):
        _expect_sha256(value, label=label)

    manifest_source = manifest.get("source")
    manifest_corpus = manifest.get("corpus")
    manifest_results = manifest.get("results")
    provenance = manifest.get("provenance")
    claims = manifest.get("claims")
    if not all(
        isinstance(value, dict)
        for value in (manifest_source, manifest_corpus, manifest_results, provenance, claims)
    ):
        raise RegistryError("benchmark manifest lacks required binding objects")
    assert isinstance(manifest_source, dict)
    assert isinstance(manifest_corpus, dict)
    assert isinstance(manifest_results, dict)
    assert isinstance(provenance, dict)
    assert isinstance(claims, dict)
    source_provenance = provenance.get("source_commit")
    evidence_provenance = provenance.get("evidence_commit")
    if not isinstance(source_provenance, dict) or not isinstance(evidence_provenance, dict):
        raise RegistryError("benchmark manifest lacks finalized commit provenance")

    expected_binding = {
        "repository": REPOSITORY,
        "benchmark_id": manifest.get("benchmark_id"),
        "run_id": manifest.get("run_id"),
        "engine_version": manifest.get("engine_version"),
        "source": {
            "commit": source_provenance.get("commit"),
            "inventory_sha256": manifest_source.get("sha256"),
            "corpus_sha256": manifest_corpus.get("sha256"),
            "case_count": manifest_corpus.get("case_count"),
        },
        "evidence": {
            "commit": evidence_provenance.get("commit"),
            "results_path": "benchmarks/results.jsonl",
            "results_sha256": _sha256(results_bytes),
            "results_bytes": len(results_bytes),
            "result_rows": len(result_rows),
        },
        "finalization": {
            "commit": finalization_commit,
            "manifest_path": "benchmarks/run-manifest.json",
            "manifest_sha256": _sha256(manifest_bytes),
            "manifest_bytes": len(manifest_bytes),
        },
    }
    if binding != expected_binding:
        raise RegistryError("benchmark_binding does not match the exact manifest/results pair")
    if registry["registry_id"] != f"synthetic-benchmark-{manifest.get('run_id')}":
        raise RegistryError("registry_id does not bind the benchmark run_id")
    if (
        claims.get("authenticated") is not False
        or claims.get("evidence_status") != "self_consistent_unattributed"
        or claims.get("general_performance_claim") is not False
    ):
        raise RegistryError("benchmark claims cannot support this synthetic registry scope")
    if len({source_commit, evidence_commit, finalization_commit}) != 3:
        raise RegistryError("source, evidence, and finalization commits must be distinct")
    if (
        manifest_results.get("path") != "benchmarks/results.jsonl"
        or manifest_results.get("sha256") != _sha256(results_bytes)
        or manifest_results.get("bytes") != len(results_bytes)
        or manifest_results.get("rows") != len(result_rows)
    ):
        raise RegistryError("benchmark manifest result binding contradicts its exact bytes")
    return finalization_commit


def _validate_observations(
    observations: list[Any],
    *,
    expected: list[dict[str, object]],
) -> None:
    expected_keys = {
        "observation_id",
        "case_id",
        "failure_class",
        "disposition",
        "truth",
        "observed_verdict",
        "expected_verdict",
        "regression_expectation_matched",
        "case_kind",
        "reason_code",
        "result_row",
        "result_record_sha256",
        *SYNTHETIC_SCOPE,
    }
    validated: list[dict[str, Any]] = []
    observation_ids: set[str] = set()
    case_ids: set[str] = set()
    for index, observation in enumerate(observations):
        value = _expect_exact_keys(
            observation, expected_keys, label=f"observations[{index}]"
        )
        observation_id = value["observation_id"]
        case_id = value["case_id"]
        if (
            not isinstance(observation_id, str)
            or OBSERVATION_ID.fullmatch(observation_id) is None
        ):
            raise RegistryError(f"observations[{index}].observation_id is invalid")
        if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
            raise RegistryError(
                f"observations[{index}].case_id must be a literal public case id"
            )
        if observation_id in observation_ids or case_id in case_ids:
            raise RegistryError("observation_id and case_id values must be unique")
        observation_ids.add(observation_id)
        case_ids.add(case_id)
        _expect_sha256(
            value["result_record_sha256"],
            label=f"observations[{index}].result_record_sha256",
        )
        per_observation_scope = {key: value[key] for key in SYNTHETIC_SCOPE}
        if per_observation_scope != SYNTHETIC_SCOPE:
            raise RegistryError(
                f"observations[{index}] conflates synthetic evidence with field evidence"
            )
        validated.append(value)

    expected_case_ids = {str(item["case_id"]) for item in expected}
    if case_ids != expected_case_ids:
        raise RegistryError(
            "registry must expose every literal observed-failure case id exactly once: "
            f"missing={sorted(expected_case_ids - case_ids)}, "
            f"extra={sorted(case_ids - expected_case_ids)}"
        )
    if validated != expected:
        raise RegistryError("observations do not exactly match the bound failure rows")


def _reviewed_git_environment() -> dict[str, str]:
    """Build the benchmark's allowlisted child environment plus Git controls."""

    raw_environment, _evidence = build_execution_environment()
    environment = cast(dict[str, str], raw_environment)
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
            "PAGER": "cat",
        }
    )
    return environment


def _git_command(root: Path, arguments: tuple[str, ...]) -> list[str]:
    return [
        "git",
        "--no-replace-objects",
        "--no-optional-locks",
        "-c",
        "core.commitGraph=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "core.pager=cat",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "credential.interactive=never",
        "-C",
        str(root),
        *arguments,
    ]


def _run_git_bytes(root: Path, *arguments: str) -> bytes:
    try:
        process = subprocess.run(
            _git_command(root, arguments),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            env=_reviewed_git_environment(),
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RegistryError(f"Git verification failed to execute: {exc}") from exc
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise RegistryError(f"Git verification failed: git {' '.join(arguments)}: {detail}")
    return process.stdout


def _reject_unsafe_repository_git_metadata(root: Path) -> None:
    common_dir_raw = _run_git_bytes(
        root,
        "rev-parse",
        "--path-format=absolute",
        "--git-common-dir",
    )
    try:
        common_dir_text = common_dir_raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise RegistryError("Git common directory is not UTF-8") from exc
    common_dir = Path(common_dir_text)
    if not common_dir.is_absolute():
        common_dir = root / common_dir
    for relative, label in (
        (Path("info") / "grafts", "Git grafts"),
        (Path("objects") / "info" / "alternates", "Git object alternates"),
    ):
        if os.path.lexists(common_dir / relative):
            raise RegistryError(f"{label} are refused during registry verification")
    replace_refs = _run_git_bytes(
        root,
        "for-each-ref",
        "--format=%(refname)",
        "refs/replace/",
    )
    if replace_refs.strip():
        raise RegistryError("Git replacement refs are refused during registry verification")


def _ensure_safe_git_context(root: Path) -> None:
    parent_keys = {key.upper() for key in os.environ}
    if any(key in parent_keys for key in GIT_REDIRECT_ENV_KEYS):
        raise RegistryError("redirected Git environment is refused")
    _reject_unsafe_repository_git_metadata(root)


def _git_bytes(root: Path, *arguments: str) -> bytes:
    _ensure_safe_git_context(root)
    return _run_git_bytes(root, *arguments)


def _require_raw_ancestry(
    root: Path,
    *,
    ancestor: str,
    descendant: str,
    label: str,
) -> None:
    """Use bounded replacement/graft-disabled Git revision traversal."""

    _expect_git_sha(ancestor, label=f"{label}.ancestor")
    _expect_git_sha(descendant, label=f"{label}.descendant")
    raw_graph = _run_git_bytes(
        root,
        "rev-list",
        "--parents",
        f"--max-count={MAX_ANCESTRY_COMMITS + 1}",
        descendant,
    )
    try:
        lines = raw_graph.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise RegistryError(f"{label} produced non-ASCII commit identities") from exc
    if len(lines) > MAX_ANCESTRY_COMMITS:
        raise RegistryError(f"{label} exceeds the ancestry traversal bound")
    for line in lines:
        identities = line.split()
        if not identities or any(GIT_SHA.fullmatch(value) is None for value in identities):
            raise RegistryError(f"{label} produced an invalid commit graph")
        if identities[0] == ancestor:
            return
    raise RegistryError(f"{label} is not present in Git commit ancestry")


def _verify_history(
    root: Path,
    *,
    finalization_commit: str,
    manifest_bytes: bytes,
    results_bytes: bytes,
    manifest_path: Path,
    results_path: Path,
) -> None:
    _ensure_safe_git_context(root)
    errors = verify_run_manifest(
        manifest_path,
        root=root,
        corpus=corpus_definition(),
        settings=RUN_SETTINGS,
        baseline_definition=BASELINE_DEFINITION,
        engine_version=ENGINE_VERSION,
        results_path=results_path,
        require_release_promotion=not ENGINE_VERSION.endswith(".dev0"),
        required_history_tip=finalization_commit,
    )
    if errors:
        raise RegistryError(f"benchmark manifest verification failed: {'; '.join(errors)}")

    manifest = load_run_manifest(manifest_path)
    provenance = manifest["provenance"]
    assert isinstance(provenance, dict)
    evidence = provenance["evidence_commit"]
    source = provenance["source_commit"]
    assert isinstance(evidence, dict)
    assert isinstance(source, dict)
    source_commit = str(source["commit"])
    evidence_commit = str(evidence["commit"])
    if (
        _run_git_bytes(root, "cat-file", "blob", f"{evidence_commit}:benchmarks/results.jsonl")
        != results_bytes
    ):
        raise RegistryError("results bytes differ from the bound evidence commit")
    if (
        _run_git_bytes(
            root,
            "cat-file",
            "blob",
            f"{finalization_commit}:benchmarks/run-manifest.json",
        )
        != manifest_bytes
    ):
        raise RegistryError("manifest bytes differ from the bound finalization commit")
    head = _run_git_bytes(root, "rev-parse", "--verify", "HEAD^{commit}")
    try:
        head_commit = head.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise RegistryError("Git HEAD identity is not ASCII") from exc
    _expect_git_sha(head_commit, label="HEAD")
    _require_raw_ancestry(
        root,
        ancestor=source_commit,
        descendant=evidence_commit,
        label="source-to-evidence ancestry",
    )
    _require_raw_ancestry(
        root,
        ancestor=evidence_commit,
        descendant=finalization_commit,
        label="evidence-to-finalization ancestry",
    )
    _require_raw_ancestry(
        root,
        ancestor=finalization_commit,
        descendant=head_commit,
        label="finalization-to-HEAD ancestry",
    )


def validate_registry(
    registry_path: Path = DEFAULT_REGISTRY,
    *,
    root: Path = ROOT,
    verify_history: bool = True,
) -> int:
    """Validate a registry and return its complete observed-failure count."""

    root = root.resolve()
    manifest_path = root / "benchmarks" / "run-manifest.json"
    results_path = root / "benchmarks" / "results.jsonl"
    registry, _registry_bytes = _load_object(
        registry_path, limit=MAX_REGISTRY_BYTES, label="synthetic failure registry"
    )
    manifest, manifest_bytes = _load_object(
        manifest_path, limit=MAX_MANIFEST_BYTES, label="benchmark manifest"
    )
    results_snapshot = read_stable_regular_file(
        results_path, max_bytes=MAX_RESULTS_BYTES, label="benchmark results"
    )
    result_rows = _parse_results(results_snapshot.payload)
    binding, observations = _validate_structure(registry)
    finalization_commit = _validate_binding(
        registry,
        binding,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        results_bytes=results_snapshot.payload,
        result_rows=result_rows,
    )
    manifest_source = manifest["source"]
    manifest_corpus = manifest["corpus"]
    assert isinstance(manifest_source, dict)
    assert isinstance(manifest_corpus, dict)
    expected = _expected_observations(
        result_rows,
        source_inventory_sha256=str(manifest_source["sha256"]),
        corpus_sha256=str(manifest_corpus["sha256"]),
    )
    _validate_observations(observations, expected=expected)
    if verify_history:
        _verify_history(
            root,
            finalization_commit=finalization_commit,
            manifest_bytes=manifest_bytes,
            results_bytes=results_snapshot.payload,
            manifest_path=manifest_path,
            results_path=results_path,
        )
    return len(expected)


def build_registry(
    *,
    root: Path = ROOT,
    finalization_commit: str,
) -> dict[str, object]:
    """Build a deterministic registry for one already-finalized benchmark pair.

    ``finalization_commit`` is intentionally supplied by the caller because a
    manifest cannot name the later commit that first contains its final bytes.
    Generation verifies that exact historical blob before returning a document.
    Failure dispositions come only from ``REVIEWED_DISPOSITIONS`` entries
    bound to the exact source/corpus digests, case ID, and failure class; any
    newly derived or context-changed mismatch is emitted as ``unresolved``.
    """

    root = root.resolve()
    finalization_commit = _expect_git_sha(
        finalization_commit, label="finalization_commit"
    )
    manifest_path = root / "benchmarks" / "run-manifest.json"
    results_path = root / "benchmarks" / "results.jsonl"
    manifest, manifest_bytes = _load_object(
        manifest_path, limit=MAX_MANIFEST_BYTES, label="benchmark manifest"
    )
    results_snapshot = read_stable_regular_file(
        results_path, max_bytes=MAX_RESULTS_BYTES, label="benchmark results"
    )
    result_rows = _parse_results(results_snapshot.payload)
    manifest_source = manifest.get("source")
    manifest_corpus = manifest.get("corpus")
    provenance = manifest.get("provenance")
    if not all(isinstance(value, dict) for value in (manifest_source, manifest_corpus, provenance)):
        raise RegistryError("benchmark manifest lacks source/corpus provenance")
    assert isinstance(manifest_source, dict)
    assert isinstance(manifest_corpus, dict)
    assert isinstance(provenance, dict)
    source_provenance = provenance.get("source_commit")
    evidence_provenance = provenance.get("evidence_commit")
    if not isinstance(source_provenance, dict) or not isinstance(evidence_provenance, dict):
        raise RegistryError("benchmark manifest lacks finalized commit provenance")

    registry: dict[str, object] = {
        "$schema": SCHEMA_REFERENCE,
        "schema_version": SCHEMA_VERSION,
        "registry_id": f"synthetic-benchmark-{manifest.get('run_id')}",
        "scope": dict(SYNTHETIC_SCOPE),
        "benchmark_binding": {
            "repository": REPOSITORY,
            "benchmark_id": manifest.get("benchmark_id"),
            "run_id": manifest.get("run_id"),
            "engine_version": manifest.get("engine_version"),
            "source": {
                "commit": source_provenance.get("commit"),
                "inventory_sha256": manifest_source.get("sha256"),
                "corpus_sha256": manifest_corpus.get("sha256"),
                "case_count": manifest_corpus.get("case_count"),
            },
            "evidence": {
                "commit": evidence_provenance.get("commit"),
                "results_path": "benchmarks/results.jsonl",
                "results_sha256": _sha256(results_snapshot.payload),
                "results_bytes": len(results_snapshot.payload),
                "result_rows": len(result_rows),
            },
            "finalization": {
                "commit": finalization_commit,
                "manifest_path": "benchmarks/run-manifest.json",
                "manifest_sha256": _sha256(manifest_bytes),
                "manifest_bytes": len(manifest_bytes),
            },
        },
        "observations": _expected_observations(
            result_rows,
            source_inventory_sha256=str(manifest_source.get("sha256")),
            corpus_sha256=str(manifest_corpus.get("sha256")),
        ),
    }
    binding, observations = _validate_structure(registry)
    validated_finalization_commit = _validate_binding(
        registry,
        binding,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        results_bytes=results_snapshot.payload,
        result_rows=result_rows,
    )
    _validate_observations(
        observations,
        expected=_expected_observations(
            result_rows,
            source_inventory_sha256=str(manifest_source.get("sha256")),
            corpus_sha256=str(manifest_corpus.get("sha256")),
        ),
    )
    _verify_history(
        root,
        finalization_commit=validated_finalization_commit,
        manifest_bytes=manifest_bytes,
        results_bytes=results_snapshot.payload,
        manifest_path=manifest_path,
        results_path=results_path,
    )
    return registry


def _render_registry(registry: dict[str, object]) -> bytes:
    return (
        json.dumps(
            registry,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _write_registry(path: Path, payload: bytes, *, replace: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "wb" if replace else "xb"
    try:
        with path.open(mode) as handle:
            handle.write(payload)
    except FileExistsError as exc:
        raise RegistryError(
            f"registry already exists: {path}; pass --replace explicitly"
        ) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the committed synthetic failure-observation registry."
    )
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--generate",
        action="store_true",
        help="generate the registry from one finalized benchmark pair",
    )
    parser.add_argument(
        "--finalization-commit",
        help="full commit containing the exact finalized manifest",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help="explicitly replace --registry during generation",
    )
    args = parser.parse_args(argv)
    try:
        if args.generate:
            if args.finalization_commit is None:
                parser.error("--generate requires --finalization-commit")
            registry = build_registry(
                root=args.root,
                finalization_commit=args.finalization_commit,
            )
            _write_registry(
                args.registry,
                _render_registry(registry),
                replace=args.replace,
            )
            generated_observations = registry["observations"]
            assert isinstance(generated_observations, list)
            count = len(generated_observations)
            print(
                f"generated {count} synthetic failure observations at {args.registry}; "
                "review unresolved dispositions before commit"
            )
            return 0
        if args.finalization_commit is not None or args.replace:
            parser.error("--finalization-commit/--replace require --generate")
        count = validate_registry(args.registry, root=args.root)
    except (OSError, RegistryError, ValueError) as exc:
        print(f"synthetic failure registry invalid: {exc}", file=sys.stderr)
        return 1
    print(
        "synthetic failure registry verified: "
        f"{count} complete literal case IDs; evidence is synthetic, "
        "self_consistent_unattributed, authenticated=false, field_evidence=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
