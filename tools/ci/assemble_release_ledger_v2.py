# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Assemble a reviewed Release Ledger v2 draft from retained local evidence.

This is deliberately an offline, non-authoritative assembler.  It never
collects GitHub state, signs a ledger, or turns operator claims into facts.  It
only completes byte-derived fields, rejects contradictions, applies every
validation possible before signing, and emits an unsigned canonical draft plus
an input-provenance manifest.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib
import importlib.machinery
import importlib.util
import os
import re
import stat
import sys
import tempfile
from collections.abc import Iterator, Mapping, MutableMapping, Sequence
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, cast

ROOT = Path(__file__).resolve().parents[2]


def _bootstrap_is_link_like(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        reparse_flag and attributes & reparse_flag
    )


def _bootstrap_path_is_within(path: Path, root: Path) -> bool:
    try:
        path_text = os.path.normcase(os.path.abspath(path))
        root_text = os.path.normcase(os.path.abspath(root))
        return os.path.commonpath((path_text, root_text)) == root_text
    except ValueError:
        return False


def _bootstrap_plain_directory(path: Path) -> bool:
    absolute = Path(os.path.abspath(path))
    for current in (absolute, *absolute.parents):
        try:
            metadata = current.lstat()
        except OSError:
            return False
        if _bootstrap_is_link_like(metadata) or not stat.S_ISDIR(metadata.st_mode):
            return False
    return True


def _bootstrap_module_paths(module: Any) -> tuple[Path, ...]:
    values: list[Path] = []
    spec = getattr(module, "__spec__", None)
    for value in (getattr(module, "__file__", None), getattr(spec, "origin", None)):
        if not isinstance(value, str) or value in {"built-in", "frozen"}:
            continue
        path = Path(value)
        if not path.is_absolute():
            return (Path(""),)
        values.append(Path(os.path.abspath(path)))
    locations = getattr(spec, "submodule_search_locations", None)
    if locations is not None:
        for value in locations:
            path = Path(value)
            if not path.is_absolute():
                return (Path(""),)
            values.append(Path(os.path.abspath(path)))
    return tuple(dict.fromkeys(values))


def _bootstrap_module_is_unsafe(module: Any, roots: Sequence[Path]) -> bool:
    paths = _bootstrap_module_paths(module)
    if not paths:
        spec = getattr(module, "__spec__", None)
        origin = getattr(spec, "origin", None)
        loader = getattr(spec, "loader", None)
        return not (
            origin == "built-in"
            and loader is importlib.machinery.BuiltinImporter
            or origin == "frozen"
            and loader is importlib.machinery.FrozenImporter
        )
    return any(
        not any(_bootstrap_path_is_within(path, root) for root in roots)
        for path in paths
    )


def _load_validator_from_isolated_runtime() -> Any:
    """Load the candidate validator with dependencies from host runtime roots.

    This is a trusted-operator bootstrap and does not claim recovery from an
    already-compromised interpreter or standard library.
    """

    prefixes = {
        Path(os.path.abspath(sys.prefix)),
        Path(os.path.abspath(sys.base_prefix)),
    }
    candidates = [
        *prefixes,
        *(Path(value) for value in sys.path if value and Path(value).is_absolute()),
    ]
    safe_roots: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        absolute = Path(os.path.abspath(candidate))
        if (
            not any(
                _bootstrap_path_is_within(absolute, prefix)
                for prefix in prefixes
            )
            or _bootstrap_path_is_within(absolute, ROOT)
            or _bootstrap_path_is_within(ROOT, absolute)
            or not _bootstrap_plain_directory(absolute)
        ):
            continue
        portable = os.path.normcase(str(absolute))
        if portable not in seen:
            safe_roots.append(absolute)
            seen.add(portable)
    if not safe_roots:
        raise RuntimeError("no isolated Python runtime path is available")
    safe_roots.sort(key=lambda path: (len(path.parts), os.path.normcase(str(path))))

    module_name = "tools.ci.validate_release_ledger_v2"
    validator_path = ROOT / "tools" / "ci" / "validate_release_ledger_v2.py"
    saved_path = list(sys.path)
    saved_meta_path = list(sys.meta_path)
    saved_hooks = list(sys.path_hooks)
    saved_cache = dict(sys.path_importer_cache)
    saved_names = set(sys.modules)
    removed_modules = {
        name: module
        for name, module in sys.modules.items()
        if name == module_name
        or name == "jsonschema"
        or name.startswith("jsonschema.")
        or _bootstrap_module_is_unsafe(module, safe_roots)
    }
    parent_package = sys.modules.get("tools.ci")
    missing = object()
    parent_attribute = (
        getattr(parent_package, "validate_release_ledger_v2", missing)
        if parent_package is not None
        else missing
    )
    try:
        for name in removed_modules:
            sys.modules.pop(name, None)
        sys.path[:] = [str(path) for path in safe_roots]
        sys.meta_path[:] = [
            importlib.machinery.BuiltinImporter,
            importlib.machinery.FrozenImporter,
            importlib.machinery.PathFinder,
        ]
        sys.path_hooks[:] = [
            importlib.machinery.FileFinder.path_hook(
                (
                    importlib.machinery.SourceFileLoader,
                    importlib.machinery.SOURCE_SUFFIXES,
                ),
                (
                    importlib.machinery.SourcelessFileLoader,
                    importlib.machinery.BYTECODE_SUFFIXES,
                ),
                (
                    importlib.machinery.ExtensionFileLoader,
                    importlib.machinery.EXTENSION_SUFFIXES,
                ),
            )
        ]
        sys.path_importer_cache.clear()
        spec = importlib.util.spec_from_file_location(module_name, validator_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot create the isolated validator import")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        for name in list(sys.modules):
            if name not in saved_names or name in removed_modules:
                sys.modules.pop(name, None)
        sys.modules.update(removed_modules)
        if parent_package is not None:
            if parent_attribute is missing:
                with suppress(AttributeError):
                    delattr(parent_package, "validate_release_ledger_v2")
            else:
                vars(parent_package)[
                    "validate_release_ledger_v2"
                ] = parent_attribute
        sys.path[:] = saved_path
        sys.meta_path[:] = saved_meta_path
        sys.path_hooks[:] = saved_hooks
        sys.path_importer_cache.clear()
        sys.path_importer_cache.update(saved_cache)
        importlib.invalidate_caches()


validator = _load_validator_from_isolated_runtime()

ASSEMBLY_FORMAT = "EVOGUARD_RELEASE_LEDGER_V2_ASSEMBLY_PROVENANCE_V1"
MAX_CLAIMS_BYTES = validator.MAX_JSON_BYTES
_RUN_INVOCATION = re.compile(
    r"https://github\.com/[^/]+/[^/]+/actions/runs/([1-9][0-9]*)/"
    r"attempts/([1-9][0-9]*)\Z"
)


class LedgerAssemblyError(ValueError):
    """The reviewed claims or retained evidence cannot form a ledger draft."""


def _fail(message: str) -> NoReturn:
    raise LedgerAssemblyError(message)


def _as_mapping(value: Any, *, label: str) -> MutableMapping[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return cast(dict[str, Any], value)


def _as_list(value: Any, *, label: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(f"{label} must be an array")
    return value


def _descriptor_slots(
    ledger: MutableMapping[str, Any],
) -> Iterator[tuple[str, MutableMapping[str, Any]]]:
    """Yield every file-descriptor location in the v2 contract explicitly."""

    scope = _as_mapping(ledger.get("ledger_scope"), label="ledger_scope")
    yield "ledger_scope.readme", _as_mapping(
        scope.get("readme"), label="ledger_scope.readme"
    )

    for index, item in enumerate(_as_list(ledger.get("artifacts"), label="artifacts")):
        yield f"artifacts[{index}]", _as_mapping(
            item, label=f"artifacts[{index}]"
        )

    controls = _as_mapping(
        ledger.get("control_evidence"), label="control_evidence"
    )
    for name, item in controls.items():
        bundle = _as_mapping(item, label=f"control_evidence.{name}")
        yield f"control_evidence.{name}.manifest", _as_mapping(
            bundle.get("manifest"),
            label=f"control_evidence.{name}.manifest",
        )
        for index, material in enumerate(
            _as_list(
                bundle.get("materials"),
                label=f"control_evidence.{name}.materials",
            )
        ):
            yield (
                f"control_evidence.{name}.materials[{index}]",
                _as_mapping(
                    material,
                    label=f"control_evidence.{name}.materials[{index}]",
                ),
            )

    source = _as_mapping(ledger.get("source_admission"), label="source_admission")
    for name in (
        "rsae",
        "protected_seal_result",
        "detached_verification_result",
        "negative_results",
    ):
        yield f"source_admission.{name}", _as_mapping(
            source.get(name), label=f"source_admission.{name}"
        )

    artifact = _as_mapping(
        ledger.get("artifact_admission"), label="artifact_admission"
    )
    for index, item in enumerate(
        _as_list(artifact.get("subjects"), label="artifact_admission.subjects")
    ):
        subject = _as_mapping(
            item, label=f"artifact_admission.subjects[{index}]"
        )
        for name in (
            "raae",
            "protected_seal_result",
            "detached_verification_result",
        ):
            yield (
                f"artifact_admission.subjects[{index}].{name}",
                _as_mapping(
                    subject.get(name),
                    label=f"artifact_admission.subjects[{index}].{name}",
                ),
            )
    yield "artifact_admission.negative_results", _as_mapping(
        artifact.get("negative_results"),
        label="artifact_admission.negative_results",
    )

    attestations = _as_mapping(ledger.get("attestations"), label="attestations")
    for name in (
        "source_producer",
        "build_provenance",
        "spdx_provenance",
        "sbom_provenance",
    ):
        attestation = _as_mapping(
            attestations.get(name), label=f"attestations.{name}"
        )
        for evidence_name in ("verification_receipt", "verification_output"):
            yield (
                f"attestations.{name}.{evidence_name}",
                _as_mapping(
                    attestation.get(evidence_name),
                    label=f"attestations.{name}.{evidence_name}",
                ),
            )

    repository_controls = _as_mapping(
        ledger.get("repository_controls"), label="repository_controls"
    )
    yield "repository_controls.observation_evidence", _as_mapping(
        repository_controls.get("observation_evidence"),
        label="repository_controls.observation_evidence",
    )

    for index, item in enumerate(
        _as_list(ledger.get("trust_roots"), label="trust_roots")
    ):
        root = _as_mapping(item, label=f"trust_roots[{index}]")
        yield f"trust_roots[{index}].public_key", _as_mapping(
            root.get("public_key"),
            label=f"trust_roots[{index}].public_key",
        )

    ledger_signature = _as_mapping(
        ledger.get("ledger_signature"), label="ledger_signature"
    )
    yield "ledger_signature.public_key", _as_mapping(
        ledger_signature.get("public_key"),
        label="ledger_signature.public_key",
    )


def _set_derived(
    value: MutableMapping[str, Any],
    key: str,
    expected: Any,
    *,
    label: str,
) -> None:
    if key in value and value[key] != expected:
        _fail(
            f"{label}.{key} contradicts retained evidence: "
            f"claimed={value[key]!r}, derived={expected!r}"
        )
    value[key] = expected


def _read_evidence_file(
    root: Path,
    relative: Any,
    *,
    label: str,
) -> tuple[str, bytes]:
    if not isinstance(relative, str):
        _fail(f"{label}.path must be a string")
    try:
        path = validator._safe_retained_path(root, relative)
        data = validator._read_regular(
            path,
            limit=validator.MAX_RETAINED_FILE_BYTES,
            label=f"assembly input {label}",
        )
    except validator.LedgerValidationError as exc:
        raise LedgerAssemblyError(str(exc)) from exc
    return relative, data


def _complete_file_descriptors(
    ledger: MutableMapping[str, Any],
    evidence_root: Path,
) -> dict[str, bytes]:
    retained: dict[str, bytes] = {}
    for label, descriptor in _descriptor_slots(ledger):
        relative, data = _read_evidence_file(
            evidence_root,
            descriptor.get("path"),
            label=label,
        )
        prior = retained.get(relative)
        if prior is not None and prior != data:
            _fail(f"retained path changed between descriptor reads: {relative}")
        retained[relative] = data
        _set_derived(
            descriptor,
            "size_bytes",
            len(data),
            label=label,
        )
        _set_derived(
            descriptor,
            "sha256",
            hashlib.sha256(data).hexdigest(),
            label=label,
        )
    return retained


def _canonical_descriptor_json(
    evidence_root: Path,
    descriptor: Mapping[str, Any],
    *,
    label: str,
) -> dict[str, Any]:
    _relative, data = _read_evidence_file(
        evidence_root,
        descriptor.get("path"),
        label=label,
    )
    try:
        value = validator._load_json_bytes(data, label=label)
    except validator.LedgerValidationError as exc:
        raise LedgerAssemblyError(str(exc)) from exc
    if validator.canonical_json_bytes(value) != data:
        _fail(f"{label} is not canonical JSON")
    return cast(dict[str, Any], value)


def _derive_attestation_facts(
    ledger: MutableMapping[str, Any],
    evidence_root: Path,
) -> dict[str, Any]:
    attestations = _as_mapping(ledger.get("attestations"), label="attestations")
    release = _as_mapping(ledger.get("release"), label="release")
    repository = release.get("repository")
    if not isinstance(repository, str):
        _fail("release.repository must be a reviewed string")
    fixed = {
        "source_producer": ("source-producer-receipt", "B"),
        "build_provenance": ("build-provenance", "E"),
        "spdx_provenance": ("spdx-file-provenance", "E"),
        "sbom_provenance": ("sbom-provenance", "E"),
    }
    facts: dict[str, Any] = {}
    for name, (role, phase) in fixed.items():
        attestation = _as_mapping(
            attestations.get(name), label=f"attestations.{name}"
        )
        receipt = _canonical_descriptor_json(
            evidence_root,
            _as_mapping(
                attestation.get("verification_receipt"),
                label=f"attestations.{name}.verification_receipt",
            ),
            label=f"{name} verification receipt",
        )
        output_descriptor = _as_mapping(
            attestation.get("verification_output"),
            label=f"attestations.{name}.verification_output",
        )
        _relative, output_bytes = _read_evidence_file(
            evidence_root,
            output_descriptor.get("path"),
            label=f"{name} verification output",
        )
        try:
            decoded = validator._load_json_value_bytes(
                output_bytes,
                label=f"{name} verification output",
            )
        except validator.LedgerValidationError as exc:
            raise LedgerAssemblyError(str(exc)) from exc
        if (
            not isinstance(decoded, list)
            or len(decoded) != 1
            or not isinstance(decoded[0], dict)
        ):
            _fail(f"{name} verification output must contain one attestation")
        result = decoded[0].get("verificationResult")
        if not isinstance(result, dict):
            _fail(f"{name} verification output has no verificationResult")
        statement = result.get("statement")
        signature = result.get("signature")
        if not isinstance(statement, dict) or not isinstance(signature, dict):
            _fail(f"{name} verification output has no statement or signature")
        subjects = statement.get("subject")
        if (
            not isinstance(subjects, list)
            or len(subjects) != 1
            or not isinstance(subjects[0], dict)
        ):
            _fail(f"{name} verification output does not contain one subject")
        subject = subjects[0]
        digest = subject.get("digest")
        if (
            not isinstance(subject.get("name"), str)
            or not isinstance(digest, dict)
            or not isinstance(digest.get("sha256"), str)
        ):
            _fail(f"{name} verification output subject is incomplete")
        predicate_type = statement.get("predicateType")
        if not isinstance(predicate_type, str):
            _fail(f"{name} verification output predicate type is missing")

        policy = receipt.get("verification_policy")
        artifact = receipt.get("artifact")
        receipt_output = receipt.get("verification_output")
        if (
            not isinstance(policy, dict)
            or not isinstance(artifact, dict)
            or not isinstance(receipt_output, dict)
        ):
            _fail(f"{name} receipt does not contain artifact/policy/output objects")
        if (
            policy.get("repository") != repository
            or policy.get("predicate_type") != predicate_type
            or artifact.get("sha256") != digest["sha256"]
            or receipt_output.get("sha256")
            != hashlib.sha256(output_bytes).hexdigest()
            or receipt_output.get("size") != len(output_bytes)
            or receipt_output.get("verified_attestation_count") != 1
        ):
            _fail(f"{name} receipt contradicts its retained raw attestation output")
        signer = policy.get("signer_workflow")
        prefix = f"{repository}/"
        if not isinstance(signer, str) or not signer.startswith(prefix):
            _fail(f"{name} receipt signer workflow is not in the release repository")

        certificate = signature.get("certificate")
        if not isinstance(certificate, dict):
            _fail(f"{name} verification output certificate is missing")
        invocation = certificate.get("runInvocationURI")
        match = _RUN_INVOCATION.fullmatch(str(invocation))
        if (
            match is None
            or not str(invocation).startswith(
                f"https://github.com/{repository}/actions/runs/"
            )
        ):
            _fail(f"{name} verification output run invocation URI is not exact")
        run_id = int(match.group(1))
        run_attempt = int(match.group(2))
        if name == "sbom_provenance":
            workflow_run = receipt.get("workflow_run")
            if not isinstance(workflow_run, dict):
                _fail("sbom_provenance receipt has no workflow_run")
            if (
                workflow_run.get("id") != run_id
                or workflow_run.get("attempt") != run_attempt
            ):
                _fail(
                    "sbom_provenance receipt contradicts its raw workflow invocation"
                )

        derived = {
            "role": role,
            "phase": phase,
            "predicate_type": predicate_type,
            "subject_name": subject["name"],
            "subject_sha256": digest["sha256"],
            "signer_workflow": signer[len(prefix) :],
            "source_ref": policy.get("source_ref"),
            "source_digest": policy.get("source_digest"),
            "run_id": run_id,
            "run_attempt": run_attempt,
        }
        for key, value in derived.items():
            _set_derived(
                attestation,
                key,
                value,
                label=f"attestations.{name}",
            )
        facts[name] = {
            **derived,
            "receipt_sha256": attestation["verification_receipt"]["sha256"],
            "output_sha256": output_descriptor["sha256"],
        }
    return facts


def _derive_embedded_facts(
    ledger: MutableMapping[str, Any],
    evidence_root: Path,
) -> dict[str, Any]:
    """Extract facts that are already encoded in retained signed/JSON bytes."""

    from evoom_guard.admission.release_artifact import (
        ReleaseArtifactAdmissionError,
        inspect_release_artifact_admission,
    )
    from evoom_guard.admission.release_source import (
        ReleaseSourceAdmissionError,
        inspect_release_source_admission,
    )

    source = _as_mapping(ledger.get("source_admission"), label="source_admission")
    rsae = _as_mapping(source.get("rsae"), label="source_admission.rsae")
    rsae_path = validator._safe_retained_path(evidence_root, rsae["path"])
    _rsae_relative, rsae_bytes = _read_evidence_file(
        evidence_root,
        rsae["path"],
        label="source_admission.rsae",
    )
    try:
        inspected_source = inspect_release_source_admission(str(rsae_path))
        source_manifest = inspected_source.manifest
    except (OSError, ReleaseSourceAdmissionError) as exc:
        raise LedgerAssemblyError(f"cannot inspect retained RSAE: {exc}") from exc
    source_auth = source_manifest["authentication"]
    source_summary = source_manifest["source"]
    for key, value in (
        ("format", source_manifest["format"]),
        ("decision", source_manifest["decision"]),
        ("target_commit_sha", source_summary["target_commit_sha"]),
        ("target_tree_sha", source_summary["target_tree_sha"]),
    ):
        _set_derived(source, key, value, label="source_admission")
    _set_derived(rsae, "algorithm", source_auth["algorithm"], label="source_admission.rsae")
    _set_derived(rsae, "key_id", source_auth["key_id"], label="source_admission.rsae")

    artifact_admission = _as_mapping(
        ledger.get("artifact_admission"), label="artifact_admission"
    )
    subjects = _as_list(
        artifact_admission.get("subjects"),
        label="artifact_admission.subjects",
    )
    artifact_facts: list[dict[str, Any]] = []
    for index, value in enumerate(subjects):
        subject = _as_mapping(
            value, label=f"artifact_admission.subjects[{index}]"
        )
        raae = _as_mapping(
            subject.get("raae"),
            label=f"artifact_admission.subjects[{index}].raae",
        )
        raae_path = validator._safe_retained_path(evidence_root, raae["path"])
        try:
            inspected_artifact = inspect_release_artifact_admission(str(raae_path))
            manifest = inspected_artifact.manifest
        except (OSError, ReleaseArtifactAdmissionError) as exc:
            raise LedgerAssemblyError(
                f"cannot inspect retained RAAE {index}: {exc}"
            ) from exc
        if inspected_artifact.release_source_admission_bytes != rsae_bytes:
            _fail(f"RAAE {index} embeds a different RSAE")
        authentication = manifest["authentication"]
        artifact = manifest["artifact"]
        _set_derived(
            artifact_admission,
            "format",
            manifest["format"],
            label="artifact_admission",
        )
        _set_derived(
            artifact_admission,
            "decision",
            manifest["decision"],
            label="artifact_admission",
        )
        _set_derived(
            subject,
            "artifact_sha256",
            artifact["sha256"],
            label=f"artifact_admission.subjects[{index}]",
        )
        _set_derived(
            subject,
            "artifact_size_bytes",
            artifact["size"],
            label=f"artifact_admission.subjects[{index}]",
        )
        _set_derived(
            raae,
            "algorithm",
            authentication["algorithm"],
            label=f"artifact_admission.subjects[{index}].raae",
        )
        _set_derived(
            raae,
            "key_id",
            authentication["key_id"],
            label=f"artifact_admission.subjects[{index}].raae",
        )
        artifact_facts.append(
            {
                "name": subject.get("name"),
                "artifact_sha256": artifact["sha256"],
                "artifact_size_bytes": artifact["size"],
                "key_id": authentication["key_id"],
                "manifest_sha256": hashlib.sha256(
                    inspected_artifact.manifest_bytes
                ).hexdigest(),
                "embedded_rsae_sha256": hashlib.sha256(
                    inspected_artifact.release_source_admission_bytes
                ).hexdigest(),
            }
        )

    controls = _as_mapping(
        ledger.get("control_evidence"), label="control_evidence"
    )
    control_facts: dict[str, Any] = {}
    run_locations = {
        "source_external_controls": (
            "workflows",
            "C",
            "run_id",
            "run_attempt",
        ),
        "artifact_external_controls": (
            "workflows",
            "F",
            "workflow_run_id",
            "workflow_run_attempt",
        ),
        "publication_controls": (
            "g",
            None,
            "workflow_run_id",
            "workflow_run_attempt",
        ),
    }
    phase_by_name = {
        "source_external_controls": "C",
        "artifact_external_controls": "F",
        "publication_controls": "G",
        "publication_ready": "H",
    }
    for name, value in controls.items():
        if name not in phase_by_name:
            _fail(f"unsupported control_evidence member: {name}")
        bundle = _as_mapping(value, label=f"control_evidence.{name}")
        manifest = _canonical_descriptor_json(
            evidence_root,
            _as_mapping(
                bundle.get("manifest"),
                label=f"control_evidence.{name}.manifest",
            ),
            label=f"{name} control manifest",
        )
        manifest_format = manifest.get("format")
        if not isinstance(manifest_format, str):
            _fail(f"{name} control manifest format is missing")
        _set_derived(
            bundle,
            "format",
            manifest_format,
            label=f"control_evidence.{name}",
        )
        _set_derived(
            bundle,
            "phase",
            phase_by_name[name],
            label=f"control_evidence.{name}",
        )
        run_location = run_locations.get(name)
        derived_run: dict[str, Any] = {}
        if run_location is not None:
            container = manifest.get(run_location[0])
            if not isinstance(container, dict):
                _fail(f"{name} control manifest has no workflow identity")
            identity = (
                container.get(run_location[1])
                if run_location[1] is not None
                else container
            )
            if not isinstance(identity, dict):
                _fail(f"{name} control manifest workflow identity is incomplete")
            run_id = identity.get(run_location[2])
            attempt = identity.get(run_location[3])
            if (
                not isinstance(run_id, str)
                or not run_id.isdigit()
                or not isinstance(attempt, int)
                or isinstance(attempt, bool)
            ):
                _fail(f"{name} control manifest run identity is not canonical")
            _set_derived(
                bundle,
                "workflow_run_id",
                int(run_id),
                label=f"control_evidence.{name}",
            )
            _set_derived(
                bundle,
                "workflow_run_attempt",
                attempt,
                label=f"control_evidence.{name}",
            )
            derived_run = {"run_id": int(run_id), "run_attempt": attempt}
        control_facts[name] = {
            "format": manifest_format,
            "phase": phase_by_name[name],
            "manifest_sha256": bundle["manifest"]["sha256"],
            **derived_run,
        }

    return {
        "source_admission": {
            "format": source_manifest["format"],
            "decision": source_manifest["decision"],
            "target_commit_sha": source_summary["target_commit_sha"],
            "target_tree_sha": source_summary["target_tree_sha"],
            "key_id": source_auth["key_id"],
            "manifest_sha256": hashlib.sha256(
                inspected_source.manifest_bytes
            ).hexdigest(),
        },
        "artifact_admission": artifact_facts,
        "control_manifests": control_facts,
        "attestations": _derive_attestation_facts(ledger, evidence_root),
    }


def _derive_file_bindings(
    ledger: MutableMapping[str, Any],
    evidence_root: Path,
) -> None:
    artifacts = {
        str(item.get("name")): _as_mapping(item, label="artifact")
        for item in _as_list(ledger.get("artifacts"), label="artifacts")
        if isinstance(item, dict)
    }
    expected_names = {"evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS"}
    if set(artifacts) != expected_names:
        _fail("artifacts must name evo-guard.pyz, evo-guard.spdx.json, and SHA256SUMS")
    for name, artifact in artifacts.items():
        _set_derived(
            artifact,
            "github_digest",
            f"sha256:{artifact['sha256']}",
            label=f"artifacts.{name}",
        )

    checksum = _as_mapping(
        ledger.get("checksum_manifest"), label="checksum_manifest"
    )
    manifest = artifacts["SHA256SUMS"]
    _set_derived(
        checksum,
        "path",
        manifest["path"],
        label="checksum_manifest",
    )
    _set_derived(
        checksum,
        "manifest_sha256",
        manifest["sha256"],
        label="checksum_manifest",
    )
    entries = [
        {"target": name, "sha256": artifacts[name]["sha256"]}
        for name in ("evo-guard.pyz", "evo-guard.spdx.json")
    ]
    _set_derived(
        checksum,
        "entries",
        entries,
        label="checksum_manifest",
    )
    _, checksum_bytes = _read_evidence_file(
        evidence_root,
        manifest["path"],
        label="checksum_manifest",
    )
    expected_checksum_bytes = "".join(
        f"{artifacts[name]['sha256']}  {name}\n"
        for name in ("evo-guard.pyz", "evo-guard.spdx.json")
    ).encode("ascii")
    if checksum_bytes != expected_checksum_bytes:
        _fail("SHA256SUMS is not the exact derived filename-ordered two-line manifest")

    source = _as_mapping(ledger.get("source_admission"), label="source_admission")
    rsae = _as_mapping(source.get("rsae"), label="source_admission.rsae")
    artifact_admission = _as_mapping(
        ledger.get("artifact_admission"), label="artifact_admission"
    )
    _set_derived(
        artifact_admission,
        "source_rsae_sha256",
        rsae["sha256"],
        label="artifact_admission",
    )
    for index, value in enumerate(
        _as_list(
            artifact_admission.get("subjects"),
            label="artifact_admission.subjects",
        )
    ):
        subject = _as_mapping(
            value, label=f"artifact_admission.subjects[{index}]"
        )
        name_value = subject.get("name")
        if (
            not isinstance(name_value, str)
            or name_value not in {"evo-guard.pyz", "evo-guard.spdx.json"}
        ):
            _fail(f"artifact_admission.subjects[{index}].name is not a release asset")
        name = name_value
        artifact = artifacts[name]
        _set_derived(
            subject,
            "artifact_sha256",
            artifact["sha256"],
            label=f"artifact_admission.subjects[{index}]",
        )
        _set_derived(
            subject,
            "artifact_size_bytes",
            artifact["size_bytes"],
            label=f"artifact_admission.subjects[{index}]",
        )

    controls = _as_mapping(
        ledger.get("control_evidence"), label="control_evidence"
    )
    source_bundle = _as_mapping(
        controls.get("source_external_controls"),
        label="control_evidence.source_external_controls",
    )
    producer_receipts = [
        item
        for item in _as_list(
            source_bundle.get("materials"),
            label="control_evidence.source_external_controls.materials",
        )
        if isinstance(item, dict)
        and PurePosixPath(str(item.get("path"))).name == "producer-receipt.json"
    ]
    if len(producer_receipts) != 1:
        _fail("source controls must contain exactly one producer-receipt.json")

    attestations = _as_mapping(ledger.get("attestations"), label="attestations")
    attestation_subjects = {
        "source_producer": producer_receipts[0]["sha256"],
        "build_provenance": artifacts["evo-guard.pyz"]["sha256"],
        "spdx_provenance": artifacts["evo-guard.spdx.json"]["sha256"],
        "sbom_provenance": artifacts["evo-guard.pyz"]["sha256"],
    }
    for name, digest in attestation_subjects.items():
        value = _as_mapping(
            attestations.get(name), label=f"attestations.{name}"
        )
        _set_derived(
            value,
            "subject_sha256",
            digest,
            label=f"attestations.{name}",
        )

    release_attestation = _as_mapping(
        attestations.get("release"), label="attestations.release"
    )
    _set_derived(
        release_attestation,
        "asset_subjects",
        [
            {"name": item["name"], "sha256": item["sha256"]}
            for item in _as_list(ledger.get("artifacts"), label="artifacts")
        ],
        label="attestations.release",
    )

    try:
        from evoom_guard.signing import public_key_id
    except ImportError as exc:
        raise LedgerAssemblyError(
            "the signing extra is required to inspect retained public roots"
        ) from exc
    roots = _as_list(ledger.get("trust_roots"), label="trust_roots")
    root_ids: dict[str, str] = {}
    for index, value in enumerate(roots):
        root = _as_mapping(value, label=f"trust_roots[{index}]")
        public_key = _as_mapping(
            root.get("public_key"),
            label=f"trust_roots[{index}].public_key",
        )
        path = validator._safe_retained_path(evidence_root, public_key["path"])
        try:
            derived_key_id = public_key_id(str(path))
        except (OSError, ValueError) as exc:
            raise LedgerAssemblyError(
                f"trust_roots[{index}] is not a usable public key"
            ) from exc
        _set_derived(
            root,
            "key_id",
            derived_key_id,
            label=f"trust_roots[{index}]",
        )
        root_ids[str(root.get("domain"))] = derived_key_id
    if set(root_ids) != set(validator.ROOT_DOMAINS):
        _fail("trust_roots do not contain the six canonical admission domains")
    _set_derived(
        rsae,
        "key_id",
        root_ids["release-source-admission-v2"],
        label="source_admission.rsae",
    )
    for index, value in enumerate(
        _as_list(
            artifact_admission.get("subjects"),
            label="artifact_admission.subjects",
        )
    ):
        subject = _as_mapping(
            value, label=f"artifact_admission.subjects[{index}]"
        )
        raae = _as_mapping(
            subject.get("raae"),
            label=f"artifact_admission.subjects[{index}].raae",
        )
        _set_derived(
            raae,
            "key_id",
            root_ids["release-artifact-admission-v1"],
            label=f"artifact_admission.subjects[{index}].raae",
        )

    ledger_signature = _as_mapping(
        ledger.get("ledger_signature"), label="ledger_signature"
    )
    ledger_public = _as_mapping(
        ledger_signature.get("public_key"),
        label="ledger_signature.public_key",
    )
    ledger_public_path = validator._safe_retained_path(
        evidence_root, ledger_public["path"]
    )
    try:
        ledger_key_id = public_key_id(str(ledger_public_path))
    except (OSError, ValueError) as exc:
        raise LedgerAssemblyError(
            "ledger_signature.public_key is not a usable public key"
        ) from exc
    _set_derived(
        ledger_signature,
        "key_id",
        ledger_key_id,
        label="ledger_signature",
    )
    if ledger_key_id in set(root_ids.values()):
        _fail("ledger signing key is not distinct from all admission roots")


def _trusted_git(
    repository: Path,
    *arguments: str,
    label: str,
    output_limit: int,
    executable: Any | None = None,
) -> bytes:
    try:
        return validator._trusted_git(
            repository,
            *arguments,
            label=label,
            output_limit=output_limit,
            executable=executable,
        )
    except validator.LedgerValidationError as exc:
        raise LedgerAssemblyError(f"cannot inspect trusted parent {label}") from exc


def _trusted_blob(
    repository: Path,
    object_id: str,
    *,
    label: str,
    limit: int,
    executable: Any | None = None,
) -> bytes:
    size_bytes = _trusted_git(
        repository,
        "cat-file",
        "-s",
        object_id,
        label=f"{label} size",
        output_limit=64,
        executable=executable,
    )
    try:
        size_text = size_bytes.decode("ascii", "strict").strip()
        size = int(size_text)
    except (UnicodeDecodeError, ValueError) as exc:
        raise LedgerAssemblyError(
            f"trusted parent {label} size is not canonical"
        ) from exc
    if str(size) != size_text or size < 1 or size > limit:
        _fail(f"trusted parent {label} size is outside 1..{limit} bytes")
    data = _trusted_git(
        repository,
        "cat-file",
        "blob",
        object_id,
        label=label,
        output_limit=limit,
        executable=executable,
    )
    if len(data) != size:
        _fail(f"trusted parent {label} returned a short or extended read")
    return data


def _trusted_contracts(
    ledger: MutableMapping[str, Any],
    evidence_root: Path,
    trusted_parent_repo: Path,
    *,
    executable: Any | None = None,
) -> dict[str, Any]:
    try:
        repository = validator._require_plain_directory(
            trusted_parent_repo,
            label="external trusted parent repository",
        )
    except validator.LedgerValidationError as exc:
        raise LedgerAssemblyError(str(exc)) from exc
    if validator._path_is_within(repository, evidence_root) or validator._path_is_within(
        evidence_root, repository
    ):
        _fail("trusted parent repository and evidence root must be disjoint")
    trusted_git = executable or validator._resolve_trusted_git(
        repository,
        evidence_root,
    )

    source = _as_mapping(ledger.get("source"), label="source")
    parent = source.get("parent_commit_sha")
    parent_tree = source.get("parent_tree_sha")
    if not isinstance(parent, str) or not isinstance(parent_tree, str):
        _fail("source parent commit/tree must be reviewed strings")
    try:
        resolved_commit = _trusted_git(
            repository,
            "rev-parse",
            "--verify",
            f"{parent}^{{commit}}",
            label="commit",
            output_limit=64,
            executable=trusted_git,
        ).decode("ascii", "strict").strip()
        resolved_tree = _trusted_git(
            repository,
            "rev-parse",
            "--verify",
            f"{parent}^{{tree}}",
            label="tree",
            output_limit=64,
            executable=trusted_git,
        ).decode("ascii", "strict").strip()
    except UnicodeDecodeError as exc:
        raise LedgerAssemblyError(str(exc)) from exc
    if resolved_commit != parent or resolved_tree != parent_tree:
        _fail("trusted parent commit/tree contradicts reviewed source claims")

    ledger_signature = _as_mapping(
        ledger.get("ledger_signature"), label="ledger_signature"
    )
    ledger_public = _as_mapping(
        ledger_signature.get("public_key"),
        label="ledger_signature.public_key",
    )
    _, retained_ledger_key = _read_evidence_file(
        evidence_root,
        ledger_public.get("path"),
        label="ledger_signature.public_key",
    )
    release = _as_mapping(ledger.get("release"), label="release")
    tag = release.get("tag")
    if not isinstance(tag, str):
        _fail("release.tag must be a reviewed string")

    values: dict[str, Any] = {}
    validator_file = getattr(validator, "__file__", None)
    if not isinstance(validator_file, str):
        _fail("cannot locate the executing release-ledger validator")
    specifications = (
        (
            "release_ledger",
            validator.OFFICIAL_SCHEMA_REPOSITORY_PATH,
            validator.DEFAULT_SCHEMA.read_bytes(),
        ),
        (
            "validator",
            validator.VALIDATOR_REPOSITORY_PATH,
            Path(validator_file).read_bytes(),
        ),
        (
            "ledger_signing_anchor",
            f"security/release-ledger-roots/{tag}.pub.pem",
            retained_ledger_key,
        ),
    )
    for name, path, executing_bytes in specifications:
        try:
            entry = _trusted_git(
                repository,
                "ls-tree",
                "-z",
                parent,
                "--",
                path,
                label=f"{name} tree entry",
                output_limit=4096,
                executable=trusted_git,
            )
        except LedgerAssemblyError:
            raise
        prefix = b"100644 blob "
        suffix = f"\t{path}\0".encode()
        if not entry.startswith(prefix) or not entry.endswith(suffix):
            _fail(f"trusted parent {name} is not one exact regular Git blob")
        blob_id = entry[len(prefix) : -len(suffix)].decode("ascii", "strict")
        blob_limit = (
            validator.MAX_PUBLIC_KEY_BYTES
            if name == "ledger_signing_anchor"
            else validator.MAX_JSON_BYTES
        )
        blob = _trusted_blob(
            repository,
            blob_id,
            label=f"{name} blob",
            limit=blob_limit,
            executable=trusted_git,
        )
        if blob != executing_bytes:
            _fail(
                f"trusted parent {name} bytes differ from the executing assembly contract"
            )
        contract = {
            "path": path,
            "sha256": hashlib.sha256(blob).hexdigest(),
            "git_blob_sha": validator._git_blob_sha(blob),
            "trusted_parent_commit_sha": parent,
            "trusted_parent_tree_sha": parent_tree,
        }
        if name == "release_ledger":
            contract = {"id": validator.OFFICIAL_SCHEMA_ID, **contract}
        values[name] = contract

    schema_contracts = _as_mapping(
        ledger.get("schema_contracts"), label="schema_contracts"
    )
    for name, contract in values.items():
        if name == "ledger_signing_anchor":
            _set_derived(
                ledger_signature,
                "trusted_parent_anchor",
                contract,
                label="ledger_signature",
            )
            continue
        _set_derived(
            schema_contracts,
            name,
            contract,
            label="schema_contracts",
        )
    toolchain = _as_mapping(ledger.get("toolchain"), label="toolchain")
    trusted_inputs = _as_mapping(
        toolchain.get("trusted_build_inputs"),
        label="toolchain.trusted_build_inputs",
    )
    _set_derived(
        trusted_inputs,
        "source_parent_sha",
        parent,
        label="toolchain.trusted_build_inputs",
    )
    _set_derived(
        trusted_inputs,
        "source_parent_tree_sha",
        parent_tree,
        label="toolchain.trusted_build_inputs",
    )
    for field, path in validator.TRUSTED_BUILD_INPUT_PATHS.items():
        entry = _trusted_git(
            repository,
            "ls-tree",
            "-z",
            parent,
            "--",
            path,
            label=f"trusted build input {path} tree entry",
            output_limit=4096,
            executable=trusted_git,
        )
        prefix = b"100644 blob "
        suffix = f"\t{path}\0".encode()
        if not entry.startswith(prefix) or not entry.endswith(suffix):
            _fail(f"trusted parent build input {path} is not one exact regular blob")
        object_id = entry[len(prefix) : -len(suffix)].decode("ascii", "strict")
        executing_path = ROOT.joinpath(*PurePosixPath(path).parts)
        try:
            executing_bytes = validator._read_regular(
                executing_path,
                limit=validator.MAX_JSON_BYTES,
                label=f"executing trusted build input {path}",
            )
        except validator.LedgerValidationError as exc:
            raise LedgerAssemblyError(str(exc)) from exc
        blob = _trusted_blob(
            repository,
            object_id,
            label=f"trusted build input {path}",
            limit=validator.MAX_JSON_BYTES,
            executable=trusted_git,
        )
        if (
            blob != executing_bytes
            or validator._git_blob_sha(blob) != object_id
        ):
            _fail(f"trusted parent build input {path} bytes are not exact")
        _set_derived(
            trusted_inputs,
            field,
            object_id,
            label="toolchain.trusted_build_inputs",
        )
        values[f"trusted_build_input:{path}"] = {
            "path": path,
            "sha256": hashlib.sha256(blob).hexdigest(),
            "git_blob_sha": object_id,
            "trusted_parent_commit_sha": parent,
            "trusted_parent_tree_sha": parent_tree,
        }
    return {
        "commit_sha": parent,
        "tree_sha": parent_tree,
        "contracts": values,
    }


def _validate_completed_evidence(
    ledger: MutableMapping[str, Any],
    evidence_root: Path,
    trusted_parent_repo: Path,
    retained: Mapping[str, bytes],
    *,
    executable: Any | None = None,
) -> dict[str, tuple[int, str]]:
    try:
        validator.validate_structure(ledger)
        _trusted_contracts(
            ledger,
            evidence_root,
            trusted_parent_repo,
            executable=executable,
        )
        inventory = validator._collect_descriptors(ledger)
        validator._require_retained_budget(inventory)
        expected_files = set(inventory)
        expected_directories = validator._expected_directories(expected_files)
        actual_files, actual_directories, identities = validator._actual_inventory(
            evidence_root,
            expected_files=expected_files,
            expected_directories=expected_directories,
        )
        if actual_files != expected_files:
            _fail(
                "evidence file set is not exact; "
                f"missing={sorted(expected_files - actual_files)}, "
                f"unexpected={sorted(actual_files - expected_files)}"
            )
        if actual_directories != expected_directories:
            _fail(
                "evidence directory set is not exact; "
                f"missing={sorted(expected_directories - actual_directories)}, "
                f"unexpected={sorted(actual_directories - expected_directories)}"
            )
        for relative, (size, digest) in inventory.items():
            data = retained.get(relative)
            if (
                data is None
                or len(data) != size
                or hashlib.sha256(data).hexdigest() != digest
            ):
                _fail(f"retained input changed or conflicts at {relative}")

        with tempfile.TemporaryDirectory(
            prefix="evoguard-ledger-v2-assembly-"
        ) as temporary:
            snapshot_root = validator._require_plain_directory(
                Path(temporary),
                label="protected assembly snapshot",
            )
            files, directories, snapshot_identities = validator._materialize_snapshot(
                snapshot_root,
                retained,
            )
            validator._validate_repository_control_observation_bytes(
                snapshot_root,
                ledger,
            )
            validator._validate_control_bytes(snapshot_root, ledger)
            validator._validate_attestation_bytes(snapshot_root, ledger)
            validator._validate_envelopes(snapshot_root, ledger)

            from evoom_guard.signing import public_key_id

            for item in ledger["trust_roots"]:
                path = validator._safe_retained_path(
                    snapshot_root,
                    item["public_key"]["path"],
                )
                if public_key_id(str(path)) != item["key_id"]:
                    _fail(
                        "retained admission public key contradicts its key ID: "
                        f"{item['domain']}"
                    )
            seal = ledger["ledger_signature"]
            ledger_key_path = validator._safe_retained_path(
                snapshot_root,
                seal["public_key"]["path"],
            )
            if public_key_id(str(ledger_key_path)) != seal["key_id"]:
                _fail("retained ledger public key contradicts its key ID")
            validator._require_inventory_unchanged(
                snapshot_root,
                files=files,
                directories=directories,
                identities=snapshot_identities,
            )

        for relative, expected in retained.items():
            current = validator._read_regular(
                validator._safe_retained_path(evidence_root, relative),
                limit=max(len(expected), 1),
                label=f"retained assembly input {relative}",
            )
            if current != expected:
                _fail(f"retained evidence changed during assembly: {relative}")
        validator._require_inventory_unchanged(
            evidence_root,
            files=actual_files,
            directories=actual_directories,
            identities=identities,
        )
        _trusted_contracts(
            ledger,
            evidence_root,
            trusted_parent_repo,
            executable=executable,
        )
    except validator.LedgerValidationError as exc:
        raise LedgerAssemblyError(str(exc)) from exc
    return cast(dict[str, tuple[int, str]], inventory)


def _safe_output_parent(path: Path, *, label: str) -> Path:
    try:
        parent = validator._require_plain_directory(
            path.parent,
            label=f"{label} parent",
        )
    except validator.LedgerValidationError as exc:
        raise LedgerAssemblyError(str(exc)) from exc
    return cast(Path, parent) / path.name


def _write_outputs(
    output: Path,
    output_bytes: bytes,
    provenance: Path,
    provenance_bytes: bytes,
) -> None:
    targets = (
        (_safe_output_parent(output, label="draft output"), output_bytes),
        (
            _safe_output_parent(provenance, label="provenance output"),
            provenance_bytes,
        ),
    )
    if targets[0][0] == targets[1][0]:
        _fail("draft and provenance outputs must be distinct")
    for path, _data in targets:
        if path.exists() or path.is_symlink():
            _fail(f"refusing to overwrite output: {path}")
    try:
        parent_snapshots = {
            path: validator._directory_chain(
                path.parent,
                label=f"assembly output parent for {path.name}",
            )
            for path, _data in targets
        }
    except validator.LedgerValidationError as exc:
        raise LedgerAssemblyError(str(exc)) from exc

    opened: list[tuple[Path, int, tuple[int, int]]] = []
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        for path, _data in targets:
            descriptor = os.open(path, flags, 0o600)
            metadata = os.fstat(descriptor)
            if (
                validator._is_link_like(metadata)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
            ):
                _fail(f"output is not a new single-link regular file: {path}")
            opened.append(
                (path, descriptor, (metadata.st_dev, metadata.st_ino))
            )
        for (_path, data), (_opened_path, descriptor, _identity) in zip(
            targets, opened, strict=True
        ):
            remaining = memoryview(data)
            while remaining:
                written = os.write(descriptor, remaining)
                if written < 1:
                    _fail("output write made no progress")
                remaining = remaining[written:]
            os.fsync(descriptor)
        for (path, data), (_opened_path, descriptor, identity) in zip(
            targets,
            opened,
            strict=True,
        ):
            metadata = os.fstat(descriptor)
            if (
                validator._is_link_like(metadata)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or (metadata.st_dev, metadata.st_ino) != identity
                or metadata.st_size != len(data)
            ):
                _fail(f"assembly output changed while writing: {path}")
            validator._require_same_directory_chain(
                parent_snapshots[path],
                label=f"assembly output parent for {path.name}",
            )
            path_metadata = path.lstat()
            if (
                validator._is_link_like(path_metadata)
                or not stat.S_ISREG(path_metadata.st_mode)
                or path_metadata.st_nlink != 1
                or (path_metadata.st_dev, path_metadata.st_ino) != identity
            ):
                _fail(f"assembly output pathname changed while writing: {path}")
    except (OSError, LedgerAssemblyError, validator.LedgerValidationError) as exc:
        for _path, descriptor, _identity in opened:
            try:
                os.close(descriptor)
            except OSError:
                pass
        for path, _descriptor, identity in opened:
            try:
                metadata = path.lstat()
                if (
                    not validator._is_link_like(metadata)
                    and stat.S_ISREG(metadata.st_mode)
                    and (metadata.st_dev, metadata.st_ino) == identity
                ):
                    path.unlink()
            except OSError:
                pass
        if isinstance(exc, LedgerAssemblyError):
            raise
        if isinstance(exc, validator.LedgerValidationError):
            raise LedgerAssemblyError(str(exc)) from exc
        raise LedgerAssemblyError("cannot create assembly outputs") from exc
    else:
        for _path, descriptor, _identity in opened:
            os.close(descriptor)


def assemble(
    evidence_root: Path,
    claims_path: Path,
    output_path: Path,
    provenance_path: Path,
    trusted_parent_repo: Path,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    """Assemble, validate, and atomically emit one unsigned canonical draft."""

    try:
        root = validator._require_plain_directory(
            evidence_root,
            label="assembly evidence root",
        )
        claims_bytes = validator._read_regular(
            claims_path,
            limit=MAX_CLAIMS_BYTES,
            label="operator-reviewed claims",
        )
        claims = validator._load_json_bytes(
            claims_bytes,
            label="operator-reviewed claims",
        )
    except validator.LedgerValidationError as exc:
        raise LedgerAssemblyError(str(exc)) from exc

    for label, path in (
        ("operator-reviewed claims", claims_path),
        ("draft output", output_path),
        ("provenance output", provenance_path),
    ):
        if validator._path_is_within(path, root):
            _fail(f"{label} must remain outside the closed evidence directory")
    if validator._path_is_within(trusted_parent_repo, root) or validator._path_is_within(
        root, trusted_parent_repo
    ):
        _fail("trusted parent repository and evidence root must be disjoint")

    ledger: MutableMapping[str, Any] = copy.deepcopy(claims)
    retained = _complete_file_descriptors(ledger, root)
    trusted_git = validator._resolve_trusted_git(root, trusted_parent_repo)
    trusted_parent = _trusted_contracts(
        ledger,
        root,
        trusted_parent_repo,
        executable=trusted_git,
    )
    try:
        first_party_contracts = validator._trusted_parent_contract_reference(
            trusted_parent_repo,
            trusted_parent["commit_sha"],
            trusted_parent["tree_sha"],
            executable=trusted_git,
        )
        with validator._trusted_parent_first_party(first_party_contracts):
            extracted_facts = _derive_embedded_facts(ledger, root)
            _derive_file_bindings(ledger, root)
            inventory = _validate_completed_evidence(
                ledger,
                root,
                trusted_parent_repo,
                retained,
                executable=trusted_git,
            )
    except validator.LedgerValidationError as exc:
        raise LedgerAssemblyError(str(exc)) from exc
    draft_bytes = validator.canonical_json_bytes(ledger)

    tool_path = Path(__file__).resolve()
    tool_bytes = validator._read_regular(
        tool_path,
        limit=validator.MAX_JSON_BYTES,
        label="release-ledger assembler",
    )
    provenance: MutableMapping[str, Any] = {
        "format": ASSEMBLY_FORMAT,
        "authoritative": False,
        "network_access": "not-performed",
        "signing": "not-performed",
        "evidence_root": ".",
        "operator_claims": {
            "name": claims_path.name,
            "size_bytes": len(claims_bytes),
            "sha256": hashlib.sha256(claims_bytes).hexdigest(),
        },
        "assembler": {
            "path": "tools/ci/assemble_release_ledger_v2.py",
            "size_bytes": len(tool_bytes),
            "sha256": hashlib.sha256(tool_bytes).hexdigest(),
            "git_blob_sha": validator._git_blob_sha(tool_bytes),
        },
        "trusted_parent": trusted_parent,
        "extracted_evidence_facts": extracted_facts,
        "retained_inputs": [
            {
                "path": relative,
                "size_bytes": size,
                "sha256": digest,
            }
            for relative, (size, digest) in sorted(inventory.items())
        ],
        "unsigned_draft": {
            "name": output_path.name,
            "size_bytes": len(draft_bytes),
            "sha256": hashlib.sha256(draft_bytes).hexdigest(),
            "canonical_json": True,
        },
        "validation_completed": [
            "official-schema-and-cross-field-semantics",
            "trusted-parent-schema-and-validator-blobs",
            "closed-world-retained-file-and-directory-inventory",
            "retained-byte-descriptors-and-checksum-manifest",
            "repository-control-observation",
            "control-manifests",
            "github-attestation-receipts-and-raw-output",
            "rsae-raae-signatures-and-bindings",
            "all-retained-public-key-identities",
            "input-stability-before-output",
        ],
        "not_established": [
            "ledger-detached-signature",
            "external-ledger-public-key-trust-anchor",
            "post-commit-validation",
            "publication-authority-retirement",
        ],
    }
    provenance_bytes = validator.canonical_json_bytes(provenance)
    _write_outputs(
        output_path,
        draft_bytes,
        provenance_path,
        provenance_bytes,
    )
    return ledger, provenance


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "evidence_root",
        type=Path,
        help="closed directory containing only the retained files described by the ledger",
    )
    parser.add_argument(
        "claims",
        type=Path,
        help="operator-reviewed JSON claims; must remain outside EVIDENCE_ROOT",
    )
    parser.add_argument(
        "output",
        type=Path,
        help="new canonical unsigned ledger draft; never overwritten",
    )
    parser.add_argument(
        "--provenance",
        type=Path,
        required=True,
        help="new canonical non-authoritative input manifest; never overwritten",
    )
    parser.add_argument(
        "--trusted-parent-repo",
        type=Path,
        required=True,
        help="disjoint local Git repository containing the admitted parent commit",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        assemble(
            args.evidence_root,
            args.claims,
            args.output,
            args.provenance,
            args.trusted_parent_repo,
        )
    except LedgerAssemblyError as exc:
        print(f"release-ledger-v2-assembly: INVALID: {exc}", file=sys.stderr)
        return 1
    print(
        "release-ledger-v2-assembly: canonical unsigned draft and "
        f"non-authoritative provenance written to {args.output} and "
        f"{args.provenance}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
