# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Deterministic installation and static inspection of the Trusted Finalizer.

This module deliberately does not call GitHub.  A successful static report
establishes that the committed files, public key, and trusted-base policy agree
with the packaged reference kit.  It does not establish that repository rules,
variables, secrets, or the protected Environment are configured on GitHub.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
from collections.abc import Callable
from importlib import resources
from pathlib import PurePosixPath
from typing import Any

from evoom_guard.pack_manifest import PackManifestError, pack_digest
from evoom_guard.policy.config import ConfigError, load_config
from evoom_guard.strict_json import strict_json_loads

KIT_FORMAT = "EVOGUARD_FINALIZER_KIT_V1"
DEPLOYMENT_FORMAT = "EVOGUARD_FINALIZER_DEPLOYMENT_V1"
REPORT_FORMAT = "EVOGUARD_FINALIZER_DEPLOYMENT_REPORT_V1"
KIT_VERSION = 1
DEPLOYMENT_MANIFEST_PATH = ".evoguard/finalizer-deployment.json"
MAX_PUBLIC_KEY_BYTES = 4096
MAX_MANIFEST_BYTES = 1024 * 1024

_KIT_RESOURCE_DIRECTORY = "templates/trusted-finalizer/v4.5.0"
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IMMUTABLE_IMAGE = re.compile(r".+@sha256:[0-9a-f]{64}\Z")
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_REPARSE_ATTRIBUTE = 0x400
_EXPECTED_RUNTIME = {
    "download_url": (
        "https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/download/"
        "v4.5.0/evo-guard.pyz"
    ),
    "release": "v4.5.0",
    "release_ledger_sha256": (
        "9ee6c49e7a3c93d611c34e208f5e3936f147bf0ed0b8ff2c41b3e53b891da239"
    ),
    "sha256": "44bf036666bc7bb2903b647f33b63254771771887de4f170c91e8cdd8307c89d",
    "source_commit": "6bb4c328e56661b661e50532886802c6ba36a997",
}
_EXPECTED_GITHUB = {
    "environment": "evoguard-finalizer",
    "guard_digest_variable": "EVOGUARD_GUARD_ARTIFACT_SHA256",
    "private_key_secret": "EVOGUARD_FINALIZER_KEY",
    "reverify_workflow_id_variable": "EVOGUARD_REVERIFY_WORKFLOW_ID",
}

REQUIRED_LIVE_CONTROLS = (
    "Set repository variable EVOGUARD_GUARD_ARTIFACT_SHA256 to the reviewed "
    "v4.5.0 zipapp SHA-256.",
    "Create the evoguard-finalizer Environment, protect it with required reviewers, "
    "and store EVOGUARD_FINALIZER_KEY only in that Environment.",
    "Dispatch EvoGuard Reverify once, then set EVOGUARD_REVERIFY_WORKFLOW_ID to its "
    "numeric workflow ID.",
    "Protect the default branch, workflows, policy, verifier pack, and public key "
    "with independent review/CODEOWNERS.",
    "Require the attempt-bound EvoGuard Trusted Finalizer check in the repository "
    "ruleset after a controlled Round 1 validation.",
)


class FinalizerDeploymentError(ValueError):
    """A finalizer kit cannot be installed or inspected safely."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & _REPARSE_ATTRIBUTE)


def _regular_file_bytes(path: str, *, limit: int, label: str) -> bytes:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise FinalizerDeploymentError(f"{label} is not readable: {path} ({exc})") from exc
    if _is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise FinalizerDeploymentError(f"{label} must be a regular non-link file: {path}")
    if metadata.st_size > limit:
        raise FinalizerDeploymentError(f"{label} exceeds the {limit}-byte limit: {path}")
    try:
        with open(path, "rb") as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        raise FinalizerDeploymentError(f"{label} is not readable: {path} ({exc})") from exc
    if len(data) > limit:
        raise FinalizerDeploymentError(f"{label} exceeds the {limit}-byte limit: {path}")
    return data


def _validated_root(root: str) -> str:
    absolute = os.path.abspath(root)
    try:
        metadata = os.lstat(absolute)
    except OSError as exc:
        raise FinalizerDeploymentError(f"repository root is not readable: {absolute} ({exc})") from exc
    if _is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise FinalizerDeploymentError(
            f"repository root must be a real non-link directory: {absolute}"
        )
    return absolute


def _safe_relative_path(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise FinalizerDeploymentError(f"{label} must be a non-empty POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix() or any(
        part in {"", ".", ".."}
        or ":" in part
        or any(ord(character) < 32 or ord(character) == 127 for character in part)
        for part in path.parts
    ):
        raise FinalizerDeploymentError(f"{label} must stay inside the repository: {value!r}")
    return value


def canonical_ed25519_public_key(data: bytes) -> tuple[bytes, str]:
    """Return canonical PEM and a DER-bound key ID for an Ed25519 public key."""

    if len(data) > MAX_PUBLIC_KEY_BYTES:
        raise FinalizerDeploymentError(
            f"public key exceeds the {MAX_PUBLIC_KEY_BYTES}-byte limit"
        )
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise FinalizerDeploymentError("public key PEM must be ASCII") from exc
    match = re.fullmatch(
        r"-----BEGIN PUBLIC KEY-----\r?\n"
        r"([A-Za-z0-9+/=\r\n]+)"
        r"-----END PUBLIC KEY-----\r?\n?",
        text,
    )
    if match is None:
        raise FinalizerDeploymentError(
            "public key must be a PEM SubjectPublicKeyInfo PUBLIC KEY; private keys "
            "are never accepted"
        )
    body = "".join(match.group(1).splitlines())
    try:
        der = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise FinalizerDeploymentError("public key PEM contains invalid base64") from exc
    if len(der) != 44 or not der.startswith(_ED25519_SPKI_PREFIX):
        raise FinalizerDeploymentError(
            "public key must be an Ed25519 SubjectPublicKeyInfo key"
        )
    encoded = base64.b64encode(der).decode("ascii")
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    canonical = (
        "-----BEGIN PUBLIC KEY-----\n"
        + "\n".join(lines)
        + "\n-----END PUBLIC KEY-----\n"
    ).encode("ascii")
    return canonical, "sha256:" + _sha256(der)


def _resource_bytes(name: str) -> bytes:
    try:
        node = resources.files("evoom_guard")
        for component in _KIT_RESOURCE_DIRECTORY.split("/"):
            node = node.joinpath(component)
        return node.joinpath(name).read_bytes()
    except (FileNotFoundError, OSError) as exc:
        raise FinalizerDeploymentError(f"packaged finalizer resource is missing: {name}") from exc


def load_finalizer_kit() -> dict[str, Any]:
    """Load the packaged kit and prove that its manifest binds every template."""

    manifest_bytes = _resource_bytes("manifest.json")
    try:
        value = strict_json_loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise FinalizerDeploymentError(f"packaged finalizer manifest is invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise FinalizerDeploymentError("packaged finalizer manifest must be a JSON object")
    if value.get("format") != KIT_FORMAT or value.get("kit_version") != KIT_VERSION:
        raise FinalizerDeploymentError("packaged finalizer manifest has an unsupported format")
    templates = value.get("templates")
    if not isinstance(templates, list) or len(templates) != 2:
        raise FinalizerDeploymentError("packaged finalizer manifest must bind two workflows")
    seen_paths: set[str] = set()
    seen_resources: set[str] = set()
    for entry in templates:
        if not isinstance(entry, dict):
            raise FinalizerDeploymentError("packaged template entry must be an object")
        install_path = _safe_relative_path(entry.get("install_path"), label="install_path")
        resource_name = entry.get("resource")
        expected_sha = entry.get("sha256")
        if (
            not isinstance(resource_name, str)
            or "/" in resource_name
            or "\\" in resource_name
            or not resource_name.endswith(".yml")
        ):
            raise FinalizerDeploymentError("packaged template resource name is unsafe")
        if not isinstance(expected_sha, str) or _HEX_SHA256.fullmatch(expected_sha) is None:
            raise FinalizerDeploymentError("packaged template SHA-256 is invalid")
        if install_path in seen_paths or resource_name in seen_resources:
            raise FinalizerDeploymentError("packaged finalizer manifest contains duplicates")
        seen_paths.add(install_path)
        seen_resources.add(resource_name)
        if _sha256(_resource_bytes(resource_name)) != expected_sha:
            raise FinalizerDeploymentError(
                f"packaged finalizer template drifted from its manifest: {resource_name}"
            )
    expected_paths = {
        ".github/workflows/evoguard-reverify.yml",
        ".github/workflows/evoguard-seal.yml",
    }
    if seen_paths != expected_paths:
        raise FinalizerDeploymentError("packaged finalizer manifest targets unexpected paths")
    runtime = value.get("runtime")
    github = value.get("github")
    if not isinstance(runtime, dict) or not isinstance(github, dict):
        raise FinalizerDeploymentError("packaged finalizer runtime/GitHub contract is invalid")
    if runtime != _EXPECTED_RUNTIME:
        raise FinalizerDeploymentError("packaged finalizer runtime contract is invalid")
    if github != _EXPECTED_GITHUB:
        raise FinalizerDeploymentError("packaged finalizer GitHub contract is invalid")
    if value.get("policy_path") != ".evoguard.json" or value.get(
        "public_key_path"
    ) != "security/evoguard-finalizer.pub.pem":
        raise FinalizerDeploymentError("packaged finalizer path contract is invalid")
    return value


def _deployment_manifest(
    kit: dict[str, Any], *, public_key: bytes, key_id: str
) -> dict[str, Any]:
    files = {
        str(entry["install_path"]): {"sha256": str(entry["sha256"])}
        for entry in kit["templates"]
    }
    return {
        "files": files,
        "format": DEPLOYMENT_FORMAT,
        "github": kit["github"],
        "kit": {"format": KIT_FORMAT, "version": KIT_VERSION},
        "policy_path": kit["policy_path"],
        "public_key": {
            "key_id": key_id,
            "path": kit["public_key_path"],
            "sha256": _sha256(public_key),
        },
        "runtime": kit["runtime"],
    }


def _ensure_parent_directories(root: str, relative: str, created: list[str]) -> None:
    current = root
    for component in PurePosixPath(relative).parts[:-1]:
        current = os.path.join(current, component)
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            try:
                os.mkdir(current)
            except OSError as exc:
                raise FinalizerDeploymentError(
                    f"could not create deployment directory: {current} ({exc})"
                ) from exc
            created.append(current)
            continue
        except OSError as exc:
            raise FinalizerDeploymentError(
                f"deployment directory is not inspectable: {current} ({exc})"
            ) from exc
        if _is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise FinalizerDeploymentError(
                f"deployment parent must be a real non-link directory: {current}"
            )


def _exclusive_write(path: str, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o644)
    except OSError as exc:
        raise FinalizerDeploymentError(f"refusing to overwrite deployment path: {path}") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise FinalizerDeploymentError(f"could not complete deployment file: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def install_finalizer_deployment(root: str, public_key_path: str) -> dict[str, Any]:
    """Install the canonical workflow pair and a public-key-bound manifest.

    Installation is deterministic and no-clobber.  All target paths are
    preflighted before the first write; a later failure removes files created
    by this invocation on a best-effort basis.
    """

    repository_root = _validated_root(root)
    source = _regular_file_bytes(
        os.path.abspath(public_key_path),
        limit=MAX_PUBLIC_KEY_BYTES,
        label="Ed25519 public key",
    )
    public_key, key_id = canonical_ed25519_public_key(source)
    kit = load_finalizer_kit()
    manifest = _deployment_manifest(kit, public_key=public_key, key_id=key_id)
    payloads: list[tuple[str, bytes]] = [
        (str(entry["install_path"]), _resource_bytes(str(entry["resource"])))
        for entry in kit["templates"]
    ]
    payloads.append((str(kit["public_key_path"]), public_key))
    payloads.append((DEPLOYMENT_MANIFEST_PATH, _canonical_json(manifest)))
    for relative, _data in payloads:
        _safe_relative_path(relative, label="deployment path")
        destination = os.path.join(repository_root, *PurePosixPath(relative).parts)
        if os.path.lexists(destination):
            raise FinalizerDeploymentError(
                f"refusing to overwrite existing deployment path: {relative}"
            )

    created_files: list[str] = []
    created_directories: list[str] = []
    try:
        for relative, data in payloads:
            _ensure_parent_directories(repository_root, relative, created_directories)
            destination = os.path.join(repository_root, *PurePosixPath(relative).parts)
            _exclusive_write(destination, data)
            created_files.append(destination)
    except Exception:
        for path in reversed(created_files):
            try:
                os.unlink(path)
            except OSError:
                pass
        for path in reversed(created_directories):
            try:
                os.rmdir(path)
            except OSError:
                pass
        raise
    return {
        "format": DEPLOYMENT_FORMAT,
        "root": repository_root,
        "runtime_release": kit["runtime"]["release"],
        "written": [relative for relative, _data in payloads],
        "public_key_id": key_id,
        "github_controls_configured": False,
    }


def _read_manifest(path: str) -> tuple[dict[str, Any], bytes]:
    data = _regular_file_bytes(path, limit=MAX_MANIFEST_BYTES, label="deployment manifest")
    try:
        value = strict_json_loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise FinalizerDeploymentError(f"deployment manifest is invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise FinalizerDeploymentError("deployment manifest must be a JSON object")
    return value, data


def inspect_finalizer_deployment(root: str) -> dict[str, Any]:
    """Return a fail-closed, static-only Trusted Finalizer deployment report."""

    checks: list[dict[str, str]] = []

    def record(identifier: str, passed: bool, message: str) -> None:
        checks.append(
            {"id": identifier, "message": message, "status": "PASS" if passed else "FAIL"}
        )

    try:
        repository_root = _validated_root(root)
        record("repository-root", True, "repository root is a real non-link directory")
    except FinalizerDeploymentError as exc:
        repository_root = os.path.abspath(root)
        record("repository-root", False, str(exc))
        return _static_report(repository_root, checks)

    try:
        kit = load_finalizer_kit()
        record("packaged-kit", True, "packaged v4.5.0 templates match their manifest")
    except FinalizerDeploymentError as exc:
        record("packaged-kit", False, str(exc))
        return _static_report(repository_root, checks)

    manifest_path = os.path.join(
        repository_root, *PurePosixPath(DEPLOYMENT_MANIFEST_PATH).parts
    )
    manifest: dict[str, Any] | None = None
    manifest_bytes = b""
    try:
        manifest, manifest_bytes = _read_manifest(manifest_path)
        record("deployment-manifest", True, "deployment manifest is strict JSON")
    except FinalizerDeploymentError as exc:
        record("deployment-manifest", False, str(exc))

    public_key: bytes | None = None
    key_id = ""
    public_path = str(kit["public_key_path"])
    try:
        public_data = _regular_file_bytes(
            os.path.join(repository_root, *PurePosixPath(public_path).parts),
            limit=MAX_PUBLIC_KEY_BYTES,
            label="installed Ed25519 public key",
        )
        public_key, key_id = canonical_ed25519_public_key(public_data)
        if public_key != public_data:
            raise FinalizerDeploymentError("installed Ed25519 public key PEM is not canonical")
        record("public-key", True, f"installed Ed25519 public key is canonical ({key_id})")
    except FinalizerDeploymentError as exc:
        record("public-key", False, str(exc))

    if manifest is not None and public_key is not None:
        expected_manifest = _deployment_manifest(kit, public_key=public_key, key_id=key_id)
        exact_object = manifest == expected_manifest
        canonical = manifest_bytes == _canonical_json(manifest)
        record(
            "manifest-bindings",
            exact_object and canonical,
            "manifest exactly binds kit, runtime, workflow hashes, and public key"
            if exact_object and canonical
            else "manifest is non-canonical or does not exactly match installed kit/key",
        )
    else:
        record("manifest-bindings", False, "manifest/key unavailable for binding check")

    for entry in kit["templates"]:
        relative = str(entry["install_path"])
        try:
            observed = _regular_file_bytes(
                os.path.join(repository_root, *PurePosixPath(relative).parts),
                limit=MAX_MANIFEST_BYTES,
                label=f"installed workflow {relative}",
            )
            expected_workflow = _resource_bytes(str(entry["resource"]))
            if observed != expected_workflow or _sha256(observed) != entry["sha256"]:
                raise FinalizerDeploymentError(
                    f"installed workflow drifted from the packaged template: {relative}"
                )
            record(f"workflow:{relative}", True, "workflow exactly matches packaged template")
        except FinalizerDeploymentError as exc:
            record(f"workflow:{relative}", False, str(exc))

    _inspect_finalizer_policy(repository_root, str(kit["policy_path"]), record)
    return _static_report(repository_root, checks)


def _inspect_finalizer_policy(
    root: str,
    relative_policy: str,
    record: Callable[[str, bool, str], None],
) -> None:
    policy_path = os.path.join(root, *PurePosixPath(relative_policy).parts)
    try:
        _regular_file_bytes(policy_path, limit=MAX_MANIFEST_BYTES, label="trusted-base policy")
        policy = load_config(policy_path, required=True, out=lambda _message: None)
        record("policy-schema", True, "trusted-base policy passes strict configuration parsing")
    except (FinalizerDeploymentError, ConfigError) as exc:
        record("policy-schema", False, str(exc))
        record("policy-safety", False, "trusted-base policy is unavailable or invalid")
        record("verifier-pack", False, "verifier pack cannot be checked without valid policy")
        return

    required = {
        "blackbox": True,
        "blackbox_only": True,
        "require_report_integrity": "external_process_isolated",
    }
    problems = [
        f"{key} must equal {expected!r}"
        for key, expected in required.items()
        if policy.get(key) != expected
    ]
    isolation = policy.get("isolation")
    if isolation not in {"docker", "gvisor"}:
        problems.append("isolation must be docker or gvisor")
    if policy.get("require_candidate_isolation") != isolation:
        problems.append("require_candidate_isolation must match isolation")
    if policy.get("docker_network", "none") != "none":
        problems.append("docker_network must be none")
    if policy.get("trust_setup_on_host", False):
        problems.append("trust_setup_on_host must be false")
    image = policy.get("docker_image")
    if not isinstance(image, str) or _IMMUTABLE_IMAGE.fullmatch(image) is None:
        problems.append("docker_image must end in @sha256:<64 lowercase hex>")
    verifier_pack = policy.get("verifier_pack")
    expected_digest = policy.get("expect_verifier_pack_sha256")
    if not isinstance(verifier_pack, str) or not verifier_pack:
        problems.append("verifier_pack must be configured")
    if not isinstance(expected_digest, str) or _HEX_SHA256.fullmatch(expected_digest) is None:
        problems.append("expect_verifier_pack_sha256 must be 64 lowercase hex")
    record(
        "policy-safety",
        not problems,
        "trusted-base policy satisfies the workflow's finalizer floor"
        if not problems
        else "; ".join(problems),
    )

    if not isinstance(verifier_pack, str) or not isinstance(expected_digest, str):
        record("verifier-pack", False, "verifier pack path/digest is unavailable")
        return
    try:
        relative_pack = _safe_relative_path(verifier_pack, label="verifier_pack")
        pack_path = os.path.join(root, *PurePosixPath(relative_pack).parts)
        observed_digest = pack_digest(pack_path)
        if observed_digest != expected_digest:
            raise FinalizerDeploymentError(
                "verifier pack digest mismatch: "
                f"expected {expected_digest}, observed {observed_digest}"
            )
        record("verifier-pack", True, f"verifier pack matches {observed_digest}")
    except (FinalizerDeploymentError, PackManifestError, OSError) as exc:
        record("verifier-pack", False, str(exc))


def _static_report(root: str, checks: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "checks": checks,
        "enforcement_ready": False,
        "format": REPORT_FORMAT,
        "github_controls_checked": False,
        "required_live_controls": list(REQUIRED_LIVE_CONTROLS),
        "root": root,
        "scope": "static",
        "static_ready": bool(checks) and all(check["status"] == "PASS" for check in checks),
    }


__all__ = [
    "DEPLOYMENT_FORMAT",
    "DEPLOYMENT_MANIFEST_PATH",
    "FinalizerDeploymentError",
    "KIT_FORMAT",
    "REPORT_FORMAT",
    "REQUIRED_LIVE_CONTROLS",
    "canonical_ed25519_public_key",
    "inspect_finalizer_deployment",
    "install_finalizer_deployment",
    "load_finalizer_kit",
]
