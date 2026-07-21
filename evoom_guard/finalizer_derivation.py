"""Raw-Git bindings for the Trusted Finalizer.

The finalizer cannot treat a verdict produced by candidate execution as the
authority for its candidate, policy, or verifier-pack fingerprints. This module
derives those values from immutable Git objects only. It never checks out,
imports, or executes a candidate tree.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evoom_guard.evidence_bundle import (
    EvidenceBundleError,
    _canonical_json,
    _load_json_object,
    _read_regular_file,
    validate_evidence_context,
)
from evoom_guard.guard import (
    _effective_policy,
    effective_policy_sha256,
    serialize_candidate_blocks,
)
from evoom_guard.pack_manifest import PACK_DIGEST_FORMAT, extract_manifest, manifest_problems
from evoom_guard.policy.config import ConfigError, load_config
from evoom_guard.strict_json import strict_json_loads
from evoom_guard.verifiers.harness_policy import is_safe_relpath
from evoom_guard.verifiers.repo_verifier import COPY_IGNORE

FINALIZER_DERIVATION_FORMAT = "EVOGUARD_FINALIZER_GIT_BINDINGS_V1"
FINALIZER_DERIVATION_ROLE = "trusted-finalizer-git-bindings"
MAX_GIT_TREE_BYTES = 16 * 1024 * 1024
MAX_GIT_TREE_ENTRIES = 100_000
MAX_POLICY_BYTES = 1 * 1024 * 1024
MAX_CANDIDATE_FILE_BYTES = 1 * 1024 * 1024
MAX_PACK_FILE_BYTES = 8 * 1024 * 1024
MAX_PACK_BYTES = 32 * 1024 * 1024
MAX_BINDINGS_BYTES = 512 * 1024
MAX_GIT_STDERR_BYTES = 64 * 1024
_GIT_STREAM_CHUNK_BYTES = 64 * 1024

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_BINDING_KEYS = {
    "format",
    "source",
    "repository",
    "repository_id",
    "guard_artifact_sha256",
    "base_tree_sha",
    "head_tree_sha",
    "candidate_sha256",
    "deleted_paths",
    "policy_sha256",
    "verifier_pack_sha256",
    "verifier_pack_manifest",
    "effective_policy",
}
_SOURCE_KEYS = {
    "pull_request_number",
    "workflow_run_id",
    "workflow_run_attempt",
    "base_sha",
    "head_sha",
}


class FinalizerDerivationError(ValueError):
    """A binding could not be derived or did not match a verdict."""


@dataclass(frozen=True)
class _GitEntry:
    """One raw Git tree entry. Git trees have no explicit directory entries."""

    mode: str
    object_type: str
    object_id: str

    @property
    def regular(self) -> bool:
        return self.mode in {"100644", "100755"} and self.object_type == "blob"


@dataclass(frozen=True)
class DerivedFinalizerBindings:
    """The canonical output of raw-Git derivation before verdict comparison."""

    payload: dict[str, Any]

    @property
    def source(self) -> dict[str, Any]:
        return dict(self.payload["source"])

    @property
    def candidate_sha256(self) -> str:
        return str(self.payload["candidate_sha256"])

    @property
    def deleted_paths(self) -> tuple[str, ...]:
        return tuple(self.payload["deleted_paths"])

    @property
    def policy_sha256(self) -> str:
        return str(self.payload["policy_sha256"])

    @property
    def verifier_pack_sha256(self) -> str | None:
        value = self.payload["verifier_pack_sha256"]
        return value if isinstance(value, str) else None

    @property
    def effective_policy(self) -> dict[str, Any]:
        return dict(self.payload["effective_policy"])


def _bounded_string(value: object, *, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise FinalizerDerivationError(
            f"{label} must be a non-empty Unicode string of at most {maximum} characters"
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise FinalizerDerivationError(f"{label} must not contain an unpaired surrogate") from exc
    if any(ord(character) < 0x20 for character in value):
        raise FinalizerDerivationError(f"{label} must not contain control characters")
    return value


def _validate_source(value: Mapping[str, Any]) -> dict[str, Any]:
    source = dict(value)
    if set(source) != _SOURCE_KEYS:
        raise FinalizerDerivationError("derivation source has non-canonical keys")
    number = source.get("pull_request_number")
    if type(number) is not int or not 1 <= number <= 2_147_483_647:
        raise FinalizerDerivationError("source.pull_request_number is invalid")
    _bounded_string(source.get("workflow_run_id"), label="source.workflow_run_id", maximum=256)
    attempt = source.get("workflow_run_attempt")
    if type(attempt) is not int or not 1 <= attempt <= 2_147_483_647:
        raise FinalizerDerivationError("source.workflow_run_attempt is invalid")
    for field in ("base_sha", "head_sha"):
        item = source.get(field)
        if not isinstance(item, str) or _GIT_SHA.fullmatch(item) is None:
            raise FinalizerDerivationError(f"source.{field} must be a lowercase Git digest")
    return source


def _validate_sha256(value: object, *, label: str, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        suffix = " or null" if nullable else ""
        raise FinalizerDerivationError(f"{label} must be a lowercase SHA-256 digest{suffix}")
    return value


def _valid_git_sha(value: str, *, label: str) -> str:
    if _GIT_SHA.fullmatch(value) is None:
        raise FinalizerDerivationError(f"{label} must be a lowercase immutable Git digest")
    return value


def _git_command(
    repo: str,
    args: list[str],
    *,
    bare: bool,
    limit: int = MAX_GIT_TREE_BYTES,
) -> bytes:
    """Run one read-only Git query with bounded streaming output.

    A raw tree can be candidate-controlled.  Do not use ``capture_output`` and
    check its size afterwards: that would let a very large tree occupy memory
    in the privileged finalizer process before the stated limit takes effect.
    Both pipes are drained concurrently so a verbose error cannot deadlock the
    child or bypass a resource bound.
    """

    command = ["git", "--no-replace-objects"]
    command.extend(["--git-dir", repo] if bare else ["-C", repo])
    command.extend(args)
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
    except OSError as exc:
        raise FinalizerDerivationError(f"could not read immutable Git object: {exc}") from exc

    assert process.stdout is not None
    assert process.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    overflow: list[str] = []
    read_errors: list[OSError] = []

    def stop_child() -> None:
        try:
            process.kill()
        except OSError:
            # The process may have exited between the stream limit and kill.
            pass

    def drain(stream: Any, *, maximum: int, target: bytearray, label: str) -> None:
        try:
            while True:
                chunk = stream.read(_GIT_STREAM_CHUNK_BYTES)
                if not chunk:
                    return
                remaining = maximum + 1 - len(target)
                if remaining > 0:
                    target.extend(chunk[:remaining])
                if len(target) > maximum:
                    overflow.append(label)
                    stop_child()
        except OSError as exc:
            read_errors.append(exc)
            stop_child()

    stdout_reader = threading.Thread(
        target=drain,
        args=(process.stdout,),
        kwargs={"maximum": limit, "target": stdout, "label": "stdout"},
        daemon=True,
    )
    stderr_reader = threading.Thread(
        target=drain,
        args=(process.stderr,),
        kwargs={"maximum": MAX_GIT_STDERR_BYTES, "target": stderr, "label": "stderr"},
        daemon=True,
    )
    stdout_reader.start()
    stderr_reader.start()
    timed_out = False
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        timed_out = True
        stop_child()
        process.wait()
    stdout_reader.join()
    stderr_reader.join()

    if timed_out:
        raise FinalizerDerivationError("could not read immutable Git object: Git query timed out")
    if read_errors:
        raise FinalizerDerivationError(
            f"could not read immutable Git object: {read_errors[0]}"
        ) from read_errors[0]
    if "stdout" in overflow:
        raise FinalizerDerivationError("Git object listing exceeds the finalizer limit")
    if "stderr" in overflow:
        raise FinalizerDerivationError("Git error output exceeds the finalizer limit")
    if process.returncode != 0:
        detail = bytes(stderr).decode("utf-8", "replace")[:512].strip()
        raise FinalizerDerivationError(f"Git object lookup failed: {detail or process.returncode}")
    return bytes(stdout)


class _GitReader:
    """Read raw objects from a worktree or bare object store without checkout."""

    def __init__(self, repo: str, *, bare: bool) -> None:
        self.repo = os.path.abspath(repo)
        self.bare = bare
        if not os.path.isdir(self.repo):
            raise FinalizerDerivationError(f"Git repository directory does not exist: {repo!r}")

    def command(self, args: list[str], *, limit: int = MAX_GIT_TREE_BYTES) -> bytes:
        return _git_command(self.repo, args, bare=self.bare, limit=limit)

    def commit_tree(self, sha: str) -> str:
        _valid_git_sha(sha, label="commit")
        output = self.command(["rev-parse", "--verify", f"{sha}^{{tree}}"], limit=256)
        return _valid_git_sha(output.decode("ascii", "strict").strip(), label="derived tree")

    def tree(self, sha: str) -> dict[str, _GitEntry]:
        _valid_git_sha(sha, label="treeish")
        raw = self.command(["ls-tree", "-rz", "--full-tree", sha])
        entries: dict[str, _GitEntry] = {}
        for row in raw.split(b"\0"):
            if not row:
                continue
            try:
                metadata, raw_path = row.split(b"\t", 1)
                mode, object_type, object_id = metadata.decode("ascii", "strict").split(" ", 2)
                path = raw_path.decode("utf-8", "strict")
            except (UnicodeDecodeError, ValueError) as exc:
                raise FinalizerDerivationError(
                    "raw Git tree contains an invalid or non-UTF-8 path"
                ) from exc
            if not is_safe_relpath(path):
                raise FinalizerDerivationError(f"raw Git tree has unsafe path: {path!r}")
            if path in entries:
                raise FinalizerDerivationError(f"raw Git tree duplicates path: {path!r}")
            if len(entries) >= MAX_GIT_TREE_ENTRIES:
                raise FinalizerDerivationError("raw Git tree exceeds the entry limit")
            entries[path] = _GitEntry(mode=mode, object_type=object_type, object_id=object_id)
        return entries

    def blob(self, object_id: str, *, maximum: int, label: str) -> bytes:
        _valid_git_sha(object_id, label=f"{label} object")
        size_raw = self.command(["cat-file", "-s", object_id], limit=128)
        try:
            size = int(size_raw.decode("ascii", "strict").strip())
        except ValueError as exc:
            raise FinalizerDerivationError(f"{label} has no valid Git blob size") from exc
        if size < 0 or size > maximum:
            raise FinalizerDerivationError(f"{label} exceeds the {maximum}-byte finalizer limit")
        data = self.command(["cat-file", "blob", object_id], limit=maximum)
        if len(data) != size:
            raise FinalizerDerivationError(f"{label} changed or was truncated while reading")
        return data


def derive_raw_ref_parent_pair(
    *,
    repository: str,
    ref: str,
    bare: bool = False,
) -> tuple[str, str, str, str]:
    """Resolve one exact ref and its single parent from raw immutable Git objects.

    This deliberately uses Git plumbing only: no checkout, no import, and no
    candidate command execution.  The returned tuple is ``(commit, tree,
    parent_commit, parent_tree)``.  A V1 caller that needs a deterministic
    before/after boundary must reject root and merge commits rather than
    silently choosing one of several parents.
    """

    if not isinstance(ref, str) or not ref.startswith("refs/") or "\x00" in ref:
        raise FinalizerDerivationError("raw Git ref must be a canonical refs/* name")
    reader = _GitReader(repository, bare=bare)
    raw_commit = reader.command(["rev-parse", "--verify", f"{ref}^{{commit}}"], limit=256)
    commit = _valid_git_sha(raw_commit.decode("ascii", "strict").strip(), label="derived ref")
    raw_parents = reader.command(["rev-list", "--parents", "-n", "1", commit], limit=512)
    try:
        parents = raw_parents.decode("ascii", "strict").strip().split()
    except UnicodeDecodeError as exc:  # pragma: no cover - defensive parity with Git reader
        raise FinalizerDerivationError("raw Git parent listing is not ASCII") from exc
    if len(parents) != 2 or parents[0] != commit:
        raise FinalizerDerivationError(
            "V1 protected-release source must be a non-merge commit with exactly one parent"
        )
    parent = _valid_git_sha(parents[1], label="derived parent commit")
    return commit, reader.commit_tree(commit), parent, reader.commit_tree(parent)


def derive_raw_evaluation_bindings(
    *,
    base_repo: str,
    head_repo: str,
    base_sha: str,
    head_sha: str,
    base_tree_sha: str,
    head_tree_sha: str,
    base_is_bare: bool = False,
    head_is_bare: bool = False,
) -> dict[str, Any]:
    """Derive candidate, policy, and verifier-pack values from raw Git only.

    This is intentionally source-shape agnostic.  The PR finalizer and the
    release-source finalizer share the exact immutable-object calculation but
    retain separate public source and evidence contracts.
    """

    for label, value in (
        ("base_sha", base_sha),
        ("head_sha", head_sha),
        ("base_tree_sha", base_tree_sha),
        ("head_tree_sha", head_tree_sha),
    ):
        _valid_git_sha(value, label=label)
    base = _GitReader(base_repo, bare=base_is_bare)
    head = _GitReader(head_repo, bare=head_is_bare)
    if base.commit_tree(base_sha) != base_tree_sha or head.commit_tree(head_sha) != head_tree_sha:
        raise FinalizerDerivationError("provided commit/tree binding is not immutable Git reality")

    base_entries = base.tree(base_sha)
    head_entries = head.tree(head_sha)
    policy_entry = base_entries.get(".evoguard.json")
    if policy_entry is None or not policy_entry.regular:
        raise FinalizerDerivationError("trusted finalizer requires a regular base .evoguard.json")
    policy_bytes = base.blob(
        policy_entry.object_id,
        maximum=MAX_POLICY_BYTES,
        label="base .evoguard.json",
    )
    head_package = head_entries.get("package.json")
    policy, pack_path, pack_pin = _effective_policy_from_raw_config(
        policy_bytes,
        head_has_package_json=head_package is not None and head_package.regular,
    )
    pack_digest: str | None = None
    pack_manifest: dict[str, Any] | None = None
    if pack_path is not None:
        pack_digest, pack_manifest = _raw_pack_identity(base, base_sha, pack_path)
        if pack_pin is None:
            raise FinalizerDerivationError(
                "trusted finalizer requires expect_verifier_pack_sha256 with verifier_pack"
            )
        if pack_digest != pack_pin:
            raise FinalizerDerivationError(
                "base verifier-pack digest does not match its immutable policy pin"
            )
    elif pack_pin is not None:
        raise FinalizerDerivationError("base policy pins a verifier pack without verifier_pack")
    candidate = serialize_candidate_blocks(
        _candidate_blocks(base, head, base_sha=base_sha, head_sha=head_sha)
    )
    return {
        "candidate_sha256": hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        "deleted_paths": _deleted_paths(base_entries, head_entries),
        "policy_sha256": effective_policy_sha256(policy),
        "verifier_pack_sha256": pack_digest,
        "verifier_pack_manifest": pack_manifest,
        "effective_policy": policy,
    }


def _ignored_path(path: str) -> bool:
    ignored = set(COPY_IGNORE) | {".git"}
    return any(part in ignored for part in path.split("/"))


def _candidate_blocks(
    base: _GitReader,
    head: _GitReader,
    *,
    base_sha: str,
    head_sha: str,
) -> dict[str, str]:
    base_tree = {
        path: entry for path, entry in base.tree(base_sha).items() if not _ignored_path(path)
    }
    head_tree = {
        path: entry for path, entry in head.tree(head_sha).items() if not _ignored_path(path)
    }
    blocks: dict[str, str] = {}
    problems: list[str] = []
    for path in sorted(head_tree):
        candidate = head_tree[path]
        original = base_tree.get(path)
        unchanged = original is not None and (
            original.mode == candidate.mode
            and original.object_type == candidate.object_type
            and original.object_id == candidate.object_id
        )
        if unchanged:
            continue
        if original is not None and original.mode != candidate.mode:
            problems.append(f"{path}: path mode changed")
            continue
        if original is not None and original.object_type != candidate.object_type:
            problems.append(f"{path}: path type changed")
            continue
        if not candidate.regular:
            problems.append(f"{path}: path is not a regular file")
            continue
        try:
            data = head.blob(
                candidate.object_id,
                maximum=MAX_CANDIDATE_FILE_BYTES,
                label=f"candidate path {path!r}",
            )
            blocks[path] = data.decode("utf-8", "strict")
        except UnicodeDecodeError:
            problems.append(f"{path}: changed file is not valid UTF-8 text")
        except FinalizerDerivationError as exc:
            problems.append(f"{path}: {exc}")
    if problems:
        raise FinalizerDerivationError(
            "changed raw Git paths cannot be represented by Guard: " + "; ".join(problems)
        )
    return blocks


def _tree_paths_with_directories(entries: Mapping[str, _GitEntry]) -> set[str]:
    """Reconstruct the tracked paths a clean checkout exposes to Guard.

    A recursive Git tree listing contains leaf entries, while Guard also sees
    ordinary parent directories created for those entries. Empty directories
    are not representable in Git, so this is the exact relevant set for a
    clean base/head checkout.
    """

    paths: set[str] = set()
    for path in entries:
        if _ignored_path(path):
            continue
        paths.add(path)
        pieces = path.split("/")
        paths.update("/".join(pieces[:index]) for index in range(1, len(pieces)))
    return paths


def _deleted_paths(
    base_entries: Mapping[str, _GitEntry],
    head_entries: Mapping[str, _GitEntry],
) -> list[str]:
    """Derive the deletion list that Guard receives for a base/head checkout."""

    return sorted(
        _tree_paths_with_directories(base_entries) - _tree_paths_with_directories(head_entries)
    )


def _parse_pack_manifest(data: bytes) -> dict[str, Any] | None:
    try:
        decoded = strict_json_loads(data.decode("utf-8", "strict"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise FinalizerDerivationError(f"raw Git pack.json is invalid JSON: {exc}") from exc
    problems = manifest_problems(decoded)
    if problems:
        raise FinalizerDerivationError("raw Git pack.json is invalid: " + "; ".join(problems))
    assert isinstance(decoded, dict)
    return extract_manifest(decoded)


def _framed_path(digest: Any, kind: bytes, path: str) -> None:
    encoded = path.encode("utf-8")
    digest.update(kind)
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)


def _raw_pack_identity(
    reader: _GitReader,
    tree_sha: str,
    pack_path: str,
) -> tuple[str, dict[str, Any] | None]:
    if not is_safe_relpath(pack_path):
        raise FinalizerDerivationError("verifier_pack must be a safe relative base-tree path")
    prefix = pack_path.rstrip("/") + "/"
    tree = reader.tree(tree_sha)
    members = {
        path[len(prefix) :]: entry for path, entry in tree.items() if path.startswith(prefix)
    }
    if not members:
        raise FinalizerDerivationError("verifier_pack is absent from the immutable base tree")
    if any(not rel or not is_safe_relpath(rel) for rel in members):
        raise FinalizerDerivationError("verifier_pack contains an unsafe raw Git path")
    if any(not entry.regular for entry in members.values()):
        raise FinalizerDerivationError(
            "verifier_pack contains a symlink, submodule, or special path"
        )
    directories: set[str] = set()
    for rel in members:
        parts = rel.split("/")
        directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    digest = hashlib.sha256()
    digest.update(PACK_DIGEST_FORMAT.encode("ascii") + b"\0")
    for directory in sorted(directories):
        _framed_path(digest, b"D", directory)
    total = 0
    manifest: dict[str, Any] | None = None
    has_test = False
    for rel in sorted(members):
        data = reader.blob(
            members[rel].object_id,
            maximum=MAX_PACK_FILE_BYTES,
            label=f"verifier-pack path {rel!r}",
        )
        total += len(data)
        if total > MAX_PACK_BYTES:
            raise FinalizerDerivationError("verifier_pack exceeds the total finalizer limit")
        _framed_path(digest, b"F", rel)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
        if os.path.basename(rel).startswith("test_") and rel.endswith(".py"):
            has_test = True
        if rel == "pack.json":
            manifest = _parse_pack_manifest(data)
    if not has_test:
        raise FinalizerDerivationError("verifier_pack contains no test_*.py file")
    return digest.hexdigest(), manifest


def _effective_policy_from_raw_config(
    policy_bytes: bytes,
    *,
    head_has_package_json: bool,
) -> tuple[dict[str, Any], str | None, str | None]:
    """Reuse Guard strict configuration validation for the finalizer profile."""

    if len(policy_bytes) > MAX_POLICY_BYTES:
        raise FinalizerDerivationError("base .evoguard.json exceeds the finalizer limit")
    try:
        policy_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise FinalizerDerivationError("base .evoguard.json is not UTF-8") from exc
    with tempfile.TemporaryDirectory(prefix=".evoguard-finalizer-policy-") as directory:
        policy_path = os.path.join(directory, ".evoguard.json")
        Path(policy_path).write_bytes(policy_bytes)
        try:
            cfg = load_config(policy_path, required=True, out=lambda _message: None)
        except ConfigError as exc:
            raise FinalizerDerivationError(f"base .evoguard.json is invalid: {exc}") from exc

    def policy_bool(key: str) -> bool:
        value = cfg.get(key)
        return value if isinstance(value, bool) else False

    def policy_int(key: str) -> int | None:
        value = cfg.get(key)
        return value if type(value) is int else None

    def policy_str(key: str) -> str | None:
        value = cfg.get(key)
        return value if isinstance(value, str) else None

    def policy_float(key: str) -> float | None:
        value = cfg.get(key)
        return value if isinstance(value, float) else None

    raw_command = cfg.get("test_command")
    if isinstance(raw_command, str):
        shell_operators = ("&&", "||", ";", "|", ">", "<", "$(", chr(96))
        test_command: list[str] | None = (
            ["sh", "-c", raw_command]
            if any(operator in raw_command for operator in shell_operators)
            else raw_command.split()
        )
    elif isinstance(raw_command, list):
        test_command = [str(item) for item in raw_command]
    else:
        test_command = None
    setup_raw = cfg.get("setup_command")
    setup_command = [str(item) for item in setup_raw] if isinstance(setup_raw, list) else None
    protected_raw = cfg.get("protected")
    protected = (
        tuple(str(item) for item in protected_raw) if isinstance(protected_raw, list) else ()
    )
    allow_raw = cfg.get("allow")
    allow = tuple(str(item) for item in allow_raw) if isinstance(allow_raw, list) else ()
    setup_globs_raw = cfg.get("setup_output_globs")
    setup_globs = (
        tuple(str(item) for item in setup_globs_raw) if isinstance(setup_globs_raw, list) else ()
    )
    timeout = policy_int("timeout") or 120
    configured_mem_limit = policy_int("mem_limit")
    mem_limit = configured_mem_limit if configured_mem_limit is not None else 1024
    if mem_limit == 1024 and head_has_package_json:
        if "mem_limit" not in cfg:
            raise FinalizerDerivationError(
                "trusted finalizer requires an explicit base-policy mem_limit for a Node project"
            )
        mem_limit = 0
    isolation = policy_str("isolation") or "subprocess"
    docker_image = policy_str("docker_image")
    docker_network = policy_str("docker_network") or "none"
    if isolation in {"docker", "gvisor"} and not docker_image:
        raise FinalizerDerivationError(f"base policy {isolation!r} requires docker_image")
    pack = policy_str("verifier_pack")
    pack_pin = policy_str("expect_verifier_pack_sha256")
    policy = _effective_policy(
        mode="blackbox" if policy_bool("blackbox") else "repo",
        isolation=isolation,
        docker_image=docker_image,
        docker_network=docker_network,
        test_command=test_command,
        setup_command=setup_command,
        trust_setup_on_host=policy_bool("trust_setup_on_host"),
        setup_output_globs=setup_globs,
        protected=protected,
        allow=allow,
        allow_new_tests=policy_bool("allow_new_tests"),
        timeout=timeout,
        mem_limit_mb=mem_limit,
        verifier_pack=pack,
        expect_verifier_pack_sha256=pack_pin,
        blackbox=policy_bool("blackbox"),
        blackbox_only=policy_bool("blackbox_only"),
        require_report_integrity=policy_str("require_report_integrity"),
        require_candidate_isolation=policy_str("require_candidate_isolation"),
        min_diff_coverage=policy_float("min_diff_coverage"),
        baseline_evidence=policy_bool("baseline_evidence"),
        require_demonstrated_fix=policy_bool("require_demonstrated_fix"),
        strict_harness=policy_bool("strict_harness"),
        policy_id=policy_str("policy_id"),
        policy_version=policy_str("policy_version"),
    )
    return policy, pack, pack_pin


def derive_finalizer_bindings(
    *,
    base_repo: str,
    head_repo: str,
    base_sha: str,
    head_sha: str,
    base_tree_sha: str,
    head_tree_sha: str,
    source: Mapping[str, Any],
    repository: str,
    repository_id: str,
    guard_artifact_sha256: str,
    base_is_bare: bool = False,
    head_is_bare: bool = False,
) -> DerivedFinalizerBindings:
    """Derive candidate, policy, and pack bindings from raw immutable Git objects."""

    verified_source = _validate_source(source)
    for label, value in (
        ("base_sha", base_sha),
        ("head_sha", head_sha),
        ("base_tree_sha", base_tree_sha),
        ("head_tree_sha", head_tree_sha),
    ):
        _valid_git_sha(value, label=label)
    if verified_source["base_sha"] != base_sha or verified_source["head_sha"] != head_sha:
        raise FinalizerDerivationError("source revision does not match derivation revision")
    _bounded_string(repository, label="repository", maximum=512)
    _bounded_string(repository_id, label="repository_id", maximum=256)
    _validate_sha256(guard_artifact_sha256, label="guard_artifact_sha256")
    raw = derive_raw_evaluation_bindings(
        base_repo=base_repo,
        head_repo=head_repo,
        base_sha=base_sha,
        head_sha=head_sha,
        base_tree_sha=base_tree_sha,
        head_tree_sha=head_tree_sha,
        base_is_bare=base_is_bare,
        head_is_bare=head_is_bare,
    )
    payload = {
        "format": FINALIZER_DERIVATION_FORMAT,
        "source": verified_source,
        "repository": repository,
        "repository_id": repository_id,
        "guard_artifact_sha256": guard_artifact_sha256,
        "base_tree_sha": base_tree_sha,
        "head_tree_sha": head_tree_sha,
        "candidate_sha256": raw["candidate_sha256"],
        "deleted_paths": raw["deleted_paths"],
        "policy_sha256": raw["policy_sha256"],
        "verifier_pack_sha256": raw["verifier_pack_sha256"],
        "verifier_pack_manifest": raw["verifier_pack_manifest"],
        "effective_policy": raw["effective_policy"],
    }
    return DerivedFinalizerBindings(payload=_validate_derived_bindings(payload))


def _validate_derived_bindings(value: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(value)
    if set(payload) != _BINDING_KEYS:
        raise FinalizerDerivationError("derived bindings have non-canonical keys")
    if payload.get("format") != FINALIZER_DERIVATION_FORMAT:
        raise FinalizerDerivationError("derived bindings have an unsupported format")
    source = payload.get("source")
    if not isinstance(source, dict):
        raise FinalizerDerivationError("derived bindings source must be an object")
    payload["source"] = _validate_source(source)
    _bounded_string(payload.get("repository"), label="repository", maximum=512)
    _bounded_string(payload.get("repository_id"), label="repository_id", maximum=256)
    _validate_sha256(payload.get("guard_artifact_sha256"), label="guard_artifact_sha256")
    for field in ("base_tree_sha", "head_tree_sha"):
        item = payload.get(field)
        if not isinstance(item, str) or _GIT_SHA.fullmatch(item) is None:
            raise FinalizerDerivationError(f"derived bindings {field} is invalid")
    _validate_sha256(payload.get("candidate_sha256"), label="candidate_sha256")
    deleted = payload.get("deleted_paths")
    if not isinstance(deleted, list) or any(
        not isinstance(path, str) or not is_safe_relpath(path) for path in deleted
    ):
        raise FinalizerDerivationError("derived bindings deleted_paths must be safe relative paths")
    if deleted != sorted(set(deleted)):
        raise FinalizerDerivationError("derived bindings deleted_paths must be sorted and unique")
    _validate_sha256(payload.get("policy_sha256"), label="policy_sha256")
    _validate_sha256(
        payload.get("verifier_pack_sha256"),
        label="verifier_pack_sha256",
        nullable=True,
    )
    policy = payload.get("effective_policy")
    if not isinstance(policy, dict):
        raise FinalizerDerivationError("derived bindings effective_policy must be an object")
    if effective_policy_sha256(policy) != payload["policy_sha256"]:
        raise FinalizerDerivationError("derived bindings policy digest is inconsistent")
    manifest = payload.get("verifier_pack_manifest")
    if manifest is not None:
        if not isinstance(manifest, dict):
            raise FinalizerDerivationError(
                "derived verifier-pack manifest must be an object or null"
            )
        problems = manifest_problems(manifest)
        if problems or extract_manifest(manifest) != manifest:
            raise FinalizerDerivationError("derived verifier-pack manifest is invalid")
    if payload["verifier_pack_sha256"] is None and manifest is not None:
        raise FinalizerDerivationError("a null verifier-pack digest cannot have a manifest")
    return payload


def validate_finalizer_bindings(value: Mapping[str, Any]) -> DerivedFinalizerBindings:
    """Validate an in-memory raw-Git derivation record."""

    return DerivedFinalizerBindings(payload=_validate_derived_bindings(value))


def read_finalizer_bindings(path: str) -> DerivedFinalizerBindings:
    """Read a canonical bindings file without treating it as a trust root."""

    try:
        data = _read_regular_file(path, limit=MAX_BINDINGS_BYTES, label="finalizer bindings")
        payload = _load_json_object(data, "finalizer bindings")
    except EvidenceBundleError as exc:
        raise FinalizerDerivationError(str(exc)) from exc
    if _canonical_json(payload) != data:
        raise FinalizerDerivationError("finalizer bindings are not canonical JSON")
    return validate_finalizer_bindings(payload)


def _write_canonical(path: str, payload: dict[str, Any], *, force: bool) -> str:
    absolute = os.path.abspath(path)
    if os.path.isdir(absolute):
        raise FinalizerDerivationError(f"output is a directory: {absolute}")
    data = _canonical_json(payload)
    parent = os.path.dirname(absolute) or os.curdir
    os.makedirs(parent, exist_ok=True)
    try:
        with open(absolute, "wb" if force else "xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise FinalizerDerivationError(
            f"refusing to overwrite existing output: {absolute}"
        ) from exc
    os.chmod(absolute, 0o644)
    return absolute


def write_finalizer_bindings(
    bindings: DerivedFinalizerBindings,
    *,
    bindings_path: str,
    force: bool = False,
) -> str:
    """Write the canonical raw-Git derivation record."""

    return _write_canonical(bindings_path, bindings.payload, force=force)


def _attestation(record: Mapping[str, Any]) -> Mapping[str, Any]:
    attestation = record.get("attestation")
    if not isinstance(attestation, dict):
        raise FinalizerDerivationError("verdict record has no attestation")
    return attestation


def context_from_verified_bindings(
    bindings: DerivedFinalizerBindings,
    record: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate raw-Git values, then form the existing source/context pair.

    A null verifier-pack value remains valid for a static Guard denial. A record
    that claims a pack result must match the independently derived base-tree
    pack digest and manifest exactly.
    """

    attestation = _attestation(record)
    if attestation.get("candidate_sha256") != bindings.candidate_sha256:
        raise FinalizerDerivationError("record candidate digest differs from raw-Git derivation")
    if attestation.get("deleted_paths") != list(bindings.deleted_paths):
        raise FinalizerDerivationError("record deleted paths differ from raw-Git derivation")
    if attestation.get("policy_sha256") != bindings.policy_sha256:
        raise FinalizerDerivationError("record policy digest differs from raw-Git derivation")
    if attestation.get("effective_policy") != bindings.effective_policy:
        raise FinalizerDerivationError("record effective policy differs from raw-Git derivation")
    record_pack = attestation.get("verifier_pack_sha256")
    if record_pack is not None and record_pack != bindings.verifier_pack_sha256:
        raise FinalizerDerivationError(
            "record verifier-pack digest differs from raw-Git derivation"
        )
    expected_manifest = (
        bindings.payload["verifier_pack_manifest"] if record_pack is not None else None
    )
    if attestation.get("verifier_pack_manifest") != expected_manifest:
        raise FinalizerDerivationError(
            "record verifier-pack manifest differs from raw-Git derivation"
        )
    for field in ("base_sha", "head_sha", "base_tree_sha", "head_tree_sha"):
        expected = (
            bindings.source[field] if field in {"base_sha", "head_sha"} else bindings.payload[field]
        )
        observed = attestation.get(field)
        if observed is not None and observed != expected:
            raise FinalizerDerivationError(f"record {field} differs from raw-Git derivation")
    source = bindings.source
    context = {
        "repository": bindings.payload["repository"],
        "repository_id": bindings.payload["repository_id"],
        "run_id": source["workflow_run_id"],
        "run_attempt": source["workflow_run_attempt"],
        "base_sha": source["base_sha"],
        "head_sha": source["head_sha"],
        "base_tree_sha": bindings.payload["base_tree_sha"],
        "head_tree_sha": bindings.payload["head_tree_sha"],
        "candidate_sha256": bindings.candidate_sha256,
        "policy_sha256": bindings.policy_sha256,
        "verifier_pack_sha256": record_pack,
        "guard_artifact_sha256": bindings.payload["guard_artifact_sha256"],
    }
    try:
        return source, validate_evidence_context(context, verdict=dict(record))
    except EvidenceBundleError as exc:
        raise FinalizerDerivationError(f"derived context does not bind verdict: {exc}") from exc


def write_verified_finalizer_context(
    bindings: DerivedFinalizerBindings,
    record: Mapping[str, Any],
    *,
    source_path: str,
    context_path: str,
    force: bool = False,
) -> tuple[str, str]:
    """Write source/context only after verdict values passed raw-Git comparison."""

    source, context = context_from_verified_bindings(bindings, record)
    source_out = _write_canonical(source_path, source, force=force)
    try:
        context_out = _write_canonical(context_path, context, force=force)
    except BaseException:
        try:
            os.unlink(source_out)
        except OSError:
            pass
        raise
    return source_out, context_out
