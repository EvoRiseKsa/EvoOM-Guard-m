# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Fail-closed verification of signed release commit and tag Git objects.

The verifier deliberately has no GitHub API dependency.  Its signer authority is
the public key pinned by a parent-owned release-maintainer root.  GitHub's
``verified`` status is useful additional control-plane evidence, but an author
login or REST response is never treated as cryptographic signer proof here.

Only the Python standard library is used.  Cryptographic verification is
delegated to ``git verify-commit`` / ``git verify-tag`` in a newly-created bare
repository whose global and system configuration and trust stores are disabled.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

ROOT_FORMAT = "EVOGUARD_RELEASE_MAINTAINER_SIGNING_ROOT_V1"
RECEIPT_FORMAT = "EVOGUARD_RELEASE_GIT_OBJECT_VERIFICATION_V1"
SSH_PRINCIPAL = "evoguard-release-maintainer"
COMMIT_MAX_BYTES = 262_144
TAG_MAX_BYTES = 32_768
ROOT_MAX_BYTES = 16_384
PUBLIC_KEY_MAX_BYTES = 65_536
COMMAND_OUTPUT_MAX_BYTES = 262_144
COMMAND_TIMEOUT_SECONDS = 30

_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
_OPENPGP_FINGERPRINT = re.compile(r"(?:[0-9A-F]{40}|[0-9A-F]{64})")
_TAG_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")
_GITHUB_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_HEADER_NAME = re.compile(rb"[a-z][a-z0-9-]*")
_SSH_KEY_TYPES = {
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
}


class VerificationError(ValueError):
    """A release Git object or its trust binding is invalid."""


@dataclass(frozen=True)
class Header:
    name: str
    value: bytes


@dataclass(frozen=True)
class Identity:
    identity: str
    name: str
    email: str
    timestamp: int
    timezone: str


@dataclass(frozen=True)
class CommitObject:
    object_id: str
    tree: str
    parent: str
    author: Identity
    committer: Identity
    encoding: str
    message: str
    signature_format: str


@dataclass(frozen=True)
class TagObject:
    object_id: str
    target: str
    tag: str
    tagger: Identity
    encoding: str
    message: str
    message_sha256: str
    signature_format: str


@dataclass(frozen=True)
class SigningRoot:
    root_path: Path
    root_sha256: str
    version: str
    github_login: str
    github_user_id: int
    key_type: str
    public_key_path: str
    public_key_sha256: str
    public_key_fingerprint: str
    public_key_bytes: bytes
    signature_namespace: str


def _fail(message: str) -> NoReturn:
    raise VerificationError(message)


def _read_regular_file(path: Path, *, maximum: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        _fail(f"{label} cannot be inspected: {exc}")
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        _fail(f"{label} must be a regular non-symlink file")
    if metadata.st_size > maximum:
        _fail(f"{label} exceeds the {maximum}-byte limit")
    try:
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
    except OSError as exc:
        _fail(f"{label} cannot be read: {exc}")
    if len(data) > maximum:
        _fail(f"{label} exceeds the {maximum}-byte limit")
    return data


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"signing root repeats JSON member {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    _fail(f"signing root contains forbidden JSON constant {value!r}")


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        _fail(f"{label} must be a non-empty canonical string")
    return value


def _safe_repository_path(value: Any, label: str) -> str:
    text = _string(value, label)
    if "\\" in text:
        _fail(f"{label} must use POSIX separators")
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or text != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        _fail(f"{label} must be a normalized repository-relative path")
    return path.as_posix()


def _canonical_sha256(value: Any, label: str) -> str:
    text = _string(value, label)
    if _HEX_SHA256.fullmatch(text) is None:
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return text


def _ascii(raw: bytes, label: str) -> str:
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        _fail(f"{label} must be ASCII")


def _ssh_public_key(raw: bytes, expected_type: str) -> tuple[str, str, str]:
    if b"\x00" in raw or b"\r" in raw:
        _fail("maintainer SSH public key contains forbidden bytes")
    text = _ascii(raw, "maintainer SSH public key")
    if not text.endswith("\n") or text.count("\n") != 1:
        _fail("maintainer SSH public key must contain exactly one LF-terminated line")
    line = text[:-1]
    if line.strip() != line:
        _fail("maintainer SSH public key has non-canonical surrounding whitespace")
    fields = line.split(" ")
    if len(fields) < 2 or any(not item for item in fields[:2]):
        _fail("maintainer SSH public key is malformed")
    key_type, encoded = fields[:2]
    if key_type != expected_type or key_type not in _SSH_KEY_TYPES:
        _fail("maintainer SSH public-key type does not match the signing root")
    try:
        blob = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        _fail("maintainer SSH public key has invalid base64")
    if not blob:
        _fail("maintainer SSH public key blob is empty")
    fingerprint_payload = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")
    fingerprint = "SHA256:" + fingerprint_payload.rstrip("=")
    return key_type, encoded, fingerprint


def load_signing_root(path: Path) -> SigningRoot:
    raw = _read_regular_file(path, maximum=ROOT_MAX_BYTES, label="signing root")
    if b"\x00" in raw or b"\r" in raw or not raw.endswith(b"\n"):
        _fail("signing root must be NUL-free LF-terminated UTF-8 JSON")
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"signing root is not strict UTF-8 JSON: {exc}")
    if not isinstance(document, dict):
        _fail("signing root must be a JSON object")
    required = {
        "format",
        "version",
        "github_login",
        "github_user_id",
        "key_type",
        "public_key_path",
        "public_key_sha256",
        "provided_source_file_sha256_crlf",
        "public_key_fingerprint",
        "signature_namespace",
        "private_key_location",
        "github_verification_required",
    }
    if set(document) != required:
        _fail("signing root member inventory is not exact")
    if document["format"] != ROOT_FORMAT:
        _fail("signing root format is not supported")
    version = _string(document["version"], "signing root version")
    if _VERSION.fullmatch(version) is None:
        _fail("signing root version must be a stable semantic version")
    login = _string(document["github_login"], "GitHub login")
    if _GITHUB_LOGIN.fullmatch(login) is None:
        _fail("signing root GitHub login is not canonical")
    user_id = document["github_user_id"]
    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
        _fail("signing root GitHub user id must be a positive integer")
    key_type = _string(document["key_type"], "public-key type")
    if key_type not in _SSH_KEY_TYPES and key_type != "openpgp":
        _fail("signing root public-key type is unsupported")
    public_key_path = _safe_repository_path(document["public_key_path"], "public-key path")
    expected_path = f"security/release-maintainer-roots/v{version}.pub"
    if public_key_path != expected_path:
        _fail("signing root public-key path is not version-bound and exact")
    public_key_sha256 = _canonical_sha256(
        document["public_key_sha256"], "public-key SHA-256"
    )
    _canonical_sha256(
        document["provided_source_file_sha256_crlf"], "provided CRLF source SHA-256"
    )
    fingerprint = _string(document["public_key_fingerprint"], "public-key fingerprint")
    if document["signature_namespace"] != "git":
        _fail("signing root signature namespace must be 'git'")
    if document["private_key_location"] != "OUTSIDE_REPOSITORY_AND_GITHUB_ACTIONS":
        _fail("signing root does not keep the private key outside repository and Actions")
    if document["github_verification_required"] is not True:
        _fail("signing root must require separate GitHub verification")

    # The root and key are deliberately required to be siblings.  The repository
    # path remains authoritative, while this avoids guessing a checkout root when
    # the object repository passed to the CLI is bare.
    key_name = PurePosixPath(public_key_path).name
    key_path = path.parent / key_name
    if key_path.parent.resolve() != path.parent.resolve():
        _fail("public key escaped the signing-root directory")
    key_raw = _read_regular_file(
        key_path, maximum=PUBLIC_KEY_MAX_BYTES, label="maintainer public key"
    )
    actual_digest = hashlib.sha256(key_raw).hexdigest()
    if actual_digest != public_key_sha256:
        _fail("maintainer public-key bytes do not match the pinned SHA-256")

    if key_type in _SSH_KEY_TYPES:
        _, _, actual_fingerprint = _ssh_public_key(key_raw, key_type)
        if fingerprint != actual_fingerprint:
            _fail("maintainer SSH public-key fingerprint does not match the pinned value")
    else:
        if _OPENPGP_FINGERPRINT.fullmatch(fingerprint) is None:
            _fail("maintainer OpenPGP fingerprint is not canonical")

    return SigningRoot(
        root_path=path.resolve(),
        root_sha256=hashlib.sha256(raw).hexdigest(),
        version=version,
        github_login=login,
        github_user_id=user_id,
        key_type=key_type,
        public_key_path=public_key_path,
        public_key_sha256=public_key_sha256,
        public_key_fingerprint=fingerprint,
        public_key_bytes=key_raw,
        signature_namespace="git",
    )


def _object_hex(value: str, object_format: str, label: str) -> str:
    if object_format not in {"sha1", "sha256"}:
        _fail("Git object format must be sha1 or sha256")
    expected_length = 40 if object_format == "sha1" else 64
    if len(value) != expected_length or re.fullmatch(r"[0-9a-f]+", value) is None:
        _fail(f"{label} is not a canonical {object_format} object id")
    return value


def _git_object_id(kind: str, raw: bytes, object_format: str) -> str:
    if object_format not in {"sha1", "sha256"}:
        _fail("Git object format must be sha1 or sha256")
    digest = hashlib.new(object_format)
    digest.update(f"{kind} {len(raw)}\0".encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _split_headers(raw: bytes, *, multiline: frozenset[str]) -> tuple[list[Header], bytes]:
    if b"\x00" in raw or b"\r" in raw:
        _fail("Git object contains forbidden NUL or CR bytes")
    separator = raw.find(b"\n\n")
    if separator <= 0:
        _fail("Git object has no canonical header/message separator")
    header_block = raw[:separator]
    body = raw[separator + 2 :]
    headers: list[Header] = []
    names: list[str] = []
    values: list[list[bytes]] = []
    for line in header_block.split(b"\n"):
        if line.startswith(b" "):
            if not names or names[-1] not in multiline:
                _fail("Git object has an illegal continued header")
            values[-1].append(line[1:])
            continue
        if line.startswith(b"\t") or b" " not in line:
            _fail("Git object has a malformed header line")
        raw_name, value = line.split(b" ", 1)
        if _HEADER_NAME.fullmatch(raw_name) is None or not value:
            _fail("Git object has a non-canonical header")
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError:
            _fail("Git object header name must be ASCII")
        names.append(name)
        values.append([value])
    for name, parts in zip(names, values, strict=True):
        headers.append(Header(name=name, value=b"\n".join(parts)))
    return headers, body


def _parse_identity(raw: bytes, label: str) -> Identity:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _fail(f"{label} identity must be UTF-8")
    match = re.fullmatch(
        r"(.+) <([^<>\s]+)> (0|[1-9][0-9]{0,11}) ([+-])([0-9]{2})([0-9]{2})",
        text,
    )
    if match is None:
        _fail(f"{label} identity is not canonical")
    name, email, epoch, sign, hours, minutes = match.groups()
    if name.strip() != name or "@" not in email:
        _fail(f"{label} identity name/email is not canonical")
    if int(hours) > 23 or int(minutes) > 59:
        _fail(f"{label} identity timezone is invalid")
    return Identity(
        identity=f"{name} <{email}>",
        name=name,
        email=email,
        timestamp=int(epoch),
        timezone=f"{sign}{hours}{minutes}",
    )


def _signature_markers(signature_format: str) -> tuple[bytes, bytes]:
    if signature_format == "ssh":
        return b"-----BEGIN SSH SIGNATURE-----", b"-----END SSH SIGNATURE-----"
    if signature_format == "openpgp":
        return b"-----BEGIN PGP SIGNATURE-----", b"-----END PGP SIGNATURE-----"
    _fail("signature format must be ssh or openpgp")


def _validate_signature_block(
    signature: bytes, *, signature_format: str, final_lf: bool
) -> None:
    begin, end = _signature_markers(signature_format)
    if b"\x00" in signature or b"\r" in signature:
        _fail("signature armor contains forbidden bytes")
    try:
        signature.decode("ascii")
    except UnicodeDecodeError:
        _fail("signature armor must be ASCII")
    expected_end = end + (b"\n" if final_lf else b"")
    if not signature.startswith(begin + b"\n") or not signature.endswith(expected_end):
        _fail("signature armor boundaries are not canonical")
    if signature.count(begin) != 1 or signature.count(end) != 1:
        _fail("Git object must contain exactly one signature armor block")
    lines = signature.splitlines()
    if len(lines) < 3 or any(len(line) > 4096 for line in lines):
        _fail("signature armor has an invalid line inventory")


def parse_commit(
    raw: bytes,
    *,
    object_format: str,
    expected_object: str,
    expected_parent: str,
    signature_format: str,
) -> CommitObject:
    if len(raw) > COMMIT_MAX_BYTES:
        _fail(f"commit object exceeds the {COMMIT_MAX_BYTES}-byte limit")
    expected_object = _object_hex(expected_object, object_format, "expected commit")
    expected_parent = _object_hex(expected_parent, object_format, "expected parent")
    actual_object = _git_object_id("commit", raw, object_format)
    if actual_object != expected_object:
        _fail("raw commit bytes do not match the expected object id")
    headers, message_raw = _split_headers(raw, multiline=frozenset({"gpgsig"}))
    names = [header.name for header in headers]
    permitted = [
        ["tree", "parent", "author", "committer", "gpgsig"],
        ["tree", "parent", "author", "committer", "encoding", "gpgsig"],
    ]
    if names not in permitted:
        _fail("signed release commit header inventory/order is not exact")
    values = {header.name: header.value for header in headers}
    tree = _object_hex(_ascii(values["tree"], "commit tree"), object_format, "commit tree")
    parent = _object_hex(
        _ascii(values["parent"], "commit parent"), object_format, "commit parent"
    )
    if parent != expected_parent:
        _fail("signed release commit is not bound to the expected sole parent")
    encoding = values.get("encoding", b"UTF-8")
    if encoding != b"UTF-8":
        _fail("signed release commit encoding must be UTF-8")
    signature = values["gpgsig"]
    _validate_signature_block(signature, signature_format=signature_format, final_lf=False)
    if not message_raw or not message_raw.endswith(b"\n"):
        _fail("signed release commit message must be non-empty and LF-terminated")
    try:
        message = message_raw.decode("utf-8")
    except UnicodeDecodeError:
        _fail("signed release commit message must be UTF-8")
    return CommitObject(
        object_id=actual_object,
        tree=tree,
        parent=parent,
        author=_parse_identity(values["author"], "commit author"),
        committer=_parse_identity(values["committer"], "commit committer"),
        encoding="UTF-8",
        message=message,
        signature_format=signature_format,
    )


def parse_tag(
    raw: bytes,
    *,
    object_format: str,
    expected_object: str,
    expected_target: str,
    expected_tag: str,
    signature_format: str,
) -> TagObject:
    if len(raw) > TAG_MAX_BYTES:
        _fail(f"tag object exceeds the {TAG_MAX_BYTES}-byte limit")
    expected_object = _object_hex(expected_object, object_format, "expected tag object")
    expected_target = _object_hex(expected_target, object_format, "expected tag target")
    if _TAG_NAME.fullmatch(expected_tag) is None:
        _fail("expected tag name is not canonical")
    actual_object = _git_object_id("tag", raw, object_format)
    if actual_object != expected_object:
        _fail("raw tag bytes do not match the expected tag object id")
    headers, body = _split_headers(raw, multiline=frozenset())
    names = [header.name for header in headers]
    if names not in (
        ["object", "type", "tag", "tagger"],
        ["object", "type", "tag", "tagger", "encoding"],
    ):
        _fail("signed annotated tag header inventory/order is not exact")
    values = {header.name: header.value for header in headers}
    target = _object_hex(_ascii(values["object"], "tag target"), object_format, "tag target")
    if target != expected_target:
        _fail("signed annotated tag is not bound to the expected target commit")
    if values["type"] != b"commit":
        _fail("signed annotated tag target type must be commit")
    tag_name = _ascii(values["tag"], "signed annotated tag name")
    if tag_name != expected_tag:
        _fail("signed annotated tag name does not match the expected tag")
    encoding = values.get("encoding", b"UTF-8")
    if encoding != b"UTF-8":
        _fail("signed annotated tag encoding must be UTF-8")
    begin, _ = _signature_markers(signature_format)
    if body.count(begin) != 1:
        _fail("signed annotated tag must contain exactly one expected signature block")
    marker = body.find(begin)
    message_raw = body[:marker]
    signature = body[marker:]
    if not message_raw or not message_raw.endswith(b"\n"):
        _fail("signed annotated tag message must be non-empty and LF-terminated")
    _validate_signature_block(signature, signature_format=signature_format, final_lf=True)
    try:
        message = message_raw.decode("utf-8")
    except UnicodeDecodeError:
        _fail("signed annotated tag message must be UTF-8")
    return TagObject(
        object_id=actual_object,
        target=target,
        tag=tag_name,
        tagger=_parse_identity(values["tagger"], "tagger"),
        encoding="UTF-8",
        message=message,
        message_sha256=hashlib.sha256(message_raw).hexdigest(),
        signature_format=signature_format,
    )


def _tool(name: str) -> str:
    value = shutil.which(name)
    if value is None:
        _fail(f"required executable {name!r} is unavailable")
    resolved = Path(value).resolve()
    if not resolved.is_file():
        _fail(f"required executable {name!r} did not resolve to a regular file")
    return str(resolved)


def _isolated_environment(home: Path) -> dict[str, str]:
    # Windows OpenSSH exits silently when PROGRAMDATA is absent.  It does not
    # provide signer trust here; the generated allowed-signers file is the sole
    # trust input.
    keep = (
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "PROGRAMDATA",
        "TMP",
        "TEMP",
    )
    environment = {name: os.environ[name] for name in keep if name in os.environ}
    environment.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "GNUPGHOME": str(home / "gnupg"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    return environment


def _run(
    arguments: Sequence[str],
    *,
    environment: dict[str, str],
    input_bytes: bytes | None = None,
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            list(arguments),
            input=input_bytes,
            capture_output=True,
            check=False,
            env=environment,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _fail(f"{label} could not run: {exc}")
    if len(result.stdout) > COMMAND_OUTPUT_MAX_BYTES or len(result.stderr) > COMMAND_OUTPUT_MAX_BYTES:
        _fail(f"{label} produced excessive output")
    if result.returncode != 0:
        detail = (result.stdout + b"\n" + result.stderr).decode("utf-8", "replace").strip()
        if len(detail) > 1000:
            detail = detail[:1000] + "..."
        _fail(f"{label} failed with exit code {result.returncode}: {detail}")
    return result


def _repository_object(
    repository: Path, *, object_id: str, expected_kind: str, git_program: str
) -> tuple[bytes, str]:
    if repository.is_symlink() or not repository.is_dir():
        _fail("object repository must be a non-symlink directory")
    with tempfile.TemporaryDirectory(prefix="evoguard-source-") as home_text:
        environment = _isolated_environment(Path(home_text))
        prefix = [git_program, "-C", str(repository)]
        bare = _run(
            [*prefix, "rev-parse", "--is-bare-repository"],
            environment=environment,
            label="Git bare-repository check",
        ).stdout.strip()
        if bare != b"true":
            _fail("object repository must be bare")
        object_format_raw = _run(
            [*prefix, "rev-parse", "--show-object-format"],
            environment=environment,
            label="Git object-format query",
        ).stdout.strip()
        try:
            object_format = object_format_raw.decode("ascii")
        except UnicodeDecodeError:
            _fail("Git object format was not ASCII")
        _object_hex(object_id, object_format, "requested object")
        kind = _run(
            [*prefix, "cat-file", "-t", object_id],
            environment=environment,
            label="Git object-type query",
        ).stdout.strip()
        if kind != expected_kind.encode("ascii"):
            _fail(f"requested Git object is not a {expected_kind}")
        size_raw = _run(
            [*prefix, "cat-file", "-s", object_id],
            environment=environment,
            label="Git object-size query",
        ).stdout.strip()
        if re.fullmatch(rb"0|[1-9][0-9]*", size_raw) is None:
            _fail("Git object size is not canonical")
        size = int(size_raw)
        maximum = COMMIT_MAX_BYTES if expected_kind == "commit" else TAG_MAX_BYTES
        if size > maximum:
            _fail(f"{expected_kind} object exceeds the {maximum}-byte limit")
        raw = _run(
            [*prefix, "cat-file", expected_kind, object_id],
            environment=environment,
            label="Git raw-object read",
        ).stdout
        if len(raw) != size:
            _fail("Git raw-object byte count changed during the bounded read")
        if _git_object_id(expected_kind, raw, object_format) != object_id:
            _fail("Git repository returned bytes that do not hash to the requested object")
        return raw, object_format


def _openpgp_inventory(
    *, gpg_program: str, home: Path, environment: dict[str, str], root: SigningRoot
) -> frozenset[str]:
    gpg_home = home / "gnupg"
    gpg_home.mkdir(mode=0o700)
    key_copy = home / "maintainer-openpgp-key"
    key_copy.write_bytes(root.public_key_bytes)
    base = [gpg_program, "--batch", "--no-options", "--homedir", str(gpg_home)]
    _run([*base, "--import", str(key_copy)], environment=environment, label="OpenPGP key import")
    secret = _run(
        [*base, "--with-colons", "--list-secret-keys"],
        environment=environment,
        label="OpenPGP secret-key inventory",
    ).stdout
    if any(line.startswith((b"sec:", b"ssb:")) for line in secret.splitlines()):
        _fail("pinned OpenPGP material unexpectedly contains a private key")
    listing = _run(
        [*base, "--with-colons", "--fingerprint", "--fingerprint", "--list-keys"],
        environment=environment,
        label="OpenPGP public-key inventory",
    ).stdout
    fingerprints: list[str] = []
    primary: list[str] = []
    waiting_for_primary = False
    for line in listing.splitlines():
        fields = line.decode("utf-8", "replace").split(":")
        record = fields[0] if fields else ""
        if record == "pub":
            if len(fields) > 1 and fields[1] in {"r", "e", "d", "i"}:
                _fail("pinned OpenPGP primary key is not currently valid")
            waiting_for_primary = True
        elif record == "sub":
            if len(fields) > 1 and fields[1] in {"r", "e", "d", "i"}:
                _fail("pinned OpenPGP signing subkey is not currently valid")
            waiting_for_primary = False
        elif record == "fpr" and len(fields) > 9:
            fingerprint = fields[9].upper()
            if _OPENPGP_FINGERPRINT.fullmatch(fingerprint) is None:
                _fail("GPG returned a malformed OpenPGP fingerprint")
            fingerprints.append(fingerprint)
            if waiting_for_primary:
                primary.append(fingerprint)
                waiting_for_primary = False
    if primary != [root.public_key_fingerprint] or not fingerprints:
        _fail("isolated OpenPGP key inventory does not match the pinned root fingerprint")
    return frozenset(fingerprints)


def _verify_git_signature(
    *,
    kind: str,
    raw: bytes,
    object_format: str,
    root: SigningRoot,
    git_program: str,
) -> dict[str, str]:
    signature_format = "ssh" if root.key_type in _SSH_KEY_TYPES else "openpgp"
    with tempfile.TemporaryDirectory(prefix="evoguard-verify-") as home_text:
        home = Path(home_text)
        environment = _isolated_environment(home)
        repository = home / "objects.git"
        _run(
            [git_program, "init", "--bare", f"--object-format={object_format}", str(repository)],
            environment=environment,
            label="isolated Git repository initialization",
        )
        written = _run(
            [git_program, "-C", str(repository), "hash-object", "-w", "-t", kind, "--stdin"],
            environment=environment,
            input_bytes=raw,
            label="isolated Git object import",
        ).stdout.strip()
        expected = _git_object_id(kind, raw, object_format).encode("ascii")
        if written != expected:
            _fail("isolated Git repository changed the raw object identity")

        verify_command = "verify-commit" if kind == "commit" else "verify-tag"
        command = [git_program, "-C", str(repository)]
        if signature_format == "ssh":
            key_type, encoded, fingerprint = _ssh_public_key(root.public_key_bytes, root.key_type)
            allowed = home / "allowed_signers"
            allowed.write_text(
                f"{SSH_PRINCIPAL} {key_type} {encoded}\n", encoding="ascii", newline="\n"
            )
            revoked = home / "revoked_signers"
            revoked.write_bytes(b"")
            ssh_keygen = _tool("ssh-keygen")
            command.extend(
                [
                    "-c",
                    "gpg.format=ssh",
                    "-c",
                    f"gpg.ssh.allowedSignersFile={allowed}",
                    "-c",
                    f"gpg.ssh.revocationFile={revoked}",
                    "-c",
                    f"gpg.ssh.program={ssh_keygen}",
                ]
            )
            result = _run(
                [*command, verify_command, "--raw", expected.decode("ascii")],
                environment=environment,
                label=f"isolated Git {kind} SSH-signature verification",
            )
            report = (result.stdout + b"\n" + result.stderr).decode("utf-8", "replace")
            required = (
                f'Good "git" signature for {SSH_PRINCIPAL} with '
            )
            if required not in report or fingerprint not in report:
                _fail("Git SSH verification did not report the pinned principal and fingerprint")
            return {
                "method": f"git {verify_command} --raw",
                "signature_format": "ssh",
                "verified_key_fingerprint": fingerprint,
            }

        gpg_program = _tool("gpg")
        allowed_fingerprints = _openpgp_inventory(
            gpg_program=gpg_program, home=home, environment=environment, root=root
        )
        command.extend(
            ["-c", "gpg.format=openpgp", "-c", f"gpg.program={gpg_program}"]
        )
        result = _run(
            [*command, verify_command, "--raw", expected.decode("ascii")],
            environment=environment,
            label=f"isolated Git {kind} OpenPGP-signature verification",
        )
        report = (result.stdout + b"\n" + result.stderr).decode("utf-8", "replace")
        bad_statuses = (
            "[GNUPG:] BADSIG",
            "[GNUPG:] ERRSIG",
            "[GNUPG:] EXPKEYSIG",
            "[GNUPG:] EXPSIG",
            "[GNUPG:] REVKEYSIG",
            "[GNUPG:] KEYEXPIRED",
            "[GNUPG:] SIGEXPIRED",
        )
        if any(status in report for status in bad_statuses):
            _fail("Git OpenPGP verification reported an invalid or expired signature/key")
        valid_lines = [line for line in report.splitlines() if "[GNUPG:] VALIDSIG " in line]
        if len(valid_lines) != 1:
            _fail("Git OpenPGP verification did not report exactly one valid signature")
        fields = valid_lines[0].split("[GNUPG:] VALIDSIG ", 1)[1].split()
        if not fields or fields[0].upper() not in allowed_fingerprints:
            _fail("Git OpenPGP verification used a key outside the pinned key inventory")
        if len(fields) >= 10 and _OPENPGP_FINGERPRINT.fullmatch(fields[-1].upper()):
            if fields[-1].upper() != root.public_key_fingerprint:
                _fail("Git OpenPGP verification did not chain to the pinned primary key")
        return {
            "method": f"git {verify_command} --raw",
            "signature_format": "openpgp",
            "verified_key_fingerprint": fields[0].upper(),
        }


def _receipt(
    *,
    kind: str,
    raw: bytes,
    object_format: str,
    parsed: CommitObject | TagObject,
    root: SigningRoot,
    verification: dict[str, str],
) -> dict[str, Any]:
    if isinstance(parsed, CommitObject):
        binding: dict[str, Any] = {
            "tree": parsed.tree,
            "parent": parsed.parent,
            "parent_count": 1,
            "author": parsed.author.identity,
            "committer": parsed.committer.identity,
            "encoding": parsed.encoding,
        }
    else:
        binding = {
            "object": parsed.target,
            "type": "commit",
            "tag": parsed.tag,
            "tagger": parsed.tagger.identity,
            "encoding": parsed.encoding,
            "message_sha256": parsed.message_sha256,
        }
    return {
        "format": RECEIPT_FORMAT,
        "verdict": "PASS",
        "object": {
            "kind": kind,
            "object_format": object_format,
            "object_id": parsed.object_id,
            "raw_size": len(raw),
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
        },
        "binding": binding,
        "signing_root": {
            "format": ROOT_FORMAT,
            "version": root.version,
            "root_sha256": root.root_sha256,
            "key_type": root.key_type,
            "public_key_path": root.public_key_path,
            "public_key_sha256": root.public_key_sha256,
            "public_key_fingerprint": root.public_key_fingerprint,
            "signature_namespace": root.signature_namespace,
            "github_login": root.github_login,
            "github_user_id": root.github_user_id,
            "github_verification_required_separately": True,
            "github_identity_used_as_signer_proof": False,
        },
        "verification": {
            **verification,
            "isolated_trust_directory": True,
            "system_and_global_git_config_disabled": True,
            "private_key_loaded": False,
        },
    }


def _write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        _fail("receipt target must be absent or a regular non-symlink file")
    if path.parent.is_symlink() or not path.parent.is_dir():
        _fail("receipt parent must be an existing non-symlink directory")
    encoded = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        _fail(f"verification receipt could not be written atomically: {exc}")
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def verify(arguments: argparse.Namespace) -> dict[str, Any]:
    root = load_signing_root(arguments.root)
    signature_format = "ssh" if root.key_type in _SSH_KEY_TYPES else "openpgp"
    git_program = _tool("git")
    raw, object_format = _repository_object(
        arguments.repository,
        object_id=arguments.object,
        expected_kind=arguments.kind,
        git_program=git_program,
    )
    if arguments.kind == "commit":
        parsed: CommitObject | TagObject = parse_commit(
            raw,
            object_format=object_format,
            expected_object=arguments.object,
            expected_parent=arguments.expected_parent,
            signature_format=signature_format,
        )
    else:
        parsed = parse_tag(
            raw,
            object_format=object_format,
            expected_object=arguments.object,
            expected_target=arguments.expected_target,
            expected_tag=arguments.expected_tag,
            signature_format=signature_format,
        )
    verification = _verify_git_signature(
        kind=arguments.kind,
        raw=raw,
        object_format=object_format,
        root=root,
        git_program=git_program,
    )
    receipt = _receipt(
        kind=arguments.kind,
        raw=raw,
        object_format=object_format,
        parsed=parsed,
        root=root,
        verification=verification,
    )
    _write_receipt(arguments.receipt, receipt)
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="kind", required=True)
    for kind in ("commit", "tag"):
        command = subparsers.add_parser(kind)
        command.add_argument("--repository", type=Path, required=True)
        command.add_argument("--object", required=True)
        command.add_argument("--root", type=Path, required=True)
        command.add_argument("--receipt", type=Path, required=True)
        if kind == "commit":
            command.add_argument("--expected-parent", required=True)
        else:
            command.add_argument("--expected-tag", required=True)
            command.add_argument("--expected-target", required=True)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(list(argv) if argv is not None else None)
        receipt = verify(arguments)
    except VerificationError as exc:
        print(f"release Git object verification failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
