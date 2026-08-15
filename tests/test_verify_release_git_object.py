# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "ci" / "verify_release_git_object.py"
SPEC = importlib.util.spec_from_file_location("verify_release_git_object", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


TREE = "1" * 40
PARENT = "2" * 40
TARGET = "3" * 40
SSH_ARMOR_HEADER = b"-----BEGIN SSH SIGNATURE-----"
SSH_ARMOR_FOOTER = b"-----END SSH SIGNATURE-----"


def _find_gpg() -> str | None:
    # Git-for-Windows' MSYS-only gpg.exe cannot consume native temporary paths
    # reliably from a native Python process; use a directly callable GPG only.
    return shutil.which("gpg")


GPG = _find_gpg()


def _commit_raw(*, parents: tuple[str, ...] = (PARENT,), extra: bytes = b"") -> bytes:
    parent_lines = b"".join(f"parent {parent}\n".encode("ascii") for parent in parents)
    return (
        f"tree {TREE}\n".encode("ascii")
        + parent_lines
        + b"author Release Tester <release@example.com> 1786752000 +0300\n"
        + b"committer Release Tester <release@example.com> 1786752000 +0300\n"
        + extra
        + b"gpgsig -----BEGIN SSH SIGNATURE-----\n"
        + b" U1NIU0lH\n"
        + b" -----END SSH SIGNATURE-----\n"
        + b"\n"
        + b"release: v4.7.0\n"
    )


def _tag_raw(*, target_type: bytes = b"commit", extra_header: bytes = b"") -> bytes:
    return (
        f"object {TARGET}\n".encode("ascii")
        + b"type "
        + target_type
        + b"\n"
        + b"tag v4.7.0\n"
        + b"tagger Release Tester <release@example.com> 1786752000 +0300\n"
        + extra_header
        + b"\n"
        + b"EvoOM Guard v4.7.0\n"
        + SSH_ARMOR_HEADER
        + b"\nU1NIU0lH\n"
        + SSH_ARMOR_FOOTER
        + b"\n"
    )


def _oid(kind: str, raw: bytes) -> str:
    return verifier._git_object_id(kind, raw, "sha1")


def _run(
    arguments: list[str], *, cwd: Path, environment: dict[str, str] | None = None
) -> str:
    result = subprocess.run(
        arguments,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )
    if result.returncode != 0:
        pytest.fail(f"command failed: {arguments!r}\nstdout={result.stdout}\nstderr={result.stderr}")
    return result.stdout.strip()


def _ssh_fingerprint(public_key: bytes) -> str:
    encoded = public_key.decode("ascii").split()[1]
    blob = base64.b64decode(encoded, validate=True)
    value = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{value}"


def _write_root(directory: Path, public_key: bytes) -> Path:
    roots = directory / "security" / "release-maintainer-roots"
    roots.mkdir(parents=True)
    public_path = roots / "v4.7.0.pub"
    public_path.write_bytes(public_key)
    document = {
        "format": verifier.ROOT_FORMAT,
        "version": "4.7.0",
        "github_login": "ReleaseTester",
        "github_user_id": 123456,
        "key_type": public_key.decode("ascii").split()[0],
        "public_key_path": "security/release-maintainer-roots/v4.7.0.pub",
        "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
        "provided_source_file_sha256_crlf": "0" * 64,
        "public_key_fingerprint": _ssh_fingerprint(public_key),
        "signature_namespace": "git",
        "private_key_location": "OUTSIDE_REPOSITORY_AND_GITHUB_ACTIONS",
        "github_verification_required": True,
    }
    root_path = roots / "v4.7.0.json"
    root_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    return root_path


def _write_openpgp_root(directory: Path, public_key: bytes, fingerprint: str) -> Path:
    roots = directory / "security" / "release-maintainer-roots"
    roots.mkdir(parents=True)
    public_path = roots / "v4.7.0.pub"
    public_path.write_bytes(public_key)
    document = {
        "format": verifier.ROOT_FORMAT,
        "version": "4.7.0",
        "github_login": "ReleaseTester",
        "github_user_id": 123456,
        "key_type": "openpgp",
        "public_key_path": "security/release-maintainer-roots/v4.7.0.pub",
        "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
        "provided_source_file_sha256_crlf": "0" * 64,
        "public_key_fingerprint": fingerprint,
        "signature_namespace": "git",
        "private_key_location": "OUTSIDE_REPOSITORY_AND_GITHUB_ACTIONS",
        "github_verification_required": True,
    }
    root_path = roots / "v4.7.0.json"
    root_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    return root_path


def test_checked_in_maintainer_root_binds_exact_public_key() -> None:
    root = verifier.load_signing_root(
        ROOT / "security" / "release-maintainer-roots" / "v4.7.0.json"
    )

    assert root.public_key_path == "security/release-maintainer-roots/v4.7.0.pub"
    assert root.public_key_sha256 == "f5a137810263756bcfbee4ebb020ca3c26a40d6876a5972ff2baa4d0ef7b0cab"
    assert root.public_key_fingerprint == (
        "SHA256:iCn7wa6HgKdu7luf/16rrKZzSk5FygJoA8EKNl3LJ24"
    )
    assert root.signature_namespace == "git"


def test_commit_parser_requires_exactly_one_expected_parent() -> None:
    raw = _commit_raw()
    parsed = verifier.parse_commit(
        raw,
        object_format="sha1",
        expected_object=_oid("commit", raw),
        expected_parent=PARENT,
        signature_format="ssh",
    )

    assert parsed.parent == PARENT
    assert parsed.tree == TREE
    assert parsed.committer.identity == "Release Tester <release@example.com>"
    assert parsed.signature_format == "ssh"

    merge = _commit_raw(parents=(PARENT, TARGET))
    with pytest.raises(verifier.VerificationError, match="inventory/order"):
        verifier.parse_commit(
            merge,
            object_format="sha1",
            expected_object=_oid("commit", merge),
            expected_parent=PARENT,
            signature_format="ssh",
        )

    with pytest.raises(verifier.VerificationError, match="expected sole parent"):
        verifier.parse_commit(
            raw,
            object_format="sha1",
            expected_object=_oid("commit", raw),
            expected_parent=TARGET,
            signature_format="ssh",
        )


def test_commit_parser_rejects_extra_headers_and_object_id_mismatch() -> None:
    extra = _commit_raw(extra=b"x-attacker injected\n")
    with pytest.raises(verifier.VerificationError, match="inventory/order"):
        verifier.parse_commit(
            extra,
            object_format="sha1",
            expected_object=_oid("commit", extra),
            expected_parent=PARENT,
            signature_format="ssh",
        )

    raw = _commit_raw()
    with pytest.raises(verifier.VerificationError, match="expected object id"):
        verifier.parse_commit(
            raw,
            object_format="sha1",
            expected_object="0" * 40,
            expected_parent=PARENT,
            signature_format="ssh",
        )


def test_tag_parser_exposes_exact_canonical_fields() -> None:
    raw = _tag_raw()
    parsed = verifier.parse_tag(
        raw,
        object_format="sha1",
        expected_object=_oid("tag", raw),
        expected_target=TARGET,
        expected_tag="v4.7.0",
        signature_format="ssh",
    )

    assert parsed.target == TARGET
    assert parsed.tag == "v4.7.0"
    assert parsed.tagger.identity == "Release Tester <release@example.com>"
    assert parsed.message == "EvoOM Guard v4.7.0\n"
    assert parsed.encoding == "UTF-8"
    assert parsed.signature_format == "ssh"


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (_tag_raw(target_type=b"blob"), "target type must be commit"),
        (_tag_raw(extra_header=b"tag duplicate\n"), "inventory/order"),
        (_tag_raw().replace(b"tag v4.7.0", b"tag v4.7.1"), "expected tag"),
        (_tag_raw() + b"trailing", "boundaries are not canonical"),
    ],
)
def test_tag_parser_rejects_noncanonical_or_unbound_objects(raw: bytes, message: str) -> None:
    with pytest.raises(verifier.VerificationError, match=message):
        verifier.parse_tag(
            raw,
            object_format="sha1",
            expected_object=_oid("tag", raw),
            expected_target=TARGET,
            expected_tag="v4.7.0",
            signature_format="ssh",
        )


def test_tag_parser_enforces_decoded_raw_byte_limit() -> None:
    raw = b"x" * (verifier.TAG_MAX_BYTES + 1)
    with pytest.raises(verifier.VerificationError, match="32768-byte limit"):
        verifier.parse_tag(
            raw,
            object_format="sha1",
            expected_object="0" * 40,
            expected_target=TARGET,
            expected_tag="v4.7.0",
            signature_format="ssh",
        )


def test_signing_root_rejects_tampered_public_key(tmp_path: Path) -> None:
    raw_key = (
        b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDZCepQbTxouwR5UwSKMF+4RvlK/"
        b"MRQ+D9HE+fxJOKdi test\n"
    )
    root_path = _write_root(tmp_path, raw_key)
    key_path = root_path.with_suffix(".pub")
    key_path.write_bytes(raw_key.replace(b"test", b"changed"))

    with pytest.raises(verifier.VerificationError, match="pinned SHA-256"):
        verifier.load_signing_root(root_path)


@pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("ssh-keygen") is None,
    reason="Git and ssh-keygen are required for the real signature integration test",
)
def test_cli_verifies_real_signed_commit_and_annotated_tag_in_isolated_trust(
    tmp_path: Path,
) -> None:
    private_key = tmp_path / "maintainer"
    _run(
        [
            str(shutil.which("ssh-keygen")),
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "release-test",
            "-f",
            str(private_key),
        ],
        cwd=tmp_path,
    )
    public_key = private_key.with_suffix(".pub").read_bytes().replace(b"\r\n", b"\n")
    root_path = _write_root(tmp_path / "trusted-parent", public_key)

    work = tmp_path / "work"
    bare = tmp_path / "objects.git"
    _run(["git", "init", str(work)], cwd=tmp_path)
    _run(["git", "config", "user.name", "Release Tester"], cwd=work)
    _run(["git", "config", "user.email", "release@example.com"], cwd=work)
    _run(["git", "config", "gpg.format", "ssh"], cwd=work)
    _run(["git", "config", "user.signingkey", str(private_key)], cwd=work)
    (work / "release.txt").write_text("parent\n", encoding="utf-8", newline="\n")
    _run(["git", "add", "release.txt"], cwd=work)
    _run(["git", "commit", "-m", "parent"], cwd=work)
    parent = _run(["git", "rev-parse", "HEAD"], cwd=work)
    (work / "release.txt").write_text("v4.7.0\n", encoding="utf-8", newline="\n")
    _run(["git", "add", "release.txt"], cwd=work)
    _run(["git", "commit", "-S", "-m", "release: v4.7.0"], cwd=work)
    commit = _run(["git", "rev-parse", "HEAD"], cwd=work)
    _run(["git", "tag", "-s", "v4.7.0", "-m", "EvoOM Guard v4.7.0"], cwd=work)
    tag_object = _run(["git", "rev-parse", "v4.7.0^{tag}"], cwd=work)
    _run(["git", "clone", "--bare", str(work), str(bare)], cwd=tmp_path)

    commit_receipt = tmp_path / "commit-receipt.json"
    assert (
        verifier.main(
            [
                "commit",
                "--repository",
                str(bare),
                "--object",
                commit,
                "--root",
                str(root_path),
                "--expected-parent",
                parent,
                "--receipt",
                str(commit_receipt),
            ]
        )
        == 0
    )
    commit_document = json.loads(commit_receipt.read_text(encoding="utf-8"))
    assert commit_document["verdict"] == "PASS"
    assert commit_document["binding"]["parent"] == parent
    assert commit_document["binding"]["parent_count"] == 1
    assert commit_document["verification"]["signature_format"] == "ssh"
    assert commit_document["signing_root"]["github_identity_used_as_signer_proof"] is False

    tag_receipt = tmp_path / "tag-receipt.json"
    assert (
        verifier.main(
            [
                "tag",
                "--repository",
                str(bare),
                "--object",
                tag_object,
                "--root",
                str(root_path),
                "--expected-tag",
                "v4.7.0",
                "--expected-target",
                commit,
                "--receipt",
                str(tag_receipt),
            ]
        )
        == 0
    )
    tag_document = json.loads(tag_receipt.read_text(encoding="utf-8"))
    assert tag_document["verdict"] == "PASS"
    assert tag_document["binding"]["object"] == commit
    assert tag_document["binding"]["type"] == "commit"
    assert tag_document["binding"]["tag"] == "v4.7.0"


@pytest.mark.skipif(
    GPG is None or shutil.which("git") is None,
    reason="Git and GPG are required for the real OpenPGP integration test",
)
def test_cli_verifies_real_openpgp_commit_in_isolated_keyring(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert GPG is not None
    gpg_home = tmp_path / "signer-gnupg"
    gpg_home.mkdir(mode=0o700)
    environment = os.environ.copy()
    environment["GNUPGHOME"] = str(gpg_home)
    _run(
        [
            GPG,
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            "Release Tester <release@example.com>",
            "rsa2048",
            "sign",
            "1d",
        ],
        cwd=tmp_path,
        environment=environment,
    )
    inventory = _run(
        [GPG, "--batch", "--with-colons", "--fingerprint", "--list-secret-keys"],
        cwd=tmp_path,
        environment=environment,
    )
    fingerprints = [line.split(":")[9] for line in inventory.splitlines() if line.startswith("fpr:")]
    assert fingerprints
    fingerprint = fingerprints[0].upper()
    exported = subprocess.run(
        [GPG, "--batch", "--armor", "--export", fingerprint],
        cwd=tmp_path,
        capture_output=True,
        check=True,
        env=environment,
    ).stdout
    assert exported
    root_path = _write_openpgp_root(tmp_path / "trusted-parent-gpg", exported, fingerprint)

    work = tmp_path / "gpg-work"
    bare = tmp_path / "gpg-objects.git"
    _run(["git", "init", str(work)], cwd=tmp_path)
    _run(["git", "config", "user.name", "Release Tester"], cwd=work)
    _run(["git", "config", "user.email", "release@example.com"], cwd=work)
    _run(["git", "config", "gpg.format", "openpgp"], cwd=work)
    _run(["git", "config", "gpg.program", GPG], cwd=work)
    _run(["git", "config", "user.signingkey", fingerprint], cwd=work)
    (work / "release.txt").write_text("parent\n", encoding="utf-8", newline="\n")
    _run(["git", "add", "release.txt"], cwd=work, environment=environment)
    _run(["git", "commit", "-m", "parent"], cwd=work, environment=environment)
    parent = _run(["git", "rev-parse", "HEAD"], cwd=work, environment=environment)
    (work / "release.txt").write_text("v4.7.0\n", encoding="utf-8", newline="\n")
    _run(["git", "add", "release.txt"], cwd=work, environment=environment)
    _run(
        ["git", "commit", "-S", "-m", "release: v4.7.0"],
        cwd=work,
        environment=environment,
    )
    commit = _run(["git", "rev-parse", "HEAD"], cwd=work, environment=environment)
    _run(["git", "clone", "--bare", str(work), str(bare)], cwd=tmp_path)

    # Make the explicitly selected GPG executable available to the verifier's
    # isolated subprocess environment without changing its trust store.
    monkeypatch.setenv("PATH", str(Path(GPG).parent) + os.pathsep + os.environ["PATH"])
    receipt_path = tmp_path / "openpgp-commit-receipt.json"
    assert (
        verifier.main(
            [
                "commit",
                "--repository",
                str(bare),
                "--object",
                commit,
                "--root",
                str(root_path),
                "--expected-parent",
                parent,
                "--receipt",
                str(receipt_path),
            ]
        )
        == 0
    )
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["verification"]["signature_format"] == "openpgp"
    assert receipt["signing_root"]["public_key_fingerprint"] == fingerprint
