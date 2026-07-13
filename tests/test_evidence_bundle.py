"""Security and reproducibility tests for the portable evidence envelope."""

from __future__ import annotations

import json
import os
import re
import stat
import struct
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from evoom_guard import evidence_bundle as bundle
from evoom_guard.signing import generate_keypair

_CANDIDATE = "a" * 64
_POLICY = "b" * 64
_ARTIFACT = "c" * 64


def _verdict(path, *, extra: str = "") -> None:
    path.write_text(
        '{"schema_version":"1.11","tool":"evoguard",'
        '"tool_version":"3.4.4","verdict":"PASS",'
        '"attestation":{"candidate_sha256":"'
        + _CANDIDATE
        + '","policy_sha256":"'
        + _POLICY
        + '","verifier_pack_sha256":null,"base_sha":null,"head_sha":null}'
        + extra
        + "}\n",
        encoding="utf-8",
        newline="\n",
    )


def _context(**overrides):
    value = {
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
        "guard_artifact_sha256": _ARTIFACT,
    }
    value.update(overrides)
    return value


def _keys(tmp_path, prefix="judge"):
    private = tmp_path / f"{prefix}.private.pem"
    public = tmp_path / f"{prefix}.public.pem"
    generate_keypair(str(private), str(public))
    return private, public


def _create(verdict, output, *, private, context=None, materials=(), force=False):
    # Most container-format tests deliberately use a minimal, semantically
    # invalid record so they can isolate structural behavior. Production callers
    # get the safe require_valid_record=True default.
    return bundle.create_evidence_bundle(
        str(verdict),
        str(output),
        context=_context() if context is None else context,
        private_key_path=str(private),
        materials=materials,
        force=force,
        require_valid_record=False,
    )


def _info(name: str, *, compression: int = zipfile.ZIP_STORED) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=bundle.ZIP_TIMESTAMP)
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.compress_type = compression
    return info


def _rewrite(source, target, transform) -> None:
    with zipfile.ZipFile(source, "r") as old:
        rows = [(item.filename, old.read(item.filename)) for item in old.infolist()]
    rows = transform(rows)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as new:
        for name, data in rows:
            new.writestr(_info(name), data)


def test_bundle_is_deterministic_and_order_independent(tmp_path) -> None:
    verdict = tmp_path / "verdict.json"
    first_material = tmp_path / "a.bin"
    second_material = tmp_path / "b.bin"
    _verdict(verdict)
    first_material.write_bytes(b"one")
    second_material.write_bytes(b"two")
    first = tmp_path / "first.evobundle"
    second = tmp_path / "second.evobundle"
    private, public = _keys(tmp_path)

    _create(
        verdict,
        first,
        private=private,
        materials=[
            bundle.EvidenceMaterial("signature", str(second_material)),
            bundle.EvidenceMaterial("junit", str(first_material)),
        ],
    )
    os.utime(verdict, None)
    _create(
        verdict,
        second,
        private=private,
        materials=[
            bundle.EvidenceMaterial("junit", str(first_material)),
            bundle.EvidenceMaterial("signature", str(second_material)),
        ],
    )
    assert first.read_bytes() == second.read_bytes()

    inspected = bundle.inspect_evidence_bundle(str(first))
    assert inspected.verdict["schema_version"] == "1.11"
    assert [item.role for item in inspected.materials] == ["junit", "signature"]
    assert inspected.materials_for("junit")[0].data == b"one"
    authenticated = bundle.authenticate_evidence_bundle(
        bundle.inspect_evidence_bundle(str(first)),
        trusted_public_key_path=str(public),
        expected_context=_context(),
    )
    assert authenticated.manifest["authentication"]["algorithm"] == "Ed25519"


def test_mutating_parsed_views_cannot_change_later_trust_checks(tmp_path) -> None:
    verdict = tmp_path / "verdict.json"
    archive = tmp_path / "evidence.evb"
    _verdict(verdict)
    private, public = _keys(tmp_path)
    _create(verdict, archive, private=private)

    inspected = bundle.inspect_evidence_bundle(str(archive))
    manifest_view = inspected.manifest
    manifest_view["context"]["repository"] = "forged/project"
    manifest_view["context"]["run_id"] = "forged-run"
    verdict_view = inspected.verdict
    verdict_view["verdict"] = "FAIL"

    assert inspected.manifest["context"]["repository"] == "owner/project"
    assert inspected.verdict["verdict"] == "PASS"
    with pytest.raises(bundle.EvidenceBundleError, match="exactly match expected context"):
        bundle.authenticate_evidence_bundle(
            inspected,
            trusted_public_key_path=str(public),
            expected_context=_context(
                repository="forged/project",
                run_id="forged-run",
            ),
        )
    authenticated = bundle.authenticate_evidence_bundle(
        inspected,
        trusted_public_key_path=str(public),
        expected_context=_context(),
    )
    assert authenticated.manifest["context"]["repository"] == "owner/project"


def test_bundle_writer_semantically_validates_by_default(tmp_path) -> None:
    verdict = tmp_path / "invalid-verdict.json"
    archive = tmp_path / "must-not-exist.evb"
    _verdict(verdict)
    private, _public = _keys(tmp_path)

    with pytest.raises(bundle.EvidenceBundleError, match="semantically invalid"):
        bundle.create_evidence_bundle(
            str(verdict),
            str(archive),
            context=_context(),
            private_key_path=str(private),
        )
    assert not archive.exists()


def test_refuses_overwrite_without_force(tmp_path) -> None:
    verdict = tmp_path / "verdict.json"
    output = tmp_path / "bundle.zip"
    _verdict(verdict)
    private, _public = _keys(tmp_path)
    output.write_bytes(b"keep")
    with pytest.raises(bundle.EvidenceBundleError, match="refusing to overwrite"):
        _create(verdict, output, private=private)
    assert output.read_bytes() == b"keep"
    _create(verdict, output, private=private, force=True)
    assert bundle.inspect_evidence_bundle(str(output)).verdict["tool"] == "evoguard"


def test_no_clobber_publication_loses_race_without_overwriting_winner(
    tmp_path, monkeypatch
) -> None:
    verdict = tmp_path / "verdict.json"
    output = tmp_path / "bundle.evb"
    _verdict(verdict)
    private, _public = _keys(tmp_path)

    def competing_publish(_source, destination, **_kwargs):
        Path(destination).write_bytes(b"race-winner")
        raise FileExistsError(destination)

    monkeypatch.setattr(bundle.os, "link", competing_publish)
    with pytest.raises(bundle.EvidenceBundleError, match="refusing to overwrite"):
        _create(verdict, output, private=private)
    assert output.read_bytes() == b"race-winner"


def test_rejects_directory_and_symlink_inputs(tmp_path) -> None:
    verdict = tmp_path / "verdict.json"
    _verdict(verdict)
    private, _public = _keys(tmp_path)
    with pytest.raises(bundle.EvidenceBundleError, match="regular non-symlink"):
        _create(
            verdict,
            tmp_path / "out.zip",
            private=private,
            materials=[bundle.EvidenceMaterial("junit", str(tmp_path))],
        )

    link = tmp_path / "link.json"
    try:
        link.symlink_to(verdict)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable to this Windows test user")
    with pytest.raises(bundle.EvidenceBundleError, match="non-symlink"):
        _create(link, tmp_path / "link.zip", private=private)


def test_rejects_duplicate_record_json_keys(tmp_path) -> None:
    verdict = tmp_path / "verdict.json"
    verdict.write_text(
        '{"schema_version":"1.11","schema_version":"1.11",'
        '"tool":"evoguard","tool_version":"3.4.4"}',
        encoding="utf-8",
    )
    private, _public = _keys(tmp_path)
    with pytest.raises(bundle.EvidenceBundleError, match="duplicate JSON key"):
        _create(verdict, tmp_path / "out.zip", private=private)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            b'{"schema_version":"1.11","tool":"evoom_guard",'
            b'"tool_version":"3.4.4","value":1e9999}',
            "non-finite JSON number",
        ),
        (
            b'{"schema_version":"1.11","tool":"evoom_guard",'
            b'"tool_version":"3.4.4","value":'
            + (b"[" * 4000)
            + b"0"
            + (b"]" * 4000)
            + b"}",
            "not strict UTF-8 JSON",
        ),
    ],
)
def test_rejects_float_overflow_and_excessive_json_nesting(
    tmp_path, payload: bytes, message: str
) -> None:
    verdict = tmp_path / "verdict.json"
    verdict.write_bytes(payload)

    with pytest.raises(bundle.EvidenceBundleError, match=message):
        bundle.create_evidence_bundle(
            str(verdict),
            str(tmp_path / "out.zip"),
            context={},
            private_key_path=str(tmp_path / "missing-key.pem"),
        )


def test_rejects_invalid_role_and_duplicate_material_role(tmp_path) -> None:
    verdict = tmp_path / "verdict.json"
    material = tmp_path / "m"
    other_material = tmp_path / "n"
    _verdict(verdict)
    private, _public = _keys(tmp_path)
    material.write_bytes(b"x")
    other_material.write_bytes(b"y")
    with pytest.raises(bundle.EvidenceBundleError, match="material role"):
        _create(
            verdict,
            tmp_path / "bad.zip",
            private=private,
            materials=[bundle.EvidenceMaterial("../junit", str(material))],
        )
    with pytest.raises(bundle.EvidenceBundleError, match="at most once"):
        _create(
            verdict,
            tmp_path / "duplicate.zip",
            private=private,
            materials=[
                bundle.EvidenceMaterial("junit", str(material)),
                bundle.EvidenceMaterial("junit", str(other_material)),
            ],
        )


def test_size_limits_are_enforced_before_archive_write(tmp_path, monkeypatch) -> None:
    verdict = tmp_path / "verdict.json"
    material = tmp_path / "large"
    _verdict(verdict)
    private, _public = _keys(tmp_path)
    material.write_bytes(b"four")
    monkeypatch.setattr(bundle, "MAX_MATERIAL_BYTES", 3)
    with pytest.raises(bundle.EvidenceBundleError, match="exceeds"):
        _create(
            verdict,
            tmp_path / "out.zip",
            private=private,
            materials=[bundle.EvidenceMaterial("junit", str(material))],
        )


def test_total_budget_rejects_next_material_before_opening_it(tmp_path, monkeypatch) -> None:
    verdict = tmp_path / "verdict.json"
    first_material = tmp_path / "first"
    next_material = tmp_path / "next"
    _verdict(verdict)
    first_material.write_bytes(b"four")
    next_material.write_bytes(b"x")
    private, _public = _keys(tmp_path)
    monkeypatch.setattr(bundle, "MAX_TOTAL_BYTES", verdict.stat().st_size + 4)

    real_open = os.open
    opened: list[str] = []

    def tracking_open(path, *args, **kwargs):
        opened.append(os.fspath(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(bundle.os, "open", tracking_open)
    with pytest.raises(bundle.EvidenceBundleError, match="0-byte limit"):
        _create(
            verdict,
            tmp_path / "out.zip",
            private=private,
            materials=[
                bundle.EvidenceMaterial("first", str(first_material)),
                bundle.EvidenceMaterial("next", str(next_material)),
            ],
        )
    assert str(next_material) not in opened


def test_bundle_signing_uses_one_private_key_snapshot_and_checks_its_id(
    tmp_path, monkeypatch
) -> None:
    from evoom_guard import signing

    verdict = tmp_path / "verdict.json"
    _verdict(verdict)
    private, _public = _keys(tmp_path)
    real_load = signing._load_private_key
    loads = 0

    def tracking_load(path):
        nonlocal loads
        loads += 1
        return real_load(path)

    monkeypatch.setattr(signing, "_load_private_key", tracking_load)
    _create(verdict, tmp_path / "one-open.evb", private=private)
    assert loads == 1

    real_sign = signing._sign_bytes_with_key_id

    def mismatched_id(payload, snapshot):
        signature, _actual_id = real_sign(payload, snapshot)
        return signature, "sha256:" + "0" * 64

    monkeypatch.setattr(signing, "_sign_bytes_with_key_id", mismatched_id)
    rejected = tmp_path / "mismatched.evb"
    with pytest.raises(bundle.EvidenceBundleError, match="key_id changed"):
        _create(verdict, rejected, private=private)
    assert not rejected.exists()


def test_tampered_verdict_bytes_are_rejected(tmp_path) -> None:
    verdict = tmp_path / "verdict.json"
    original = tmp_path / "original.zip"
    tampered = tmp_path / "tampered.zip"
    _verdict(verdict)
    private, _public = _keys(tmp_path)
    _create(verdict, original, private=private)

    def transform(rows):
        return [
            (name, data.replace(b'"PASS"', b'"FAIL"'))
            if name == bundle.VERDICT_PATH
            else (name, data)
            for name, data in rows
        ]

    _rewrite(original, tampered, transform)
    with pytest.raises(bundle.EvidenceBundleError, match="verdict bytes"):
        bundle.inspect_evidence_bundle(str(tampered))


def test_undeclared_and_traversal_members_are_rejected(tmp_path) -> None:
    verdict = tmp_path / "verdict.json"
    original = tmp_path / "original.zip"
    extra = tmp_path / "extra.zip"
    traversal = tmp_path / "traversal.zip"
    _verdict(verdict)
    private, _public = _keys(tmp_path)
    _create(verdict, original, private=private)
    _rewrite(original, extra, lambda rows: rows + [("materials/999-extra", b"x")])
    with pytest.raises(bundle.EvidenceBundleError, match="exactly match"):
        bundle.inspect_evidence_bundle(str(extra))
    _rewrite(original, traversal, lambda rows: rows + [("../escape", b"x")])
    with pytest.raises(bundle.EvidenceBundleError, match="unsafe archive member"):
        bundle.inspect_evidence_bundle(str(traversal))


def test_duplicate_archive_names_are_rejected(tmp_path) -> None:
    verdict = tmp_path / "verdict.json"
    original = tmp_path / "original.zip"
    duplicate = tmp_path / "duplicate.zip"
    _verdict(verdict)
    private, _public = _keys(tmp_path)
    _create(verdict, original, private=private)
    with zipfile.ZipFile(original, "r") as old:
        rows = [(item.filename, old.read(item.filename)) for item in old.infolist()]
    with pytest.warns(UserWarning, match="Duplicate name"):
        with zipfile.ZipFile(duplicate, "w", compression=zipfile.ZIP_STORED) as new:
            for name, data in rows:
                new.writestr(_info(name), data)
            new.writestr(_info(bundle.VERDICT_PATH), rows[1][1])
    with pytest.raises(bundle.EvidenceBundleError, match="duplicate archive member"):
        bundle.inspect_evidence_bundle(str(duplicate))


def test_noncanonical_manifest_and_compression_are_rejected(tmp_path) -> None:
    verdict = tmp_path / "verdict.json"
    original = tmp_path / "original.zip"
    pretty = tmp_path / "pretty.zip"
    compressed = tmp_path / "compressed.zip"
    _verdict(verdict)
    private, _public = _keys(tmp_path)
    _create(verdict, original, private=private)

    def pretty_manifest(rows):
        result = []
        for name, data in rows:
            if name == bundle.MANIFEST_PATH:
                value = json.loads(data)
                data = json.dumps(value, indent=2).encode("utf-8")
            result.append((name, data))
        return result

    _rewrite(original, pretty, pretty_manifest)
    with pytest.raises(bundle.EvidenceBundleError, match="not canonical JSON"):
        bundle.inspect_evidence_bundle(str(pretty))

    with zipfile.ZipFile(original, "r") as old:
        rows = [(item.filename, old.read(item.filename)) for item in old.infolist()]
    with zipfile.ZipFile(compressed, "w") as new:
        for name, data in rows:
            new.writestr(_info(name, compression=zipfile.ZIP_DEFLATED), data)
    with pytest.raises(bundle.EvidenceBundleError, match="compressed archive member"):
        bundle.inspect_evidence_bundle(str(compressed))


def test_authentication_requires_external_key_and_exact_context(tmp_path) -> None:
    verdict = tmp_path / "verdict.json"
    archive = tmp_path / "evidence.evb"
    _verdict(verdict)
    private, public = _keys(tmp_path, "trusted")
    _wrong_private, wrong_public = _keys(tmp_path, "wrong")
    _create(verdict, archive, private=private)

    with pytest.raises(bundle.EvidenceBundleError, match="externally trusted key"):
        bundle.verify_evidence_bundle(
            str(archive),
            trusted_public_key_path=str(wrong_public),
            expected_context=_context(),
        )


def test_full_admission_rejects_authenticated_semantically_invalid_record(tmp_path) -> None:
    verdict = tmp_path / "invalid-verdict.json"
    archive = tmp_path / "invalid-but-signed.evb"
    _verdict(verdict)
    private, public = _keys(tmp_path)
    _create(verdict, archive, private=private)

    authenticated = bundle.authenticate_evidence_bundle(
        bundle.inspect_evidence_bundle(str(archive)),
        trusted_public_key_path=str(public),
        expected_context=_context(),
    )
    assert authenticated.verdict["verdict"] == "PASS"
    with pytest.raises(bundle.EvidenceBundleError, match="semantically invalid"):
        bundle.verify_evidence_bundle(
            str(archive),
            trusted_public_key_path=str(public),
            expected_context=_context(),
        )
    with pytest.raises(bundle.EvidenceBundleError, match="exactly match expected context"):
        bundle.verify_evidence_bundle(
            str(archive),
            trusted_public_key_path=str(public),
            expected_context=_context(repository="other/project"),
        )


def test_context_is_bound_to_record_attestation_before_signing(tmp_path) -> None:
    verdict = tmp_path / "verdict.json"
    archive = tmp_path / "evidence.evb"
    _verdict(verdict)
    private, _public = _keys(tmp_path)
    with pytest.raises(bundle.EvidenceBundleError, match="does not match verdict"):
        _create(
            verdict,
            archive,
            private=private,
            context=_context(candidate_sha256="d" * 64),
        )


def test_structurally_valid_signature_tamper_fails_authentication(tmp_path) -> None:
    verdict = tmp_path / "verdict.json"
    original = tmp_path / "original.evb"
    tampered = tmp_path / "tampered.evb"
    _verdict(verdict)
    private, public = _keys(tmp_path)
    _create(verdict, original, private=private)

    import base64

    fake_signature = base64.b64encode(b"\0" * 64)
    _rewrite(
        original,
        tampered,
        lambda rows: [
            (name, fake_signature if name == bundle.SIGNATURE_PATH else data)
            for name, data in rows
        ],
    )
    bundle.inspect_evidence_bundle(str(tampered))
    with pytest.raises(bundle.EvidenceBundleError, match="signature is invalid"):
        bundle.verify_evidence_bundle(
            str(tampered),
            trusted_public_key_path=str(public),
            expected_context=_context(),
        )


@pytest.mark.parametrize("placement", ["prefix", "suffix"])
def test_unsigned_prefix_and_suffix_bytes_are_rejected(tmp_path, placement) -> None:
    verdict = tmp_path / "verdict.json"
    original = tmp_path / "original.evb"
    mutated = tmp_path / f"{placement}.evb"
    _verdict(verdict)
    private, _public = _keys(tmp_path)
    _create(verdict, original, private=private)
    payload = original.read_bytes()
    mutated.write_bytes(b"UNSIGNED" + payload if placement == "prefix" else payload + b"UNSIGNED")
    with pytest.raises(bundle.EvidenceBundleError, match="canonical ZIP|end record"):
        bundle.inspect_evidence_bundle(str(mutated))


def test_member_reordering_and_nonzero_flags_are_rejected(tmp_path) -> None:
    verdict = tmp_path / "verdict.json"
    original = tmp_path / "original.evb"
    reordered = tmp_path / "reordered.evb"
    flagged = tmp_path / "flagged.evb"
    _verdict(verdict)
    private, _public = _keys(tmp_path)
    material = tmp_path / "junit.xml"
    material.write_bytes(b"<testsuite/>")
    _create(
        verdict,
        original,
        private=private,
        materials=[bundle.EvidenceMaterial("junit", str(material))],
    )

    def reorder(rows):
        by_name = dict(rows)
        return [
            (bundle.MANIFEST_PATH, by_name[bundle.MANIFEST_PATH]),
            (bundle.VERDICT_PATH, by_name[bundle.VERDICT_PATH]),
            (bundle.SIGNATURE_PATH, by_name[bundle.SIGNATURE_PATH]),
            *[(name, data) for name, data in rows if name.startswith("materials/")],
        ]

    _rewrite(original, reordered, reorder)
    with pytest.raises(bundle.EvidenceBundleError, match="canonical order"):
        bundle.inspect_evidence_bundle(str(reordered))

    for flag in (0x0008, 0x0800):
        payload = bytearray(original.read_bytes())
        central = payload.find(b"PK\x01\x02")
        assert central > 0
        struct.pack_into("<H", payload, 6, flag)
        struct.pack_into("<H", payload, central + 8, flag)
        flagged.write_bytes(payload)
        with pytest.raises(bundle.EvidenceBundleError, match="flags must be zero"):
            bundle.inspect_evidence_bundle(str(flagged))


def test_entry_count_is_bounded_before_zipfile_parsing(tmp_path) -> None:
    verdict = tmp_path / "verdict.json"
    original = tmp_path / "original.evb"
    bomb = tmp_path / "count-bomb.evb"
    _verdict(verdict)
    private, _public = _keys(tmp_path)
    _create(verdict, original, private=private)
    payload = bytearray(original.read_bytes())
    end_record = len(payload) - 22
    struct.pack_into("<H", payload, end_record + 8, 10_000)
    struct.pack_into("<H", payload, end_record + 10, 10_000)
    bomb.write_bytes(payload)
    with pytest.raises(bundle.EvidenceBundleError, match="too many archive members"):
        bundle.inspect_evidence_bundle(str(bomb))


def test_archive_comments_and_member_extra_fields_are_rejected(tmp_path) -> None:
    verdict = tmp_path / "verdict.json"
    original = tmp_path / "original.evb"
    commented = tmp_path / "commented.evb"
    extra = tmp_path / "extra-field.evb"
    _verdict(verdict)
    private, _public = _keys(tmp_path)
    _create(verdict, original, private=private)
    with zipfile.ZipFile(original, "r") as old:
        rows = [(item.filename, old.read(item.filename)) for item in old.infolist()]

    with zipfile.ZipFile(commented, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in rows:
            archive.writestr(_info(name), data)
        archive.comment = b"unsigned comment"
    with pytest.raises(bundle.EvidenceBundleError, match="end record"):
        bundle.inspect_evidence_bundle(str(commented))

    with zipfile.ZipFile(extra, "w", compression=zipfile.ZIP_STORED) as archive:
        for index, (name, data) in enumerate(rows):
            info = _info(name)
            if index == 0:
                info.extra = b"\x01\x00\x00\x00"
            archive.writestr(info, data)
    with pytest.raises(bundle.EvidenceBundleError, match="metadata must be empty"):
        bundle.inspect_evidence_bundle(str(extra))


def test_snapshot_rejects_metadata_change_during_read(tmp_path, monkeypatch) -> None:
    verdict = tmp_path / "verdict.json"
    archive = tmp_path / "evidence.evb"
    _verdict(verdict)
    private, _public = _keys(tmp_path)
    _create(verdict, archive, private=private)
    real_fstat = os.fstat
    calls = 0

    def changing_fstat(descriptor):
        nonlocal calls
        calls += 1
        current = real_fstat(descriptor)
        if calls == 1:
            return current
        return SimpleNamespace(
            st_mode=current.st_mode,
            st_dev=current.st_dev,
            st_ino=current.st_ino,
            st_size=current.st_size,
            st_mtime_ns=current.st_mtime_ns + 1,
            st_ctime_ns=current.st_ctime_ns,
            st_file_attributes=getattr(current, "st_file_attributes", 0),
        )

    monkeypatch.setattr(bundle.os, "fstat", changing_fstat)
    with pytest.raises(bundle.EvidenceBundleError, match="changed while it was being read"):
        bundle.inspect_evidence_bundle(str(archive))


def test_published_evidence_schemas_are_valid_json_and_match_v1_constants() -> None:
    root = Path(__file__).resolve().parents[1]
    context_schema = json.loads(
        (root / "evoom_guard" / "schemas" / "evidence-context-1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    manifest_schema = json.loads(
        (root / "evoom_guard" / "schemas" / "evidence-manifest-1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(context_schema)
    Draft202012Validator.check_schema(manifest_schema)
    assert context_schema["additionalProperties"] is False
    assert manifest_schema["properties"]["format"]["const"] == bundle.BUNDLE_FORMAT
    assert (
        manifest_schema["properties"]["authentication"]["properties"]["signature_path"][
            "const"
        ]
        == bundle.SIGNATURE_PATH
    )


def test_context_schema_string_constraints_match_runtime_validator() -> None:
    root = Path(__file__).resolve().parents[1]
    schema = json.loads(
        (root / "evoom_guard" / "schemas" / "evidence-context-1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    limits = {"repository": 512, "repository_id": 256, "run_id": 256}
    lone_surrogate = json.loads('"\\ud800"')

    for field, maximum in limits.items():
        contract = schema["properties"][field]
        assert contract["minLength"] == 1
        assert contract["maxLength"] == maximum
        pattern = re.compile(contract["pattern"])
        samples = [
            "x",
            "é" * maximum,
            "",
            "x" * (maximum + 1),
            "line\nbreak",
            lone_surrogate,
        ]
        for sample in samples:
            schema_accepts = (
                1 <= len(sample) <= maximum and pattern.fullmatch(sample) is not None
            )
            context = _context()
            context[field] = sample
            try:
                bundle._validate_context(context, verdict=None)
            except bundle.EvidenceBundleError:
                runtime_accepts = False
            else:
                runtime_accepts = True
            assert runtime_accepts is schema_accepts, (field, repr(sample))


def test_context_run_attempt_constraints_match_runtime_validator() -> None:
    root = Path(__file__).resolve().parents[1]
    schema = json.loads(
        (root / "evoom_guard" / "schemas" / "evidence-context-1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    contract = schema["properties"]["run_attempt"]
    assert contract == {"type": "integer", "minimum": 1, "maximum": 2_147_483_647}

    for sample in (1, 2_147_483_647, 0, -1, 2_147_483_648, True, "1", None):
        schema_accepts = (
            type(sample) is int
            and contract["minimum"] <= sample <= contract["maximum"]
        )
        context = _context(run_attempt=sample)
        try:
            bundle._validate_context(context, verdict=None)
        except bundle.EvidenceBundleError:
            runtime_accepts = False
        else:
            runtime_accepts = True
        assert runtime_accepts is schema_accepts, repr(sample)


def test_real_bundle_manifest_and_context_validate_against_published_schemas(
    tmp_path,
) -> None:
    root = Path(__file__).resolve().parents[1]
    schema_dir = root / "evoom_guard" / "schemas"
    context_schema = json.loads(
        (schema_dir / "evidence-context-1.schema.json").read_text(encoding="utf-8")
    )
    manifest_schema = json.loads(
        (schema_dir / "evidence-manifest-1.schema.json").read_text(encoding="utf-8")
    )
    registry = Registry().with_resource(
        context_schema["$id"],
        Resource.from_contents(context_schema, default_specification=DRAFT202012),
    )

    verdict = tmp_path / "verdict.json"
    archive = tmp_path / "evidence.evb"
    _verdict(verdict)
    private, _public = _keys(tmp_path)
    _create(verdict, archive, private=private)
    manifest = bundle.inspect_evidence_bundle(str(archive)).manifest

    Draft202012Validator(context_schema).validate(manifest["context"])
    Draft202012Validator(manifest_schema, registry=registry).validate(manifest)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b'{"x":1e9999}', "non-finite"),
        (b'{"x":' + b"1" * 129 + b"}", "128-digit"),
        (("{\"x\":" * 20_000 + "0" + "}" * 20_000).encode(), "strict UTF-8 JSON"),
    ],
    ids=("float-overflow", "huge-integer", "deep-nesting"),
)
def test_json_parser_failures_are_evidence_errors(payload, message) -> None:
    with pytest.raises(bundle.EvidenceBundleError, match=message):
        bundle._load_json_object(payload, "hostile JSON")


def test_context_lone_surrogate_is_an_evidence_error() -> None:
    context = _context(repository=json.loads('"\\ud800"'))
    with pytest.raises(bundle.EvidenceBundleError, match="unpaired surrogate"):
        bundle._validate_context(context, verdict=None)


def test_v1_archive_has_a_stable_golden_digest(tmp_path) -> None:
    private = tmp_path / "fixed-test-key.pem"
    private.write_text(
        "-----BEGIN PRIVATE KEY-----\n"
        "MC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n"
        "-----END PRIVATE KEY-----\n",
        encoding="ascii",
        newline="\n",
    )
    verdict = tmp_path / "verdict.json"
    archive = tmp_path / "golden.evb"
    _verdict(verdict)
    _create(verdict, archive, private=private)
    assert bundle._sha256(archive.read_bytes()) == (
        "f4e095f4e34a9c99c87b4e95c9b7dd0dd735bd138aaaec2e12cc91c48c20efd0"
    )
