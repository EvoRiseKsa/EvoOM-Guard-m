# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""The single-file zipapp build (``ops/build_pyz.py``).

EvoGuard's core is stdlib-only, so it ships as one executable archive. These tests
build ``evo-guard.pyz`` and drive it as a subprocess — proving it is self-contained
(no third-party imports) and, critically, that the CLI's return value becomes the
process **exit code** (a zipapp ``-m`` entry would drop it, making the gate exit 0
on every verdict). Build is stdlib-only, so the suite stays green without extras.
"""

import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard import __version__


def _build(tmp_path, *, root=None) -> str:
    # ops/ is not part of the installed package — add it on demand to import the
    # build helper (keeps the module-level import block clean).
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ops"))
    import build_pyz

    kwargs = {} if root is None else {"root": str(root)}
    return build_pyz.build(str(tmp_path / "evo-guard.pyz"), **kwargs)


def test_pyz_builds_and_reports_version(tmp_path):
    out = _build(tmp_path)
    assert os.path.exists(out) and os.access(out, os.X_OK)
    r = subprocess.run([sys.executable, out, "version"], capture_output=True, text=True, timeout=90)
    assert r.returncode == 0
    assert __version__ in r.stdout


def test_pyz_exposes_github_attestation_admission_cli_contract(tmp_path):
    out = _build(tmp_path)
    sealed = subprocess.run(
        [sys.executable, out, "seal-github-attestation-admission", "--help"],
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert sealed.returncode == 0, sealed.stdout + sealed.stderr
    assert "--receipt-out" in sealed.stdout
    assert "--raw-output-out" in sealed.stdout
    assert "--finalizer-pub" in sealed.stdout
    assert "--expected-context" in sealed.stdout
    assert "--sign-key" in sealed.stdout
    assert "--force" not in sealed.stdout

    verified = subprocess.run(
        [sys.executable, out, "verify-github-attestation-admission", "--help"],
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert "--trusted-pub" in verified.stdout
    assert "--finalizer-pub" in verified.stdout
    assert "--expected-source" in verified.stdout


def test_pyz_contains_the_offline_record_verifier(tmp_path):
    out = _build(tmp_path)
    record = tmp_path / "invalid-record.json"
    record.write_text("{}\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, out, "verify-record", str(record)],
        capture_output=True,
        text=True,
        timeout=90,
    )

    assert result.returncode == 1, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["record_verifier"] == "evoguard"
    assert report["record_verifier_version"] == "1.0"
    assert report["ok"] is False
    assert report["input_sha256"] == hashlib.sha256(record.read_bytes()).hexdigest()


def test_pyz_build_is_byte_reproducible(tmp_path):
    first = _build(tmp_path / "first")
    second = _build(tmp_path / "second")

    with open(first, "rb") as first_file, open(second, "rb") as second_file:
        assert first_file.read() == second_file.read()

    with zipfile.ZipFile(first) as archive:
        entries = archive.infolist()
        names = {entry.filename for entry in entries}
        assert [entry.filename for entry in entries] == sorted(
            entry.filename for entry in entries
        )
        assert all(entry.date_time == (1980, 1, 1, 0, 0, 0) for entry in entries)
        assert {
            "evoom_guard/artifact_admission.py",
            "evoom_guard/artifact_digest_admission.py",
            "evoom_guard/github_attestation.py",
            "evoom_guard/schemas/artifact-binding-1.schema.json",
            "evoom_guard/schemas/artifact-digest-binding-2.schema.json",
            "evoom_guard/schemas/github-attestation-receipt-1.schema.json",
            "LICENSE",
            "evoom_guard/schemas/evidence-context-1.schema.json",
            "evoom_guard/schemas/evidence-manifest-1.schema.json",
            "evoom_guard/schemas/verdict-record-1.11.schema.json",
        } <= names
        assert archive.read("LICENSE") == (
            Path(__file__).parents[1].joinpath("LICENSE").read_bytes()
            .replace(b"\r\n", b"\n")
            .replace(b"\r", b"\n")
        )


def test_pyz_build_is_identical_from_lf_and_crlf_source_trees(tmp_path):
    sources = {
        "__init__.py": b'__version__ = "test"\n',
        "cli.py": (
            b'def main():\n'
            b'    message = "logical source is unchanged"\n'
            b'    return 0 if message else 1\n'
        ),
        "nested/module.py": b'VALUE = "same"\n',
        "schemas/example.schema.json": b'{\n  "type": "object"\n}\n',
    }
    non_python_payload = b"binary-like\r\npayload\rwith-newlines\n"

    roots = {}
    for checkout, newline in (("lf", b"\n"), ("crlf", b"\r\n")):
        root = tmp_path / checkout
        package = root / "evoom_guard"
        for relative, source in sources.items():
            path = package / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(source.replace(b"\n", newline))
        (root / "LICENSE").write_bytes(b"test license\n".replace(b"\n", newline))
        (package / "payload.bin").write_bytes(non_python_payload)
        roots[checkout] = root

    lf_build = _build(tmp_path / "lf-build", root=roots["lf"])
    crlf_build = _build(tmp_path / "crlf-build", root=roots["crlf"])
    lf_bytes = Path(lf_build).read_bytes()
    crlf_bytes = Path(crlf_build).read_bytes()

    assert lf_bytes == crlf_bytes
    assert hashlib.sha256(lf_bytes).digest() == hashlib.sha256(crlf_bytes).digest()
    with zipfile.ZipFile(crlf_build) as archive:
        for name in sources:
            archived = archive.read(f"evoom_guard/{name}")
            assert b"\r" not in archived
        assert archive.read("evoom_guard/payload.bin") == non_python_payload
        assert archive.read("LICENSE") == b"test license\n"


def test_pyz_build_refuses_to_omit_the_license(tmp_path):
    root = tmp_path / "unlicensed"
    package = root / "evoom_guard"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text('__version__ = "test"\n', encoding="utf-8")

    with pytest.raises(FileNotFoundError, match="LICENSE not found"):
        _build(tmp_path / "build", root=root)


def test_pyz_exit_codes_propagate(tmp_path):
    out = _build(tmp_path)
    # doctor → environment OK → exit 0
    assert subprocess.run([sys.executable, out, "doctor"], capture_output=True, timeout=90).returncode == 0
    # no subcommand → argparse usage error → exit 2 (proves main()'s int return is
    # the process exit code, not silently 0).
    assert subprocess.run([sys.executable, out], capture_output=True, timeout=90).returncode == 2


def test_pyz_guard_gates_with_correct_exit_codes(tmp_path):
    out = _build(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "m.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")  # bug
    (repo / "test_m.py").write_text(
        "from m import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8"
    )
    fix = tmp_path / "fix.patch"
    fix.write_text("<<<FILE: m.py>>>\ndef add(a, b):\n    return a + b\n<<<END FILE>>>", encoding="utf-8")
    hack = tmp_path / "hack.patch"
    hack.write_text(
        "<<<FILE: test_m.py>>>\ndef test_add():\n    assert True\n<<<END FILE>>>", encoding="utf-8"
    )

    # honest fix → PASS → exit 0
    p = subprocess.run(
        [sys.executable, out, "guard", str(repo), "--patch", str(fix)],
        capture_output=True, text=True, timeout=180,
    )
    assert p.returncode == 0, p.stdout + p.stderr

    # reward-hack (edits the test) → REJECTED → exit 1 (the gate blocks)
    h = subprocess.run(
        [sys.executable, out, "guard", str(repo), "--patch", str(hack)],
        capture_output=True, text=True, timeout=180,
    )
    assert h.returncode == 1
